//! Cold start: prepare the boot, bind it, boot it and register its host services.

use super::admission::{admitted_ingress, admitted_network_limits};
use super::broker::admitted_broker_bindings;
use super::*;

impl<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    /// Maps an already-bound configuration into a backend boot. Production
    /// callers must hold the lifecycle lease and pass the verifier's paths.
    #[cfg(test)]
    pub(super) fn boot_bound_workload(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
    ) -> Result<Box<dyn RunningVm>> {
        self.boot_bound_workload_guarded(inputs, None, Vec::new(), None)
    }

    pub(super) fn require_caller_registration_shape(&self, config: &VmStartConfig) -> Result<()> {
        if config.caller_registration.is_some() {
            anyhow::ensure!(
                self.driver.kind() == mvm_core::vm_backend::BackendKind::Hvf,
                "caller registration requires a cold HVF workload"
            );
            let plan = config
                .plan_json
                .as_deref()
                .context("caller registration requires a signed plan")?;
            serde_json::from_str::<mvm_core::plan::SignedExecutionPlan>(plan)
                .context("caller registration requires a signed plan")?;
        }
        Ok(())
    }

    pub(super) fn check_installed_endpoint_inputs(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
    ) -> Result<()> {
        #[cfg(unix)]
        if inputs.config.host_lifetime.is_some() {
            anyhow::ensure!(
                self.driver.supports_host_lifetime(),
                "installed native backend unavailable"
            );
            anyhow::ensure!(
                inputs.network_policy == &inputs.config.network_policy,
                "installed endpoint policy differs from launch configuration"
            );
        }
        anyhow::ensure!(
            !cmdline::uses_installed_payload_anchor(inputs.config)
                || (mvm_agentd::vsock::host_signer_pub_token(&inputs.cmdline).is_none()
                    && (!cfg!(target_os = "linux")
                        || !inputs
                            .cmdline
                            .split_ascii_whitespace()
                            .any(|token| token.starts_with("mvm.verb_grant=")
                                || token.starts_with("mvm.require_grant=")))),
            "installed workload cmdline contains an unbound host signer anchor"
        );
        #[cfg(unix)]
        if cmdline::uses_installed_payload_anchor(inputs.config) {
            anyhow::ensure!(
                self.spawner.supports_registered_installed_endpoint(),
                "registered installed endpoint startup unavailable"
            );
        }
        Ok(())
    }

    /// Prepare the same policy, endpoint and device mapping for both ordinary
    /// boots and the concrete owned cold channel.
    pub(super) fn prepare_workload_boot(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
        mailbox_runtime: Option<&crate::runtime_evidence::VerifiedMailboxReader>,
    ) -> Result<PreparedWorkloadBoot> {
        self.check_installed_endpoint_inputs(inputs)?;
        // A caller times this call from outside and cannot see past it, yet the
        // VMM boot and every post-boot registration happen in here. Off unless
        // a measurement asked for it.
        let mut trace =
            mvm_core::launch_trace::LaunchTraceRecorder::new(self.driver.kind().as_str());

        let state_dir = vm_state_dir(&inputs.config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;
        crate::base::runtime_meta::record_from_start_config(
            &inputs.config.name,
            StartMode::Detached,
            inputs.config,
        )?;
        let network_limits = admitted_network_limits(inputs.config.plan_json.as_deref())?;
        let ingress = admitted_ingress(inputs.config.plan_json.as_deref())?;
        let reader_plan = inputs
            .config
            .plan_json
            .as_deref()
            .map(mvm_core::plan::plan_from_admitted_json)
            .transpose()
            .context("parse admitted mailbox reader plan")?;

        // Spawn the per-child substitution endpoint through the shared
        // `ClaimGuards`, so a warm claim stands up the identical guarded endpoint
        // a cold boot does, keyed on this VM's own id. A deny-all, secret-free
        // workload receives no egress channel and therefore needs no process.
        let guards = ClaimGuards::new(&self.spawner);
        let socks = standing_sockets(&state_dir, inputs.config);
        let endpoint_inputs = EndpointSpawnInputs {
            state_dir: &state_dir,
            tenant: inputs.tenant,
            secrets: inputs.secrets,
            redaction: inputs.redaction,
            network_policy: inputs.network_policy,
            network_limits,
            ingress: &ingress,
            reader_plan: reader_plan.as_ref().filter(|plan| plan.mailbox.is_some()),
            mailbox_runtime,
            // A cold boot mints this guest's identity and hands it a drive.
            identity: FlowMuxIdentitySource::Mint,
        };
        #[cfg(unix)]
        let installed = if let Some(owner) = &inputs.config.host_lifetime {
            let slot = self
                .installed
                .find(&VmId(inputs.config.name.clone()))?
                .context("original installed slot missing")?;
            anyhow::ensure!(slot.matches(owner), "installed launch owner differs");
            owner.verify_config(inputs.config, self.driver.kind())?;
            Some(slot)
        } else {
            None
        };
        let mut boot_cmdline = inputs.cmdline.clone();
        #[cfg(unix)]
        let endpoint = if let Some(slot) = &installed {
            let id = VmId(inputs.config.name.clone());
            if cmdline::uses_installed_payload_anchor(inputs.config) {
                let registrar = self
                    .installed_agent
                    .get()
                    .context("original installed host agent missing")?;
                let (services, capabilities) =
                    admitted_broker_bindings(inputs.config.plan_json.as_deref())?;
                let request = BrokerRegisterRequest {
                    vm_name: &inputs.config.name,
                    state_dir: &state_dir,
                    tenant: inputs.config.tenant_id.as_deref(),
                    broker_listen_socket: socks.broker.as_deref(),
                    services: &services,
                    capability_bindings: &capabilities,
                    service_proxies: &inputs.config.service_proxies,
                };
                let broker = match self.broker.register_installed(&request, registrar) {
                    Ok(broker) => broker,
                    Err(error) => {
                        let failed = error
                            .downcast::<mvm_vmm::host::host_agent_spawn::OwnedRegistrationError>(
                        )?;
                        let (reason, registration) = failed.into_parts();
                        slot.retain_broker(BrokerGuard::from_owned_registration(registration))?;
                        return Err(reason);
                    }
                };
                trace.degrade_unless("host_services", broker.services_healthy(&services));
                slot.retain_broker(broker)?;
                trace.mark("broker_register");
                let registration = slot.broker_registration()?;
                let original = mvm_vmm::host::network_endpoint_spawn::InstalledHostServices::new(
                    registrar,
                    &registration,
                    request.host_agent_params()?,
                )?;
                original.append_host_signer_cmdline(&mut boot_cmdline)?;
                #[cfg(target_os = "linux")]
                crate::microvm::activation::append_registered_boot_grant(
                    inputs.config,
                    &mut boot_cmdline,
                )
                .context(installed::StartupStage::RegisteredBootGrant)?;
                slot.begin_endpoint_start()?;
                guards.spawn_endpoint_installed(
                    &id,
                    &endpoint_inputs,
                    inputs.config,
                    Some(&original),
                )?
            } else {
                slot.begin_endpoint_start()?;
                guards.spawn_endpoint_installed(&id, &endpoint_inputs, inputs.config, None)?
            }
        } else {
            guards.spawn_endpoint(&VmId(inputs.config.name.clone()), &endpoint_inputs)?
        };
        #[cfg(not(unix))]
        let endpoint =
            guards.spawn_endpoint(&VmId(inputs.config.name.clone()), &endpoint_inputs)?;
        let identity_drive = endpoint.identity_drive().map(Path::to_path_buf);
        let egress_uds = endpoint.egress_uds().map(Path::to_path_buf);
        #[cfg(unix)]
        let endpoint = if let Some(slot) = &installed {
            slot.retain_endpoint(endpoint)?;
            None
        } else {
            Some(endpoint)
        };
        #[cfg(not(unix))]
        let endpoint = Some(endpoint);
        trace.mark("endpoint_spawn");

        if let Some(token) =
            mvm_vmm::host::egress_bridge::telemetry_cmdline_token(&inputs.config.name)
        {
            append_cmdline_token(&mut boot_cmdline, &token);
        }
        if let Some(problem) = cmdline::cmdline_overflow(&boot_cmdline) {
            anyhow::bail!("refusing to start VM {}: {problem}", inputs.config.name);
        }

        // A GPU launch gets its host endpoint before the spec is assembled:
        // the channel the guest dials must already have a listener, and the
        // socket path the endpoint bound is by construction the one
        // `standing_sockets` resolves for the spec.
        if inputs.config.gpu {
            let gpu_transport = Self::gpu_endpoint_transport(self.driver.kind(), &state_dir);
            mvm_vmm::host::gpu_endpoint_spawn::spawn_gpu_endpoint(
                &inputs.config.name,
                &state_dir,
                gpu_transport,
                inputs.config.gpu_device,
            )
            .context("spawning the GPU endpoint")?;
        }
        let spec = workload_spec(&WorkloadSpecInputs {
            config: inputs.config,
            identity_drive: identity_drive.as_deref(),
            sockets: socks.with_egress(egress_uds.as_deref()),
            cmdline: boot_cmdline,
            console_log: socks.console_log.clone(),
        });

        trace.mark("spec_assembly");

        Ok(PreparedWorkloadBoot {
            spec,
            socks,
            endpoint,
            #[cfg(unix)]
            installed,
            trace: Some(trace),
        })
    }

    /// Maps an already-bound configuration into a backend boot. Production
    /// callers must hold the lifecycle lease and pass the verifier's paths.
    pub(super) fn boot_bound_workload_guarded(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
        kernel: Option<&crate::kernel_custody::KernelBoundLaunch>,
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        mailbox_runtime: Option<&crate::runtime_evidence::VerifiedMailboxReader>,
    ) -> Result<Box<dyn RunningVm>> {
        anyhow::ensure!(
            (inputs.config.canonical_kernel.is_none()
                && inputs.config.kernel_read_sha256.is_none())
                || kernel.is_some(),
            "canonical kernel launch has no actual final-config custody guard"
        );
        if let Some(kernel) = kernel {
            anyhow::ensure!(
                std::ptr::eq(inputs.config, kernel.config()),
                "launch substituted the final config object"
            );
        }
        let PreparedWorkloadBoot {
            spec,
            socks,
            mut endpoint,
            #[cfg(unix)]
            installed,
            trace,
        } = self.prepare_workload_boot(inputs, mailbox_runtime)?;
        let mut trace = trace.context("prepared workload launch trace missing")?;
        let state_dir = vm_state_dir(&inputs.config.name);
        // Unconditional and best-effort. The follower can wait for a console
        // file that does not exist yet, so install it alongside VMM boot rather
        // than serializing its process setup after guest readiness.
        let capture = ConsoleCapture {
            vm_name: &inputs.config.name,
            supervisor_owned: supervisor_owns_console(self.driver.kind()),
            console_log: &socks.console_log,
            display_socket: socks.display.as_deref(),
            redaction: inputs.redaction,
            retention: plan_stream_retention(inputs.config.plan_json.as_deref()),
        };
        durability::wait_for_unactivated_boot(inputs.config)?;
        if let Some(kernel) = kernel {
            kernel.before_boot(&spec)?;
        }
        let streamer = Arc::clone(&self.console_streamer);
        #[cfg(unix)]
        let disks = mvm_vmm::driver::prepared_disks::PreparedWritableDisks::bind_sources(
            &spec,
            writable_images,
        )?;
        let boot = console_boot::boot_while_starting_console(
            || {
                #[cfg(unix)]
                {
                    if let Some(slot) = &installed {
                        slot.begin_native_dispatch()?;
                    }
                    match kernel {
                        Some(kernel) => kernel.boot_custodied(&self.driver, &spec, disks),
                        None => {
                            disks.validate_spec(&spec)?;
                            self.driver.boot_custodied(
                                &spec,
                                mvm_vmm::driver::prepared_disks::PreparedBootFiles {
                                    kernel: None,
                                    workload_root: None,
                                    writable: disks,
                                    data: None,
                                },
                            )
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    match kernel {
                        Some(kernel) => kernel.boot(&self.driver, &spec),
                        None => self.driver.boot(&spec),
                    }
                }
            },
            || streamer.start(&capture),
            || trace.mark("driver_boot"),
        );
        let vm = match boot {
            Ok(vm) => vm,
            Err(error) => {
                return Err(cold_hvf_channel::retain_boot_error(
                    error,
                    (endpoint, Arc::clone(&self.console_streamer)),
                ));
            }
        };
        #[cfg(unix)]
        let vm = if let Some(slot) = &installed {
            slot.retain_vm(vm)?
        } else {
            vm
        };
        if let Some(kernel) = kernel {
            let observation = kernel.observe_booted(&*vm);
            #[cfg(unix)]
            let observation = if installed.is_some() {
                observation.context(installed::StartupStage::KernelObservation)
            } else {
                observation
            };
            observation?;
        }
        trace.mark("console_stream_start");

        // Universal initramfs path: the guest PID-1 agent waits for a signed
        // ActivateEnvironment before exposing operational RPCs. Send it now,
        // while the broker registration below still has a guard that rolls back
        // on failure. A rootfs boot whose universal initramfs could not be
        // resolved was refused at launch resolution, before the VMM started.
        if crate::microvm::booted_with_universal_initramfs(inputs.config) {
            durability::wait_for_activation(inputs.config, &*vm, &*self.console_streamer)?;
            #[cfg(unix)]
            if let Some(owner) = &inputs.config.host_lifetime {
                owner.check_parent_current(inputs.config, self.driver.kind())?;
            }
            trace.mark("admission_durable");
            #[cfg(target_os = "linux")]
            let retained = if let Some(slot) = installed.as_ref() {
                slot.activate_entrypoint(&*vm, inputs.config, &spec.cmdline)
                    .context(installed::StartupStage::GuestActivation)?
            } else {
                false
            };
            #[cfg(not(target_os = "linux"))]
            let retained = false;
            if !retained {
                let activation = crate::microvm::activate_workload(&*vm, inputs.config);
                #[cfg(unix)]
                let activation = if installed.is_some() {
                    activation.context(installed::StartupStage::GuestActivation)
                } else {
                    activation
                };
                activation.context("activate workload after boot")?;
            }
        }
        trace.mark("activate_workload");

        #[cfg(unix)]
        if cmdline::uses_installed_payload_anchor(inputs.config) {
            trace.write_to(&state_dir);
            return Ok(vm);
        }

        // Register the per-VM broker for the exact admitted host-service set.
        // The guard's Drop reaps on any early return until it is defused. A
        // requested service whose broker cannot start fails the launch closed.
        let (mut broker_guard, services) = self.register_workload_broker(inputs.config, &socks)?;
        trace.mark("broker_register");
        trace.degrade_unless("host_services", broker_guard.services_healthy(&services));
        #[cfg(unix)]
        if let Some(slot) = installed {
            slot.retain_broker(broker_guard)?;
            trace.write_to(&state_dir);
            return Ok(vm);
        }
        endpoint
            .as_mut()
            .context("legacy endpoint missing")?
            .defuse();
        broker_guard.defuse();
        trace.write_to(&state_dir);
        Ok(vm)
    }

    pub(super) fn register_workload_broker(
        &self,
        config: &VmStartConfig,
        socks: &sockets::StandingSockets,
    ) -> Result<(BrokerGuard, Vec<ServiceId>)> {
        let state_dir = vm_state_dir(&config.name);
        let (services, capability_bindings) =
            admitted_broker_bindings(config.plan_json.as_deref())?;
        let guard = self.broker.register(&BrokerRegisterRequest {
            vm_name: &config.name,
            state_dir: &state_dir,
            tenant: config.tenant_id.as_deref(),
            broker_listen_socket: socks.broker.as_deref(),
            services: &services,
            capability_bindings: &capability_bindings,
            service_proxies: &config.service_proxies,
        })?;
        Ok((guard, services))
    }
}
