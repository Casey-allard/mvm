//! Persistent-machine boot path for OCI-image / manifest-backed VMs —
//! resolves the runtime-source policy, the effective kernel/initrd, and
//! runs admission before handing the prepared `VmStartConfig` to the
//! selected backend.

use anyhow::{Context, Result};

use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::naming::validate_vm_name;
use mvm_hostd::plan_admission::{
    InMemoryNonceLedger, populate_audit_substrate, stash_plan_for_bridge, thread_tenant_id,
};

use crate::launch::start_params::VmStartParams;

use crate::record_readiness as record_vm_readiness;

use super::runtime_source::{
    attach_runtime_overlay_if_cached, attach_universal_initramfs_if_cached,
    emit_runtime_source_status,
};
use crate::admission::policy::shares_from_volume_cfg;
use crate::admission::{
    AdmitPlanForBootParams, admit_plan_for_boot_configured_ingress, attach_guest_boot_config,
    emit_failed, emit_launched, enforce_kernel, enforce_shares, guest_profile_for_boot,
};

fn preopen_console_for_profile(profile: &str) -> bool {
    profile == "dev"
}

/// Whether the admitted plan must be persisted to `<state_dir>/plan.json`
/// *before* `backend.start()`. Every backend whose `start()` reads that file
/// off disk to decide whether to stand up its egress endpoint needs the pre-start
/// persist:
///
/// - **Firecracker / libkrun / hvf / apple-container**: the runner-backed
///   endpoint reads `<state_dir>/plan.json` during endpoint setup. The
///   apple-container backend holds the same HVF runner, so its `start()` reads
///   the same file.
///
/// QEMU is excluded: it reads the in-memory config and must not overwrite the
/// persisted plan.
pub fn persists_plan_before_start(hypervisor: &str) -> bool {
    matches!(
        hypervisor,
        "firecracker" | "libkrun" | "hvf" | "apple-container"
    )
}

pub use crate::admission::secrets::load_workload_ir;

pub struct PersistentImageStartParams<'a> {
    pub name: &'a str,
    pub image_label: &'a str,
    pub resolved_digest: &'a str,
    pub rootfs_path: &'a std::path::Path,
    pub profile: &'a str,
    pub cpus: u32,
    pub memory_mib: u32,
    pub mem_initial_mib: Option<u32>,
    /// The machine's volumes, already merged with its registered ones and
    /// leased for this launch. The leases are committed once the backend has
    /// started and released if it does not.
    pub prepared_volumes: crate::volume::LaunchPreparation,
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Loopback ingress mappings persisted with the machine.
    pub ports: &'a [String],
    /// Concrete backend selected by the caller.
    pub backend_name: &'a str,
    /// The workload kernel to boot, or `None` for the in-memory mock, which
    /// boots nothing. Resolved by the
    /// caller: the CLI may build one through the builder VM, and a library
    /// embedder never builds.
    pub kernel_path: Option<String>,
    /// Raw `--agent-verb` strings from the CLI. Empty ⇒ use the computed
    /// sealed-prod default.
    pub agent_verb: Vec<String>,
    /// Opaque commitment persisted with and admitted for this machine.
    pub caller_commitment: Option<mvm_core::plan::CallerCommitment>,
    /// Publisher-verified image pack to bind on every start, if selected.
    pub registry_pack_image: Option<mvm_core::registry_pack::PackPin>,
    /// True when the caller will run a trailing `-- argv` command after boot
    /// (i.e. the machine is booted only to exec an ad-hoc command). An ad-hoc
    /// command issues the DevOnly `Exec` verb, so the admitted plan must NOT
    /// carry an attenuated ProdSafe-only grant. Baked-entrypoint boots (no
    /// trailing argv, non-dev profile) may still receive the grant.
    pub has_ad_hoc_argv: bool,
    /// The machine spec's resolved permission set, baked into the signed plan
    /// on every start. Its egress dimension is already reflected in
    /// [`network_policy`](Self::network_policy), which the caller derived from
    /// the same spec.
    pub grants: Option<mvm_contract::grants::Grants>,
    pub mailbox: Option<mvm_contract::protocol::mailbox::MailboxGrant>,
    /// GPU remoting plane from the persisted spec (`--gpu` at create/start).
    pub gpu: bool,
    /// Optional host GPU ordinal persisted with the machine.
    pub gpu_device: Option<u32>,
    /// Local workload source directory to scan for project instruction files and
    /// policies on each start, when the persistent machine came from one.
    pub workload_dir: Option<&'a std::path::Path>,
    /// The machine's recorded secret references, already validated against
    /// the caller's secret service.
    pub secrets: crate::admission::secrets::ResolvedPlanSecrets,
    /// The backend that starts the VM, an instance of `backend_name`.
    pub backend: mvm_runtime::backend::AnyBackend,
}

/// The network mode every newly admitted networked workload uses: the
/// authenticated, host-mediated FlowMux endpoint. The raw-packet mode is
/// retired.
pub fn preflight_network() -> mvm_contract::plan::NetworkMode {
    mvm_contract::plan::NetworkMode::HostVsockProxy
}

/// Parse a port mapping: `HOST:GUEST`, or a single port used on both sides.
pub fn parse_port_spec(spec: &str) -> Result<(u16, u16)> {
    if let Some((local, guest)) = spec.split_once(':') {
        let local: u16 = local
            .parse()
            .with_context(|| format!("invalid local port '{}'", local))?;
        let guest: u16 = guest
            .parse()
            .with_context(|| format!("invalid guest port '{}'", guest))?;
        Ok((local, guest))
    } else {
        let port: u16 = spec
            .parse()
            .with_context(|| format!("invalid port '{}'", spec))?;
        Ok((port, port))
    }
}

fn machine_port_ingress(ports: &[String]) -> Result<Vec<mvm_core::plan::IngressMapping>> {
    ports
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            let (host, guest) = parse_port_spec(mapping)?;
            let mapping_id = u16::try_from(index + 1)
                .context("too many declared ingress mappings for the signed plan")?;
            mvm_core::plan::IngressMapping::builder()
                .mapping_id(mapping_id)
                .protocol(mvm_core::plan::IngressProtocol::Tcp)
                .host_addr("127.0.0.1")
                .host_port(host)
                .guest_addr("127.0.0.1")
                .guest_port(guest)
                .transform(mvm_core::plan::IngressTransform::Opaque)
                .build()
                .with_context(|| format!("lowering declared ingress mapping {mapping:?}"))
        })
        .collect()
}

/// Resolve the initrd a persistent OCI boot should carry.
///
/// Sealed OCI boots rely on the universal initramfs; the legacy per-rootfs
/// verity initrd is no longer supported. The universal initramfs attach step
/// later in the boot sets `initrd_path`, so this function returns `None` and
/// lets that step own the initramfs.
///
/// This is the boot-policy contract surface the dev-only conformance harness
/// drives directly; it is re-exported at `mvm_cli::boot_policy` for that
/// harness and is not a general-purpose API.
pub fn persistent_oci_effective_initrd(_rootfs_path: &std::path::Path) -> Result<Option<String>> {
    Ok(None)
}

fn register_vm_name(vm_name: &str, network_name: &str) {
    // Through the client boundary: mvm-client owns the host name-registry reach
    // (load → deregister-stale → register → save), so the CLI stays off the
    // runtime crate's registry internals.
    crate::register_machine(&crate::MachineRegistration {
        vm_dir: mvm_core::config::vm_state_dir(vm_name)
            .to_string_lossy()
            .into_owned(),
        ..crate::MachineRegistration::minimal(vm_name, network_name)
    });
}

/// Admit and start a persistent machine. Returns the admitted plan the
/// machine booted under.
pub fn start_persistent_oci_machine(
    params: PersistentImageStartParams<'_>,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    let vacant = super::mailbox_owner::VacantOwner::claim(params.name)?;
    start_persistent_with_mailbox(params, None, vacant)
}

pub(super) fn start_persistent_with_mailbox(
    params: PersistentImageStartParams<'_>,
    provisioner: Option<&dyn super::mailbox_owner::InstalledMailboxProvisioner>,
    vacant: super::mailbox_owner::VacantOwner,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    let mut cancellation = provisioner
        .and_then(|p| p.original_cast_pair())
        .map(|pair| pair.cancel_on_drop(params.name));
    let PreparedPersistentBoot {
        backend,
        start_config,
        admission,
        prepared_volumes,
        built_runtime: _built_runtime,
    } = prepare_persistent_boot(params)?;
    let name_label = start_config.name.clone();
    let name = name_label.as_str();
    let backend_label = backend.name().to_string();
    let backend_name = backend_label.as_str();
    let result = finish_persistent(
        backend,
        start_config,
        admission,
        prepared_volumes,
        name,
        backend_name,
        provisioner,
        vacant,
    );
    if result.is_ok() {
        if let Some(c) = &mut cancellation {
            c.disarm();
        }
    }
    result
}
struct PreparedPersistentBoot {
    backend: mvm_runtime::backend::AnyBackend,
    start_config: mvm_core::vm_backend::VmStartConfig,
    admission: crate::admission::AdmissionContext,
    prepared_volumes: crate::volume::LaunchPreparation,
    built_runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
}

fn prepare_persistent_boot(
    params: PersistentImageStartParams<'_>,
) -> Result<PreparedPersistentBoot> {
    let PersistentImageStartParams {
        name,
        image_label,
        resolved_digest,
        rootfs_path,
        profile,
        mut cpus,
        memory_mib,
        mem_initial_mib,
        prepared_volumes,
        network_policy,
        ports,
        backend_name,
        kernel_path,
        agent_verb,
        caller_commitment,
        registry_pack_image,
        has_ad_hoc_argv,
        grants,
        mailbox,
        gpu,
        gpu_device,
        workload_dir,
        secrets: resolved_secrets,
        backend,
    } = params;
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    if let Some(granted) = crate::clamp_vcpus_for_backend(backend_name, cpus) {
        mvm_runtime::ui::warn(&format!(
            "{backend_name} supports at most {granted} vCPU(s); {cpus} requested, booting with {granted}"
        ));
        tracing::info!(
            backend = backend_name,
            requested = cpus,
            granted,
            "vcpu request clamped to the backend ceiling"
        );
        cpus = granted;
    }
    crate::admission::instructions::refuse_wasm_host_snapshots(
        backend.kind(),
        &prepared_volumes
            .volumes
            .iter()
            .filter_map(|volume| {
                volume.materialized_image.as_deref().map(|image| {
                    crate::admission::instructions::MaterializedMount {
                        host_path: std::path::PathBuf::from(&volume.host),
                        image_path: std::path::PathBuf::from(image),
                    }
                })
            })
            .collect::<Vec<_>>(),
    )?;
    let volumes = &prepared_volumes.volumes;
    register_vm_name(name, "default");
    let (verity_path, roothash) =
        mvm_runtime::microvm::probe_verity_sidecar(&rootfs_path.to_string_lossy());
    let initrd_path = persistent_oci_effective_initrd(rootfs_path)?;
    let bundle_archive = super::bundle_runtime::installed_archive_for_rootfs(rootfs_path)?;

    let mut start_config = VmStartParams::builder()
        .name(name.to_string())
        .rootfs_path(rootfs_path.display().to_string())
        .vmlinux_path(kernel_path.unwrap_or_default())
        .initrd_path(initrd_path)
        .verity_path(verity_path)
        .roothash(roothash)
        .revision_hash(resolved_digest.to_string())
        .flake_ref(format!("oci:{image_label}"))
        .profile(profile.to_string())
        .cpus(cpus)
        .memory_mib(memory_mib)
        .mem_initial_mib(mem_initial_mib)
        .volumes(volumes)
        .config_files(&[])
        .secret_files(&[])
        .port_mappings(&[])
        // Persistent named machines are long-lived; they are not transient
        // auto-named launches and are never claimed from the warm standby pool.
        .warm_pool_size(0)
        .network_policy(network_policy.clone())
        .gpu(gpu)
        .gpu_device(gpu_device)
        .build()?
        .into_start_config();
    // Only dev-profile machines can be attached to later with `machine shell`
    // or `machine console`. Keep the host-side console listeners absent for
    // sealed production boots; the guest profile and verb grant remain the
    // authoritative RPC gates as well.
    start_config.dev_console = preopen_console_for_profile(profile);
    // Everything the boot waits on is prepared before admission, because
    // admission starts the plan's validity window and the verb grant minted
    // from it lives exactly as long. See `crate::launch::boot_order`.
    let admission = crate::launch::boot_order::admit_after_preparation(
        &mut start_config,
        |config| {
            attach_runtime_overlay_if_cached(config, backend_name)?;
            attach_universal_initramfs_if_cached(config, backend_name)
        },
        |config| {
            let admission_ledger = InMemoryNonceLedger::new();
            let ingress = machine_port_ingress(ports)?;
            let instruction_mounts = volumes
                .iter()
                .filter_map(|volume| {
                    volume.materialized_image.as_deref().map(|image| {
                        crate::admission::instructions::MaterializedMount {
                            host_path: std::path::PathBuf::from(&volume.host),
                            image_path: std::path::PathBuf::from(image),
                        }
                    })
                })
                .collect::<Vec<_>>();
            admit_plan_for_boot_configured_ingress(
                AdmitPlanForBootParams {
                    mailbox,
                    // What the backend will arm, so the admitted tier opens
                    // the GPU endpoint's vsock socket exactly when there is one.
                    gpu: config.gpu,
                    instructions: crate::admission::InstructionSources::for_workload(workload_dir)
                        .with_mount_roots(&[])
                        .with_materialized_mounts(&instruction_mounts),
                    outputs: Vec::new(),
                    network_mode: preflight_network(),
                    tenant: "local",
                    vm_name: name,
                    backend_name,
                    configured_images_dir: mvm_build::image_source::configured_images_dir()
                        .as_deref(),
                    rootfs_path,
                    kernel_path: config.kernel_path.as_deref().map(std::path::Path::new),
                    precomputed_image_sha256: None,
                    boot_artifact_identity: None,
                    runtime_config: Some(config),
                    cpus,
                    mem_mib: u64::from(memory_mib),
                    seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                    secret_release: resolved_secrets.secret_release,
                    secrets: resolved_secrets.secrets,
                    caller_commitment,
                    ledger: &admission_ledger,
                    keys_dir: None,
                    audit_dir: None,
                    policy_dir: None,
                    bundle_pin: bundle_archive
                        .as_deref()
                        .map(crate::admission::BundlePin::boots),
                    bundle_posture: None,
                    deps_volume: None,
                    shares: shares_from_volume_cfg(volumes),
                    assets: registry_pack_image
                        .into_iter()
                        .map(crate::admission::AssetSpec::RegistryPack)
                        .collect(),
                    redaction: mvm_core::policy::RedactionPolicy::default(),
                    network_policy: network_policy.clone(),
                    agent_verb_override: agent_verb.to_vec(),
                    // Persistent machines carrying a trailing argv run an ad-hoc Exec (DevOnly);
                    // they must not receive an attenuated ProdSafe-only grant. Baked-entrypoint
                    // boots (no argv, non-dev profile) keep the grant.
                    restrict_agent_verbs: crate::admission::agent_verbs::grant_eligible(
                        false,
                        has_ad_hoc_argv,
                        profile == "dev",
                    ),
                    services: Vec::new(),
                    grants,
                    // The typed kind of the backend this start resolved, so the grant gate
                    // measures a declared bound against the mechanisms that tier has rather
                    // than refusing for want of an answer.
                    backend_kind: Some(crate::backend_kind_for(backend_name)),
                    entrypoint:
                        crate::admission::entrypoint_resolve::ResolvedEntrypoint::for_launch(
                            rootfs_path,
                            has_ad_hoc_argv,
                        ),
                },
                ingress,
            )
        },
    )?;
    for volume in &mut start_config.volumes {
        if admission
            .admitted
            .plan()
            .shares
            .iter()
            .any(|share| share.host_path == volume.host && share.read_only)
        {
            volume.read_only = true;
        }
    }
    emit_runtime_source_status(&start_config);
    thread_tenant_id(&mut start_config, &admission.admitted);
    populate_audit_substrate(
        &mut start_config,
        &admission.admitted,
        admission.policy_bundle.as_ref(),
    )?;
    let guest_profile = guest_profile_for_boot(profile == "dev", rootfs_path);
    attach_guest_boot_config(&mut start_config, &admission, guest_profile)?;
    if persists_plan_before_start(backend_name) {
        stash_plan_for_bridge(&start_config)?;
    }
    enforce_shares(&admission, &start_config.volumes)?;
    // Against the config the backend is about to be handed, not the local the
    // plan was synthesized from — that is what makes this a check rather than a
    // restatement of what admission already believed.
    enforce_kernel(
        &admission,
        start_config
            .kernel_path
            .as_deref()
            .map(std::path::Path::new),
    )?;
    let _built_runtime = mvm_hostd::plan_admission::prepare_built_pack_start(
        &admission.admitted,
        &mut start_config,
        crate::backend_kind_for(backend_name),
    )
    .inspect_err(|error| {
        emit_failed(&admission, "registry-pack-boot", error);
    })?;
    if let Some(runtime) = &_built_runtime {
        runtime.verify_config(&start_config).inspect_err(|error| {
            emit_failed(&admission, "registry-pack-runtime", error);
        })?;
    }
    Ok(PreparedPersistentBoot {
        backend,
        start_config,
        admission,
        prepared_volumes,
        built_runtime: _built_runtime,
    })
}

#[cfg(unix)]
fn complete_writable_images(
    config: &mvm_core::vm_backend::VmStartConfig,
    images: &mut mvm_vmm::driver::prepared_disks::WritableVolumeImages,
) -> Result<()> {
    for volume in &config.volumes {
        if volume.read_only {
            continue;
        }
        let source = std::path::Path::new(volume.block_source());
        if images.iter().any(|(path, _)| path == source) {
            continue;
        }
        let size_mib = mvm_core::util::parse_human_size(&volume.size)?;
        let lock = mvm_build::builder_vm_runtime::ensure_persistent_volume_image(
            source,
            u64::from(size_mib) * 1024 * 1024,
            false,
        )?;
        if let Some(image) = lock.into_image() {
            images.push(image);
        }
    }
    Ok(())
}

fn finish_persistent(
    backend: mvm_runtime::backend::AnyBackend,
    mut start_config: mvm_core::vm_backend::VmStartConfig,
    mut admission: crate::admission::AdmissionContext,
    mut prepared_volumes: crate::volume::LaunchPreparation,
    name: &str,
    backend_name: &str,
    provisioner: Option<&dyn super::mailbox_owner::InstalledMailboxProvisioner>,
    vacant: super::mailbox_owner::VacantOwner,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    mvm_hostd::mailbox_process::require_servable(&start_config, &backend)?;
    let mut owned = match (provisioner, admission.admitted.plan().mailbox.as_ref()) {
        (Some(host), Some(_)) => Some(super::mailbox_owner::OwnedLaunch::begin(
            host,
            &admission.admitted,
            &backend,
            vacant,
        )?),
        _ => None,
    };
    if let (Some(worker), Some(host)) = (&mut owned, provisioner) {
        start_config.installed_mailbox_owner = Some(worker.broker_binding()?);
        if let Some(pair) = host.original_cast_pair() {
            let original = std::sync::Arc::new(admission.admitted);
            let config = std::sync::Arc::new(start_config);
            worker.bind_original_cast(pair, original.clone(), config.clone())?;
            admission.admitted = std::sync::Arc::try_unwrap(original).map_err(|_| {
                anyhow::anyhow!("original admission still held after Cast rendezvous")
            })?;
            start_config = std::sync::Arc::try_unwrap(config).map_err(|_| {
                anyhow::anyhow!("original VMM config still held after Cast rendezvous")
            })?;
        }
    }
    // VMM selection + workload-support check + start move behind the facade; the
    // admission gate (above) and the launched/failed emits stay here.
    #[cfg(unix)]
    let started = {
        let prepared = (|| -> Result<_> {
            let mut images = prepared_volumes.take_writable_images();
            complete_writable_images(&start_config, &mut images)?;
            mvm_runtime::workload_backend::require_workload_backend(&backend)?;
            Ok(images)
        })();
        let result = match (owned.as_ref(), prepared) {
            (Some(worker), Ok(images)) => worker.start_native(|| crate::boot::enter_prepared_native(backend, &start_config, images)),
            (None, Ok(images)) => crate::boot::enter_prepared_native(backend, &start_config, images),
            (_, Err(error)) => Err(error),
        };
        match result {
            Ok(started) => started,
            Err(cause) => {
                if let Some(worker) = owned.as_mut() {
                    let settled = worker.settle_native_start();
                    return Err(settle_mailbox_failure(&admission, name, "backend-start", cause,
                        worker, &mut prepared_volumes, settled));
                }
                emit_failed(&admission, "backend-start", &cause);
                return Err(cause);
            }
        }
    };
    #[cfg(not(unix))]
    let started = match crate::start_prepared(backend, &start_config) {
        Ok(started) => started,
        Err(err) => {
            let err = anyhow::anyhow!("{err}");
            emit_failed(&admission, "backend-start", &err);
            return Err(err);
        }
    };
    // The guest asserts a mailbox exactly when the plan grants one, so the
    // host side starts here or the launch is rolled back.
    let serving = match &mut owned {
        Some(worker) => worker.configure_and_wait(started.backend()),
        None => mvm_hostd::mailbox_process::serve_started(
            started.backend(),
            started.vm_id(),
            &start_config,
        ),
    };
    if let Err(error) = serving {
        if let Some(worker) = owned.as_mut() {
            return Err(settle_mailbox_failure(
                &admission,
                name,
                "mailbox-process",
                error,
                worker,
                &mut prepared_volumes,
                started.backend().abort_start(started.vm_id()).map(|_| ()),
            ));
        }
        emit_failed(&admission, "mailbox-process", &error);
        cleanup_after_refusal(name);
        return Err(error);
    }
    if let Err(error) =
        super::detached::require_serving_guest(name, &started, std::time::Duration::from_secs(30))
    {
        if let Some(worker) = owned.as_mut() {
            let abort = match &error {
                super::detached::DetachedReadinessError::AbortUnresolved { source, .. } => {
                    Err(anyhow::anyhow!("{source:#}"))
                }
                _ => Ok(()),
            };
            return Err(settle_mailbox_failure(
                &admission,
                name,
                "guest-readiness",
                error.into(),
                worker,
                &mut prepared_volumes,
                abort,
            ));
        }
        audit_detached_readiness_failure(&admission, name, &error);
        if error.abort_is_unresolved() {
            prepared_volumes.commit();
        } else {
            cleanup_after_refusal(name);
        }
        return Err(error.into());
    }

    if let Some(worker) = owned.as_mut() {
        // Both original owners must be collected before the session can be sealed.
        let enforce =
            super::grants_report::report_enforced_grants_with_emitter(&admission, &started, None)
                .map_err(|e| ("grants", e))
                .and_then(|_| {
                    mvm_hostd::plan_admission::record_charge_or_undo_launch(
                        started.backend(),
                        started.vm_id(),
                        name,
                        &admission.admitted,
                        None,
                    )
                    .map_err(|e| ("host-budget", e))
                });
        if let Err((stage, error)) = enforce {
            let abort = if mvm_hostd::plan_admission::rollback_is_unconfirmed(&error) {
                Err(anyhow::anyhow!("original VM stop was unconfirmed"))
            } else {
                Ok(())
            };
            return Err(settle_mailbox_failure(
                &admission,
                name,
                stage,
                error,
                worker,
                &mut prepared_volumes,
                abort,
            ));
        }
    } else {
        super::grants_report::report_enforced_grants(&admission, &started)?;
        super::budget_charge::record_boot_charge(&admission, name, &started)?;
    }
    prepared_volumes.commit();
    emit_launched(&admission, backend_name, true);
    record_vm_readiness(name, InstanceReadiness::LaunchAccepted);
    mvm_core::audit_emit!(VmStart, vm: name);
    if let Some(worker) = owned {
        worker.commit();
    }
    Ok(admission.admitted)
}

fn cleanup_after_refusal(name: &str) {
    if let Err(error) = crate::local::remove_stopped_runtime_state(name) {
        tracing::warn!(%error, machine = name, "removing runtime state after launch abort failed");
    }
}

/// Record a terminal failure only after both the VMM and its mailbox worker have stopped.
fn settle_mailbox_failure(
    ctx: &crate::admission::AdmissionContext,
    name: &str,
    stage: &str,
    cause: anyhow::Error,
    worker: &mut super::mailbox_owner::OwnedLaunch,
    volumes: &mut crate::volume::LaunchPreparation,
    backend_abort: Result<()>,
) -> anyhow::Error {
    let mut terminal = false;
    let outcome = backend_abort.and_then(|_| {
        worker.rollback_after_abort(|| {
            emit_failed(ctx, stage, &cause);
            terminal = true;
            crate::local::remove_stopped_runtime_state(name)?;
            Ok(())
        })
    });
    if let Err(error) = outcome {
        volumes.commit();
        if !terminal {
            super::record_unsealed_end(
                Some((&ctx.emitter, ctx.admitted.plan())),
                super::UnsealedEnd::new(name, super::UnsealedReason::StopFailed)
                    .error(format!("{cause:#}; {error:#}")),
            );
        }
        return cause.context(format!(
            "installed mailbox rollback remains unresolved: {error:#}"
        ));
    }
    cause
}

fn audit_detached_readiness_failure(
    admission: &crate::admission::AdmissionContext,
    name: &str,
    error: &super::detached::DetachedReadinessError,
) {
    if error.abort_is_unresolved() {
        crate::launch::record_unsealed_end(
            Some((&admission.emitter, admission.admitted.plan())),
            crate::launch::UnsealedEnd::new(name, crate::launch::UnsealedReason::StopFailed)
                .error(format!("{error:#}")),
        );
    } else {
        emit_failed(admission, "guest-readiness", &anyhow::anyhow!("{error:#}"));
    }
}

#[cfg(test)]
mod persistent_oci_boot_tests {
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    use crate::admission::admit_plan_tests::admitted_libkrun;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn readiness_audit_seals_completed_abort_but_leaves_unresolved_abort_unsealed() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());

        let (resolved, _resolved_keys, resolved_audit) = admitted_libkrun("resolved-abort", None);
        super::audit_detached_readiness_failure(
            &resolved,
            "resolved-abort",
            &crate::launch::detached::DetachedReadinessError::RolledBack {
                name: "resolved-abort".into(),
                timeout_secs: 1,
            },
        );
        let resolved_chain = std::fs::read_to_string(resolved_audit.path().join("local.jsonl"))
            .expect("resolved chain");
        assert!(resolved_chain.contains("plan.failed"), "{resolved_chain}");
        assert!(
            resolved_chain.contains("guest-readiness"),
            "{resolved_chain}"
        );
        assert!(
            resolved_chain.contains("session.sealed"),
            "{resolved_chain}"
        );
        assert!(
            !resolved_chain.contains("plan.launched"),
            "{resolved_chain}"
        );

        let (unresolved, _unresolved_keys, unresolved_audit) =
            admitted_libkrun("unresolved-abort", None);
        super::audit_detached_readiness_failure(
            &unresolved,
            "unresolved-abort",
            &crate::launch::detached::DetachedReadinessError::AbortUnresolved {
                name: "unresolved-abort".into(),
                timeout_secs: 1,
                source: anyhow::anyhow!("VMM still alive"),
            },
        );
        let unresolved_chain = std::fs::read_to_string(unresolved_audit.path().join("local.jsonl"))
            .expect("unresolved chain");
        assert!(
            unresolved_chain.contains("plan.teardown_failed"),
            "{unresolved_chain}"
        );
        assert!(
            unresolved_chain.contains("stop-failed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("plan.failed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("session.sealed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("plan.launched"),
            "{unresolved_chain}"
        );
    }

    #[test]
    fn persistent_registration_records_the_runtime_directory() {
        use mvm_runtime::vm::reconcile::{FsRuntimeView, RuntimeView};

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let vm_name = "persistent-registration";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        super::register_vm_name(vm_name, "default");

        let registry =
            mvm_runtime::vm::name_registry::VmNameRegistry::load(&crate::name_registry_path())
                .unwrap();
        let registration = registry.vms.get(vm_name).expect("registered machine");
        assert_eq!(registration.vm_dir, state_dir.to_string_lossy());
        let view = FsRuntimeView::new(home.path().join("vms"));
        assert!(view.state_present(registration));
    }

    #[test]
    fn machine_ports_lower_to_admitted_flowmux_ingress() {
        let mappings = super::machine_port_ingress(&["18080:80".into(), "8443:443".into()])
            .expect("valid CLI ports lower to ingress mappings");

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].mapping_id, 1);
        assert_eq!(mappings[0].host_addr, "127.0.0.1");
        assert_eq!(mappings[0].host_port, 18080);
        assert_eq!(mappings[0].guest_addr, "127.0.0.1");
        assert_eq!(mappings[0].guest_port, 80);
        assert_eq!(mappings[0].protocol, mvm_core::plan::IngressProtocol::Tcp);
        assert_eq!(
            mappings[0].transform,
            mvm_core::plan::IngressTransform::Opaque
        );
        assert_eq!(mappings[1].mapping_id, 2);
        assert_eq!(mappings[1].host_port, 8443);
        assert_eq!(mappings[1].guest_port, 443);
    }

    #[test]
    fn persistent_oci_console_preopen_is_limited_to_dev_profile() {
        assert!(super::preopen_console_for_profile("dev"));
        assert!(!super::preopen_console_for_profile("prod"));
        assert!(!super::preopen_console_for_profile("sealed-prod"));
    }

    #[test]
    fn persistent_oci_required_overlay_returns_no_initrd() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let sibling = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        // A sibling legacy initrd, if present, must be ignored.
        std::fs::write(&sibling, b"legacy-initrd").unwrap();

        let resolved = super::persistent_oci_effective_initrd(&rootfs).unwrap();

        assert_eq!(resolved, None, "legacy initrd must not be returned");
    }

    /// exactly the way the real build/install path lays it out.
    fn seed_warm_universal_initramfs(mvm_home: &std::path::Path) {
        let version = env!("CARGO_PKG_VERSION");
        let arch = mvm_core::arch::GuestArch::host();
        let source = mvm_home.join("source");
        std::fs::create_dir_all(&source).unwrap();
        // The installer verifies the image against its hash sidecar, so the
        // fixture has to match what the build emits: a real gzip stream, the
        // SHA-256 of the uncompressed payload, and the compressed length.
        let payload = b"cpio-payload";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, payload).unwrap();
        let image = encoder.finish().unwrap();
        std::fs::write(source.join("initramfs.cpio.gz"), &image).unwrap();
        std::fs::write(
            source.join("initramfs.hash"),
            format!(
                "{}\n",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(payload))
            ),
        )
        .unwrap();
        std::fs::write(source.join("initramfs.size"), format!("{}\n", image.len())).unwrap();
        std::fs::write(source.join("VERSION"), version).unwrap();

        let cache_root = mvm_home.join("cache").join("initramfs");
        mvm_build::initramfs::install_initramfs_into_cache(&source, &cache_root, version, arch)
            .unwrap();
        // A warm cache in a source checkout has to say what built it, or the
        // fingerprint eviction treats it as stale and discards it.
        if let Some(workspace_root) =
            crate::launch::runtime_overlay::runtime_overlay_source_checkout_root()
            && let Ok(fingerprint) =
                mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(
                    &workspace_root,
                )
        {
            mvm_build::initramfs::record_source_fingerprint(
                &cache_root,
                version,
                arch,
                &fingerprint,
            )
            .unwrap();
        }
    }

    #[test]
    fn persistent_oci_warm_universal_initramfs_skips_legacy_resolution_without_sibling() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let cache = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(cache.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );
        seed_warm_universal_initramfs(cache.path());

        let resolved = super::persistent_oci_effective_initrd(&rootfs).unwrap();

        // The universal initramfs attach step later in the boot supplies the
        // initramfs, so the effective initrd is always empty here.
        assert_eq!(resolved, None);
    }

    #[test]
    fn persistent_oci_warm_universal_initramfs_skips_source_checkout_verity_build() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(_workspace_root) =
            crate::launch::runtime_overlay::runtime_overlay_source_checkout_root()
        else {
            // The source-checkout branch only exists in a source checkout.
            return;
        };

        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let sibling = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&sibling, b"initrd").unwrap();

        let cache = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(cache.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );
        seed_warm_universal_initramfs(cache.path());

        let resolved = super::persistent_oci_effective_initrd(&rootfs).unwrap();

        // Source-checkout mode previously refreshed a legacy verity initrd.
        // That path is no longer supported; the universal initramfs attach
        // step owns the initramfs, so no initrd is resolved here.
        assert_eq!(resolved, None);
    }
}

#[cfg(test)]
mod persists_plan_before_start_tests {
    use super::*;

    #[test]
    fn persists_plan_before_start_covers_the_substitution_backends() {
        // The substitution endpoint reads <state_dir>/plan.json inside start() to
        // decide whether to spawn, so every backend that spawns it must persist the
        // plan first — including the hvf backend and the apple-container backend,
        // which holds the same HVF runner. QEMU must not (it would
        // overwrite the in-memory config).
        for hv in ["firecracker", "libkrun", "hvf", "apple-container"] {
            assert!(
                persists_plan_before_start(hv),
                "{hv} spawns the substitution endpoint and must persist plan.json"
            );
        }
        assert!(!persists_plan_before_start("qemu"));
        assert!(!persists_plan_before_start("mock"));
    }
}

#[cfg(test)]
mod port_spec_tests {
    use super::parse_port_spec;

    #[test]
    fn test_parse_port_spec_single() {
        let (local, guest) = parse_port_spec("3000").unwrap();
        assert_eq!(local, 3000);
        assert_eq!(guest, 3000);
    }

    #[test]
    fn test_parse_port_spec_mapping() {
        let (local, guest) = parse_port_spec("8080:3000").unwrap();
        assert_eq!(local, 8080);
        assert_eq!(guest, 3000);
    }

    #[test]
    fn test_parse_port_spec_invalid() {
        assert!(parse_port_spec("abc").is_err());
        assert!(parse_port_spec("abc:3000").is_err());
        assert!(parse_port_spec("3000:abc").is_err());
        assert!(parse_port_spec("99999").is_err());
    }
}
