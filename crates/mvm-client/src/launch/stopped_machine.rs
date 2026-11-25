//! Stopped-machine restart/removal using the original lifecycle reservations.
use super::*;

impl LocalBackend {
    /// Boot a stopped, previously defined machine under a one-start journal
    /// grant. The original helper is returned in the caller's owner slot.
    /// An already running machine has its own boot and cannot be adopted.
    pub async fn start_persistent_with_journal(
        &self,
        name: &str,
        grant: mvm_contract::protocol::mailbox::MailboxGrant,
        journal: &mut persistent::journal::InstalledJournal<'_>,
    ) -> Result<machine_start::MachineStart> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let _wake_peer = match &*journal {
            persistent::journal::InstalledJournal::Object { launch, .. } => Some(launch.guard()),
            _ => None,
        };
        persistent::journal::validate_slot(Some(journal), Some(&grant))
            .map_err(crate::local::backend_err)?;
        let lifecycle = crate::local::machine_lifecycle(name).await?;
        let reservation = reserve_named_lifecycle(name)?;
        let mut spec = mp::load_machine_spec(name).map_err(|e| MvmError::NotFound {
            id: format!("{name}: {e}"),
        })?;
        if spec.name != name || self.machine_running(name) {
            return Err(MvmError::Conflict {
                reason: format!(
                    "journal start requires the original stopped definition for {name:?}"
                ),
            });
        }
        ensure_spec_bootable_in_process(&spec)?;
        self.validate_sidecar_refs(name)?;
        let (started, _) = self
            .boot_spec(
                &mut spec,
                None,
                false,
                Some(grant),
                Some(journal),
                PersistentStartGuards {
                    reservation: &reservation,
                    lifecycle: &lifecycle,
                },
            )
            .await?;
        Ok(started)
    }

    /// Start a stopped persistent machine from its persisted definition:
    /// sidecar secret references re-validated fail-closed, registered
    /// attachments re-resolved and leased, then the canonical admitted boot.
    /// Starting a machine that is already running returns its state.
    pub async fn start_persistent(&self, name: &str) -> Result<MachineState> {
        let barrier = mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()
            .map_err(crate::local::backend_err)?;
        if cfg!(target_os = "linux")
            && self.backend.kind() != mvm_core::vm_backend::BackendKind::Mock
        {
            crate::policy_profiles::coordinator::ensure_if_activated()
                .map_err(crate::local::backend_err)?;
        }
        let lifecycle = crate::local::machine_lifecycle(name).await?;
        let reservation = reserve_named_lifecycle(name)?;
        let spec = mp::load_machine_spec(name).map_err(|e| MvmError::NotFound {
            id: format!("{name}: {e}"),
        })?;
        crate::policy_profiles::coordinator::validate_machine_spec_generation(&spec, &barrier)
            .map_err(crate::local::backend_err)?;
        if self.machine_running(name) {
            return Ok(MachineState {
                id: MachineId(name.to_string()),
                name: name.to_string(),
                status: MachineStatus::Running,
                cpus: spec.cpus,
                ..Default::default()
            });
        }
        ensure_spec_bootable_in_process(&spec)?;
        self.validate_sidecar_refs(name)?;
        let mut spec = spec;
        let (_, backend) = self
            .boot_spec(
                &mut spec,
                None,
                false,
                None,
                None,
                PersistentStartGuards {
                    reservation: &reservation,
                    lifecycle: &lifecycle,
                },
            )
            .await?;
        let memory_mib = mvm_core::util::parse_human_size(&spec.memory).unwrap_or_default();
        Ok(MachineState {
            id: MachineId(name.to_string()),
            name: name.to_string(),
            status: MachineStatus::Running,
            backend,
            cpus: spec.cpus,
            memory_mib,
            profile: Some(spec.profile.clone()),
            ..Default::default()
        })
    }

    /// Remove a machine. For a persistent definition this is the separate
    /// confirmed action that deletes the spec: a RUNNING persistent machine
    /// is refused unless `options.force` explicitly requests the reviewed
    /// force flow (stop, then remove). A spec-less name gets transient
    /// semantics: stop + idempotent session cleanup. Removing an absent
    /// machine is `Ok`. A failed stop preserves the definition and resources;
    /// force does not bypass that failure.
    pub async fn remove_machine_with(&self, id: &MachineId, options: RemoveOptions) -> Result<()> {
        let name = id.0.as_str();
        let lifecycle = crate::local::machine_lifecycle(name).await?;
        let reservation = reserve_named_lifecycle(name)?;
        let has_spec = machine_spec_path(name).exists();
        if has_spec {
            if self.machine_running(name) {
                if !options.force {
                    return Err(MvmError::Conflict {
                        reason: format!(
                            "machine {name:?} is running; stop it first, or explicitly \
                             request the force removal flow"
                        ),
                    });
                }
                self.stop_for_recreate(name, &lifecycle)?;
            }
            self.remove_definition(name, &lifecycle)?;
            mvm_core::audit_emit!(
                ConfigChange,
                vm: name,
                "action=machine.remove mode=persistent force={force}",
                force = options.force,
            );
            return Ok(());
        }
        // Transient semantics: stop whatever is live, then idempotent cleanup.
        self.cleanup_transient_reserved(name, &reservation, &lifecycle)
    }

    /// Release every session-owned resource `name` holds: registered volume
    /// attachments, attachment leases (re-sealing just-in-time unlocks),
    /// secret-reference sidecar, name-registry entry. Idempotent.
    pub(super) fn release_session_resources(&self, name: &str) -> Result<()> {
        #[cfg(unix)]
        mvm_core::host_lifetime::require_no_installed_native(name)
            .map_err(crate::local::backend_err)?;
        let service = LocalVolumeService::new();
        match service.list_attachments(name) {
            Ok(attachments) => {
                for attachment in attachments {
                    if let Err(e) = service.detach(name, &attachment.guest_path) {
                        tracing::warn!(error = %e, machine = name, guest = %attachment.guest_path, "detach during cleanup failed");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, machine = name, "listing attachments during cleanup failed");
            }
        }
        service
            .release_owner_leases(name)
            .map_err(|e| crate::local::backend_err(format!("releasing volume leases: {e:#}")))?;
        self.clear_secret_refs(name)?;
        crate::local::deregister_from_name_registry(name);
        Ok(())
    }

    /// Idempotent transient cleanup: stop the VM when live, release every
    /// session-owned resource, and drop the per-VM state dirs. Safe to call
    /// repeatedly and on names that never launched. An attempted stop error
    /// returns before any session resource is released.
    ///
    /// A transient session releases only what its receipt names and only
    /// while the receipt still describes the resources; otherwise they are
    /// retained, with the state that records them.
    pub fn cleanup_transient(&self, name: &str) -> Result<()> {
        let lifecycle = mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(name)
            .map_err(crate::local::backend_err)?;
        let reservation = reserve_named_lifecycle(name)?;
        self.cleanup_transient_reserved(name, &reservation, &lifecycle)
    }

    pub(crate) fn cleanup_transient_reserved(
        &self,
        name: &str,
        reservation: &PairedBootReservation,
        lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
    ) -> Result<()> {
        reservation
            .require_name(name)
            .map_err(crate::local::backend_err)?;
        #[cfg(unix)]
        mvm_core::host_lifetime::require_no_installed_native(name)
            .map_err(crate::local::backend_err)?;
        lifecycle
            .require_name(name)
            .map_err(crate::local::backend_err)?;
        if self.machine_running(name) {
            self.stop_for_recreate(name, lifecycle)?;
        }
        let retained = if machine_spec_path(name).exists() {
            self.release_session_resources(name)?;
            false
        } else {
            self.release_transient_resources(name)?
        };
        reap_stopped_runtime_state(name, lifecycle)?;
        // The state dir under machines/ only carries session sidecars for a
        // transient (no machine.json); never touch a persistent definition.
        if !retained && !machine_spec_path(name).exists() {
            remove_dir_if_present(&machine_state_dir(name))?;
        }
        Ok(())
    }
}

impl LocalBackend {
    /// Wait for a transient launch to run to completion, report its captured
    /// exit code, and clean up its session-owned resources. Polls the owning
    /// backend; fails with a timeout error if the machine is still running
    /// after `timeout`. The `plan.exited` chain entry carries the exit code.
    pub fn wait_for_exit(
        &self,
        outcome: &LaunchOutcome,
        poll: std::time::Duration,
        timeout: std::time::Duration,
    ) -> Result<ExitReport> {
        #[cfg(unix)]
        if outcome.host_lifetime.is_some() {
            return Err(crate::local::backend_err(
                "installed wait requires the original resident lifecycle; no name-based exit observation",
            ));
        }
        let name = outcome.machine.name.clone();
        let deadline = std::time::Instant::now() + timeout;
        while self.machine_running(&name) {
            if std::time::Instant::now() >= deadline {
                return Err(crate::local::backend_err(format!(
                    "machine {name:?} still running after {}s",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(poll);
        }
        self.report_exit(outcome)
    }

    /// Report an already-exited machine's captured exit code, emit the
    /// chain-signed `plan.exited` entry, and (for a transient) run the
    /// idempotent cleanup.
    pub fn report_exit(&self, outcome: &LaunchOutcome) -> Result<ExitReport> {
        #[cfg(unix)]
        if outcome.host_lifetime.is_some() {
            return Err(crate::local::backend_err(
                "installed exit reporting requires original native retirement; sidecars are not an exit proof",
            ));
        }
        let name = outcome.machine.name.as_str();
        let state_dir = vm_state_dir(name);
        let exit_code = mvm_core::exit_capture::read_captured(&state_dir);
        // Capture fidelity: a missing capture is recorded as uncaptured,
        // never attested as exit 0.
        //
        // Whatever the process that owned the VM managed to observe. An
        // absent sidecar reads as all-unavailable, which is the honest
        // answer for a tier that cannot observe, a run that crashed before
        // teardown, and a backend that has not been taught to write one yet.
        let mut usage = mvm_core::usage_capture::read_captured(&state_dir);
        // Two dimensions the host observes about itself, so they hold on
        // every backend regardless of what the VMM could report.
        usage.host_state_bytes = mvm_core::usage_capture::host_state_bytes(&state_dir);
        if let Some(span) = outcome.launched_at.map(|at| at.elapsed()) {
            usage.wall_ms = mvm_core::usage_capture::wall_ms(span);
        }
        // Read before cleanup: a transient's state dir, which names the scope,
        // is removed below.
        let memory_limit_exceeded =
            mvm_core::spawn_scope::ScopeProbe::default().memory_limit_exceeded(&state_dir);
        if let Some(emitter) = build_audit_emitter() {
            let closing = ClosingRecords {
                plan: &outcome.plan,
                machine: name,
                memory_limit_exceeded: memory_limit_exceeded.as_ref(),
                exit: ExitRecord {
                    exit_code,
                    backend: &outcome.machine.backend,
                    usage,
                },
            };
            // `record` owns the batch: one flush for the run's closing
            // records, a failed flush recorded there as an unsealed end.
            // Batching here again would nest, which the emitter refuses.
            if closing.record(&emitter) {
                mvm_hostd::audit::witness::flush_configured(
                    emitter.audit_dir(),
                    &outcome.plan.tenant.0,
                );
            }
        }
        if outcome.mode == LifecycleMode::Transient {
            self.cleanup_transient(name)?;
        }
        Ok(ExitReport { exit_code })
    }
}

/// Checked retirement under the caller's original machine lifecycle lock.
pub(super) fn reap_stopped_runtime_state(
    name: &str,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> Result<()> {
    lifecycle
        .require_name(name)
        .map_err(crate::local::backend_err)?;
    #[cfg(unix)]
    if crate::local::ordinary_runtime_root_absent(name).map_err(crate::local::backend_err)? {
        return Ok(());
    }
    #[cfg(unix)]
    mvm_core::host_lifetime::require_no_installed_native(name)
        .map_err(crate::local::backend_err)?;
    if !lifecycle
        .reap_unowned_state()
        .map_err(crate::local::backend_err)?
    {
        return Err(MvmError::Conflict {
            reason: format!("machine {name:?} still owns its runtime state"),
        });
    }
    Ok(())
}

/// Remove a directory tree, treating "already absent" as success.
pub(super) fn remove_dir_if_present(dir: &std::path::Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(crate::local::backend_err(format!(
            "removing {}: {e}",
            dir.display()
        ))),
    }
}
