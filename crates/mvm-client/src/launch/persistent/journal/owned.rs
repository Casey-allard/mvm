//! In-process custody for an explicitly resource-owned journal boot.
use super::*;
use mvm_core::host_lifetime::{HostLifetimeAnchor, PreparedHostLifetime};
use mvm_core::vm_backend::{BackendKind, VmId};
use mvm_runtime::AnyBackend;
use std::sync::Arc;
mod agent_verbs;
#[cfg(all(test, feature = "test-support"))]
mod unused_tests;

fn check_start_binding(
    backend: &AnyBackend,
    name: &str,
    lifetime: &PreparedHostLifetime,
) -> Result<()> {
    ensure!(
        lifetime.binding().backend == backend.kind() && lifetime.binding().vm_name == name,
        "original journal lifetime binding differs"
    );
    ensure!(
        cfg!(target_os = "linux")
            && backend.kind() == BackendKind::Firecracker
            && backend.supports_host_lifetime(),
        "original installed journal backend unavailable"
    );
    mvm_hostd::host_lifetime_parent::require_installed()?;
    Ok(())
}

pub(crate) struct JournalStartContext {
    original: Arc<crate::LocalBackend>,
    anchor: Arc<HostLifetimeAnchor>,
    boot: Option<Box<super::super::PreparedPersistentBoot>>,
    support: Option<Box<JournalSupport>>,
    retired: bool,
    retirement: Option<mvm_runtime::workload_runner::OwnedRetirement>,
    parent_finished: bool,
    native_id: Option<VmId>,
    helper_attempt: Option<mvm_hostd::mailbox_process::original_journal::JournalStartAttempt>,
    no_helper: Option<mvm_hostd::mailbox_process::original_journal::NoHelperStart>,
}

struct JournalSupport {
    _backend: AnyBackend,
    _config: mvm_core::vm_backend::VmStartConfig,
    _volumes: crate::volume::LaunchPreparation,
    _runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
}

impl JournalStartContext {
    pub(crate) fn agent_verbs(&self, requested: &[String]) -> Result<Vec<String>> {
        agent_verbs::select(requested)
    }

    pub(crate) fn start(
        &mut self,
        params: super::super::PersistentImageStartParams<'_>,
        journal: Option<&mut InstalledJournal<'_>>,
        fresh: Option<mvm_hostd::mailbox_process::original_journal::FreshState>,
    ) -> Result<AdmittedPlan> {
        let journal = journal.context("original installed journal missing")?;
        ensure!(
            self.boot.is_none(),
            "original journal boot already prepared"
        );
        let anchor = Arc::clone(&self.anchor);
        self.boot = Some(Box::new(super::super::prepare_persistent_boot_with_owner(
            params,
            Some(journal),
            |config| {
                anchor.bind_to_config(config)?;
                let kernel = anchor
                    .canonical_kernel()
                    .context("installed journal requires a prepared canonical kernel")?;
                kernel.bind_to_config(config)?;
                mvm_hostd::plan_admission::prepare_installed_journal_runtime(
                    config,
                    &self.original.backend,
                )
            },
            agent_verbs::require_ephemeral(mvm_core::plan::StreamRetention::Ephemeral)?,
        )?));
        let boot = self.boot.as_mut().expect("original prepared journal");
        let name = boot.start_config.name.clone();
        let mut images = boot.prepared_volumes.take_writable_images();
        super::super::complete_writable_images(&boot.start_config, &mut images)?;
        if let Some(state) = fresh {
            state.commit();
        }
        // The entire prepared group is held before canonical dispatch can
        // create a process or register an installed endpoint.
        let id = boot.admission.admitted.start_persistent_journal_original(
            &self.original.backend,
            boot.start_config.clone(),
            images,
            boot.admission.policy_bundle.as_ref(),
        )?;
        self.native_id = Some(id.clone());
        let mut attempt = mvm_hostd::mailbox_process::original_journal::JournalStartAttempt::new();
        let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            journal.serve_on_tracked(
                &boot.admission.admitted,
                &self.original.backend,
                &id,
                &mut attempt,
            )
        }));
        let served = match served {
            Ok(result) => result,
            Err(_) => {
                attempt.fence_uncertain();
                Err(anyhow::anyhow!(
                    "original helper construction unwound; custody uncertain"
                ))
            }
        };
        if let Err(error) = served {
            use mvm_hostd::mailbox_process::original_journal::JournalStartDisposition;
            let rollback = match attempt.disposition() {
                JournalStartDisposition::ChildOwned => journal.abort_original_owned(
                    &boot.admission.admitted,
                    &self.original.backend,
                    &id,
                    &self.anchor,
                ),
                JournalStartDisposition::NoExec => {
                    self.no_helper = Some(attempt.take_no_exec()?);
                    (|| {
                        self.original.backend.stop_owned(&id, &self.anchor)?;
                        self.retirement = Some(
                            self.original
                                .backend
                                .take_owned_retirement(&id, &self.anchor)?,
                        );
                        Ok(())
                    })()
                }
                JournalStartDisposition::Uncertain => journal
                    .abort_original_owned(
                        &boot.admission.admitted,
                        &self.original.backend,
                        &id,
                        &self.anchor,
                    )
                    .or_else(|_| self.original.backend.stop_owned(&id, &self.anchor)),
            };
            self.helper_attempt = Some(attempt);
            return match rollback {
                Ok(()) => Err(error.context(
                    "original journal serving refused; native stop confirmed, retirement pending",
                )),
                Err(rollback) => Err(error.context(format!(
                    "original journal serving refused; native rollback unresolved: {rollback:#}"
                ))),
            };
        }
        self.helper_attempt = Some(attempt);
        #[cfg(target_os = "linux")]
        let ready = self.original.backend.check_owned_journal_ready(
            &id,
            &self.anchor,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        );
        #[cfg(not(target_os = "linux"))]
        let ready: Result<()> = Err(anyhow::anyhow!("owned journal control requires Linux"));
        if let Err(error) = ready {
            journal
                .abort_original_owned(
                    &boot.admission.admitted,
                    &self.original.backend,
                    &id,
                    &self.anchor,
                )
                .context("owned journal readiness failed and original rollback was unresolved")?;
            return Err(error.context("original owned journal readiness failed"));
        }
        account_started_on(
            &boot.admission,
            &self.original.backend,
            &id,
            &name,
            || {
                journal.abort_original_owned(
                    &boot.admission.admitted,
                    &self.original.backend,
                    &id,
                    &self.anchor,
                )
            },
            || boot.prepared_volumes.commit(),
        )?;
        boot.prepared_volumes.commit();
        crate::admission::emit_launched(&boot.admission, self.original.backend.name(), true);
        crate::record_readiness(
            &name,
            mvm_core::domain::instance::InstanceReadiness::LaunchAccepted,
        );
        // Admission moves into the success owner. Native custody remains in
        // this same backend's installed slot, still funded by this anchor.
        let boot = self.boot.take().expect("original prepared journal");
        self.support = Some(Box::new(JournalSupport {
            _backend: boot.backend,
            _config: boot.start_config,
            _volumes: boot.prepared_volumes,
            _runtime: boot.built_runtime,
        }));
        Ok(boot.admission.admitted)
    }
}

impl Drop for JournalStartContext {
    fn drop(&mut self) {
        if !self.retired {
            // Abandonment is not positive collection. Preserve the original
            // reservations and uncommitted volume custody for reconciliation.
            std::mem::forget((
                Arc::clone(&self.original),
                Arc::clone(&self.anchor),
                self.boot.take(),
                self.support.take(),
                self.retirement.take(),
                self.helper_attempt.take(),
                self.no_helper.take(),
            ));
        }
    }
}

#[must_use = "retain original journal startup custody until positive retirement"]
pub struct OwnedJournalStart {
    pub(super) machine: Option<crate::launch::machine_start::MachineStart>,
    context: Option<Box<JournalStartContext>>,
}
impl OwnedJournalStart {
    /// Run one bounded input through this original journal's native control owner.
    /// Calls serialize in the installed slot; uncertain dispatch fences future
    /// calls while preserving the separate original stop/retirement authority.
    #[cfg(target_os = "linux")]
    pub fn run_entrypoint(
        &mut self,
        input: &[u8],
        until: std::time::Instant,
        observer: &mut dyn crate::entrypoint::CallObserver,
    ) -> Result<crate::entrypoint::CallOutcome> {
        use crate::entrypoint::{
            CallOutcome, CallTerminal, CaptureReport, RecordedDivergence, route_event,
        };
        ensure!(
            input.len() <= 64 << 10,
            "owned journal input exceeds 64 KiB"
        );
        ensure!(
            std::time::Instant::now() < until,
            "owned journal call deadline elapsed"
        );
        let context = self
            .context
            .as_ref()
            .context("original journal control custody missing")?;
        ensure!(!context.retired, "original journal already retired");
        let machine = self
            .machine
            .as_ref()
            .context("original journal admission missing")?;
        machine
            .admitted
            .check_original_entrypoint(&context.anchor)?;
        let name = &context.anchor.binding().vm_name;
        crate::guest::emit_vsock_rpc_audit(
            name,
            &mvm_agentd::vsock::GuestRequest::RunEntrypoint {
                stdin: input.to_vec(),
                timeout_secs: until
                    .saturating_duration_since(std::time::Instant::now())
                    .as_secs(),
                env: Vec::new(),
                stream_input: false,
            },
        );
        let mut capture = mvm_hostd::stream::EntrypointSink::unrecorded();
        let recorded = capture.is_recorded();
        let mut divergence = RecordedDivergence::default();
        observer.dispatching(name, false);
        let terminal = context.original.backend.run_owned_journal_entrypoint(
            &VmId(name.clone()),
            &context.anchor,
            input,
            until,
            &mut |event| {
                route_event(event, &mut capture, &mut divergence, observer);
            },
        );
        drop(capture);
        observer.dispatched();
        let result = CallOutcome {
            terminal: CallTerminal::from_event(&terminal?),
            capture: Some(CaptureReport {
                recorded,
                divergence,
            }),
        };
        observer.call_finished(name, &result);
        Ok(result)
    }

    pub fn machine(&self) -> &crate::launch::machine_start::MachineStart {
        self.machine
            .as_ref()
            .expect("original machine admission retained")
    }
    pub fn retains_parent_owner<T: Send + Sync + 'static>(&self, owner: &Arc<T>) -> bool {
        self.context
            .as_ref()
            .is_some_and(|context| context.anchor.retains_parent_owner(owner))
    }

    /// Publish retained telemetry through its original parent before releasing
    /// the original journal marker. Failure preserves the remaining stages.
    pub fn stop_and_collect(
        &mut self,
        journal: &mut mvm_hostd::mailbox_process::original_journal::JournalOwner<'_>,
        until: std::time::Instant,
        finish: impl FnMut(
            &mvm_core::plan::ExecutionPlan,
            bool,
            &mut mvm_runtime::workload_runner::OwnedRetirement,
        ) -> Result<()>,
    ) -> Result<mvm_hostd::mailbox_process::original_journal::JournalStopOutcome> {
        finish_owned_journal(
            self.context
                .as_mut()
                .context("original startup custody missing")?,
            journal,
            until,
            finish,
        )
    }
}

impl Drop for OwnedJournalStart {
    fn drop(&mut self) {
        if self
            .context
            .as_ref()
            .is_some_and(|context| !context.retired)
        {
            std::mem::forget((self.machine.take(), self.context.take()));
        }
    }
}

fn finish_owned_journal(
    context: &mut JournalStartContext,
    journal: &mut mvm_hostd::mailbox_process::original_journal::JournalOwner<'_>,
    until: std::time::Instant,
    mut finish: impl FnMut(
        &mvm_core::plan::ExecutionPlan,
        bool,
        &mut mvm_runtime::workload_runner::OwnedRetirement,
    ) -> Result<()>,
) -> Result<mvm_hostd::mailbox_process::original_journal::JournalStopOutcome> {
    let original = Arc::clone(&context.original);
    let anchor = Arc::clone(&context.anchor);
    let id = VmId(anchor.binding().vm_name.clone());
    let outcome = journal.stop_and_collect_owned(
        &id.0,
        until,
        &original.backend,
        &anchor,
        |plan, aborted| {
            if context.retirement.is_none() {
                context.retirement = Some(original.backend.take_owned_retirement(&id, &anchor)?);
            }
            if !context.parent_finished {
                finish(
                    plan,
                    aborted,
                    context
                        .retirement
                        .as_mut()
                        .expect("original collected retirement"),
                )?;
                context.parent_finished = true;
            }
            if !aborted {
                crate::launch::seal_stopped_session(plan, &id.0);
            }
            original.release_stopped_leases(&id.0)?;
            crate::local::deregister_from_name_registry(&id.0);
            Ok(())
        },
    )?;
    context.retired = true;
    Ok(outcome)
}

#[must_use = "retain pending original journal startup ownership"]
pub struct OwnedJournalStartFailure {
    error: anyhow::Error,
    context: Option<Box<JournalStartContext>>,
    unused: Option<Box<PreparedHostLifetime>>,
}

/// Positive native/collector retirement after a proven unexecuted helper.
/// Runtime files remain retained; there is no invented mailbox-helper exit.
#[must_use]
#[derive(Debug)]
pub struct NoHelperRetirement {
    _private: (),
}
impl OwnedJournalStartFailure {
    pub fn error(&self) -> &anyhow::Error {
        &self.error
    }

    pub fn helper_disposition(
        &self,
    ) -> mvm_hostd::mailbox_process::original_journal::JournalStartDisposition {
        use mvm_hostd::mailbox_process::original_journal::JournalStartDisposition;
        self.context
            .as_ref()
            .map_or(JournalStartDisposition::Uncertain, |context| {
                if context.no_helper.is_some() {
                    JournalStartDisposition::NoExec
                } else {
                    context
                        .helper_attempt
                        .as_ref()
                        .map_or(JournalStartDisposition::Uncertain, |attempt| {
                            attempt.disposition()
                        })
                }
            })
    }

    /// Complete only a creation-boundary-proven no-exec helper refusal.
    /// This returns no helper status and does not remove retained runtime data.
    pub fn finish_without_helper(
        &mut self,
        until: std::time::Instant,
        mut finish: impl FnMut(
            &mvm_core::plan::ExecutionPlan,
            &mut mvm_runtime::workload_runner::OwnedRetirement,
        ) -> Result<()>,
    ) -> Result<NoHelperRetirement> {
        let context = self
            .context
            .as_mut()
            .context("original failed startup custody missing")?;
        ensure!(
            !context.retired && std::time::Instant::now() < until,
            "original no-helper retirement unavailable"
        );
        let proof = context
            .no_helper
            .as_ref()
            .context("creation-boundary no-exec proof missing")?;
        let boot = context
            .boot
            .as_ref()
            .context("original failed admission missing")?;
        let plan = boot.admission.admitted.plan();
        proof.check_original(plan)?;
        let id = context
            .native_id
            .as_ref()
            .context("original native dispatch missing")?;
        ensure!(
            id.0 == context.anchor.binding().vm_name,
            "original native identity differs"
        );
        if context.retirement.is_none() {
            context.original.backend.stop_owned(id, &context.anchor)?;
            context.retirement = Some(
                context
                    .original
                    .backend
                    .take_owned_retirement(id, &context.anchor)?,
            );
        }
        proof.check_original(plan)?;
        ensure!(
            std::time::Instant::now() < until,
            "original no-helper publication deadline elapsed"
        );
        if !context.parent_finished {
            finish(
                plan,
                context
                    .retirement
                    .as_mut()
                    .expect("positive original runtime retirement"),
            )?;
            context.parent_finished = true;
        }
        proof.check_original(plan)?;
        context.original.release_stopped_leases(&id.0)?;
        crate::local::deregister_from_name_registry(&id.0);
        context.retired = true;
        Ok(NoHelperRetirement { _private: () })
    }
    pub fn into_unused(self) -> std::result::Result<PreparedHostLifetime, Self> {
        if self.context.is_some() || self.unused.is_none() {
            return Err(self);
        }
        let Self { unused, .. } = self;
        Ok(*unused.expect("checked unused original preparation"))
    }

    pub fn stop_and_collect(
        &mut self,
        journal: &mut mvm_hostd::mailbox_process::original_journal::JournalOwner<'_>,
        until: std::time::Instant,
        finish: impl FnMut(
            &mvm_core::plan::ExecutionPlan,
            bool,
            &mut mvm_runtime::workload_runner::OwnedRetirement,
        ) -> Result<()>,
    ) -> Result<mvm_hostd::mailbox_process::original_journal::JournalStopOutcome> {
        finish_owned_journal(
            self.context
                .as_mut()
                .context("original pending startup missing")?,
            journal,
            until,
            finish,
        )
    }
}
impl std::fmt::Debug for OwnedJournalStartFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedJournalStartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for OwnedJournalStartFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}
impl std::error::Error for OwnedJournalStartFailure {}

impl crate::LocalBackend {
    /// Start one persistent journal with the actual installed parent resource owner.
    pub async fn start_persistent_with_journal_and_host_lifetime(
        self: &Arc<Self>,
        name: &str,
        grant: MailboxGrant,
        journal: &mut InstalledJournal<'_>,
        lifetime: PreparedHostLifetime,
    ) -> std::result::Result<OwnedJournalStart, OwnedJournalStartFailure> {
        let preflight = (|| {
            check_start_binding(&self.backend, name, &lifetime)?;
            validate_slot(Some(journal), Some(&grant))?;
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = preflight {
            return Err(OwnedJournalStartFailure {
                error,
                context: None,
                unused: Some(Box::new(lifetime)),
            });
        }
        let mut context = Box::new(JournalStartContext {
            original: Arc::clone(self),
            anchor: lifetime.into_anchor(),
            boot: None,
            support: None,
            retired: false,
            retirement: None,
            parent_finished: false,
            native_id: None,
            helper_attempt: None,
            no_helper: None,
        });
        let result = self
            .start_owned_journal(name, grant, Some(journal), &mut context)
            .await;
        match result {
            Ok(machine) => Ok(OwnedJournalStart {
                machine: Some(machine),
                context: Some(context),
            }),
            Err(error) => Err(OwnedJournalStartFailure {
                error,
                context: Some(context),
                unused: None,
            }),
        }
    }

    async fn start_owned_journal(
        &self,
        name: &str,
        grant: MailboxGrant,
        journal: Option<&mut InstalledJournal<'_>>,
        context: &mut JournalStartContext,
    ) -> Result<crate::launch::machine_start::MachineStart> {
        use crate::launch::machine_start;
        let reservation = crate::launch::reserve_named_lifecycle(name)?;
        let mut spec = mvm_runtime::machine::persist::load_machine_spec(name)?;
        ensure!(
            spec.name == name && !self.machine_running(name),
            "original stopped journal definition required"
        );
        crate::launch::ensure_spec_bootable_in_process(&spec)?;
        self.validate_sidecar_refs(name)?;
        let image = match &spec.image {
            Some(reference) => Some(machine_start::resolve_boot_image(reference, name).await?),
            None => None,
        };
        let host = machine_start::EmbedderStartHost::new(image, &spec.profile)
            .with_secret_service(self.secrets()?)
            .with_backend(&self.backend);
        let started = machine_start::start_machine_spec_with_journal_context(
            &spec,
            &host,
            machine_start::MachineStartParams {
                hypervisor: self.backend.name(),
                has_ad_hoc_argv: false,
                mailbox: Some(grant),
            },
            journal,
            &reservation,
            Some(context),
        )?;
        machine_start::record_machine_started(&mut spec, started.resolved_digest.clone());
        if let Err(error) = mvm_runtime::machine::persist::overwrite_machine_spec(&spec) {
            tracing::warn!(error = %error, "updating machine start metadata failed");
        }
        Ok(started)
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use mvm_core::host_lifetime::{HostLaunchBinding, HostLeaseExpectation, HostLifetimeInputs};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    #[test]
    fn journal_call_refuses_oversized_input_before_consulting_native_custody() {
        let mut owner = OwnedJournalStart {
            machine: None,
            context: None,
        };
        let mut output = crate::entrypoint::dispatch::CapturedOutput::default();
        let error = owner
            .run_entrypoint(
                &vec![0; (64 << 10) + 1],
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                &mut output,
            )
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 64 KiB"));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }

    #[test]
    fn journal_call_refuses_expired_deadline_before_consulting_native_custody() {
        let mut owner = OwnedJournalStart {
            machine: None,
            context: None,
        };
        let mut output = crate::entrypoint::dispatch::CapturedOutput::default();
        let error = owner
            .run_entrypoint(b"{}", std::time::Instant::now(), &mut output)
            .unwrap_err();
        assert!(error.to_string().contains("deadline elapsed"));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }

    pub(super) fn preparation(
        root: &std::path::Path,
        backend: BackendKind,
    ) -> PreparedHostLifetime {
        preparation_with_owner(root, backend, ())
    }

    pub(super) fn preparation_with_owner(
        root: &std::path::Path,
        backend: BackendKind,
        owner: impl Send + Sync + 'static,
    ) -> PreparedHostLifetime {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("state"), b"live").unwrap();
        fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("holders"))
            .unwrap();
        PreparedHostLifetime::bind(
            HostLifetimeInputs {
                directory: File::open(root).unwrap(),
                holder,
                expected: HostLeaseExpectation {
                    state_name: "state".into(),
                    state_bytes: 4,
                    state_sha256: Sha256::digest(b"live").into(),
                    absent_names: ["next".into(), "intent".into()],
                },
                binding: HostLaunchBinding {
                    installation: [1; 32],
                    profile: [2; 32],
                    generation: 1,
                    grant_serial: 1,
                    vm_name: "owned-journal".into(),
                    backend,
                    cpus: 1,
                    memory_mib: 128,
                },
            },
            owner,
        )
        .unwrap()
    }

    #[test]
    fn journal_preflight_refuses_foreign_binding_without_consuming_preparation() {
        let home = tempfile::tempdir().unwrap();
        let lifetime = preparation(home.path(), BackendKind::Firecracker);
        let backend = AnyBackend::Mock(mvm_runtime::MockBackend::new());
        let error = check_start_binding(&backend, "foreign-journal", &lifetime).unwrap_err();
        assert!(error.to_string().contains("lifetime binding differs"));
        lifetime.into_anchor().verify_current().unwrap();
        assert_eq!(fs::read(home.path().join("state")).unwrap(), b"live");
    }

    #[test]
    fn journal_preflight_refuses_mock_isolation_without_consuming_preparation() {
        let home = tempfile::tempdir().unwrap();
        let lifetime = preparation(home.path(), BackendKind::Mock);
        let backend = AnyBackend::Mock(mvm_runtime::MockBackend::new());
        let error = check_start_binding(&backend, "owned-journal", &lifetime).unwrap_err();
        assert!(error.to_string().contains("backend unavailable"));
        lifetime.into_anchor().verify_current().unwrap();
    }

    #[test]
    fn installed_journal_gate_refuses_mock_before_backend_dispatch() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (mut admission, _keys, _audit) =
            crate::admission::admit_plan_tests::admitted_libkrun("journal-gate", None);
        let backend = AnyBackend::Mock(mvm_runtime::MockBackend::new());
        let error = admission
            .admitted
            .start_persistent_journal_original(
                &backend,
                mvm_core::vm_backend::VmStartConfig {
                    name: "journal-gate".into(),
                    ..Default::default()
                },
                Vec::new(),
                None,
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fresh original installed journal admission")
        );
        assert!(backend.list().unwrap().is_empty());
    }
}
