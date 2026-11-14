//! Original mailbox authorities supplied by the persistent-machine orchestrator.
use anyhow::{Context, Result, ensure};
#[cfg(unix)]
mod owned;
use mvm_contract::protocol::mailbox::MailboxGrant;
use mvm_hostd::{
    mailbox_process::{
        original_journal::{
            OriginalJournalDestination, authorization::PairedJournalAdmission,
            relay::OriginalJournalSourceHost,
        },
        paired_incoming::IncomingJournalAdmission,
    },
    plan_admission::{AdmittedPlan, RunPosture},
};
#[cfg(unix)]
pub(crate) use owned::JournalStartContext;
#[cfg(unix)]
pub use owned::{NoHelperRetirement, OwnedJournalStart, OwnedJournalStartFailure};

/// The caller owns the helper slot across startup, including a later guest
/// readiness or resource-accounting failure. Stop the VM and collect that
/// exact helper before releasing the slot. A recovered PID is insufficient.
pub enum InstalledJournal<'a> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Object {
        launch:
            &'a mvm_hostd::mailbox_process::original_journal::object_workers::OriginalObjectLaunch<
                'a,
            >,
        owner: &'a mut Option<
            mvm_hostd::mailbox_process::original_journal::object_workers::OriginalObjectWorker,
        >,
    },
    Destination {
        admission: &'a IncomingJournalAdmission,
        owner: &'a mut Option<OriginalJournalDestination>,
    },
    Source {
        admission: &'a PairedJournalAdmission,
        owner: &'a mut Option<OriginalJournalSourceHost>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalRole {
    Ordinary,
    Destination,
    Source,
}

impl JournalRole {
    fn require_shape(self, incoming: bool, outgoing: bool) -> Result<()> {
        ensure!(
            matches!(
                (self, incoming, outgoing),
                (Self::Ordinary, false, false)
                    | (Self::Destination, true, false)
                    | (Self::Source, false, true)
            ),
            "persistent mailbox launcher does not match requested journal direction"
        );
        Ok(())
    }
}

pub(crate) fn validate_slot(
    endpoint: Option<&InstalledJournal<'_>>,
    grant: Option<&MailboxGrant>,
) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(InstalledJournal::Object { launch, owner }) = endpoint {
        ensure!(
            owner.is_none() && grant == Some(&launch.plan().grant()),
            "selected object grant or original worker slot differs"
        );
        return Ok(());
    }
    ensure!(
        grant.is_none_or(|g| g.durable_object_pair_sha256_v1.is_none()),
        "selected object grant requires the original pair launcher"
    );
    let role = match endpoint {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some(InstalledJournal::Object { .. }) => unreachable!(),
        Some(InstalledJournal::Destination { owner, .. }) => {
            ensure!(
                owner.is_none(),
                "original destination helper is still owned"
            );
            JournalRole::Destination
        }
        Some(InstalledJournal::Source { owner, .. }) => {
            ensure!(owner.is_none(), "original source helper is still owned");
            JournalRole::Source
        }
        None => JournalRole::Ordinary,
    };
    role.require_shape(
        grant.is_some_and(|g| g.incoming_journal_policy_sha256_v1.is_some()),
        grant.is_some_and(|g| g.outbound_journal_v1.is_some()),
    )
}

impl InstalledJournal<'_> {
    pub(crate) fn authorize<'a>(&'a self, posture: RunPosture<'a>) -> RunPosture<'a> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Object { launch, .. } => posture.with_original_object_worker(launch),
            Self::Destination { admission, .. } => posture.with_incoming_journal(admission),
            Self::Source { admission, .. } => posture.with_paired_journal(admission),
        }
    }

    pub(super) fn abort_original(
        &mut self,
        admitted: &AdmittedPlan,
        started: &crate::StartedVm,
    ) -> Result<()> {
        use mvm_hostd::mailbox_process::original_journal::JournalOwner;
        let plan = admitted.plan();
        let original = match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Object { owner, .. } => {
                return match owner.as_mut() {
                    Some(w) => {
                        w.owner()
                            .abort_original_launch(plan, started.backend(), started.vm_id())
                    }
                    None => admitted.abort_unserved_object(started.backend(), started.vm_id()),
                };
            }
            Self::Destination { owner, .. } => owner.as_mut().map(JournalOwner::Destination),
            Self::Source { owner, .. } => owner.as_mut().map(JournalOwner::Source),
        };
        match original {
            Some(mut held) => held.abort_original_launch(plan, started.backend(), started.vm_id()),
            None => started.backend().abort_start(started.vm_id()).map(|_| ()),
        }
    }

    pub(super) fn serve(
        &mut self,
        admitted: &AdmittedPlan,
        started: &crate::StartedVm,
    ) -> Result<()> {
        self.serve_on(admitted, started.backend(), started.vm_id())
    }

    #[cfg(unix)]
    fn abort_original_owned(
        &mut self,
        admitted: &AdmittedPlan,
        backend: &mvm_runtime::AnyBackend,
        id: &mvm_core::vm_backend::VmId,
        anchor: &std::sync::Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
    ) -> Result<()> {
        use mvm_hostd::mailbox_process::original_journal::JournalOwner;
        let held = match self {
            Self::Destination { owner, .. } => owner.as_mut().map(JournalOwner::Destination),
            Self::Source { owner, .. } => owner.as_mut().map(JournalOwner::Source),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Object { .. } => {
                anyhow::bail!("original collector rollback does not serve object workers")
            }
        };
        held.context("original journal helper missing during installed rollback")?
            .abort_original_launch_owned(admitted.plan(), backend, id, anchor)
    }

    fn serve_on(
        &mut self,
        admitted: &AdmittedPlan,
        backend: &mvm_runtime::AnyBackend,
        id: &mvm_core::vm_backend::VmId,
    ) -> Result<()> {
        self.serve_on_with_attempt(admitted, backend, id, None)
    }

    #[cfg(unix)]
    fn serve_on_tracked(
        &mut self,
        admitted: &AdmittedPlan,
        backend: &mvm_runtime::AnyBackend,
        id: &mvm_core::vm_backend::VmId,
        attempt: &mut mvm_hostd::mailbox_process::original_journal::JournalStartAttempt,
    ) -> Result<()> {
        self.serve_on_with_attempt(admitted, backend, id, Some(attempt))
    }

    fn serve_on_with_attempt(
        &mut self,
        admitted: &AdmittedPlan,
        backend: &mvm_runtime::AnyBackend,
        id: &mvm_core::vm_backend::VmId,
        mut attempt: Option<&mut mvm_hostd::mailbox_process::original_journal::JournalStartAttempt>,
    ) -> Result<()> {
        let posture = admitted
            .mailbox_posture()
            .context("missing admitted mailbox posture")?;
        let name = &id.0;
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Object { .. } => anyhow::bail!("object worker requires bilateral original join"),
            Self::Destination { owner, .. } => {
                **owner = Some(match attempt.as_deref_mut() {
                    Some(attempt) => OriginalJournalDestination::start_custodied_tracked(
                        admitted.plan(),
                        backend,
                        name,
                        &posture,
                        attempt,
                    )?,
                    None => OriginalJournalDestination::start_custodied(
                        admitted.plan(),
                        backend,
                        name,
                        &posture,
                    )?,
                });
                if let Some(attempt) = attempt {
                    attempt.child_owned()?;
                }
                owner.as_ref().expect("retained original").require_ready()?;
            }
            Self::Source { admission, owner } => {
                **owner = Some(match attempt.as_deref_mut() {
                    Some(attempt) => admission.launch_custodied_source_tracked(
                        admitted.plan(),
                        backend,
                        name,
                        &posture,
                        attempt,
                    )?,
                    None => admission.launch_custodied_source(
                        admitted.plan(),
                        backend,
                        name,
                        &posture,
                    )?,
                });
                if let Some(attempt) = attempt {
                    attempt.child_owned()?;
                }
                owner.as_ref().expect("retained original").require_ready()?;
            }
        }
        Ok(())
    }
}

/// The abort closure targets the same backend that started this VM. A failed
/// abort leaves the volume leases and the original mailbox helper in custody.
pub(super) fn account_started(
    ctx: &crate::admission::AdmissionContext,
    started: &crate::StartedVm,
    name: &str,
    abort: impl FnMut() -> Result<()>,
    retain: impl FnMut(),
) -> Result<()> {
    account_started_on(ctx, started.backend(), started.vm_id(), name, abort, retain)
}

fn account_started_on(
    ctx: &crate::admission::AdmissionContext,
    backend: &mvm_runtime::AnyBackend,
    id: &mvm_core::vm_backend::VmId,
    name: &str,
    mut abort: impl FnMut() -> Result<()>,
    mut retain: impl FnMut(),
) -> Result<()> {
    let mut rollback = || {
        let result = abort();
        if let Err(error) = &result {
            retain();
            crate::launch::record_unsealed_end(
                Some((&ctx.emitter, ctx.admitted.plan())),
                crate::launch::UnsealedEnd::new(name, crate::launch::UnsealedReason::StopFailed)
                    .error(format!("{error:#}")),
            );
        }
        result
    };
    let enforced = mvm_hostd::plan_admission::apply_grants_with_owned_rollback(
        backend,
        id,
        &ctx.admitted,
        Some(&ctx.emitter),
        &mut rollback,
    )?;
    crate::launch::grants_report::publish_grants_for(ctx, id, &enforced);
    mvm_hostd::plan_admission::record_charge_with_owned_rollback(
        backend,
        id,
        name,
        &ctx.admitted,
        Some(&ctx.emitter),
        rollback,
    )
}

impl crate::LocalBackend {
    /// Keep the actual helper and runtime state in custody until the original
    /// VM stop and helper collection both succeed. The deadline bounds helper
    /// collection; native VM stop retains the backend's own shutdown bounds.
    pub async fn stop_persistent_journal(
        &self,
        id: &mvm_core::client::dto::MachineId,
        original: &mut mvm_hostd::mailbox_process::original_journal::JournalOwner<'_>,
        until: std::time::Instant,
    ) -> mvm_core::client::Result<mvm_hostd::mailbox_process::original_journal::JournalStopOutcome>
    {
        let name = &id.0;
        original
            .stop_and_collect(name, until, |plan, aborted| {
                if !aborted {
                    crate::launch::seal_stopped_session(plan, name);
                }
                self.release_stopped_leases(name)?;
                crate::local::deregister_from_name_registry(name);
                let removed = mvm_runtime::vm::reconcile::reap_unowned_state_dir(
                    &mvm_core::config::vm_state_dir(name),
                    &mvm_core::config::instance_dir(name),
                )
                .map_err(anyhow::Error::msg)?;
                ensure!(
                    removed,
                    "stopped original VM runtime still has a lifecycle owner"
                );
                Ok(())
            })
            .map_err(crate::local::backend_err)
    }
}

#[cfg(test)]
mod tests {
    use super::JournalRole::{Destination, Ordinary, Source};

    #[cfg(feature = "test-support")]
    #[test]
    fn persistent_journal_accounting_retains_ownership_when_abort_is_uncertain() {
        use crate::admission::admit_plan_tests::admitted_libkrun;
        use mvm_core::util::test_env::TestEnv;
        for grant_failure in [true, false] {
            for uncertain in [true, false] {
                let home = tempfile::tempdir().unwrap();
                let mut env = TestEnv::new();
                env.isolate_mvm_home(home.path());
                let vm = "journal-accounting";
                let (ctx, _keys, audit) = admitted_libkrun(vm, None);
                let mock = mvm_runtime::MockBackend::new();
                let mock = if grant_failure {
                    mock.with_failing_apply_grants()
                } else {
                    mock
                };
                let backend = mvm_runtime::AnyBackend::Mock(mock.clone());
                let id = backend
                    .start(&mvm_core::vm_backend::VmStartConfig {
                        name: vm.into(),
                        rootfs_path: "/store/synthetic.ext4".into(),
                        ..Default::default()
                    })
                    .unwrap();
                let started = crate::StartedVm::from_started(backend, id);
                // The target of the durable charge write is a directory.
                let state = mvm_core::config::vm_state_dir_at(home.path(), vm);
                std::fs::create_dir_all(state.join("admitted-charge.json")).unwrap();
                let mut retained = false;
                let failure = super::account_started(
                    &ctx,
                    &started,
                    vm,
                    || {
                        if uncertain {
                            anyhow::bail!("fixture abort unresolved")
                        } else {
                            started.backend().abort_start(started.vm_id()).map(|_| ())
                        }
                    },
                    || retained = true,
                )
                .unwrap_err();
                assert_eq!(retained, uncertain, "{failure:#}");
                assert_eq!(mock.count(), usize::from(uncertain));
                let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
                assert_eq!(chain.contains("plan.failed"), !uncertain, "{chain}");
                assert_eq!(chain.contains("plan.teardown_failed"), uncertain, "{chain}");
                assert!(!chain.contains("plan.launched"));
            }
        }
    }

    #[test]
    fn persistent_journal_role_must_match_both_signed_direction_fields() {
        for role in [Ordinary, Destination, Source] {
            for incoming in [false, true] {
                for outgoing in [false, true] {
                    let expected = matches!(
                        (role, incoming, outgoing),
                        (Ordinary, false, false)
                            | (Destination, true, false)
                            | (Source, false, true)
                    );
                    assert_eq!(role.require_shape(incoming, outgoing).is_ok(), expected);
                }
            }
        }
    }
}
