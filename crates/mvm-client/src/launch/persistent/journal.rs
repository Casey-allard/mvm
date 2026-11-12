//! Original mailbox authorities supplied by the persistent-machine orchestrator.
use anyhow::{Context, Result, ensure};
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

/// The caller owns the helper slot across startup, including a later guest
/// readiness or resource-accounting failure. Stop the VM and collect that
/// exact helper before releasing the slot. A recovered PID is insufficient.
pub enum InstalledJournal<'a> {
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
    let role = match endpoint {
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
            Self::Destination { admission, .. } => posture.with_incoming_journal(admission),
            Self::Source { admission, .. } => posture.with_paired_journal(admission),
        }
    }

    pub(super) fn serve(
        &mut self,
        admitted: &AdmittedPlan,
        started: &crate::StartedVm,
    ) -> Result<()> {
        let posture = admitted
            .mailbox_posture()
            .context("missing admitted mailbox posture")?;
        let name = &started.vm_id().0;
        let backend = started.backend();
        match self {
            Self::Destination { owner, .. } => {
                **owner = Some(OriginalJournalDestination::start_custodied(
                    admitted.plan(),
                    backend,
                    name,
                    &posture,
                )?);
                owner.as_ref().expect("retained original").require_ready()?;
            }
            Self::Source { admission, owner } => {
                **owner = Some(admission.launch_custodied_source(
                    admitted.plan(),
                    backend,
                    name,
                    &posture,
                )?);
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
        started.backend(),
        started.vm_id(),
        &ctx.admitted,
        Some(&ctx.emitter),
        &mut rollback,
    )?;
    crate::launch::grants_report::publish_grants(ctx, started, &enforced);
    mvm_hostd::plan_admission::record_charge_with_owned_rollback(
        started.backend(),
        started.vm_id(),
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
            .stop_and_collect(name, until, |plan| {
                crate::launch::seal_stopped_session(plan, name);
                self.release_stopped_leases(name)?;
                crate::local::deregister_from_name_registry(name);
                crate::local::remove_stopped_runtime_state(name)?;
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
