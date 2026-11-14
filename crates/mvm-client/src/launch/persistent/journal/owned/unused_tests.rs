use super::*;
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId};

fn context(
    original: Arc<crate::LocalBackend>,
    lifetime: PreparedHostLifetime,
) -> Box<JournalStartContext> {
    Box::new(JournalStartContext::new(original, lifetime))
}

fn grant() -> MailboxGrant {
    MailboxGrant {
        mailbox: MailboxId::from_bytes([3; 32]),
        authority_key: ed25519_dalek::SigningKey::from_bytes(&[4; 32])
            .verifying_key()
            .to_bytes(),
        epoch: ExecutionEpoch::new(1).unwrap(),
        report: None,
        retention: None,
        durable_object_pair_sha256_v1: None,
        incoming_journal_policy_sha256_v1: None,
        outbound_journal_v1: None,
    }
}

fn failure(context: Box<JournalStartContext>) -> OwnedJournalStartFailure {
    OwnedJournalStartFailure {
        error: anyhow::anyhow!("original startup refusal"),
        context: Some(context),
        unused: None,
    }
}

#[tokio::test]
async fn stopped_definition_refusal_returns_original_unused_preparation_and_holder() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let owner_dir = tempfile::tempdir().unwrap();
    let parent = Arc::new(());
    let lifetime =
        super::tests::preparation_with_owner(owner_dir.path(), BackendKind::Mock, parent.clone());
    let binding = lifetime.binding().clone();
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(owner_dir.path().join("holders"))
        .unwrap();
    assert!(matches!(
        holder.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    let original = Arc::new(crate::LocalBackend::with_hypervisor("mock"));
    let mut context = context(original.clone(), lifetime);
    // Exercise definition loading through the real private path. No journal
    // authority is supplied because this fixture must refuse before using it.
    let error = original
        .start_owned_journal("owned-journal", grant(), None, &mut context)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not exist"));
    assert!(context.boot.is_none() && context.native_id.is_none());
    assert!(original.backend.list().unwrap().is_empty());
    let failure = OwnedJournalStartFailure {
        error,
        context: Some(context),
        unused: None,
    };
    let returned = failure
        .into_unused_for_parent()
        .expect("definition refused before entering journal preparation");
    assert_eq!(returned.binding(), &binding);
    assert!(returned.retains_parent_owner(&parent));
    assert!(matches!(
        holder.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    returned
        .into_prepared()
        .into_anchor()
        .verify_current()
        .unwrap();
    holder.try_lock().unwrap();
    assert_eq!(Arc::strong_count(&parent), 1);
}

#[test]
fn entered_preparation_refuses_unused_extraction_without_losing_original_anchor() {
    let home = tempfile::tempdir().unwrap();
    let lifetime = super::tests::preparation(home.path(), BackendKind::Mock);
    let original = Arc::new(crate::LocalBackend::with_hypervisor("mock"));
    let mut context = context(original, lifetime);
    assert!(context.anchor().is_err());
    let anchor = context.enter_preparation().unwrap();
    assert!(context.boot.is_none() && context.native_id.is_none());
    assert!(context.enter_preparation().is_err());
    let refused = failure(context).into_unused_for_parent().unwrap_err();
    let mut refused = refused
        .into_unused()
        .err()
        .expect("entered state remains owned");
    assert_eq!(refused.error().to_string(), "original startup refusal");
    let held = refused.context.as_mut().unwrap();
    assert!(Arc::ptr_eq(held.anchor().unwrap(), &anchor));
    held.anchor().unwrap().verify_current().unwrap();
    // This unit fixture entered only the private transition, not preparation.
    held.retired = true;
}

#[test]
fn retained_startup_state_refuses_extraction_and_preserves_failure_for_retry() {
    enum Retained {
        Retired,
        ParentFinished,
        Native,
        HelperAttempt,
    }
    for retained in [
        Retained::Retired,
        Retained::ParentFinished,
        Retained::Native,
        Retained::HelperAttempt,
    ] {
        let home = tempfile::tempdir().unwrap();
        let lifetime = super::tests::preparation(home.path(), BackendKind::Mock);
        let original = Arc::new(crate::LocalBackend::with_hypervisor("mock"));
        let mut context = context(original, lifetime);
        match retained {
            Retained::Retired => context.retired = true,
            Retained::ParentFinished => context.parent_finished = true,
            Retained::Native => context.native_id = Some(VmId("owned-journal".into())),
            Retained::HelperAttempt => {
                context.helper_attempt =
                    Some(mvm_hostd::mailbox_process::original_journal::JournalStartAttempt::new())
            }
        }
        assert!(context.enter_preparation().is_err());
        let mut refused = failure(context)
            .into_unused()
            .err()
            .expect("uncertain state remains owned");
        assert_eq!(refused.error().to_string(), "original startup refusal");
        let held = refused.context.as_mut().unwrap();
        assert!(matches!(held.lifetime, Some(JournalLifetime::Unused(_))));
        match retained {
            Retained::Retired => {
                assert!(held.retired);
                held.retired = false;
            }
            Retained::ParentFinished => {
                assert!(held.parent_finished);
                held.parent_finished = false;
            }
            Retained::Native => {
                assert_eq!(held.native_id.as_ref().unwrap().0, "owned-journal");
                held.native_id = None;
            }
            Retained::HelperAttempt => {
                assert!(held.helper_attempt.is_some());
                held.helper_attempt = None;
            }
        }
        refused
            .into_unused()
            .unwrap()
            .into_anchor()
            .verify_current()
            .unwrap();
    }
}

#[test]
fn missing_transition_state_refuses_without_reconstructing_preparation() {
    let home = tempfile::tempdir().unwrap();
    let lifetime = super::tests::preparation(home.path(), BackendKind::Mock);
    let original = Arc::new(crate::LocalBackend::with_hypervisor("mock"));
    let mut context = context(original, lifetime);
    let original_state = context.lifetime.take();
    assert!(context.enter_preparation().is_err());
    let mut refused = failure(context)
        .into_unused()
        .err()
        .expect("uncertain state remains owned");
    assert!(refused.context.as_ref().unwrap().lifetime.is_none());
    refused.context.as_mut().unwrap().lifetime = original_state;
    refused
        .into_unused()
        .unwrap()
        .into_anchor()
        .verify_current()
        .unwrap();
}

#[test]
fn abandoning_unused_context_keeps_the_original_holder_and_parent() {
    let home = tempfile::tempdir().unwrap();
    let parent = Arc::new(());
    let lifetime =
        super::tests::preparation_with_owner(home.path(), BackendKind::Mock, parent.clone());
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.path().join("holders"))
        .unwrap();
    let original = Arc::new(crate::LocalBackend::with_hypervisor("mock"));
    drop(context(original, lifetime));
    assert_eq!(Arc::strong_count(&parent), 2);
    assert!(matches!(
        holder.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
}
