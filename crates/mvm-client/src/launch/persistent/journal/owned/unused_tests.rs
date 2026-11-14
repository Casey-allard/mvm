use super::*;
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId};

fn context(
    original: Arc<crate::LocalBackend>,
    lifetime: PreparedHostLifetime,
) -> Box<JournalStartContext> {
    Box::new(JournalStartContext {
        original,
        anchor: lifetime.into_anchor(),
        boot: None,
        support: None,
        retired: false,
        retirement: None,
        parent_finished: false,
        native_id: None,
        helper_attempt: None,
        no_helper: None,
    })
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
        .into_unused()
        .expect("definition refused before entering journal preparation");
    assert_eq!(returned.binding(), &binding);
    assert!(returned.retains_parent_owner(&parent));
    assert!(matches!(
        holder.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    returned.into_anchor().verify_current().unwrap();
    holder.try_lock().unwrap();
    assert_eq!(Arc::strong_count(&parent), 1);
}
