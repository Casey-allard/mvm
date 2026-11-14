//! Creation-boundary controls; no microVM or native retirement is fabricated.
use super::*;
use mvm_contract::protocol::mailbox::{
    ExecutionEpoch, MailboxGrant, MailboxId, MailboxRetentionPolicy,
};
use mvm_core::{
    plan::{compute_plan_id, test_support::PlanFixture},
    util::test_env::TestEnv,
};
use std::fs;

fn fixture() -> (
    TestEnv,
    tempfile::TempDir,
    ExecutionPlan,
    JournalStartAttempt,
) {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut plan = PlanFixture::new().build();
    plan.image.name = "attempt-test".into();
    plan.mailbox = Some(MailboxGrant {
        durable_object_pair_sha256_v1: None,
        incoming_journal_policy_sha256_v1: None,
        outbound_journal_v1: None,
        mailbox: MailboxId::from_bytes([1; 32]),
        authority_key: [2; 32],
        epoch: ExecutionEpoch::new(1).unwrap(),
        report: None,
        retention: Some(MailboxRetentionPolicy::new(1000).unwrap()),
    });
    plan.plan_id = compute_plan_id(&plan);
    let state = mvm_core::config::vm_state_dir(&plan.image.name);
    mvm_core::config::create_private_dir(&state).unwrap();
    let guest = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key();
    let ack = ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key();
    MailboxReaderBootBinding::mint(&plan, guest, ack.to_bytes())
        .unwrap()
        .persist(&state)
        .unwrap();
    let dir = owner_dir(&mvm_core::config::mvm_keys_dir(), &plan.image.name).unwrap();
    let claim = claim_launch(&state, &dir, true).unwrap();
    let mut attempt = JournalStartAttempt::new();
    attempt.arm(&plan, &state, claim).unwrap();
    (env, home, plan, attempt)
}

#[test]
fn unarmed_or_panicked_attempt_cannot_mint_no_exec_proof() {
    assert!(JournalStartAttempt::new().take_no_exec().is_err());
    let (_env, _home, _plan, mut attempt) = fixture();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt.fence_uncertain();
        panic!("fixture creation unwind");
    }));
    assert!(result.is_err());
    assert_eq!(attempt.disposition(), JournalStartDisposition::Uncertain);
    assert!(attempt.take_no_exec().is_err());
}

#[test]
fn actual_exec_refusal_retains_original_claim_boot_and_directory() {
    let (_env, home, plan, mut attempt) = fixture();
    let dir = owner_dir(&mvm_core::config::mvm_keys_dir(), &plan.image.name).unwrap();
    let command = std::process::Command::new(home.path().join("absent-helper"));
    assert!(spawn_claimed_tracked(&dir, command, Some(&mut attempt)).is_err());
    assert_eq!(attempt.disposition(), JournalStartDisposition::NoExec);
    let proof = attempt.take_no_exec().unwrap();
    proof.check_original(&plan).unwrap();
    let state = mvm_core::config::vm_state_dir(&plan.image.name);
    assert!(claim_launch(&state, &dir, true).is_err());
    let mut foreign = plan.clone();
    foreign.image.name = "foreign-attempt".into();
    assert!(proof.check_original(&foreign).is_err());
    fs::rename(&state, home.path().join("held-original-state")).unwrap();
    mvm_core::config::create_private_dir(&state).unwrap();
    assert!(proof.check_original(&plan).is_err());
}

#[test]
fn actual_returned_child_never_becomes_no_exec_evidence() {
    let (_env, _home, _plan, mut attempt) = fixture();
    let dir = mvm_core::config::vm_mailbox_original_owner_at(
        &mvm_core::config::mvm_keys_dir(),
        "attempt-test",
    );
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", "exit 0"]);
    let (mut child, mut marker) = spawn_claimed_tracked(&dir, command, Some(&mut attempt)).unwrap();
    assert_eq!(attempt.disposition(), JournalStartDisposition::Uncertain);
    attempt.child_owned().unwrap();
    assert_eq!(attempt.disposition(), JournalStartDisposition::ChildOwned);
    assert!(attempt.take_no_exec().is_err());
    assert!(child.wait().unwrap().success());
    marker.clear_original().unwrap();
}
