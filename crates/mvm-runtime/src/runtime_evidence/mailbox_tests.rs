//! Pure profile-policy controls; fixtures do not establish release authenticity.
use super::*;
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
use mvm_core::mailbox::reader::{
    MailboxReaderBootBinding, MailboxReaderCompatibilityV1, MailboxReaderFeatureV1,
};

fn plan() -> mvm_core::plan::ExecutionPlan {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.mailbox = Some(MailboxGrant {
        mailbox: MailboxId::from_bytes([4; 32]),
        authority_key: ed25519_dalek::SigningKey::from_bytes(&[5; 32])
            .verifying_key()
            .to_bytes(),
        epoch: ExecutionEpoch::new(1).unwrap(),
        report: None,
        retention: None,
        durable_object_pair_sha256_v1: None,
        outbound_journal_v1: None,
        incoming_journal_policy_sha256_v1: None,
    });
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    plan
}

#[test]
fn legacy_runtime_refuses_semantic_extension_even_below_2048() {
    let mut plan = plan();
    plan.mailbox.as_mut().unwrap().durable_object_pair_sha256_v1 = Some([6; 32]);
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let binding = MailboxReaderBootBinding::mint(
        &plan,
        key.verifying_key(),
        ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    assert!(serde_json::to_vec(&binding).unwrap().len() < 2048);
    assert!(require_mailbox_profile(None, &plan, None).is_err());
    assert!(require_mailbox_profile(None, &plan, Some(&binding)).is_err());
}

#[test]
fn exact_declared_boot_size_passes_and_one_byte_less_refuses() {
    let plan = plan();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let binding = MailboxReaderBootBinding::mint(
        &plan,
        key.verifying_key(),
        ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let mut profile = MailboxReaderCompatibilityV1 {
        format: 1,
        max_boot_bytes: serde_json::to_vec(&binding).unwrap().len() as u64,
        features: vec![],
    };
    require_mailbox_profile(Some(&profile), &plan, Some(&binding)).unwrap();
    profile.max_boot_bytes -= 1;
    assert!(require_mailbox_profile(Some(&profile), &plan, Some(&binding)).is_err());
}

#[test]
fn malformed_profile_and_mismatched_actual_binding_refuse() {
    let plan = plan();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let mut binding = MailboxReaderBootBinding::mint(
        &plan,
        key.verifying_key(),
        ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let mut profile = MailboxReaderCompatibilityV1 {
        format: 99,
        max_boot_bytes: 8192,
        features: vec![MailboxReaderFeatureV1::ObjectPairV1],
    };
    assert!(require_mailbox_profile(Some(&profile), &plan, None).is_err());
    profile.format = 1;
    binding.ack_public_key = [9; 32];
    binding.plan_nonce = mvm_core::plan::Nonce::from_bytes([9; 16]);
    assert!(require_mailbox_profile(Some(&profile), &plan, Some(&binding)).is_err());
}

#[test]
fn checked_declaration_refuses_wrong_architecture_and_malformed_profile() {
    let mut declaration = RuntimeAssembly {
        assembly_format: mvm_build::guest_bins::assembly::RUNTIME_ASSEMBLY_FORMAT,
        arch: GuestArch::X86_64,
        protocol_version: 2,
        min_supported_protocol_version: 1,
        overlay_sha256: "a".repeat(64),
        overlay_verity_sha256: "b".repeat(64),
        overlay_roothash: "c".repeat(64),
        initramfs_sha256: "d".repeat(64),
        mailbox_reader_v1: None,
    };
    assert!(checked_mailbox_reader(&declaration, GuestArch::Aarch64).is_err());
    checked_mailbox_reader(&declaration, GuestArch::X86_64).unwrap();
    declaration.mailbox_reader_v1 = Some(MailboxReaderCompatibilityV1 {
        format: 99,
        max_boot_bytes: 8192,
        features: vec![],
    });
    assert!(checked_mailbox_reader(&declaration, GuestArch::X86_64).is_err());
}
