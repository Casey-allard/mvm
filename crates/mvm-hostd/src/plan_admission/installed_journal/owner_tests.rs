//! Original-owner admission predicates; no backend or opaque grant is fabricated.
use super::*;
use mvm_core::host_lifetime::{
    HostLaunchBinding, HostLeaseExpectation, HostLifetimeInputs, PreparedHostLifetime,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::Arc,
};

fn fixture(
    root: &std::path::Path,
) -> (
    Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
    VmStartConfig,
    ExecutionPlan,
) {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("state"), b"live").unwrap();
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("holder"))
        .unwrap();
    let anchor = PreparedHostLifetime::bind(
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
                vm_name: "journal-owner".into(),
                backend: BackendKind::Firecracker,
                cpus: 1,
                memory_mib: 128,
            },
        },
        (),
    )
    .unwrap()
    .into_anchor();
    let mut config = VmStartConfig {
        name: "journal-owner".into(),
        cpus: 1,
        memory_mib: 128,
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = mvm_core::plan::test_support::PlanFixture::new()
        .workload("journal-owner")
        .build();
    plan.image.name = config.name.clone();
    plan.resources.cpus = 1;
    plan.resources.mem_mib = 128;
    plan.secrets.clear();
    plan.ingress.clear();
    plan.stream_edges.clear();
    plan.stream_retention = mvm_core::plan::StreamRetention::Ephemeral;
    plan.agent_verbs = Some(vec![
        mvm_core::plan::VerbId::new("activate-environment").unwrap(),
        mvm_core::plan::VerbId::new("run-entrypoint").unwrap(),
    ]);
    use mvm_contract::protocol::mailbox::{
        ExecutionEpoch, MailboxGrant, MailboxId, MailboxRetentionPolicy,
    };
    plan.mailbox = Some(MailboxGrant {
        durable_object_pair_sha256_v1: None,
        incoming_journal_policy_sha256_v1: Some([3; 32]),
        outbound_journal_v1: None,
        mailbox: MailboxId::from_bytes([4; 32]),
        authority_key: [5; 32],
        epoch: ExecutionEpoch::new(1).unwrap(),
        report: None,
        retention: Some(MailboxRetentionPolicy::new(1000).unwrap()),
    });
    plan.bundle = Some(mvm_core::plan::PlanArtifact::new(
        "a".repeat(64),
        &[7; 64],
        mvm_core::plan::bundle::KeyId("b".repeat(32)),
    ));
    plan.asset_identities
        .retain(|asset| asset.name != "network_policy");
    plan.asset_identities.push(
        mvm_core::plan::AssetIdentity::new(
            mvm_core::plan::AssetKind::Policy,
            "network_policy",
            mvm_core::policy::network_policy::content_sha256(&config.network_policy),
        )
        .unwrap(),
    );
    (anchor, config, plan)
}

#[test]
fn original_journal_owner_refuses_a_distinct_arc_or_missing_owner() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let (owner, mut config, plan) = fixture(root.path());
    let (foreign, _, _) = fixture(other.path());
    verify_original_owner(&config, &owner, BackendKind::Firecracker, &plan).unwrap();
    assert!(verify_original_owner(&config, &foreign, BackendKind::Firecracker, &plan).is_err());
    config.host_lifetime = None;
    assert!(verify_original_owner(&config, &owner, BackendKind::Firecracker, &plan).is_err());
}

#[test]
fn original_journal_owner_refuses_a_stale_original_lease() {
    let root = tempfile::tempdir().unwrap();
    let (owner, config, plan) = fixture(root.path());
    fs::write(root.path().join("state"), b"dead").unwrap();
    assert!(verify_original_owner(&config, &owner, BackendKind::Firecracker, &plan).is_err());
}

#[test]
fn journal_capture_requires_actual_opaque_direction_admission() {
    let root = tempfile::tempdir().unwrap();
    let (owner, config, plan) = fixture(root.path());
    let mut posture =
        RunPosture::on_backend(Variant::Prod, BackendKind::Firecracker).with_runtime(Some(&config));
    assert!(
        posture
            .with_installed_journal_owner(&config, &owner)
            .is_err()
    );
    // Predicate-level setup cannot manufacture the missing opaque authority.
    posture.direct_owner = Some(&owner);
    assert!(capture_owner(posture, &plan).is_err());
    posture.runtime_config = None;
    assert!(capture_owner(posture, &plan).is_err());
}

#[test]
fn original_owner_does_not_turn_ordinary_or_object_mailboxes_into_journals() {
    let root = tempfile::tempdir().unwrap();
    let (owner, config, mut plan) = fixture(root.path());
    let grant = plan.mailbox.as_mut().unwrap();
    grant.durable_object_pair_sha256_v1 = Some([6; 32]);
    assert!(verify_original_owner(&config, &owner, BackendKind::Firecracker, &plan).is_err());
    let grant = plan.mailbox.as_mut().unwrap();
    grant.durable_object_pair_sha256_v1 = None;
    grant.incoming_journal_policy_sha256_v1 = None;
    assert!(verify_original_owner(&config, &owner, BackendKind::Firecracker, &plan).is_err());
}

#[test]
fn original_journal_owner_refuses_changed_signed_network_policy() {
    let root = tempfile::tempdir().unwrap();
    let (owner, config, mut plan) = fixture(root.path());
    plan.asset_identities
        .iter_mut()
        .find(|asset| asset.name == "network_policy")
        .unwrap()
        .digest = "0".repeat(64);
    assert!(verify_original_owner(&config, &owner, BackendKind::Firecracker, &plan).is_err());
}
