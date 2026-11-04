use mvm_contract::stream::secret_fingerprint::{SecretCategory, SecretFingerprint};
use mvm_core::plan::signing::test_support::sample_plan;
use mvm_hostd::stream::access_guard::{AccessGuardError, AccessPayloadGuard};
use std::sync::Arc;

#[test]
fn selected_access_requires_factory_but_plain_mvm_remains_compatible() {
    let registry = mvm_hostd::owner_access::OwnerAccessRegistry::new(2, None, false).unwrap();
    let plan = sample_plan();
    registry.require(&plan).unwrap();
    assert!(
        mvm_hostd::owner_access::OwnerAccessRegistry::new(2, None, true)
            .unwrap()
            .require(&plan)
            .is_err()
    );
    assert!(mvm_hostd::owner_access::OwnerAccessRegistry::new(0, None, false).is_err());
}

#[test]
fn genuine_guest_identity_is_not_an_enrolled_owner_identity() {
    use ed25519_dalek::SigningKey;
    use mvm_core::net::session::Session;
    use mvm_hostd::owner_access::*;
    use std::{
        net::{Shutdown, TcpListener, TcpStream},
        time::Duration,
    };
    struct Factory(Vec<OwnerPin>);
    impl OwnerAccessFactory for Factory {
        fn owner_pins(&self) -> &[OwnerPin] {
            &self.0
        }
        fn preflight(
            &self,
            _: &mvm_hostd::plan_admission::AdmittedPlan,
            _: &mvm_core::vm_backend::VmStartConfig,
        ) -> anyhow::Result<()> {
            panic!("identity test must not reach admission")
        }
        fn activate(
            &self,
            _: &mvm_hostd::plan_admission::AdmittedPlan,
            _: &mvm_core::vm_backend::VmStartConfig,
            _: CurrentAccessBoot,
        ) -> anyhow::Result<Arc<dyn OwnerAccessEndpoint>> {
            panic!("identity test must not create endpoint")
        }
    }
    let owner = SigningKey::from_bytes(&[41; 32]);
    let registry = OwnerAccessRegistry::new(
        1,
        Some(Arc::new(Factory(vec![OwnerPin {
            owner: "actual-owner".into(),
            tenant: "tenant-a".into(),
            key: owner.verifying_key(),
        }]))),
        false,
    )
    .unwrap();
    for key in [SigningKey::from_bytes(&[32; 32]), owner] {
        let enrolled = key.verifying_key() == SigningKey::from_bytes(&[41; 32]).verifying_key();
        let expected = key.verifying_key();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client =
            TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
                .unwrap();
        let (mut server, _) = listener.accept().unwrap();
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        let interrupt = client.try_clone().unwrap();
        let worker =
            std::thread::spawn(move || Session::host(&mut client, "owned-owner-auth", key));
        let session = Session::guest(&mut server, SigningKey::from_bytes(&[42; 32]), &expected);
        let _ = interrupt.shutdown(Shutdown::Both);
        let peer = worker.join().unwrap();
        assert!(peer.is_ok());
        let (session, _) = session.unwrap();
        let proof = registry.authenticated_owner(&session);
        assert_eq!(
            proof.is_ok(),
            enrolled,
            "a genuine cryptographic guest key has no owner permission by itself"
        );
        if let Ok(proof) = proof {
            assert_eq!(proof.owner(), "actual-owner");
            assert_eq!(proof.tenant(), "tenant-a");
        }
    }
}

#[test]
fn access_audit_uses_canonical_signed_chain_and_keeps_operation_bytes_out() {
    use mvm_contract::{
        grants::owner_access::{ExecutionIdentity, PolicyRevision},
        protocol::owner_access::{OwnerAccessAudit, OwnerAccessAuditKind},
    };
    let mut plan = sample_plan();
    plan.bundle = Some(mvm_contract::plan::bundle::PlanArtifact::new(
        "b".repeat(64),
        &[7; 64],
        mvm_contract::plan::bundle::KeyId("fixture-key".into()),
    ));
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    let directory = tempfile::tempdir().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    let emitter =
        mvm_hostd::audit::emitter::AuditEmitter::with_dir(key.clone(), directory.path()).unwrap();
    let record = OwnerAccessAudit {
        kind: OwnerAccessAuditKind::Request,
        policy: PolicyRevision {
            plan_id: plan.plan_id.clone(),
            plan_version: plan.plan_version,
        },
        execution: ExecutionIdentity {
            instance_id: "fixture-instance".into(),
            plan_nonce: plan.nonce.clone(),
            bundle_sha256: Some("b".repeat(64)),
        },
        request_digest: [5; 32],
        sequence: 1,
        operation: "status".into(),
        request_bytes: 17,
        reply_bytes: 0,
        reason: None,
    };
    emitter.emit_owner_access(&plan, &record).unwrap();
    let root = emitter.publish_root(&plan.tenant.0).unwrap();
    mvm_contract::merkle::verify_signed_root(&root, &key.verifying_key()).unwrap();
    let text = std::fs::read_to_string(mvm_hostd::audit::emitter::audit_path_for_tenant(
        directory.path(),
        &plan.tenant.0,
    ))
    .unwrap();
    assert!(text.contains("access.request"));
    assert!(!text.contains("payload"));
    assert!(!text.contains("command"));
    let mut foreign = record;
    foreign.policy.plan_version += 1;
    assert!(emitter.emit_owner_access(&plan, &foreign).is_err());
}

#[test]
fn access_guard_reuses_canonical_split_secret_scan_and_policy_transform() {
    let plan = sample_plan();
    let secret = b"owned-fixture-sensitive-value";
    let fingerprints = Arc::new(vec![
        SecretFingerprint::of(secret, SecretCategory::HostSecret).unwrap(),
    ]);
    let mut guard = AccessPayloadGuard::from_admitted(&plan, fingerprints.clone()).unwrap();
    assert!(
        guard.admit(&secret[..8]).unwrap().is_empty(),
        "a live secret prefix must remain withheld"
    );
    assert_eq!(
        guard.admit(&secret[8..]),
        Err(AccessGuardError::SecretMatch)
    );
    assert_eq!(guard.flush(), Err(AccessGuardError::Closed));
    let mut guard = AccessPayloadGuard::from_admitted(&plan, fingerprints.clone()).unwrap();
    assert_eq!(
        guard.clear_message(b"public status").unwrap(),
        b"public status"
    );
    assert_eq!(
        guard.clear_message(secret),
        Err(AccessGuardError::SecretMatch)
    );
    let mut guard = AccessPayloadGuard::from_admitted(&plan, Arc::new(vec![])).unwrap();
    assert_ne!(
        guard.clear_message(b"owner@example.com").unwrap(),
        b"owner@example.com"
    );
    assert_eq!(
        guard.clear_message(&vec![b'x'; 65537]),
        Err(AccessGuardError::Limit)
    );
    assert!(!format!("{:?}", AccessGuardError::SecretMatch).contains("sensitive-value"));
}
