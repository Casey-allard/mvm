use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
use mvm_core::protocol::broker_control::{self, ControlRequest, ControlResponse, DeregisterVm};
use mvm_core::protocol::mailbox_worker_control::*;

fn request() -> MailboxWorkerRequest {
    MailboxWorkerRequest {
        domain: MAILBOX_WORKER_DOMAIN.into(),
        version: 1,
        request_nonce: [1; 32],
        tenant: "tenant-1".into(),
        vm_id: "vm-1".into(),
        workload_id: "workload-1".into(),
        plan_commitment: [2; 32],
        mailbox_grant: MailboxGrant {
            mailbox: MailboxId::from_bytes([3; 32]),
            authority_key: [4; 32],
            epoch: ExecutionEpoch::new(7).unwrap(),
            local_service: None,
        },
        admission_expires_at_unix_ms: 20_000,
        deadline_unix_ms: 12_000,
        backend: MailboxWorkerBackend::Firecracker,
        operation: MailboxWorkerOperation::Query { owner: owner() },
    }
}
fn owner() -> MailboxWorkerOwner {
    MailboxWorkerOwner {
        daemon_boot_nonce: [5; 32],
        lease: [6; 32],
        generation: 1,
        context_commitment: [7; 32],
    }
}
fn key() -> VerifyingKey {
    SigningKey::from_bytes(&[7; 32]).verifying_key()
}
#[test]
fn legacy_signed_shape_and_unit_ok_stay_exact() {
    let r = ControlRequest::Deregister(DeregisterVm {
        vm_id: "vm-1".into(),
    });
    assert_eq!(
        serde_jcs::to_vec(&r).unwrap(),
        br#"{"kind":"deregister","vm_id":"vm-1"}"#
    );
    let signed = broker_control::sign(r, &[7; 32]).unwrap();
    // Independent OpenSSL 3 Ed25519 vector, seed [7;32], exact JCS above.
    assert_eq!(
        signed.sig,
        "TzuM1aEbbKN4wwIEFsisa2EtqpQNmCviHsbHANN9EBiCJhthdrCz4Pibfao5WEtCB+QVjbJjXepqcrury6veBA=="
    );
    assert_eq!(
        broker_control::verify(&signed, &key()).unwrap(),
        &signed.request
    );
    assert_eq!(
        serde_json::to_string(&ControlResponse::Ok).unwrap(),
        r#"{"kind":"ok"}"#
    );
}
#[test]
fn signed_worker_request_binds_domain_version_and_every_context_field() {
    let mut r = request();
    bind_context(&mut r);
    let mut signed = broker_control::sign(
        ControlRequest::MailboxWorkerV1(Box::new(r.clone())),
        &[7; 32],
    )
    .unwrap();
    assert_eq!(verify_request(&signed, &key(), 10_000).unwrap(), &r);
    if let ControlRequest::MailboxWorkerV1(ref mut r) = signed.request {
        r.mailbox_grant.epoch = ExecutionEpoch::new(8).unwrap();
    }
    assert!(verify_request(&signed, &key(), 10_000).is_err());
    for bad in ["domain", "version", "tenant", "deadline", "zero_nonce"] {
        let mut r = request();
        bind_context(&mut r);
        match bad {
            "domain" => r.domain = "mvm-host-control".into(),
            "version" => r.version = 2,
            "tenant" => r.tenant = "../tenant".into(),
            "deadline" => r.deadline_unix_ms = 15_001,
            _ => r.request_nonce = [0; 32],
        }
        let signed =
            broker_control::sign(ControlRequest::MailboxWorkerV1(Box::new(r)), &[7; 32]).unwrap();
        assert!(verify_request(&signed, &key(), 10_000).is_err(), "{bad}");
    }
}
#[test]
fn stop_can_collect_existing_owner_after_admission_expiry_but_not_after_deadline() {
    let mut r = request();
    r.admission_expires_at_unix_ms = 9_000;
    r.operation = MailboxWorkerOperation::Stop { owner: owner() };
    bind_context(&mut r);
    let signed =
        broker_control::sign(ControlRequest::MailboxWorkerV1(Box::new(r)), &[7; 32]).unwrap();
    assert!(verify_request(&signed, &key(), 10_000).is_ok());
    assert!(verify_request(&signed, &key(), 12_000).is_err());
}
#[test]
fn response_correlates_exact_request_and_original_owner_before_fd_exposure() {
    let r = request();
    let result = MailboxWorkerResult {
        request_nonce: r.request_nonce,
        owner: owner(),
        state: MailboxWorkerState::Reserved,
        delegates_config: false,
    };
    assert!(verify_result(&r, &result).is_ok());
    let mut stale = result.clone();
    stale.owner.daemon_boot_nonce = [9; 32];
    assert!(verify_result(&r, &stale).is_err());
    let mut stale = result.clone();
    stale.request_nonce = [9; 32];
    assert!(verify_result(&r, &stale).is_err());
    let mut invalid = result;
    invalid.delegates_config = true;
    assert!(verify_result(&r, &invalid).is_err());
}
#[test]
fn worker_signed_jcs_matches_independent_fixed_vector() {
    use sha2::{Digest, Sha256};
    let request = ControlRequest::MailboxWorkerV1(Box::new(request()));
    let bytes = serde_jcs::to_vec(&request).unwrap();
    assert_eq!(bytes.len(), 879);
    assert_eq!(
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "9375a58de946468928eaa55dfdc54c278ce850f7d19046a7ac2dbdab66fac3a3"
    );
    // Independently generated Python canonical integer JSON + OpenSSL Ed25519.
    // Format vector only: its fixed [7;32] owner context is not admission proof.
    assert_eq!(
        broker_control::sign(request, &[7; 32]).unwrap().sig,
        "JvCfALcROLr0jdSH6laQRfun+sIPb8+BrFxqdpF+Tra+YA9AXYM2WPfP4R+hJ//+srJpBfwoLwVy45SZ9y3AAw=="
    );
}
#[test]
fn acquire_commitment_changes_with_any_immutable_admission_context() {
    let mut r = request();
    r.operation = MailboxWorkerOperation::Acquire;
    let mut result = MailboxWorkerResult {
        request_nonce: r.request_nonce,
        owner: owner(),
        state: MailboxWorkerState::Reserved,
        delegates_config: false,
    };
    result.owner.context_commitment = context_commitment(&r).unwrap();
    assert!(verify_result(&r, &result).is_ok());
    for field in [
        "tenant", "vm", "workload", "plan", "grant", "expiry", "backend",
    ] {
        let mut r = r.clone();
        match field {
            "tenant" => r.tenant.push('x'),
            "vm" => r.vm_id.push('x'),
            "workload" => r.workload_id.push('x'),
            "plan" => r.plan_commitment[0] ^= 1,
            "grant" => r.mailbox_grant.epoch = ExecutionEpoch::new(8).unwrap(),
            "expiry" => r.admission_expires_at_unix_ms += 1,
            _ => r.backend = MailboxWorkerBackend::Hvf,
        };
        assert!(verify_result(&r, &result).is_err(), "{field}");
    }
}

fn bind_context(r: &mut MailboxWorkerRequest) {
    let context = context_commitment(r).unwrap();
    match &mut r.operation {
        MailboxWorkerOperation::DelegateConfig { owner }
        | MailboxWorkerOperation::Query { owner }
        | MailboxWorkerOperation::Stop { owner } => owner.context_commitment = context,
        MailboxWorkerOperation::Acquire => (),
    }
}
#[test]
fn cleanup_query_remains_available_after_expiry_but_start_work_does_not() {
    let mut r = request();
    r.admission_expires_at_unix_ms = 9_000;
    bind_context(&mut r);
    let MailboxWorkerOperation::Query { owner } = r.operation.clone() else {
        unreachable!()
    };
    for operation in [
        MailboxWorkerOperation::Query {
            owner: owner.clone(),
        },
        MailboxWorkerOperation::Stop {
            owner: owner.clone(),
        },
    ] {
        r.operation = operation;
        let signed = broker_control::sign(
            ControlRequest::MailboxWorkerV1(Box::new(r.clone())),
            &[7; 32],
        )
        .unwrap();
        assert!(verify_request(&signed, &key(), 10_000).is_ok());
        assert!(verify_request(&signed, &key(), 12_000).is_err());
    }
    for operation in [
        MailboxWorkerOperation::Acquire,
        MailboxWorkerOperation::DelegateConfig { owner },
    ] {
        r.operation = operation;
        let signed = broker_control::sign(
            ControlRequest::MailboxWorkerV1(Box::new(r.clone())),
            &[7; 32],
        )
        .unwrap();
        assert!(verify_request(&signed, &key(), 10_000).is_err());
    }
}
#[test]
fn cleanup_context_commitment_is_bound_even_with_valid_host_signature() {
    for operation in [
        MailboxWorkerOperation::Query { owner: owner() },
        MailboxWorkerOperation::Stop { owner: owner() },
        MailboxWorkerOperation::DelegateConfig { owner: owner() },
    ] {
        let mut r = request();
        r.operation = operation;
        bind_context(&mut r);
        r.plan_commitment[0] ^= 1;
        let signed =
            broker_control::sign(ControlRequest::MailboxWorkerV1(Box::new(r)), &[7; 32]).unwrap();
        assert!(verify_request(&signed, &key(), 10_000).is_err());
    }
}
