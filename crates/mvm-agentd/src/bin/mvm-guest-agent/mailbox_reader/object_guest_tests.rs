use super::*;
use mvm_contract::plan::{Nonce, PlanId};
use mvm_contract::protocol::mailbox::*;
use mvm_core::mailbox::reader::{
    object_delivery_commitment, sign_delivery_lease, sign_guest_reader_enrollment,
    verify_reader_possession,
};
use mvm_core::mailbox::reader_wire::{read_request, write_application_request};
use mvm_core::mailbox::sign_capability;
fn fixture(
    now: i64,
) -> (
    SigningKey,
    SigningKey,
    MailboxGrant,
    PlanId,
    Nonce,
    MailboxCapabilityGrant,
    MailboxGuestReaderEnrollment,
) {
    let authority = SigningKey::from_bytes(&[5; 32]);
    let guest = SigningKey::from_bytes(&[6; 32]);
    let address = MailboxAddress {
        tenant: TenantId::from_bytes([1; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
        mailbox: MailboxId::from_bytes([3; 32]),
        recipient: PrincipalId::from_bytes([4; 32]),
    };
    let epoch = ExecutionEpoch::new(7).unwrap();
    let plan = MailboxGrant {
        durable_object_pair_sha256_v1: Some([71; 32]),
        incoming_journal_policy_sha256_v1: None,
        outbound_journal_v1: None,
        mailbox: address.mailbox,
        authority_key: authority.verifying_key().to_bytes(),
        epoch,
        report: None,
        retention: None,
    };
    let plan_id = PlanId(format!("sha256:{}", "a".repeat(64)));
    let plan_nonce = Nonce::from_bytes([7; 16]);
    let receive = MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id: CapabilityId::from_bytes([8; 32]),
        issuer: PrincipalId::from_bytes([9; 32]),
        subject: PrincipalId::from_bytes([10; 32]),
        address,
        operations: CapabilityOperations::from_operations(&[MailboxOperation::Receive]),
        message_kinds: vec![MailboxMessageKind::Call],
        content_types: vec![ContentType::parse("application/spiralcore-object", 1).unwrap()],
        max_payload_bytes: 1024,
        max_messages_per_minute: 60,
        max_outstanding_calls: 1,
        max_queue_contribution_bytes: 4096,
        minimum_execution_epoch: epoch,
        maximum_execution_epoch: epoch,
        policy_epoch: 12,
        not_before_unix_ms: now - 5000,
        expires_at_unix_ms: now + 20_000,
        revocation_id: RevocationId::from_bytes([11; 32]),
        delegation_depth: 0,
    };
    let enrollment = MailboxGuestReaderEnrollment {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        plan_id: plan_id.clone(),
        plan_nonce: plan_nonce.clone(),
        address,
        consumer: receive.subject,
        consumer_boot: BootId::from_bytes([12; 32]),
        consumer_session: ConsumerSessionId::from_bytes([13; 32]),
        receive_capability_id: receive.capability_id,
        ack_public_key: guest.verifying_key().to_bytes(),
        execution_epoch: epoch,
        policy_epoch: receive.policy_epoch,
        issued_at_unix_ms: now - 1000,
        expires_at_unix_ms: now + 10_000,
    };
    (
        authority, guest, plan, plan_id, plan_nonce, receive, enrollment,
    )
}

struct SelectedCall {
    now: i64,
    guest: SigningKey,
    role: SignedObjectRoleV1,
    boot: MailboxReaderBootBinding,
    pair: [u8; 32],
    receive_cap: SignedMailboxCapability,
    signed_enrollment: SignedMailboxGuestReaderEnrollment,
    header: MailboxEnvelopeHeader,
    lease: SignedMailboxDeliveryLease,
    payload: Vec<u8>,
}
fn selected_call(
    make_call: impl FnOnce([u8; 32]) -> (MessageId, CorrelationId, Vec<u8>),
) -> SelectedCall {
    let now = now_unix_ms().unwrap();
    let (authority, guest, mut plan, _, _, mut receive, mut enrollment) = fixture(now);
    let (issued, _, b) = signed_source(now);
    let mut body = issued.role;
    body.role = mvm_core::mailbox::object_pair::role::ObjectParticipantRole::Callee;
    let role = SignedObjectRoleV1::issue(body, &b, now).unwrap();
    let boot = role.role.callee.clone();
    let pair = boot.durable_object_pair_sha256_v1.unwrap();
    plan.durable_object_pair_sha256_v1 = Some(pair);
    enrollment.plan_id = boot.plan_id.clone();
    enrollment.plan_nonce = boot.plan_nonce.clone();
    enrollment.consumer_boot = boot.boot;
    receive.capability_id = CapabilityId::from_bytes([87; 32]);
    enrollment.receive_capability_id = receive.capability_id;
    let receive_cap = sign_capability(receive.clone(), &authority).unwrap();
    let signed_enrollment = sign_guest_reader_enrollment(enrollment.clone(), &authority).unwrap();
    let (message_id, correlation_id, payload) = make_call(pair);
    let header = MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant: receive.address.tenant,
        authorization_domain: receive.address.authorization_domain,
        sender: role.role.call.grant.subject,
        recipient: receive.address.recipient,
        mailbox: plan.mailbox,
        sender_boot: role.role.caller.boot,
        execution_epoch: plan.epoch,
        message_id,
        correlation_id,
        causation_id: mvm_contract::protocol::mailbox::CausationId::from_bytes([34; 32]),
        kind: MailboxMessageKind::Call,
        reply_to: Some(ReplyRoute {
            address: role.role.reply.grant.address,
            capability_id: role.role.reply.grant.capability_id,
        }),
        ordering_scope: OrderingScope::parse("report").unwrap(),
        sequence: SequenceNumber::new(1).unwrap(),
        issued_at_unix_ms: now - 1000,
        expires_at_unix_ms: now + 5000,
        nonce: ReplayNonce::from_bytes([35; 16]),
        content_type: receive.content_types[0].clone(),
        capability_id: role.role.call.grant.capability_id,
        policy_epoch: receive.policy_epoch,
        encryption: EncryptionContext {
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id: [37; 32],
        },
        plaintext_len: payload.len().try_into().unwrap(),
    };
    let lease = sign_delivery_lease(
        MailboxDeliveryLease {
            object_projection_v1: Some(
                object_delivery_commitment(&pair, &header, &payload).unwrap(),
            ),
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            address: receive.address,
            sender: header.sender,
            sender_boot: header.sender_boot,
            message_id: header.message_id,
            delivery_id: DeliveryId::from_bytes([69; 32]),
            execution_epoch: plan.epoch,
            consumer: receive.subject,
            consumer_session: enrollment.consumer_session,
            receive_capability_id: receive.capability_id,
            policy_epoch: receive.policy_epoch,
            ciphertext_commitment: [14; 32],
            issued_at_unix_ms: now - 200,
            expires_at_unix_ms: now + 4000,
            lease_nonce: DeliveryLeaseNonce::from_bytes([44; 16]),
        },
        &authority,
    )
    .unwrap();

    SelectedCall {
        now,
        guest,
        role,
        boot,
        pair,
        receive_cap,
        signed_enrollment,
        header,
        lease,
        payload,
    }
}

#[test]
fn selected_guest_application_socket_rejects_downgrade_and_substitution_after_possession() {
    let SelectedCall {
        now,
        guest,
        role,
        boot,
        pair,
        receive_cap,
        signed_enrollment,
        header,
        lease,
        payload,
        ..
    } = selected_call(|_| {
        (
            MessageId::from_bytes([32; 32]),
            CorrelationId::from_bytes([33; 32]),
            b"hello".to_vec(),
        )
    });
    let seed = Box::leak(Box::new(Zeroizing::new(guest.to_bytes())));
    let reader = Arc::new(GuestReader {
        ordinal: None,
        role: Some(role.clone()),
        settlement: Default::default(),
        outbox: Default::default(),
        boot: boot.clone(),
        ack_seed: seed,
        active: Mutex::new(None),
    });
    for variant in 0..3 {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let state = reader.clone();
        std::thread::scope(|scope| {
            let app = scope.spawn(move || application_request(&mut server, &tx, &state));
            write_application_request(
                &mut client,
                &ApplicationReaderRequest::ReceiveObjectPairV1 { pair },
            )
            .unwrap();
            let pending = rx.recv_timeout(LOCAL_TIMEOUT).unwrap();
            let (mut host, mut original_guest) = UnixStream::pair().unwrap();
            let engine = scope.spawn(move || exchange(&mut original_guest, pending));
            assert_eq!(
                read_request(&mut host).unwrap(),
                ReaderRequest::ReceiveObjectPairV1 { pair }
            );
            let challenge = [49 + variant; 32];
            write_response(
                &mut host,
                &ReaderResponse::Challenge {
                    enrollment: Box::new(signed_enrollment.clone()),
                    capability: Box::new(receive_cap.clone()),
                    challenge,
                },
            )
            .unwrap();
            let ReaderRequest::Possession { signature } = read_request(&mut host).unwrap() else {
                panic!("missing possession")
            };
            verify_reader_possession(
                &signed_enrollment,
                &challenge,
                &signature,
                &guest.verifying_key(),
            )
            .unwrap();
            let response = if variant == 1 {
                ReaderResponse::Delivery {
                    lease: Box::new(lease.clone()),
                    content_type: header.content_type.clone(),
                    payload: payload.clone(),
                }
            } else {
                ReaderResponse::ObjectDeliveryV1 {
                    lease: Box::new(lease.clone()),
                    header: Box::new(header.clone()),
                    payload: if variant == 2 {
                        b"HELLO".to_vec()
                    } else {
                        payload.clone()
                    },
                }
            };
            write_response(&mut host, &response).unwrap();
            engine.join().unwrap().unwrap();
            let result = app.join().unwrap().unwrap();
            if variant == 0 {
                assert_eq!(result, response);
            } else {
                assert_eq!(
                    result,
                    ReaderResponse::Refused {
                        reason: Refusal::NotAuthorized
                    }
                );
            }
        });
    }
    let challenge = [63; 32];
    let request = ApplicationReaderRequest::AuthorizeObjectCallV1 {
        pair,
        lease: Box::new(lease.clone()),
        challenge,
    };
    for deny in [false, true] {
        let (mut client, mut local) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let r = reader.clone();
            let app = scope.spawn(move || application_request(&mut local, &tx, &r));
            write_application_request(&mut client, &request).unwrap();
            let pending = rx.recv().unwrap();
            let (mut original, mut host) = UnixStream::pair().unwrap();
            let service = scope.spawn(move || exchange(&mut original, pending));
            assert!(
                matches!(read_request(&mut host).unwrap(),ReaderRequest::AuthorizeObjectCallV1{lease:l,..} if *l==lease)
            );
            let verdict = if deny {
                ReaderResponse::Refused {
                    reason: Refusal::NotAuthorized,
                }
            } else {
                ReaderResponse::ObjectRoleV1 {
                    signed: Box::new(role.clone()),
                }
            };
            write_response(&mut host, &verdict).unwrap();
            service.join().unwrap().unwrap();
            let response = app.join().unwrap().unwrap();
            let verify = |challenge, body| {
                mvm_core::mailbox::reader::verify_object_call_authority(
                    &boot, &pair, &lease, &header, body, challenge, &response, now,
                )
            };
            assert_eq!(verify(&challenge, b"hello").is_ok(), !deny);
            assert!(verify(&[99; 32], b"hello").is_err());
            assert!(verify(&challenge, b"HELLO").is_err());
        });
    }
}

fn signed_source(now: i64) -> (SignedObjectRoleV1, SigningKey, SigningKey) {
    use mvm_core::mailbox::object_pair::{ObjectPairGrants, role::*};
    let (b_key, guest, _, _, _, mut forward, _) = fixture(now);
    let a_key = SigningKey::from_bytes(&[21; 32]);
    forward.issuer = PrincipalId::from_bytes(b_key.verifying_key().to_bytes());
    forward.operations = CapabilityOperations::from_operations(&[MailboxOperation::Send]);
    let mut reverse = forward.clone();
    reverse.issuer = PrincipalId::from_bytes(a_key.verifying_key().to_bytes());
    reverse.subject = forward.address.recipient;
    reverse.address.recipient = forward.subject;
    reverse.address.mailbox = MailboxId::from_bytes([31; 32]);
    reverse.capability_id = CapabilityId::from_bytes([32; 32]);
    reverse.operations = CapabilityOperations::from_operations(&[MailboxOperation::Reply]);
    reverse.message_kinds = vec![MailboxMessageKind::Reply];
    let call = sign_capability(forward, &b_key).unwrap();
    let reply = sign_capability(reverse, &a_key).unwrap();
    let a = Nonce::from_bytes([17; 16]);
    let b = Nonce::from_bytes([18; 16]);
    let pair = ObjectPairGrants {
        call: &call,
        reply: &reply,
    }
    .commitment(&a, &b)
    .unwrap();
    let boot = |n: u8, plan_nonce, cap: &SignedMailboxCapability| MailboxReaderBootBinding {
        durable_object_pair_sha256_v1: Some(pair),
        outbound_journal_v1: None,
        plan_id: PlanId(format!("sha256:{}", format!("{n:02x}").repeat(32))),
        plan_nonce,
        mailbox: cap.grant.address.mailbox,
        authority_key: *cap.grant.issuer.as_bytes(),
        execution_epoch: cap.grant.minimum_execution_epoch,
        boot: BootId::from_bytes([n; 32]),
        guest_identity_key: [n; 32],
        ack_public_key: guest.verifying_key().to_bytes(),
    };
    let caller = boot(50, a, &reply);
    let callee = boot(51, b, &call);
    let role = SignedObjectRoleV1::issue(
        ObjectRoleV1 {
            role: ObjectParticipantRole::Caller,
            caller,
            callee,
            call,
            reply,
            not_before_unix_ms: now - 2000,
            expires_at_unix_ms: now + 15000,
        },
        &a_key,
        now,
    )
    .unwrap();
    (role, a_key, b_key)
}

struct Counted {
    stream: UnixStream,
    read: u64,
    wrote: u64,
}
impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.stream.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}
impl Write for Counted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.stream.write(buf)?;
        self.wrote += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[test]
fn status_replays_exact_staged_operation_after_lost_v2_and_fences_other_signers() {
    use mvm_core::mailbox::{reader_wire::ObjectSubmissionV1, sign_receipt};
    let now = now_unix_ms().unwrap();
    let (role, a, b) = signed_source(now);
    let dir = tempfile::tempdir().unwrap();
    let original = role.role.caller.clone();
    let pair = original.durable_object_pair_sha256_v1.unwrap();
    let new_reader = || {
        Arc::new(GuestReader {
            ordinal: None,
            boot: original.clone(),
            ack_seed: Box::leak(Box::new(Zeroizing::new([8; 32]))),
            active: Mutex::new(None),
            role: Some(role.clone()),
            settlement: Default::default(),
            outbox: dir.path().to_owned(),
        })
    };
    let reader = new_reader();
    let message_id = MessageId::from_bytes([65; 32]);
    let submission = ObjectSubmissionV1::Call {
        message_id,
        correlation_id: CorrelationId::from_bytes([66; 32]),
        payload: b"a\0b\0".to_vec(),
    };
    let operation = ApplicationReaderRequest::StageObjectV1 {
        pair,
        submission: Box::new(submission.clone()),
    };
    let local = |state: &Arc<GuestReader>, op: &ApplicationReaderRequest| {
        let (mut application, mut service) = UnixStream::pair().unwrap();
        write_application_request(&mut application, op).unwrap();
        let (tx, _rx) = mpsc::sync_channel(1);
        application_request(&mut service, &tx, state)
    };
    assert_eq!(
        local(&reader, &operation),
        Ok(ReaderResponse::ObjectStagedV1 { pair, message_id })
    );
    let body = DestinationReceipt {
        protocol_version: ProtocolVersion::V2,
        signature_algorithm: SignatureAlgorithm::ED25519,
        delivery_id: DeliveryId::from_bytes([67; 32]),
        message_id,
        address: role.role.call.grant.address,
        execution_epoch: original.execution_epoch,
        outcome: DeliveryOutcome::AcceptedLocalDurable,
        observed_at_unix_ms: now,
        ciphertext_commitment: [68; 32],
    };
    let original_seal = mvm_core::mailbox::reader_wire::OriginalObjectSealV1 {
        pair,
        sender_boot: original.boot,
        intent_sha256: mvm_core::mailbox::reader_wire::original_object_intent_digest(&submission)
            .unwrap(),
        delivery_id: DeliveryId::from_bytes([67; 32]),
        ciphertext_commitment: [68; 32],
    };
    let host_reply = |r| ReaderResponse::ObjectSealAcceptedV1 {
        original: original_seal.clone(),
        receipt: Box::new(r),
    };
    let valid = host_reply(sign_receipt(body.clone(), &b).unwrap());
    let mut other_seal = body.clone();
    other_seal.ciphertext_commitment = [72; 32];
    other_seal.delivery_id = DeliveryId::from_bytes([73; 32]);
    let other = host_reply(sign_receipt(other_seal, &b).unwrap());
    let accepted = ReaderResponse::ObjectAcceptedV1 {
        receipt: Box::new(sign_receipt(body.clone(), &b).unwrap()),
    };
    let status = ApplicationReaderRequest::ObjectSubmissionStatusV1 { pair, message_id };
    let attempt = |name: &str, reader: &Arc<GuestReader>, response: Option<&ReaderResponse>| {
        std::thread::scope(|s| {
            let (mut app, mut svc) = UnixStream::pair().unwrap();
            let (tx, rx) = mpsc::sync_channel(1);
            let client = s.spawn(move || application_request(&mut svc, &tx, reader));
            write_application_request(&mut app, &status).unwrap();
            let pending = rx.recv_timeout(LOCAL_TIMEOUT).unwrap();
            let (mut host, guest) = UnixStream::pair().unwrap();
            let start = Instant::now();
            let guest = s.spawn(move || {
                let mut counted = Counted {
                    stream: guest,
                    read: 0,
                    wrote: 0,
                };
                exchange(&mut counted, pending).unwrap();
                (counted.wrote, counted.read)
            });
            assert_eq!(
                read_request(&mut host).unwrap(),
                ReaderRequest::SubmitObjectV1 {
                    pair,
                    submission: Box::new(submission.clone())
                }
            );
            if let Some(r) = response {
                write_response(&mut host, r).unwrap();
            }
            drop(host);
            let (to_host, to_guest) = guest.join().unwrap();
            let reply = client.join().unwrap().unwrap();
            eprintln!(
                "OBJECT_SUBMISSION sample={name} source_to_host={to_host} host_to_source={to_guest} elapsed_ns={}",
                start.elapsed().as_nanos()
            );
            reply
        })
    };
    assert_eq!(
        attempt("lost", &reader, None),
        ReaderResponse::ObjectPendingV1 { pair, message_id }
    );
    let wrong = host_reply(sign_receipt(body, &a).unwrap());
    assert_eq!(
        attempt("different_seal", &reader, Some(&other)),
        ReaderResponse::Refused {
            reason: Refusal::NotAuthorized
        }
    );
    assert_eq!(
        attempt("unbound", &reader, Some(&accepted)),
        ReaderResponse::Refused {
            reason: Refusal::NotAuthorized
        }
    );
    assert_eq!(
        attempt("wrong_signer", &reader, Some(&wrong)),
        ReaderResponse::Refused {
            reason: Refusal::NotAuthorized
        }
    );
    let mut next = submission.clone();
    if let ObjectSubmissionV1::Call { message_id, .. } = &mut next {
        *message_id = MessageId::from_bytes([69; 32])
    }
    let next = ApplicationReaderRequest::StageObjectV1 {
        pair,
        submission: Box::new(next),
    };
    assert_eq!(local(&reader, &next), Err(Refusal::QueueFull(1)));
    assert_eq!(attempt("accepted", &reader, Some(&valid)), accepted);
    assert_eq!(local(&reader, &status), Ok(accepted.clone()));
    drop(reader);
    let reopened = new_reader();
    assert_eq!(local(&reopened, &next), Err(Refusal::QueueFull(1)));
    assert_eq!(attempt("reopened", &reopened, Some(&valid)), accepted);
    assert_eq!(
        local(&reopened, &next),
        Ok(ReaderResponse::ObjectStagedV1 {
            pair,
            message_id: MessageId::from_bytes([69; 32])
        })
    );
}

#[cfg(target_os = "linux")]
#[path = "worker_component.rs"]
mod worker_component;
