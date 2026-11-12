use super::*;
use crate::audit::host_keypair;
use ed25519_dalek::SigningKey;
use mvm_core::mailbox::{
    reader::{mint_guest_receive_capability, sign_reader_possession, verify_reader_possession},
    sign_capability,
};
use mvm_core::plan::{sign_plan, test_support::PlanFixture};

fn public_grant(dir: &Path, mail: u8) -> MailboxGrant {
    let mailbox = MailboxId::from_bytes([mail; 32]);
    let epoch = ExecutionEpoch::new(1).unwrap();
    MailboxGrant {
        mailbox,
        epoch,
        authority_key: super::super::authority_key_for(dir, &mailbox, epoch)
            .unwrap()
            .to_bytes(),
        report: None,
        retention: Some(MailboxRetentionPolicy::new(60_000).unwrap()),
        incoming_journal_policy_sha256_v1: None,
        outbound_journal_v1: None,
        durable_object_pair_sha256_v1: None,
    }
}

fn flow(
    keys: &Path,
    to: &MailboxGrant,
    from: &MailboxGrant,
    kind: MailboxMessageKind,
    op: MailboxOperation,
    id: u8,
    now: i64,
) -> SignedMailboxCapability {
    let src = super::super::derived_keys(keys, &from.mailbox, from.epoch).unwrap();
    let dst = super::super::derived_keys(keys, &to.mailbox, to.epoch).unwrap();
    let receive = op == MailboxOperation::Receive;
    let address = MailboxAddress {
        tenant: TenantId::from_bytes([1; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
        mailbox: to.mailbox,
        recipient: PrincipalId::from_bytes(dst.sender.verifying_key().to_bytes()),
    };
    sign_capability(
        MailboxCapabilityGrant {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            capability_id: CapabilityId::from_bytes([id; 32]),
            revocation_id: RevocationId::from_bytes([id; 32]),
            issuer: PrincipalId::from_bytes(to.authority_key),
            subject: if receive {
                address.recipient
            } else {
                PrincipalId::from_bytes(src.sender.verifying_key().to_bytes())
            },
            address,
            operations: CapabilityOperations::from_operations(&[op]),
            message_kinds: vec![kind],
            content_types: vec![ContentType::parse("application/spiralcore-object", 1).unwrap()],
            minimum_execution_epoch: to.epoch,
            maximum_execution_epoch: to.epoch,
            policy_epoch: 1,
            not_before_unix_ms: now - 1000,
            expires_at_unix_ms: now + 120_000,
            max_payload_bytes: if kind == MailboxMessageKind::Call {
                4152
            } else {
                88
            },
            max_messages_per_minute: 60,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 8192,
            delegation_depth: 0,
        },
        &dst.authority,
    )
    .unwrap()
}

struct Originals {
    dir: tempfile::TempDir,
    a: MailboxGrant,
    b: MailboxGrant,
    credentials: ObjectPairCredentials,
    now: i64,
}
impl Originals {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        host_keypair::load_or_init_at(dir.path()).unwrap();
        let now = super::super::now_unix_ms();
        let a = public_grant(dir.path(), 31);
        let b = public_grant(dir.path(), 32);
        let credentials = ObjectPairCredentials {
            call: flow(
                dir.path(),
                &b,
                &a,
                MailboxMessageKind::Call,
                MailboxOperation::Send,
                7,
                now,
            ),
            reply: flow(
                dir.path(),
                &a,
                &b,
                MailboxMessageKind::Reply,
                MailboxOperation::Reply,
                8,
                now,
            ),
            receive_at_caller: flow(
                dir.path(),
                &a,
                &b,
                MailboxMessageKind::Reply,
                MailboxOperation::Receive,
                9,
                now,
            ),
            receive_at_callee: flow(
                dir.path(),
                &b,
                &a,
                MailboxMessageKind::Call,
                MailboxOperation::Receive,
                10,
                now,
            ),
        };
        Self {
            dir,
            a,
            b,
            credentials,
            now,
        }
    }
    fn prepare(&self, credentials: ObjectPairCredentials) -> Result<PreparedObjectPair> {
        PreparedObjectPair::prepare_at(
            self.dir.path(),
            &self.a,
            &Nonce::from_bytes([1; 16]),
            &self.b,
            &Nonce::from_bytes([2; 16]),
            credentials,
            self.now,
        )
    }
}

struct BootFixture {
    dir: tempfile::TempDir,
    signed: SignedExecutionPlan,
    boot: MailboxReaderBootBinding,
    posture: MailboxLaunchPosture,
    ack: SigningKey,
}
impl BootFixture {
    fn new(keys: &Path, grant: MailboxGrant, n: u8, now: i64) -> Self {
        let mut plan = PlanFixture::new()
            .workload(format!("vm-{n}"))
            .nonce([n; 16])
            .validity(
                chrono::DateTime::from_timestamp_millis(now - 5000).unwrap(),
                chrono::DateTime::from_timestamp_millis(now + 120000).unwrap(),
            )
            .mailbox(grant)
            .build();
        plan.image.name = format!("vm-{n}");
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let signer = host_keypair::load_or_init_at(keys).unwrap();
        let signed = sign_plan(&plan, &signer.signing, &host_keypair::host_signer_id());
        let ack = SigningKey::from_bytes(&[n + 31; 32]);
        let boot = MailboxReaderBootBinding::mint(
            &plan,
            SigningKey::from_bytes(&[n + 21; 32]).verifying_key(),
            ack.verifying_key().to_bytes(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        boot.persist(dir.path()).unwrap();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Prod);
        Self {
            dir,
            signed,
            boot,
            posture,
            ack,
        }
    }
    fn input(&self) -> BootInput<'_> {
        BootInput {
            plan: &self.signed,
            state: self.dir.path(),
            boot: &self.boot,
            posture: &self.posture,
            current_epoch: ExecutionEpoch::new(1).unwrap(),
        }
    }
}

#[test]
fn original_installation_rejects_an_unissued_or_swapped_return_reader() {
    let f = Originals::new();
    let mut wrong = f.credentials.clone();
    wrong.receive_at_caller = wrong.receive_at_callee.clone();
    assert!(f.prepare(wrong).is_err());
    let mut bad = f.credentials.clone();
    bad.reply.signature[0] ^= 1;
    assert!(f.prepare(bad).is_err());
    let mut too_large = f.credentials.clone();
    let aa = super::super::derived_keys(f.dir.path(), &f.a.mailbox, f.a.epoch).unwrap();
    too_large.receive_at_caller.grant.max_payload_bytes += 1;
    too_large.receive_at_caller =
        sign_capability(too_large.receive_at_caller.grant, &aa.authority).unwrap();
    assert!(f.prepare(too_large).is_err());
    let p = f.prepare(f.credentials.clone()).unwrap();
    let (a, b) = p.selected_grants();
    assert!(a.durable_object_pair_sha256_v1.is_some());
    assert_eq!(
        a.durable_object_pair_sha256_v1,
        b.durable_object_pair_sha256_v1
    );
    assert_eq!(f.a.durable_object_pair_sha256_v1, None);
    assert!(!f.dir.path().join(super::super::ENCRYPTION_ROOT).exists());
}

#[test]
fn independent_direction_keys_and_original_reader_possession_survive_restart() {
    let f = Originals::new();
    let p = f.prepare(f.credentials.clone()).unwrap();
    let (ag, bg) = p.selected_grants();
    let a = BootFixture::new(f.dir.path(), ag, 1, f.now);
    let b = BootFixture::new(f.dir.path(), bg, 2, f.now);
    let auth = super::super::derived_keys(f.dir.path(), &ag.mailbox, ag.epoch)
        .unwrap()
        .authority;
    assert!(
        mint_guest_receive_capability(
            &ag,
            &a.boot,
            &f.credentials.reply,
            f.credentials.reply.grant.address,
            &auth
        )
        .is_err(),
        "canonical own-mailbox mint must refuse Reply as a Send substitute"
    );
    let bind = || p.bind_at(f.dir.path(), a.input(), b.input(), f.now);
    assert!(
        bind().is_err(),
        "missing KEK cannot silently create a different DEK"
    );
    let root = f.dir.path().join(super::super::ENCRYPTION_ROOT);
    Key::load_or_create(&root).unwrap();
    let first = bind().unwrap();
    let caller_store = first.caller.custody.storage_paths(f.dir.path()).unwrap();
    let callee_store = first.callee.custody.storage_paths(f.dir.path()).unwrap();
    assert_ne!(caller_store.source_intents, callee_store.source_intents);
    assert_eq!(
        first.caller.custody.address(),
        f.credentials.reply.grant.address
    );
    assert_eq!(
        first.callee.custody.address(),
        f.credentials.call.grant.address
    );
    assert_eq!(
        first.caller.reader.capability,
        f.credentials.receive_at_caller
    );
    assert_eq!(
        first.callee.reader.capability,
        f.credentials.receive_at_callee
    );
    for (original, peer) in [
        (&first.caller, &first.callee),
        (&first.callee, &first.caller),
    ] {
        assert!(original.outbound_key.expose_bytes() == peer.inbound_key.expose_bytes());
        assert!(original.inbound_key.expose_bytes() != original.outbound_key.expose_bytes());
    }
    for (role, material) in [(&a, &first.caller), (&b, &first.callee)] {
        let challenge = [81u8; 32];
        let proof =
            sign_reader_possession(&material.reader.enrollment, &challenge, &role.ack).unwrap();
        verify_reader_possession(
            &material.reader.enrollment,
            &challenge,
            &proof,
            &role.ack.verifying_key(),
        )
        .unwrap();
    }
    let second = bind().unwrap();
    assert_eq!(
        second.caller.custody.history_reference(),
        first.caller.custody.history_reference()
    );
    assert_eq!(
        second.callee.custody.history_reference(),
        first.callee.custody.history_reference()
    );
    assert_eq!(
        first.caller.reader.enrollment,
        second.caller.reader.enrollment
    );
    assert_eq!(
        first.callee.reader.enrollment,
        second.callee.reader.enrollment
    );
    assert!(first.caller.outbound_key.expose_bytes() == second.callee.inbound_key.expose_bytes());
    let revoke = revocations_path(b.dir.path());
    std::fs::write(
        &revoke,
        serde_json::to_vec(&[f.credentials.receive_at_callee.grant.revocation_id]).unwrap(),
    )
    .unwrap();
    assert!(bind().is_err());
    std::fs::remove_file(&revoke).unwrap();
    std::fs::write(&root, [66u8; 32]).unwrap();
    assert!(
        bind().is_err(),
        "changed retained directional keys must refuse"
    );
}

struct History(mvm_core::mailbox::journal::HistoryKeyRef);
impl mvm_core::mailbox::journal::HistoryKeyCustody for History {
    fn load_existing(
        &self,
        r: &mvm_core::mailbox::journal::HistoryKeyRef,
    ) -> std::result::Result<Key, mvm_core::mailbox::journal::JournalError> {
        if r != &self.0 {
            return Err(mvm_core::mailbox::journal::JournalError::HistoryKeyUnavailable);
        }
        Ok(Key::from_bytes([44; 32]))
    }
}

#[test]
fn original_seals_exact_object_bodies_and_restores_only_the_matching_retained_lease() {
    use mvm_core::mailbox::{
        OpenContext,
        journal::*,
        object_pair::role::ObjectParticipantRole::{Callee, Caller},
        reader::*,
        reader_wire::ObjectSubmissionV1,
    };
    let f = Originals::new();
    let p = f.prepare(f.credentials.clone()).unwrap();
    let (ag, bg) = p.selected_grants();
    let a = BootFixture::new(f.dir.path(), ag, 1, f.now);
    let b = BootFixture::new(f.dir.path(), bg, 2, f.now);
    Key::load_or_create(&f.dir.path().join(super::super::ENCRYPTION_ROOT)).unwrap();
    let material = p
        .bind_at(f.dir.path(), a.input(), b.input(), f.now)
        .unwrap();
    let msg = MessageId::from_bytes([72; 32]);
    let corr = CorrelationId::from_bytes([73; 32]);
    let seq = SequenceNumber::new(1).unwrap();
    let callbody = b"SC\0\x11\0";
    let replybody = b"reply\0\0";
    let call = material
        .seal_turn(Caller, msg, Some(corr), seq, callbody, None, f.now)
        .unwrap();
    assert_eq!(call.header().correlation_id, corr);
    assert!(
        material
            .seal_turn(
                Caller,
                msg,
                Some(CorrelationId::from_bytes([0; 32])),
                seq,
                callbody,
                None,
                f.now
            )
            .is_err()
    );
    let sub = ObjectSubmissionV1::Call {
        message_id: msg,
        correlation_id: corr,
        payload: callbody.to_vec(),
    };
    let source_dir = tempfile::tempdir().unwrap();
    let source_start = std::time::Instant::now();
    let record_name =
        crate::mailbox_service::object_intent::original_record_name(p.stamp, a.boot.boot, msg);
    let (ordinal, original) = crate::mailbox_service::object_intent_slot_tests::publish_then_reopen(
        source_dir.path(),
        &record_name,
        mvm_core::mailbox::reader_wire::original_object_intent_digest(&sub).unwrap(),
        &mvm_core::mailbox::frame::encode_frame(call.capability(), call.envelope()).unwrap(),
    );
    let (restored_grant, restored_envelope) =
        mvm_core::mailbox::frame::decode_frame(&original).unwrap();
    let restored = material
        .reopen(
            Caller,
            &restored_grant,
            restored_envelope,
            ordinal,
            &sub,
            None,
            f.now,
        )
        .unwrap();
    let source_time = source_start.elapsed();
    assert_eq!(restored.envelope(), call.envelope());
    let incorrect = ObjectSubmissionV1::Call {
        message_id: msg,
        correlation_id: corr,
        payload: b"SC\0\x11".to_vec(),
    };
    assert!(
        material
            .reopen(
                Caller,
                call.capability(),
                call.envelope().clone(),
                seq,
                &incorrect,
                None,
                f.now
            )
            .is_err()
    );

    let g = &f.credentials.call.grant;
    let address = g.address;
    let signer = super::super::derived_keys(f.dir.path(), &bg.mailbox, bg.epoch)
        .unwrap()
        .authority;
    let sender = material.caller.sender.verifying_key();
    let context = OpenContext {
        expected_tenant: address.tenant,
        expected_authorization_domain: address.authorization_domain,
        expected_mailbox: address.mailbox,
        expected_sender: g.subject,
        expected_recipient: address.recipient,
        acting_principal: g.subject,
        expected_capability_issuer: g.issuer,
        current_execution_epoch: bg.epoch,
        current_policy_epoch: g.policy_epoch,
        required_operation: MailboxOperation::Send,
        now_unix_ms: f.now,
        accepted_content_types: g.content_types.clone(),
        revoked_capabilities: Vec::new(),
    };
    let dir = tempfile::tempdir().unwrap();
    let anchor = FileJournalAnchor::open(&dir.path().join("anchor"), address, [29; 32]).unwrap();
    let history = History(HistoryKeyRef::new(address, bg.epoch, [19; 32], 1).unwrap());
    let mut journal = MailboxJournal::open_local_with_custody(
        &dir.path().join("journal"),
        history.0,
        signer.verifying_key(),
        JournalLimits {
            max_records: 8,
            max_bytes: 131072,
        },
        &history,
        &anchor,
        bg.retention.unwrap(),
    )
    .unwrap();
    // Run the same immutable source ciphertext twice through a real local socket.
    // B admits from the received frame, not from the sender's in-memory object.
    let mut exchange = || {
        use mvm_core::mailbox::frame::{decode_frame, send_local_receipted_frame};
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (mut source, mut destination) = UnixStream::pair().unwrap();
        let start = std::time::Instant::now();
        let (received, sent, response) = std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let body = crate::mailbox_service::read_frame(65536, &mut destination).unwrap();
                let (capability, envelope) = decode_frame(&body).unwrap();
                assert_eq!(envelope, *call.envelope());
                let receipt = journal
                    .admit_local(
                        JournalAdmission {
                            envelope: &envelope,
                            capability: &capability,
                            context: &context,
                            encryption_key: &material.callee.inbound_key,
                            sender_key: &sender,
                            signer: &signer,
                        },
                        &anchor,
                    )
                    .unwrap();
                let verdict =
                    serde_json::to_vec(&Ok::<_, crate::mailbox_service::Refusal>(receipt)).unwrap();
                destination.write_all(&verdict).unwrap();
                destination.shutdown(std::net::Shutdown::Write).unwrap();
                (body.len() + 4, verdict.len())
            });
            let response = send_local_receipted_frame(
                &mut source,
                restored.capability(),
                restored.envelope(),
                restored.header(),
                &signer.verifying_key(),
            )
            .unwrap();
            let (received, sent) = handle.join().unwrap();
            (received, sent, response)
        });
        println!(
            "original_object_store source_reopen_ns={} socket_forward_bytes={} socket_return_bytes={} through_signed_receipt_ns={}",
            source_time.as_nanos(),
            received,
            sent,
            start.elapsed().as_nanos()
        );
        response
    };
    let receipt = exchange();
    let retry = exchange();
    assert_eq!(receipt, retry);
    material.verify_accepted(Caller, &call, &receipt).unwrap();
    let a_alt_state = tempfile::tempdir().unwrap();
    a.boot.persist(a_alt_state.path()).unwrap();
    let b2 = BootFixture::new(f.dir.path(), bg, 2, f.now);
    assert_ne!(b.boot.boot, b2.boot.boot);
    let other = p
        .bind_at(
            f.dir.path(),
            BootInput {
                state: a_alt_state.path(),
                ..a.input()
            },
            b2.input(),
            f.now,
        )
        .unwrap();
    assert!(
        other.verify_accepted(Caller, &call, &receipt).is_err(),
        "another receiver incarnation accepted this original ciphertext"
    );
    for t in [
        call.header().issued_at_unix_ms - 1,
        call.header().expires_at_unix_ms,
    ] {
        let mut replacement = receipt.receipt.clone();
        replacement.observed_at_unix_ms = t;
        let replacement = mvm_core::mailbox::sign_receipt(replacement, &signer).unwrap();
        assert!(
            material
                .verify_accepted(Caller, &call, &replacement)
                .is_err(),
            "receipt outside original validity"
        );
    }
    assert!(material.verify_accepted(Callee, &call, &receipt).is_err());
    let reader = &material.callee.reader;
    let enroll = &reader.enrollment;
    let session = enroll.enrollment.consumer_session;
    let challenge = [5; 32];
    let proof = sign_reader_possession(enroll, &challenge, &b.ack).unwrap();
    let mut read = context.clone();
    read.acting_principal = address.recipient;
    read.required_operation = MailboxOperation::Receive;
    let (key_a, key_b) = (
        host_keypair::load_or_init_at(f.dir.path())
            .unwrap()
            .verifying,
        host_keypair::load_or_init_at(f.dir.path())
            .unwrap()
            .verifying,
    );
    let id = host_keypair::host_signer_id();
    let trust_a = [(id.as_str(), &key_a)];
    let trust_b = [(id.as_str(), &key_b)];
    let live = PairAuthorityState {
        caller_boot: a.boot.boot,
        callee_boot: b.boot.boot,
        caller_epoch: ag.epoch,
        callee_epoch: bg.epoch,
        caller_policy: 1,
        callee_policy: 1,
        at_caller: &[],
        at_callee: &[],
    };
    let pair = ObjectPairV1::check_originals(
        &OriginalObjectEndpoint {
            plan: &a.signed,
            boot: &a.boot,
            trusted_signers: &trust_a,
        },
        &OriginalObjectEndpoint {
            plan: &b.signed,
            boot: &b.boot,
            trusted_signers: &trust_b,
        },
        ObjectPairGrants {
            call: &f.credentials.call,
            reply: &f.credentials.reply,
        },
        f.now,
        live,
    )
    .unwrap();
    let read_scope = MailboxGuestReaderScope {
        plan: &bg,
        plan_id: &b.boot.plan_id,
        plan_nonce: &b.boot.plan_nonce,
        receive: &reader.capability.grant,
        current_boot: b.boot.boot,
        current_session: session,
        now_unix_ms: f.now,
    };
    let request = JournalGuestLease {
        plan: &bg,
        scope: read_scope,
        receive: JournalReceive {
            context: &read,
            capability: &reader.capability,
            encryption_key: &material.callee.inbound_key,
            sender_key: &sender,
        },
        enrollment: enroll,
        challenge: &challenge,
        possession_signature: &proof,
        signer: &signer,
    };
    let leased = journal
        .lease_next_object(
            request,
            ObjectLeaseScope {
                pair: &pair,
                destination: &b.boot,
                state: live,
                original_call: None,
            },
            |tip| anchor.advance(tip),
        )
        .unwrap()
        .unwrap();
    assert_eq!(leased.payload(), callbody, "destination journal readback");
    let signed = leased.lease().clone();
    let current = journal.original_object_call(&signed, f.now).unwrap();
    let reply_id = MessageId::from_bytes([78; 32]);
    let reply = material
        .seal_turn(
            Callee,
            reply_id,
            None,
            seq,
            replybody,
            Some(&current),
            f.now,
        )
        .unwrap();
    let recover = |dir: &std::path::Path, envelope: &MailboxEnvelope| {
        super::pending::recover(
            &material.caller,
            dir,
            &pair,
            live,
            reply.capability(),
            envelope,
            f.now,
        )
    };
    recover(source_dir.path(), reply.envelope()).unwrap();
    let absent = tempfile::tempdir().unwrap();
    assert!(recover(absent.path(), reply.envelope()).is_err());
    assert_eq!(std::fs::read_dir(absent.path()).unwrap().count(), 0);
    let bad_reply = {
        let mut h = reply.header().clone();
        h.correlation_id = CorrelationId::from_bytes([164; 32]);
        mvm_core::mailbox::seal_envelope(
            mvm_core::mailbox::SealRequest {
                header: h,
                routing: reply.envelope().routing.clone(),
                plaintext: replybody,
            },
            &material.callee.outbound_key,
            &material.callee.sender,
        )
        .unwrap()
    };
    assert!(recover(source_dir.path(), &bad_reply).is_err());
    let record_path = source_dir.path().join(&record_name);
    let saved = std::fs::read(&record_path).unwrap();
    for byte in [7, 8] {
        let mut changed = saved.clone();
        changed[byte] ^= 2;
        std::fs::write(&record_path, &changed).unwrap();
        assert!(recover(source_dir.path(), reply.envelope()).is_err());
    }
    std::fs::write(&record_path, saved).unwrap();
    recover(source_dir.path(), reply.envelope()).unwrap();
    let rs = ObjectSubmissionV1::Reply {
        message_id: reply_id,
        original_call: Box::new(signed.clone()),
        payload: replybody.to_vec(),
    };
    assert_eq!(
        material
            .reopen(
                Callee,
                reply.capability(),
                reply.envelope().clone(),
                seq,
                &rs,
                Some(&current),
                f.now
            )
            .unwrap()
            .envelope(),
        reply.envelope()
    );
    assert_eq!(reply.header().causation_id.as_bytes(), msg.as_bytes());
    assert_eq!(reply.header().correlation_id, corr);
    let mut bad = signed.clone();
    bad.lease.lease_nonce = DeliveryLeaseNonce::from_bytes([0; 16]);
    assert!(journal.original_object_call(&bad, f.now).is_err());
    assert!(
        journal
            .original_object_call(&signed, signed.lease.expires_at_unix_ms)
            .is_err()
    );
}
