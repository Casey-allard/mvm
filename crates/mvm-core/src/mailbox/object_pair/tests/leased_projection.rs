use super::*;
use crate::mailbox::journal::*;
use crate::mailbox::reader::*;
use crate::mailbox::reader_wire::{ReaderResponse, read_response, write_response};

struct OriginalKey(HistoryKeyRef);
impl HistoryKeyCustody for OriginalKey {
    fn load_existing(&self, reference: &HistoryKeyRef) -> Result<Key, JournalError> {
        if reference != &self.0 {
            return Err(JournalError::HistoryKeyUnavailable);
        }
        Ok(Key::from_bytes([44; 32]))
    }
}

#[test]
fn leased_call_survives_restart_with_exact_header_payload_and_original_signature() {
    lease_and_reopen(false)
}

#[test]
fn reply_only_lease_reopens_under_original_call_and_requires_signed_ack() {
    lease_and_reopen(true)
}

fn lease_and_reopen(reply: bool) {
    let c = grant(false);
    let r = grant(true);
    let grants = ObjectPairGrants {
        call: &c,
        reply: &r,
    };
    let selection = grants
        .commitment(&Nonce::from_bytes([1; 16]), &Nonce::from_bytes([2; 16]))
        .unwrap();
    let (a, ab) = original(&r, Some(selection), 1);
    let (b, bb) = original(&c, Some(selection), 2);
    let ak = key(1).verifying_key();
    let bk = key(2).verifying_key();
    let ae = OriginalObjectEndpoint {
        plan: &a,
        boot: &ab,
        trusted_signers: &[("original", &ak)],
    };
    let be = OriginalObjectEndpoint {
        plan: &b,
        boot: &bb,
        trusted_signers: &[("original", &bk)],
    };
    let state = live(ab.boot, bb.boot);
    let pair = ObjectPairV1::check_originals(&ae, &be, grants, NOW, state).unwrap();
    let (destination, signed, auth, sender_key, grant, vm, guest) = if reply {
        (&ae, &a, key(2), key(11).verifying_key(), &r, &ab, key(41))
    } else {
        (&be, &b, key(3), key(10).verifying_key(), &c, &bb, key(42))
    };
    let plan = verify_plan(signed, destination.trusted_signers)
        .unwrap()
        .mailbox
        .unwrap();
    let address = grant.grant.address;
    let expected_id = if reply { 61 } else { 60 };
    let data = Key::from_bytes([expected_id; 32]);
    let return_route = ReplyRoute {
        address: r.grant.address,
        capability_id: r.grant.capability_id,
    };
    let call = sealed(&c, ab.boot, Some(return_route), NOW - 10, 71, 70);
    let pending = pair
        .pending_call(
            call.clone(),
            NOW,
            state,
            &Key::from_bytes([60; 32]),
            &mut InMemoryReplayProtector::default(),
        )
        .unwrap();
    let envelope = if reply {
        sealed(&r, bb.boot, None, NOW - 1, 71, 60)
    } else {
        call
    };
    let context = crate::mailbox::OpenContext {
        expected_tenant: address.tenant,
        expected_authorization_domain: address.authorization_domain,
        expected_mailbox: address.mailbox,
        expected_sender: grant.grant.subject,
        expected_recipient: address.recipient,
        acting_principal: grant.grant.subject,
        expected_capability_issuer: grant.grant.issuer,
        current_execution_epoch: plan.epoch,
        current_policy_epoch: grant.grant.policy_epoch,
        required_operation: if reply {
            MailboxOperation::Reply
        } else {
            MailboxOperation::Send
        },
        now_unix_ms: NOW,
        accepted_content_types: grant.grant.content_types.clone(),
        revoked_capabilities: vec![],
    };
    let dir = tempfile::tempdir().unwrap();
    let history = OriginalKey(HistoryKeyRef::new(address, plan.epoch, [19; 32], 1).unwrap());
    let start = || {
        let anchor =
            FileJournalAnchor::open(&dir.path().join("anchor"), address, [29; 32]).unwrap();
        let journal = MailboxJournal::open_local_with_custody(
            &dir.path().join("journal"),
            history.0.clone(),
            auth.verifying_key(),
            JournalLimits {
                max_records: 8,
                max_bytes: 128 * 1024,
            },
            &history,
            &anchor,
            plan.retention.unwrap(),
        )
        .unwrap();
        (journal, anchor)
    };
    let (mut journal, anchor) = start();
    let receipt = journal
        .admit_local(
            JournalAdmission {
                envelope: &envelope,
                capability: grant,
                context: &context,
                encryption_key: &data,
                sender_key: &sender_key,
                signer: &auth,
            },
            &anchor,
        )
        .unwrap();
    assert_eq!(
        receipt.receipt.message_id,
        MessageId::from_bytes([expected_id; 32])
    );
    let mut receive = grant.grant.clone();
    receive.subject = address.recipient;
    receive.capability_id = CapabilityId::from_bytes([33; 32]);
    receive.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    let cap = sign_capability(receive, &auth).unwrap();
    let mut read = context.clone();
    read.required_operation = MailboxOperation::Receive;
    read.acting_principal = address.recipient;
    let session = ConsumerSessionId::from_bytes([36; 32]);

    let enrollment = sign_guest_reader_enrollment(
        MailboxGuestReaderEnrollment {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            plan_id: vm.plan_id.clone(),
            plan_nonce: vm.plan_nonce.clone(),
            address,
            consumer: address.recipient,
            consumer_boot: vm.boot,
            consumer_session: session,
            receive_capability_id: cap.grant.capability_id,
            ack_public_key: guest.verifying_key().to_bytes(),
            execution_epoch: plan.epoch,
            policy_epoch: cap.grant.policy_epoch,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 4500,
        },
        &auth,
    )
    .unwrap();
    let exercise = |journal: &mut MailboxJournal, anchor: &FileJournalAnchor, value: u8| {
        let challenge = [value; 32];
        let proof = sign_reader_possession(&enrollment, &challenge, &guest).unwrap();
        let request = || JournalGuestLease {
            receive: JournalReceive {
                capability: &cap,
                context: &read,
                encryption_key: &data,
                sender_key: &sender_key,
            },
            plan: &plan,
            scope: MailboxGuestReaderScope {
                plan: &plan,
                plan_id: &vm.plan_id,
                plan_nonce: &vm.plan_nonce,
                receive: &cap.grant,
                current_boot: vm.boot,
                current_session: session,
                now_unix_ms: NOW,
            },
            enrollment: &enrollment,
            challenge: &challenge,
            possession_signature: &proof,
            signer: &auth,
        };
        let authority = |state| ObjectLeaseScope {
            pair: &pair,
            destination: vm,
            state,
            original_call: reply.then_some(&pending),
        };
        let prior = journal.tip();
        assert!(
            journal
                .lease_next(request(), |_| panic!(
                    "cannot downgrade the selected reader"
                ))
                .is_err()
        );
        let revoked = [grant.grant.revocation_id];
        assert!(
            journal
                .lease_next_object(
                    request(),
                    authority(PairAuthorityState {
                        at_caller: if reply { &revoked } else { &[] },
                        at_callee: if reply { &[] } else { &revoked },
                        ..state
                    }),
                    |_| panic!("cannot expose after revocation")
                )
                .is_err()
        );
        assert_eq!(journal.tip(), prior);
        let record = journal
            .lease_next_object(request(), authority(state), |tip| anchor.advance(tip))
            .unwrap()
            .unwrap();
        let wire = record.into_reader_response(Some(selection)).unwrap();
        let mut bytes = Vec::new();
        write_response(&mut bytes, &wire).unwrap();
        let decoded = read_response(&mut &bytes[..]).unwrap();
        let ReaderResponse::ObjectDeliveryV1 {
            lease,
            header,
            payload,
        } = &decoded
        else {
            panic!("wrong delivery")
        };
        verify_object_delivery_projection(
            &selection,
            header,
            payload,
            lease,
            &auth.verifying_key(),
        )
        .unwrap();
        assert_eq!(header.reply_to, (!reply).then_some(return_route));
        assert_eq!(payload, b"obj\0");
        decoded
    };
    let first = exercise(&mut journal, &anchor, 46);
    drop(journal);
    drop(anchor);
    let (mut journal, anchor) = start();
    assert_eq!(exercise(&mut journal, &anchor, 47), first);
}
