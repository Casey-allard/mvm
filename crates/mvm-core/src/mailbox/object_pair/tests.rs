use super::*;
use crate::crypto::aead::Key;
use crate::mailbox::{InMemoryReplayProtector, SealRequest, seal_envelope, sign_capability};
use crate::plan::{sign_plan, test_support::PlanFixture};
use ed25519_dalek::SigningKey;

const NOW: i64 = 1_800_000_000_000;
fn live(caller_boot: BootId, callee_boot: BootId) -> PairAuthorityState<'static> {
    PairAuthorityState {
        caller_boot,
        callee_boot,
        caller_epoch: ExecutionEpoch::new(1).unwrap(),
        callee_epoch: ExecutionEpoch::new(1).unwrap(),
        caller_policy: 12,
        callee_policy: 12,
        at_caller: &[],
        at_callee: &[],
    }
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn principal(n: u8) -> PrincipalId {
    PrincipalId::from_bytes(key(n).verifying_key().to_bytes())
}

fn grant(reply: bool) -> SignedMailboxCapability {
    let (auth, src, dst, op, kind, id) = if reply {
        (
            2,
            11,
            10,
            MailboxOperation::Reply,
            MailboxMessageKind::Reply,
            20,
        )
    } else {
        (
            3,
            10,
            11,
            MailboxOperation::Send,
            MailboxMessageKind::Call,
            21,
        )
    };
    sign_capability(
        MailboxCapabilityGrant {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            issuer: principal(auth),
            subject: principal(src),
            address: MailboxAddress {
                tenant: TenantId::from_bytes([5; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([6; 32]),
                mailbox: MailboxId::from_bytes([id; 32]),
                recipient: principal(dst),
            },
            capability_id: CapabilityId::from_bytes([id; 32]),
            revocation_id: RevocationId::from_bytes([id; 32]),
            operations: CapabilityOperations::from_operations(&[op]),
            message_kinds: vec![kind],
            content_types: vec![ContentType::parse("application/spiralcore-object", 1).unwrap()],
            max_payload_bytes: if reply { 88 } else { 4152 },
            max_messages_per_minute: 60,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 4152,
            minimum_execution_epoch: ExecutionEpoch::new(1).unwrap(),
            maximum_execution_epoch: ExecutionEpoch::new(1).unwrap(),
            policy_epoch: 12,
            not_before_unix_ms: NOW - 10_000,
            expires_at_unix_ms: NOW + 10_000,
            delegation_depth: 0,
        },
        &key(auth),
    )
    .unwrap()
}

fn original(
    signed: &SignedMailboxCapability,
    selection: Option<[u8; 32]>,
    n: u8,
) -> (SignedExecutionPlan, MailboxReaderBootBinding) {
    let g = &signed.grant;
    let plan = PlanFixture::new()
        .nonce([n; 16])
        .workload(format!("vm-{n}"))
        .validity(
            chrono::DateTime::from_timestamp_millis(NOW - 20_000).unwrap(),
            chrono::DateTime::from_timestamp_millis(NOW + 20_000).unwrap(),
        )
        .mailbox(MailboxGrant {
            durable_object_pair_sha256_v1: selection,
            incoming_journal_policy_sha256_v1: None,
            outbound_journal_v1: None,
            mailbox: g.address.mailbox,
            authority_key: *g.issuer.as_bytes(),
            epoch: g.minimum_execution_epoch,
            report: None,
            retention: Some(MailboxRetentionPolicy::new(25_000).unwrap()),
        })
        .build();
    let s = sign_plan(&plan, &key(n), "original");
    let verified = verify_plan(&s, &[("original", &key(n).verifying_key())]).unwrap();
    let boot = MailboxReaderBootBinding::mint(
        &verified,
        key(n + 30).verifying_key(),
        key(n + 40).verifying_key().to_bytes(),
    )
    .unwrap();
    (s, boot)
}

fn sealed(
    signed: &SignedMailboxCapability,
    boot: BootId,
    reply_to: Option<ReplyRoute>,
    issued: i64,
    corr: u8,
    cause: u8,
) -> MailboxEnvelope {
    let g = &signed.grant;
    let reply = g.message_kinds[0] == MailboxMessageKind::Reply;
    let msg = if reply { 61 } else { 60 };
    let body = b"obj\0";
    let header = MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant: g.address.tenant,
        authorization_domain: g.address.authorization_domain,
        sender: g.subject,
        recipient: g.address.recipient,
        mailbox: g.address.mailbox,
        sender_boot: boot,
        execution_epoch: g.minimum_execution_epoch,
        message_id: MessageId::from_bytes([msg; 32]),
        correlation_id: CorrelationId::from_bytes([corr; 32]),
        causation_id: CausationId::from_bytes([cause; 32]),
        kind: g.message_kinds[0],
        reply_to,
        ordering_scope: OrderingScope::parse("original").unwrap(),
        sequence: SequenceNumber::new(1).unwrap(),
        issued_at_unix_ms: issued,
        expires_at_unix_ms: NOW + 5000,
        nonce: ReplayNonce::from_bytes([msg; 16]),
        content_type: g.content_types[0].clone(),
        capability_id: g.capability_id,
        policy_epoch: g.policy_epoch,
        encryption: EncryptionContext {
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id: [msg; 32],
        },
        plaintext_len: body.len() as u32,
    };
    let routing = MailboxRoutingFrame {
        protocol_version: ProtocolVersion::V1,
        authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes([7; 32]),
        destination_route_token: DestinationRouteToken::from_bytes([8; 32]),
        delivery_id: DeliveryId::from_bytes([msg; 32]),
        ciphertext_len: 0,
        padding: CiphertextPadding::Exact,
        expires_at_unix_ms: header.expires_at_unix_ms,
        hop_limit: 1,
        transport_binding_id: TransportBindingId::from_bytes([9; 32]),
    };
    seal_envelope(
        SealRequest {
            routing,
            header,
            plaintext: body,
        },
        &Key::from_bytes([msg; 32]),
        &key(if reply { 11 } else { 10 }),
    )
    .unwrap()
}

#[test]
fn original_enrollment_and_correlated_verified_envelopes() {
    let c = grant(false);
    let r = grant(true);
    let selected = ObjectPairGrants {
        call: &c,
        reply: &r,
    };
    let commitment = selected
        .commitment(&Nonce::from_bytes([1; 16]), &Nonce::from_bytes([2; 16]))
        .unwrap();
    let (a, ab) = original(&r, Some(commitment), 1);
    let (b, bb) = original(&c, Some(commitment), 2);
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
    let pair =
        ObjectPairV1::check_originals(&ae, &be, selected, NOW, live(ab.boot, bb.boot)).unwrap();
    let mut stripped = ab.clone();
    stripped.durable_object_pair_sha256_v1 = None;
    assert!(
        ObjectPairV1::check_originals(
            &OriginalObjectEndpoint {
                boot: &stripped,
                ..ae
            },
            &be,
            selected,
            NOW,
            live(ab.boot, bb.boot)
        )
        .is_err()
    );
    let route = ReplyRoute {
        address: r.grant.address,
        capability_id: r.grant.capability_id,
    };
    let call = || sealed(&c, ab.boot, Some(route), NOW - 2, 88, 70);
    let ar = &Key::from_bytes([60; 32]);
    let br = &Key::from_bytes([61; 32]);
    let mut calls = InMemoryReplayProtector::default();
    let pending = pair
        .pending_call(call(), NOW, live(ab.boot, bb.boot), ar, &mut calls)
        .unwrap();
    assert!(
        pair.pending_call(call(), NOW, live(ab.boot, bb.boot), ar, &mut calls)
            .is_err()
    );
    let revoked = [r.grant.revocation_id];
    let check = |msg, now, rev| {
        pair.check_reply(
            &pending,
            msg,
            now,
            rev,
            br,
            &mut InMemoryReplayProtector::default(),
        )
    };
    assert!(
        check(
            sealed(&r, bb.boot, None, NOW - 1, 88, 60),
            NOW,
            live(ab.boot, bb.boot)
        )
        .is_ok()
    );
    for msg in [
        sealed(&r, bb.boot, None, NOW - 1, 88, 77),
        sealed(&r, bb.boot, None, NOW - 1, 89, 60),
        sealed(&r, ab.boot, None, NOW - 1, 88, 60),
        sealed(&r, bb.boot, None, NOW - 3, 88, 60),
    ] {
        assert!(check(msg, NOW, live(ab.boot, bb.boot)).is_err());
    }
    assert!(
        check(
            sealed(&r, bb.boot, None, NOW - 1, 88, 60),
            NOW,
            PairAuthorityState {
                at_caller: &revoked,
                ..live(ab.boot, bb.boot)
            }
        )
        .is_err()
    );
    assert!(
        check(
            sealed(&r, bb.boot, None, NOW - 1, 88, 60),
            NOW + 5_000,
            live(ab.boot, bb.boot)
        )
        .is_err()
    );
    let mut replay = InMemoryReplayProtector::default();
    let original_reply = || sealed(&r, bb.boot, None, NOW - 1, 88, 60);
    for replacement in [
        PairAuthorityState {
            caller_boot: BootId::from_bytes([99; 32]),
            ..live(ab.boot, bb.boot)
        },
        PairAuthorityState {
            callee_boot: BootId::from_bytes([99; 32]),
            ..live(ab.boot, bb.boot)
        },
    ] {
        assert!(
            pair.check_reply(
                &pending,
                original_reply(),
                NOW,
                replacement,
                br,
                &mut replay
            )
            .is_err()
        );
    }

    assert!(
        pair.check_reply(
            &pending,
            original_reply(),
            NOW,
            PairAuthorityState {
                caller_policy: 13,
                ..live(ab.boot, bb.boot)
            },
            br,
            &mut replay
        )
        .is_err()
    );
    assert!(
        pair.check_reply(
            &pending,
            sealed(&r, bb.boot, None, NOW - 1, 88, 99),
            NOW,
            live(ab.boot, bb.boot),
            br,
            &mut replay
        )
        .is_err()
    );
    assert!(
        pair.check_reply(
            &pending,
            original_reply(),
            NOW,
            live(ab.boot, bb.boot),
            br,
            &mut replay
        )
        .is_ok()
    );
    assert!(
        pair.check_reply(
            &pending,
            original_reply(),
            NOW,
            live(ab.boot, bb.boot),
            br,
            &mut replay
        )
        .is_err()
    );
    let wrong = ReplyRoute {
        address: c.grant.address,
        ..route
    };
    assert!(
        pair.pending_call(
            sealed(&c, ab.boot, Some(wrong), NOW - 2, 88, 70),
            NOW,
            live(ab.boot, bb.boot),
            ar,
            &mut InMemoryReplayProtector::default()
        )
        .is_err()
    );
}

#[test]
fn grants_and_both_original_signed_plans_are_required() {
    let c = grant(false);
    let r = grant(true);
    let fixture = |reply: &SignedMailboxCapability, selected: bool, wrong_nonce: bool| {
        let pair = ObjectPairGrants { call: &c, reply };
        let stamp = pair
            .commitment(&Nonce::from_bytes([1; 16]), &Nonce::from_bytes([2; 16]))
            .unwrap();
        let (a, ab) = original(reply, selected.then_some(stamp), 1);
        let (b, bb) = original(&c, Some(stamp), if wrong_nonce { 3 } else { 2 });
        let ak = key(1).verifying_key();
        let bk = key(if wrong_nonce { 3 } else { 2 }).verifying_key();
        ObjectPairV1::check_originals(
            &OriginalObjectEndpoint {
                plan: &a,
                boot: &ab,
                trusted_signers: &[("original", &ak)],
            },
            &OriginalObjectEndpoint {
                plan: &b,
                boot: &bb,
                trusted_signers: &[("original", &bk)],
            },
            pair,
            NOW,
            live(ab.boot, bb.boot),
        )
        .is_ok()
    };
    assert!(fixture(&r, true, false));
    assert!(!fixture(&r, false, false));
    assert!(!fixture(&r, true, true));
    let mut wrong = r.grant.clone();
    wrong.operations = CapabilityOperations::from_operations(&[MailboxOperation::Send]);
    assert!(!fixture(
        &sign_capability(wrong, &key(2)).unwrap(),
        true,
        false
    ));
    assert!(!fixture(
        &sign_capability(r.grant.clone(), &key(99)).unwrap(),
        true,
        false
    ));
}
