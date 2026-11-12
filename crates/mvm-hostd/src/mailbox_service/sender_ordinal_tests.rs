use super::{
    sender_window::{Original, SenderWindow},
    *,
};
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    BootId, DeliveryOutcome, DestinationReceipt, MailboxJournalDirectionV1, ProtocolVersion,
    SenderSettlementProfile, SignatureAlgorithm,
};
use mvm_core::mailbox::{
    outbound::{journal_direction_commitment, journal_intent_digest},
    reader::MailboxReaderBootBinding,
    sender_ordinal::{SenderOrdinalV1, SenderSettlementV1},
    sign_receipt,
};

#[test]
fn ordinal_reopens_exact_pending_at_capacity_and_fences_retired_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let (sealer, destination, send) = super::tests::external_fixture(dir.path());
    let key = SigningKey::from_bytes(&[81; 32]);
    let b = SigningKey::from_bytes(&[79; 32]);
    let direction = MailboxJournalDirectionV1 {
        sender_settlement: Some(SenderSettlementProfile::OrdinalV1),
        source: sealer.header.sender,
        destination_plan_sha256: [37; 32],
        destination_plan_nonce: [39; 16],
        destination_boot: BootId::from_bytes([41; 32]),
        address: send.grant.address,
        execution_epoch: sealer.header.execution_epoch,
        policy_epoch: sealer.header.policy_epoch,
        receipt_key: b.verifying_key().to_bytes(),
        source_scope_grant_sha256: [42; 32],
        send_grant_sha256: mvm_core::mailbox::outbound::journal_capability_digest(&send).unwrap(),
        receive_grant_sha256: [43; 32],
        not_before_unix_ms: send.grant.not_before_unix_ms,
        expires_at_unix_ms: send.grant.expires_at_unix_ms,
        max_payload_bytes: 313,
    };
    let boot = MailboxReaderBootBinding {
        durable_object_pair_sha256_v1: None,
        outbound_journal_v1: Some(direction),
        plan_id: mvm_core::plan::PlanId("sha256:original-test-plan".into()),
        plan_nonce: mvm_core::plan::Nonce::from_bytes([40; 16]),
        mailbox: sealer.header.mailbox,
        authority_key: sealer.authority_key.verifying_key().to_bytes(),
        execution_epoch: sealer.header.execution_epoch,
        boot: sealer.header.sender_boot,
        guest_identity_key: [44; 32],
        ack_public_key: key.verifying_key().to_bytes(),
    };
    let id = journal_direction_commitment(&boot).unwrap();
    let h = |ordinal| SenderOrdinalV1 {
        direction: id,
        ordinal,
    };
    let message = |ordinal| OutboxMessage {
        recipient: sealer.header.recipient,
        message_id: h(ordinal).message_id().unwrap(),
        body: vec![0, ordinal as u8, 0],
    };
    SenderWindow::provision(dir.path(), id).unwrap();
    let window = SenderWindow::reopen(dir.path(), id).unwrap();
    let mut pending = Vec::new();
    let mut replay = InMemoryReplayProtector::default();
    for ordinal in 1..=64 {
        let m = message(ordinal);
        let Original::Send(bytes) = window
            .reserve(h(ordinal), journal_intent_digest(&m), || {
                let (cap, env, _) = sealer.seal_at(&m, Some(&send), ordinal)?;
                encode_frame(&cap, &env)
            })
            .unwrap()
        else {
            panic!("first submit returned cached receipt")
        };
        let (cap, env) = decode_frame(&bytes).unwrap();
        let opened = open_authenticated_envelope(
            &env,
            &cap,
            &destination.context,
            &destination.encryption_key,
            &destination.sender_key,
            &b.verifying_key(),
            &mut replay,
        )
        .unwrap();
        assert_eq!(opened.header().sequence.get(), ordinal);
        assert_eq!(opened.header().message_id, m.message_id);
        assert_eq!(opened.payload(), m.body);
        let receipt = sign_receipt(
            DestinationReceipt {
                protocol_version: ProtocolVersion::V2,
                signature_algorithm: SignatureAlgorithm::ED25519,
                delivery_id: env.routing.delivery_id,
                message_id: m.message_id,
                address: direction.address,
                execution_epoch: direction.execution_epoch,
                outcome: DeliveryOutcome::AcceptedLocalDurable,
                observed_at_unix_ms: send.grant.not_before_unix_ms,
                ciphertext_commitment: env.ciphertext_commitment,
            },
            &b,
        )
        .unwrap();
        pending.push((bytes, receipt));
    }
    let never = || -> Result<Vec<u8>, Refusal> { panic!("unexpected reseal") };
    assert!(matches!(
        window.reserve(h(65), [0; 32], never),
        Err(Refusal::QueueFull(64))
    ));
    assert!(matches!(
        window.reserve(h(66), [0; 32], never),
        Err(Refusal::SenderOrdinalGap)
    ));
    drop(window);
    // An interrupted invocation left part of its next snapshot. Only the
    // atomically committed original is authoritative after reopening.
    mvm_core::atomic_io::write_private(&dir.path().join("ordinal-state-v1/next"), b"partial")
        .unwrap();
    let window = SenderWindow::reopen(dir.path(), id).unwrap();
    let Original::Send(retried) = window
        .reserve(h(1), journal_intent_digest(&message(1)), never)
        .unwrap()
    else {
        panic!("missing pending")
    };
    assert_eq!(retried, pending[0].0);
    assert!(matches!(
        window.reserve(h(1), [0; 32], never),
        Err(Refusal::NotAuthorized)
    ));
    for ordinal in (1..=64).rev() {
        let (bytes, r) = &pending[(ordinal - 1) as usize];
        window.accept(h(ordinal), bytes, r.clone()).unwrap();
        let statement = SenderSettlementV1::sign(&boot, ordinal, r, &key).unwrap();
        assert!(window.settle(&statement, &b.verifying_key()).is_err());
        let original = window
            .reserve(h(ordinal), journal_intent_digest(&message(ordinal)), never)
            .unwrap();
        assert!(matches!(original,Original::Accepted(s,receipt) if s==*bytes && receipt==*r));
        let retired = window.settle(&statement, &key.verifying_key()).unwrap();
        assert_eq!(retired, if ordinal == 1 { 64 } else { 0 });
        if ordinal == 2 {
            assert!(matches!(
                window.reserve(h(65), [0; 32], never),
                Err(Refusal::QueueFull(64))
            ));
        }
    }
    drop(window);
    let window = SenderWindow::reopen(dir.path(), id).unwrap();
    assert!(matches!(
        window.reserve(h(1), journal_intent_digest(&message(1)), never),
        Err(Refusal::SenderOrdinalRetired)
    ));
    let settled = SenderSettlementV1::sign(&boot, 1, &pending[0].1, &key).unwrap();
    assert_eq!(window.settle(&settled, &key.verifying_key()).unwrap(), 64);
    let m = message(65);
    let Original::Send(next) = window
        .reserve(h(65), journal_intent_digest(&m), || {
            let (cap, env, _) = sealer.seal_at(&m, Some(&send), 65)?;
            encode_frame(&cap, &env)
        })
        .unwrap()
    else {
        panic!("expected fresh 65")
    };
    let (cap, env) = decode_frame(&next).unwrap();
    let opened = open_authenticated_envelope(
        &env,
        &cap,
        &destination.context,
        &destination.encryption_key,
        &destination.sender_key,
        &b.verifying_key(),
        &mut replay,
    )
    .unwrap();
    assert_eq!(opened.header().sequence.get(), 65);
    assert_eq!(opened.payload(), m.body);
    assert!(SenderWindow::provision(dir.path(), [99; 32]).is_err());
    drop(window);
    std::fs::remove_dir_all(dir.path().join("ordinal-state-v1")).unwrap();
    assert!(SenderWindow::provision(dir.path(), id).is_err());
    eprintln!(
        "ORDINAL_WINDOW opened=65 distinct_payloads=65 unresolved_limit=64 retired=64 retained_exact_retry_bytes={} next_sequence=65",
        retried.len()
    );
}
