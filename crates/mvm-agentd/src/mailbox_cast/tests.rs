
use super::*;
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    CausationId, ContentType, CorrelationId, ExecutionEpoch, MailboxGrant, MailboxId, PrincipalId,
    local::LocalGreeting, local_service::MailboxLocalServiceGrant,
};
use mvm_core::plan::{
    signing::{sign_plan, verify_plan},
    test_support::PlanFixture,
};
use std::time::Duration;

fn fixture() -> (
    GuestCastEndpoint,
    CastWorkloadReader,
    LocalGreeting,
    LocalDelivery,
) {
    let now = chrono::Utc::now().timestamp_millis();
    let source = PrincipalId::from_bytes([4; 32]);
    let recipient = PrincipalId::from_bytes([5; 32]);
    let key = SigningKey::from_bytes(&[3; 32]);
    let vk = key.verifying_key();
    let trust = [("issuer", &vk)];
    let mut profile = MailboxLocalServiceGrant::reliable_v1();
    profile.limits.payload_bytes = 512;
    profile.limits.max_frame_bytes = 1536;
    let make = |name, id| {
        let mut plan = PlanFixture::new()
            .workload(name)
            .validity(
                chrono::DateTime::from_timestamp_millis(now - 60_000).unwrap(),
                chrono::DateTime::from_timestamp_millis(now + 60_000).unwrap(),
            )
            .build();
        plan.mailbox = Some(MailboxGrant {
            mailbox: MailboxId::from_bytes([id; 32]),
            authority_key: vk.to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            local_service: Some(profile),
        });
        sign_plan(&plan, &key, "issuer")
    };
    let src = make("source", 1);
    let dst = make("destination", 2);
    let hello = LocalGreeting {
        role: LocalRole::Deliver,
        binding: [99; 32],
        generation: 1,
    };
    let channel = CastChannel::from_signed_pair(
        &src,
        &dst,
        &trust,
        (
            &verify_plan(&src, &trust).unwrap().plan_id,
            &verify_plan(&dst, &trust).unwrap().plan_id,
        ),
        hello,
        source,
        recipient,
        now,
    )
    .unwrap();
    let (guest, reader) = GuestCastEndpoint::new(channel, profile.limits).unwrap();
    guest
        .workload
        .set_read_timeout(Some(Duration::from_millis(12)))
        .unwrap();
    let item = LocalDelivery {
        delivery_sequence: 1,
        message_id: MessageId::from_bytes([2; 32]),
        correlation: CorrelationId::from_bytes([0; 32]),
        causation: CausationId::from_bytes([0; 32]),
        sender: source,
        recipient,
        kind: MailboxMessageKind::Cast,
        content_type: ContentType::parse("application/octet-stream", 1).unwrap(),
        expires_at_unix_ms: now + 30_000,
        reply_token: vec![],
        body: vec![0, 255, 1, 0, 0],
    };
    (guest, reader, hello, item)
}

fn admit(
    guest: &mut GuestCastEndpoint,
    hello: LocalGreeting,
    item: &LocalDelivery,
) -> LocalInboxDisposition {
    let frame = encode_local_frame(
        &LocalFrame::Deliver(Box::new(item.clone())),
        LocalRole::Deliver,
        LocalDirection::HostToGuest,
        &guest.limits,
    )
    .unwrap();
    let ack = guest
        .channel
        .receive_cast(
            hello,
            &frame,
            chrono::Utc::now().timestamp_millis(),
            &mut guest.inbox,
        )
        .unwrap();
    let LocalFrame::DeliveryAck(ack) = decode_local_frame(
        &ack,
        LocalRole::Deliver,
        LocalDirection::GuestToHost,
        &guest.limits,
    )
    .unwrap() else {
        panic!("expected admission")
    };
    ack.disposition
}

#[test]
fn original_reader_retries_after_lost_ack_without_duplicate_callback_or_reordering() {
    let (mut guest, reader, hello, first) = fixture();
    let (fd, context) = reader.into_launch_fd().unwrap();
    let context = serde_json::from_slice(&serde_json::to_vec(&context).unwrap()).unwrap();
    let mut reader = CastWorkloadReader::from_launch_fd(fd, context).unwrap();
    assert_eq!(
        admit(&mut guest, hello, &first),
        LocalInboxDisposition::Accepted
    );
    // Timeout occurs after the send reached the workload's datagram queue.
    assert!(guest.offer_to_workload().is_err());
    assert!(
        reader
            .receive_with(|delivered| {
                assert_eq!(delivered, &first);
                Ok(())
            })
            .unwrap()
    );
    let mut discarded = [0u8; 64];
    guest.workload.recv(&mut discarded).unwrap();
    let mut second = first.clone();
    second.body = vec![1, 0, 0, 4, 0];
    second.delivery_sequence = 2;
    second.message_id = MessageId::from_bytes([6; 32]);
    assert_eq!(
        admit(&mut guest, hello, &second),
        LocalInboxDisposition::Full
    );
    assert_eq!(
        admit(&mut guest, hello, &first),
        LocalInboxDisposition::Accepted
    );
    guest
        .workload
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    reader.repeat_last_verdict().unwrap();
    assert!(guest.offer_to_workload().unwrap());
    assert!(!guest.offer_to_workload().unwrap());
    assert_eq!(
        admit(&mut guest, hello, &second),
        LocalInboxDisposition::Accepted
    );
    std::thread::scope(|s| {
        let app = s.spawn(|| {
            reader.receive_with(|delivery| {
                assert_eq!(delivery, &second);
                Ok(())
            })
        });
        assert!(guest.offer_to_workload().unwrap());
        assert!(app.join().unwrap().unwrap());
    });
}

#[test]
fn conflicting_ack_failed_consumer_and_oversize_input_retain_unread() {
    let (mut guest, mut reader, hello, item) = fixture();
    assert_eq!(
        admit(&mut guest, hello, &item),
        LocalInboxDisposition::Accepted
    );
    let bad = LocalFrame::DeliveryAck(LocalDeliveryAck {
        delivery_sequence: 1,
        message_id: MessageId::from_bytes([9; 32]),
        disposition: LocalInboxDisposition::Accepted,
    });
    let bytes = encode_local_frame(
        &bad,
        LocalRole::Deliver,
        LocalDirection::GuestToHost,
        &guest.limits,
    )
    .unwrap();
    reader.socket.send(&bytes).unwrap();
    assert!(guest.offer_to_workload().is_err());
    assert!(
        reader
            .receive_with(|_| Err(invalid("workload read failed")))
            .is_err()
    );
    assert!(reader.last.is_none());
    let mut lost = [0; 64];
    guest.workload.recv(&mut lost).unwrap();
    reader.repeat_last_verdict().unwrap();
    assert!(
        guest.offer_to_workload().is_err(),
        "negative receipt keeps item unread and allows one retransmit"
    );
    let oversize = vec![0; guest.limits.max_frame_bytes as usize + 5];
    guest.workload.send(&oversize).unwrap();
    assert!(reader.receive_with(|_| panic!("unverified data")).is_err());
    guest
        .workload
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    std::thread::scope(|s| {
        let app = s.spawn(|| {
            reader.receive_with(|v| {
                assert_eq!(v, &item);
                Ok(())
            })
        });
        assert!(guest.offer_to_workload().unwrap());
        assert!(app.join().unwrap().unwrap());
    });
}

#[test]
fn workload_refuses_expiry_between_admission_and_use() {
    let (mut guest, mut reader, hello, item) = fixture();
    assert_eq!(
        admit(&mut guest, hello, &item),
        LocalInboxDisposition::Accepted
    );
    assert!(guest.offer_to_workload().is_err());
    reader.context.validity.end = chrono::Utc::now().timestamp_millis();
    assert!(
        reader
            .receive_with(|_| panic!("expired delivery reached application"))
            .is_err()
    );
    assert!(guest.offer_to_workload().is_err());
    assert!(reader.last.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn workload_socket_is_never_a_host_mailbox_port() {
    let (mut guest, _, _, _) = fixture();
    let (stream, _) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(guest.receive_on_host_port(stream.into()).is_err());
}

#[test]
fn a_stream_or_named_socket_cannot_replace_the_private_workload_fd() {
    let (_, fresh, _, _) = fixture();
    let (_, context) = fresh.into_launch_fd().unwrap();
    let (stream, _) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(CastWorkloadReader::from_launch_fd(stream.into(), context.clone()).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("named");
    let named = UnixDatagram::bind(&path).unwrap();
    assert!(CastWorkloadReader::from_launch_fd(named.into(), context).is_err());
}
