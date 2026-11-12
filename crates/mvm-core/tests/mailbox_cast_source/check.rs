use super::*;
use mvm_contract::protocol::mailbox::{
    MailboxEnvelope, local::*, local_service::MailboxLocalServiceGrant,
};
use mvm_core::mailbox::frame::cast::{CastChannel, route::AddressedCastGrants, source::CastSource};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

pub(super) fn check(
    addressed: &CastChannel,
    grants: AddressedCastGrants<'_>,
    a_policy: &OpenContext,
    live: &OpenContext,
    h: &MailboxEnvelopeHeader,
    sender_key: &SigningKey,
    authority_key: &SigningKey,
    encryption_key: &Key,
    input: &[u8],
) {
    use mvm_contract::protocol::mailbox::local::LocalSubmit;
    use mvm_core::mailbox::frame::cast::source::{
        CastSource, SourceCastEnrollment, SourceCastSlot,
    };
    use mvm_core::mailbox::frame::local::encode_local_frame;
    let source_binding = [91; 32];
    let mut counter = 0;
    let mut slot = SourceCastSlot::new((), 32768);
    let enrollment = || SourceCastEnrollment {
        source_binding,
        enrollment_commitment: [47; 32],
        sender_boot: h.sender_boot,
        signer: sender_key,
        encryption: h.encryption.clone(),
        data_key: encryption_key,
        ordering_scope: h.ordering_scope.clone(),
        routing: routing(),
    };
    let mut lane =
        CastSource::new(addressed, grants, enrollment(), &mut counter, &mut slot).unwrap();
    let source_request = |n: u64, bytes: &[u8]| {
        encode_local_frame(
            &LocalFrame::Submit(Box::new(LocalSubmit {
                originating_binding: source_binding,
                request_id: n,
                kind: MailboxMessageKind::Cast,
                recipient: recipient(),
                content_type: content_type(),
                expires_at_unix_ms: 2000,
                timeout_ms: 0,
                correlation: CorrelationId::from_bytes([0; 32]),
                causation: CausationId::from_bytes([0; 32]),
                reply_token: Vec::new(),
                body: bytes.to_vec(),
            })),
            LocalRole::Submit,
            LocalDirection::GuestToHost,
            &MailboxLocalServiceGrant::reliable_v1().limits,
        )
        .unwrap()
    };
    let first_request = source_request(7, input);
    let first = measured_transfer(
        &mut lane,
        &first_request,
        addressed,
        grants,
        a_policy,
        live,
        encryption_key,
        input,
    );
    drop(lane);
    let mut stale_sequence = 0;
    assert!(
        CastSource::new(
            addressed,
            grants,
            enrollment(),
            &mut stale_sequence,
            &mut slot
        )
        .is_err()
    );
    let mut changed = enrollment();
    changed.source_binding = [92; 32];
    assert!(CastSource::new(addressed, grants, changed, &mut counter, &mut slot).is_err());
    let mut lane =
        CastSource::new(addressed, grants, enrollment(), &mut counter, &mut slot).unwrap();
    let mut past = (*a_policy).clone();
    past.now_unix_ms -= 1;
    let mut past_dst = (*live).clone();
    past_dst.now_unix_ms -= 1;
    assert!(lane.prepare(&first_request, &past, &past_dst).is_err());
    let replayed = lane.prepare(&first_request, a_policy, live).unwrap();
    assert_eq!(&first, replayed);
    assert!(
        lane.prepare(&source_request(7, b"different"), a_policy, live)
            .is_err()
    );
    assert!(
        lane.prepare(&source_request(8, input), a_policy, live)
            .is_err()
    );
    let mut denied = (*live).clone();
    denied
        .revoked_capabilities
        .push(grants.receive.grant.revocation_id);
    assert!(lane.prepare(&first_request, a_policy, &denied).is_err());
    let mut expired = (*live).clone();
    expired.now_unix_ms = 2000;
    let mut a_expired = (*a_policy).clone();
    a_expired.now_unix_ms = 2000;
    assert!(lane.prepare(&first_request, &a_expired, &expired).is_err());
    let recovered = mvm_core::mailbox::open_envelope(
        &first,
        grants.send,
        live,
        encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        &mut InMemoryReplayProtector::default(),
    )
    .unwrap();
    assert_eq!(recovered.as_slice(), input);
    let mut replay_owner = InMemoryReplayProtector::default();
    assert!(
        addressed
            .open_addressed(
                first.clone(),
                grants,
                a_policy,
                live,
                &Key::from_bytes([249; 32]),
                &mut replay_owner,
                1.try_into().unwrap()
            )
            .is_err()
    );
    assert!(
        addressed
            .open_addressed(
                first.clone(),
                grants,
                a_policy,
                live,
                encryption_key,
                &mut replay_owner,
                1.try_into().unwrap()
            )
            .is_ok()
    );
    assert!(
        lane.retire_after(&source_request(7, b"different"), || panic!())
            .is_err()
    );
    assert!(
        lane.retire_after(&first_request, || Err(std::io::Error::other(
            "failed publication"
        )))
        .is_err()
    );
    assert_eq!(
        lane.prepare(&first_request, a_policy, live).unwrap(),
        &first
    );
    lane.retire_after(&first_request, || Ok(())).unwrap();
    drop(lane);
    let mut lane =
        CastSource::new(addressed, grants, enrollment(), &mut counter, &mut slot).unwrap();
    assert!(lane.prepare(&first_request, a_policy, live).is_err());
    let second = lane
        .prepare(&source_request(8, input), a_policy, live)
        .unwrap();
    assert_ne!(first.routing.delivery_id, second.routing.delivery_id);
    assert_ne!(first.ciphertext, second.ciphertext);
    drop(lane);
    assert_eq!(counter, 2);
}

fn measured_transfer<C>(
    lane: &mut CastSource<'_, C>,
    submit: &[u8],
    channel: &CastChannel,
    grants: AddressedCastGrants<'_>,
    source: &OpenContext,
    destination: &OpenContext,
    key: &Key,
    input: &[u8],
) -> MailboxEnvelope {
    use mvm_core::mailbox::frame::{Refusal, decode_frame, send_frame};
    let meter = |io| Meter {
        io,
        read: 0,
        written: 0,
    };
    let (tx, rx) = UnixStream::pair().unwrap();
    let (host, guest) = UnixStream::pair().unwrap();
    for socket in [&tx, &rx, &host, &guest] {
        let timeout = Some(std::time::Duration::from_secs(5));
        socket.set_read_timeout(timeout).unwrap();
        socket.set_write_timeout(timeout).unwrap();
    }
    let mut tx = meter(tx);
    let mut rx = meter(rx);
    let mut host = meter(host);
    let mut guest = meter(guest);
    std::thread::scope(|scope| {
        let guest_handle = scope.spawn(|| {
            let cpu = thread_cpu_ns();
            let mut inbox = channel.inbox();
            channel
                .receive_on(&mut guest, || destination.now_unix_ms, &mut inbox)
                .unwrap();
            assert_eq!(inbox.take().unwrap().body.as_slice(), input);
            (thread_cpu_ns() - cpu, guest.read, guest.written)
        });
        let receiver = scope.spawn(|| {
            let cpu = thread_cpu_ns();
            let mut prefix = [0; 4];
            rx.read_exact(&mut prefix).unwrap();
            let length = u32::from_be_bytes(prefix) as usize;
            assert!(length <= 8192);
            let mut body = vec![0; length];
            rx.read_exact(&mut body).unwrap();
            let (send, received) = decode_frame(&body).unwrap();
            assert_eq!(send, *grants.send);
            let verified = channel
                .open_addressed(
                    received,
                    AddressedCastGrants {
                        send: &send,
                        ..grants
                    },
                    source,
                    destination,
                    key,
                    &mut InMemoryReplayProtector::default(),
                    1.try_into().unwrap(),
                )
                .unwrap();
            verified
                .dispatch_on(channel, &mut host, || Ok((source, destination)))
                .unwrap();
            let (guest_cpu, read, written) = guest_handle.join().unwrap();
            assert_eq!((host.written, host.read), (read, written));
            rx.write_all(&serde_json::to_vec(&Ok::<(), Refusal>(())).unwrap())
                .unwrap();
            rx.io.shutdown(std::net::Shutdown::Write).unwrap();
            (
                thread_cpu_ns() - cpu,
                guest_cpu,
                rx.read,
                rx.written,
                host.written,
                host.read,
            )
        });
        let cpu = thread_cpu_ns();
        let started = std::time::Instant::now();
        let first = lane.prepare(submit, source, destination).unwrap();
        let prepared_ns = started.elapsed().as_nanos();
        send_frame(&mut tx, grants.send, first).unwrap();
        let total_ns = started.elapsed().as_nanos();
        let sender_cpu = thread_cpu_ns() - cpu;
        let (dest_cpu, guest_cpu, read, written, forward, reverse) = receiver.join().unwrap();
        assert_eq!((tx.written, tx.read), (read, written));
        println!(
            "source_cast_transfer payload={} peer_forward={} peer_reverse={} deliver_forward={} deliver_reverse={} prepare_ns={} through_ack_ns={} sender_cpu_ns={} destination_cpu_ns={} guest_role_cpu_ns={}",
            input.len(),
            read,
            written,
            forward,
            reverse,
            prepared_ns,
            total_ns,
            sender_cpu,
            dest_cpu,
            guest_cpu
        );
        first.clone()
    })
}
