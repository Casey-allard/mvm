// Use the canonical producer/signing fixture unchanged. These tests select Cast
// explicitly and exercise the production local frame codecs in both directions.
mod canonical {
    include!("mailbox_crypto.rs");

    #[cfg(all(unix, feature = "test-support"))]
    struct Meter<S> {
        io: S,
        read: u64,
        written: u64,
    }
    #[cfg(all(unix, feature = "test-support"))]
    impl<S: std::io::Read> std::io::Read for Meter<S> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let n = self.io.read(bytes)?;
            self.read += n as u64;
            Ok(n)
        }
    }
    #[cfg(all(unix, feature = "test-support"))]
    impl<S: std::io::Write> std::io::Write for Meter<S> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let n = self.io.write(bytes)?;
            self.written += n as u64;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.io.flush()
        }
    }
    #[cfg(all(unix, feature = "test-support"))]
    fn thread_cpu_ns() -> u64 {
        let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes a writable timespec on success.
        let result =
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, time.as_mut_ptr()) };
        assert_eq!(result, 0);
        let time = unsafe { time.assume_init() };
        (time.tv_sec as u64) * 1_000_000_000 + time.tv_nsec as u64
    }
    #[cfg(all(unix, feature = "test-support"))]
    #[test]
    fn authorized_cast_delivers_exact_bytes_and_rejects_changed_authority() {
        use mvm_contract::protocol::mailbox::{
            MailboxGrant,
            local::{LocalDirection, LocalFrame, LocalGreeting, LocalInboxDisposition, LocalRole},
            local_service::MailboxLocalServiceGrant,
        };
        use mvm_core::mailbox::frame::{cast::CastChannel, local::decode_local_frame};
        let sender_key = SigningKey::from_bytes(&[21; 32]);
        let authority_key = SigningKey::from_bytes(&[22; 32]);
        let encryption_key = Key::from_bytes([23; 32]);
        let sender = || PrincipalId::from_bytes(sender_key.verifying_key().to_bytes());
        let mut live = context();
        live.expected_sender = sender();
        live.required_operation = MailboxOperation::Send;
        live.acting_principal = sender();
        let mut claim = grant();
        claim.subject = sender();
        claim.message_kinds = vec![MailboxMessageKind::Cast];
        let cap = sign_capability(claim, &authority_key).unwrap();
        let mut h = header();
        h.kind = MailboxMessageKind::Cast;
        h.sender = sender();
        h.reply_to = None;
        h.correlation_id = CorrelationId::from_bytes([0; 32]);
        h.causation_id = CausationId::from_bytes([0; 32]);
        let input = b"\0A\xffB\0";
        h.plaintext_len = input.len() as u32;
        let envelope = seal_envelope(
            SealRequest {
                routing: routing(),
                header: h.clone(),
                plaintext: input,
            },
            &encryption_key,
            &sender_key,
        )
        .unwrap();
        let profile = MailboxLocalServiceGrant::reliable_v1();
        let dest = MailboxGrant {
            mailbox: live.expected_mailbox,
            authority_key: authority_key.verifying_key().to_bytes(),
            epoch: ExecutionEpoch::new(11).unwrap(),
            local_service: Some(profile),
        };
        let mut receive = cap.grant.clone();
        receive.subject = recipient();
        receive.capability_id = CapabilityId::from_bytes([31; 32]);
        receive.revocation_id = RevocationId::from_bytes([32; 32]);
        receive.minimum_execution_epoch = dest.epoch;
        receive.maximum_execution_epoch = dest.epoch;
        receive.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
        let recv_cap = sign_capability(receive, &authority_key).unwrap();
        let greeting = LocalGreeting {
            binding: [84; 32],
            generation: 2,
            role: LocalRole::Deliver,
        };
        use mvm_core::plan::signing::{sign_plan, verify_plan};
        let from = chrono::DateTime::from_timestamp_millis(1000).unwrap();
        let to = chrono::DateTime::from_timestamp_millis(2500).unwrap();
        let mut src = mvm_core::plan::test_support::PlanFixture::new()
            .workload("source")
            .validity(from, to)
            .build();
        let mut dst = mvm_core::plan::test_support::PlanFixture::new()
            .workload("destination")
            .validity(from, to)
            .build();
        let mut origin = dest;
        origin.epoch = live.current_execution_epoch;
        origin.mailbox = MailboxId::from_bytes([111; 32]);
        src.mailbox = Some(origin);
        dst.mailbox = Some(dest);
        let plan_key = SigningKey::from_bytes(&[49; 32]);
        let vk = plan_key.verifying_key();
        let trusted = [("pinned", &vk)];
        let signed_src = sign_plan(&src, &plan_key, "pinned");
        let signed_dst = sign_plan(&dst, &plan_key, "pinned");
        let sid = verify_plan(&signed_src, &trusted).unwrap().plan_id;
        let did = verify_plan(&signed_dst, &trusted).unwrap().plan_id;
        let new_channel = |to| {
            CastChannel::from_signed_pair(
                &signed_src,
                &signed_dst,
                &trusted,
                (&sid, &did),
                greeting,
                sender(),
                to,
                1500,
            )
        };
        assert!(
            CastChannel::from_signed_pair(
                &signed_src,
                &signed_dst,
                &trusted,
                (&did, &sid),
                greeting,
                sender(),
                recipient(),
                1500
            )
            .is_err()
        );
        let chan = new_channel(recipient()).unwrap();
        let mut replay = InMemoryReplayProtector::default();
        let proof = chan
            .verify(
                envelope,
                &cap,
                &live,
                &encryption_key,
                &mut replay,
                1.try_into().unwrap(),
            )
            .unwrap();
        let packet = chan
            .encode_delivery(greeting, &proof, &live, &recv_cap, 1)
            .unwrap();
        assert!(
            chan.encode_delivery(greeting, &proof, &live, &cap, 1)
                .is_err()
        );
        let ack_kind = |bytes: &[u8]| match decode_local_frame(
            bytes,
            LocalRole::Deliver,
            LocalDirection::GuestToHost,
            &profile.limits,
        )
        .unwrap()
        {
            LocalFrame::DeliveryAck(ack) => ack.disposition,
            _ => panic!("expected delivery ack"),
        };
        let mut inbox = chan.inbox();
        assert!(
            chan.encode_delivery(greeting, &proof, &live, &recv_cap, 2)
                .is_err()
        );
        let wrong = LocalGreeting {
            generation: 3,
            ..greeting
        };
        assert!(
            chan.receive_cast(wrong, &packet, live.now_unix_ms, &mut inbox)
                .is_err()
        );
        assert_eq!(
            ack_kind(
                &chan
                    .receive_cast(greeting, &packet, 2_000, &mut inbox)
                    .unwrap()
            ),
            LocalInboxDisposition::Expired
        );
        assert!(inbox.take().is_none());
        let wrong_recipient = new_channel(PrincipalId::from_bytes([91; 32])).unwrap();
        assert!(
            wrong_recipient
                .receive_cast(greeting, &packet, live.now_unix_ms, &mut inbox)
                .is_err()
        );
        assert!(
            wrong_recipient
                .encode_delivery(greeting, &proof, &live, &recv_cap, 1)
                .is_err()
        );

        let (host, guest) = std::os::unix::net::UnixStream::pair().unwrap();
        for io in [&host, &guest] {
            io.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            io.set_write_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
        }
        let mut host = Meter {
            io: host,
            read: 0,
            written: 0,
        };
        let mut guest = Meter {
            io: guest,
            read: 0,
            written: 0,
        };
        std::thread::scope(|scope| {
            let receiver = scope.spawn(|| {
                let cpu = thread_cpu_ns();
                chan.receive_on(&mut guest, || live.now_unix_ms, &mut inbox)
                    .unwrap();
                (thread_cpu_ns() - cpu, guest.read, guest.written)
            });
            let start = std::time::Instant::now();
            let host_cpu = thread_cpu_ns();
            let ack = chan
                .dispatch_on(&mut host, || {
                    Ok(mvm_core::mailbox::frame::cast::CastAdmission {
                        verified: &proof,
                        current: &live,
                        receive: &recv_cap,
                        sequence: 1,
                    })
                })
                .unwrap();
            assert_eq!(ack.disposition, LocalInboxDisposition::Accepted);
            assert_eq!(
                ack.message_id,
                proof.admission().journal_view().header().message_id
            );
            assert_eq!(ack.delivery_sequence, 1);
            let host_cpu = thread_cpu_ns() - host_cpu;
            let wall = start.elapsed().as_nanos();
            let (guest_cpu, guest_read, guest_written) = receiver.join().unwrap();
            assert_eq!(host.written, guest_read);
            assert_eq!(host.read, guest_written);
            println!(
                "cast_socketpair payload={} host_to_guest={} guest_to_host={} dispatch_ack_ns={} host_thread_cpu_ns={} guest_thread_cpu_ns={}",
                input.len(),
                host.written,
                host.read,
                wall,
                host_cpu,
                guest_cpu
            );
        });
        let mut second = h;
        second.message_id = MessageId::from_bytes([42; 32]);
        let next = seal_envelope(
            SealRequest {
                routing: routing(),
                header: second,
                plaintext: input,
            },
            &encryption_key,
            &sender_key,
        )
        .unwrap();
        let next = chan
            .verify(
                next,
                &cap,
                &live,
                &encryption_key,
                &mut replay,
                2.try_into().unwrap(),
            )
            .unwrap();
        let second_packet = chan
            .encode_delivery(greeting, &next, &live, &recv_cap, 2)
            .unwrap();
        assert_eq!(
            ack_kind(
                &chan
                    .receive_cast(greeting, &second_packet, 1_500, &mut inbox)
                    .unwrap()
            ),
            LocalInboxDisposition::Full
        );
        let first = inbox.take().unwrap();
        assert_eq!(first.body, input);
        assert_eq!(first.sender, sender());
        assert_eq!(first.recipient, recipient());
        // Lost first ACK. Retrying the exact original before/after take cannot
        // cause another application enqueue. The second Cast was not lost.
        assert_eq!(
            ack_kind(
                &chan
                    .receive_cast(greeting, &packet, 1_500, &mut inbox)
                    .unwrap()
            ),
            LocalInboxDisposition::Accepted
        );
        assert!(inbox.take().is_none());
        let retry = chan
            .encode_delivery(greeting, &next, &live, &recv_cap, 2)
            .unwrap();
        assert_eq!(retry, second_packet);
        assert_eq!(
            ack_kind(
                &chan
                    .receive_cast(greeting, &retry, 1_500, &mut inbox)
                    .unwrap()
            ),
            LocalInboxDisposition::Accepted
        );
        assert_eq!(
            inbox.take().unwrap().message_id,
            next.admission().journal_view().header().message_id
        );
        assert!(inbox.take().is_none());
        live.revoked_capabilities.push(cap.grant.revocation_id);
        assert!(
            chan.encode_delivery(greeting, &proof, &live, &recv_cap, 1)
                .is_err()
        );
    }
}
