// Use the canonical producer/signing fixture unchanged. These tests select Cast
// explicitly and exercise the production local frame codecs in both directions.
mod canonical {
    include!("mailbox_crypto.rs");
    #[cfg(all(unix, feature = "test-support"))]
    mod source_transfer {
        include!("mailbox_cast_source/check.rs");
    }

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
        // Bind two independently attested canonical domains before opening.
        // A's original own-address Call is only a membership credential. Its
        // operations are never applied to the addressed Cast.
        let src_authority = SigningKey::from_bytes(&[111; 32]);
        let mut src_plan = src.clone();
        let mut src_grant = src_plan.mailbox.unwrap();
        src_grant.authority_key = src_authority.verifying_key().to_bytes();
        src_plan.mailbox = Some(src_grant);
        let a = sign_plan(&src_plan, &plan_key, "pinned");
        let aid = verify_plan(&a, &trusted).unwrap().plan_id;
        let mut addressed = CastChannel::from_signed_pair(
            &a,
            &signed_dst,
            &trusted,
            (&aid, &did),
            greeting,
            sender(),
            recipient(),
            1500,
        )
        .unwrap();
        addressed.restrict_frame_budget(4096).unwrap();
        let mut a_policy = live.clone();
        a_policy.expected_mailbox = src_grant.mailbox;
        let mut member = cap.grant.clone();
        member.address.mailbox = src_grant.mailbox;
        member.message_kinds = vec![MailboxMessageKind::Call];
        let a_witness = sign_capability(member.clone(), &src_authority).unwrap();
        use mvm_core::mailbox::frame::cast::route::AddressedCastGrants;
        let grants = AddressedCastGrants {
            source_scope: &a_witness,
            send: &cap,
            receive: &recv_cap,
        };
        assert!(addressed.matches_original_source(
            src_grant.mailbox, src_grant.epoch, &src_grant.authority_key
        ));
        assert!(!addressed.matches_original_source(
            dest.mailbox, src_grant.epoch, &src_grant.authority_key
        ));
        assert!(!addressed.matches_original_source(
            src_grant.mailbox, src_grant.epoch, &dest.authority_key
        ));
        let mut replacement_plan = dst.clone();
        replacement_plan.valid_until = chrono::DateTime::from_timestamp_millis(2499).unwrap();
        let replacement = sign_plan(&replacement_plan, &plan_key, "pinned");
        let replacement_id = verify_plan(&replacement, &trusted).unwrap().plan_id;
        let make_channel = |plan, id, limit| {
            let mut channel = CastChannel::from_signed_pair(
                &a, plan, &trusted, (&aid, id), greeting, sender(), recipient(), 1500
            ).unwrap();
            channel.restrict_frame_budget(limit).unwrap();
            channel
        };
        let narrow = make_channel(&signed_dst, &did, 2048);
        let other_plan = make_channel(&replacement, &replacement_id, 4096);
        source_transfer::check(
            &addressed, [&narrow, &other_plan], grants, &a_policy, &live, &h, &sender_key, &authority_key,
            &encryption_key, input,
        );
        let mut unbounded = a_policy.clone();
        unbounded.revoked_capabilities = vec![a_witness.grant.revocation_id; 33];
        assert!(grants.check_compact_policy(&unbounded, &live).is_err());
        assert!(grants.admits_encoded_contribution(4096));
        assert!(!grants.admits_encoded_contribution(4097));
        // Same textual local tenant can have unrelated signed binary domains.
        member.address.authorization_domain =
            mvm_contract::protocol::mailbox::AuthorizationDomainId::from_bytes([244; 32]);
        let own_domain = sign_capability(member, &src_authority).unwrap();
        let mut default_policy = a_policy.clone();
        default_policy.expected_authorization_domain =
            own_domain.grant.address.authorization_domain;
        assert!(
            addressed
                .authorize_addressed(
                    AddressedCastGrants {
                        source_scope: &own_domain,
                        ..grants
                    },
                    &default_policy,
                    &live
                )
                .is_err()
        );
        assert!(
            addressed
                .authorize_addressed(
                    AddressedCastGrants {
                        source_scope: &recv_cap,
                        ..grants
                    },
                    &a_policy,
                    &live
                )
                .is_err()
        );
        assert!(
            addressed
                .authorize_addressed(
                    AddressedCastGrants {
                        receive: &cap,
                        ..grants
                    },
                    &a_policy,
                    &live
                )
                .is_err()
        );
        let mut revoked_a = a_policy.clone();
        revoked_a
            .revoked_capabilities
            .push(a_witness.grant.revocation_id);
        assert!(
            addressed
                .authorize_addressed(grants, &revoked_a, &live)
                .is_err()
        );
        // The authenticated message must also fit the destination Receive grant.
        // A refused Receive must not consume its canonical replay tuple.
        let mut small = recv_cap.grant.clone();
        small.max_payload_bytes = 1;
        let small = sign_capability(small, &authority_key).unwrap();
        let mut rows = InMemoryReplayProtector::default();
        let seq = 1.try_into().unwrap();
        assert!(
            addressed
                .open_addressed(
                    envelope.clone(),
                    AddressedCastGrants {
                        receive: &small,
                        ..grants
                    },
                    &a_policy,
                    &live,
                    &encryption_key,
                    &mut rows,
                    seq
                )
                .is_err()
        );
        let admitted = addressed
            .open_addressed(
                envelope.clone(),
                grants,
                &a_policy,
                &live,
                &encryption_key,
                &mut rows,
                seq,
            )
            .unwrap();
        use std::io::{Read as _, Write as _};
        // A valid callback cannot change either signed credential after open.
        // A denied retry transmits only the greeting and no delivery or body.
        let mut revoked_b = live.clone();
        revoked_b
            .revoked_capabilities
            .push(recv_cap.grant.revocation_id);
        for (left, right) in [(&revoked_a, &live), (&a_policy, &revoked_b)] {
            let (mut host, mut guest) = std::os::unix::net::UnixStream::pair().unwrap();
            std::thread::scope(|scope| {
                let other = scope.spawn(|| {
                    let mut hello = [0; 52];
                    guest.read_exact(&mut hello).unwrap();
                    guest.write_all(&hello).unwrap();
                    let mut body = Vec::new();
                    guest.read_to_end(&mut body).unwrap();
                    body
                });
                assert!(
                    admitted
                        .dispatch_on(&addressed, &mut host, || Ok((left, right)))
                        .is_err()
                );
                drop(host);
                assert!(other.join().unwrap().is_empty());
            });
        }
        let mut inbox = addressed.inbox();
        let (mut host, mut guest) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| addressed.receive_on(&mut guest, || 1500, &mut inbox));
            admitted
                .dispatch_on(&addressed, &mut host, || Ok((&a_policy, &live)))
                .unwrap();
            reader.join().unwrap().unwrap();
        });
        assert_eq!(inbox.take().unwrap().body, input);
        assert!(
            addressed
                .open_addressed(
                    envelope.clone(),
                    grants,
                    &a_policy,
                    &live,
                    &encryption_key,
                    &mut rows,
                    seq
                )
                .is_err()
        );
        // Independent fresh synthetic destination. Time one contiguous open,
        // signed-scope recheck, local Deliver and correlated guest ACK. Count
        // successful bytes at both actual socket ends, excluding fixture setup.
        let canonical_size = mvm_core::mailbox::encode_envelope(&envelope).unwrap().len();
        let (host, guest) = std::os::unix::net::UnixStream::pair().unwrap();
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
        let mut fresh = addressed.inbox();
        let mut once = InMemoryReplayProtector::default();
        std::thread::scope(|scope| {
            let rx = scope.spawn(|| {
                let t = thread_cpu_ns();
                addressed
                    .receive_on(&mut guest, || 1500, &mut fresh)
                    .unwrap();
                (thread_cpu_ns() - t, guest.read, guest.written)
            });
            let wall = std::time::Instant::now();
            let cpu = thread_cpu_ns();
            let verified = addressed
                .open_addressed(
                    envelope.clone(),
                    grants,
                    &a_policy,
                    &live,
                    &encryption_key,
                    &mut once,
                    seq,
                )
                .unwrap();
            let ack = verified
                .dispatch_on(&addressed, &mut host, || Ok((&a_policy, &live)))
                .unwrap();
            let elapsed = wall.elapsed().as_nanos();
            let tx_cpu = thread_cpu_ns() - cpu;
            let (rx_cpu, read, written) = rx.join().unwrap();
            assert_eq!((host.written, host.read), (read, written));
            assert_eq!(ack.delivery_sequence, 1);
            println!(
                "addressed_cast_component payload={} encoded_envelope_not_sent={} host_to_guest={} guest_to_host={} open_through_ack_ns={} destination_host_thread_cpu_ns={} guest_thread_cpu_ns={}",
                input.len(),
                canonical_size,
                host.written,
                host.read,
                elapsed,
                tx_cpu,
                rx_cpu
            );
        });
        assert_eq!(fresh.take().unwrap().body, input);
        let mut chan = new_channel(recipient()).unwrap();
        let mut smaller = profile.limits;
        smaller.payload_bytes = 24;
        assert_eq!(chan.narrow_guest_limits(smaller).unwrap(), smaller);
        assert_eq!(chan.narrow_guest_limits(profile.limits).unwrap(), smaller);
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
        let failed = inbox.consume_with(|delivery| {
            assert_eq!(delivery.body, input);
            Err::<(), _>(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        });
        assert_eq!(
            failed.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            ack_kind(
                &chan
                    .receive_cast(greeting, &second_packet, 1_500, &mut inbox)
                    .unwrap()
            ),
            LocalInboxDisposition::Full
        );
        let first = inbox
            .consume_with(|delivery| Ok::<_, ()>(delivery.clone()))
            .unwrap()
            .unwrap();
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
