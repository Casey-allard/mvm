use super::*;
use crate::mailbox_launch::{authority_key_for, derive_launch_keys};
use mvm_contract::protocol::mailbox::*;
use mvm_core::{
    mailbox::{self, frame::cast::route::AddressedCastGrants},
    vm_backend::HostDialRoute,
};

use crate::mailbox_process::destination_ingress::test_meter::{Meter, thread_cpu};
fn owner(b: u8) -> MailboxWorkerOwner {
    MailboxWorkerOwner {
        daemon_boot_nonce: [42; 32],
        lease: [b; 32],
        context_commitment: [b + 5; 32],
        generation: u64::from(b),
    }
}
fn config(home: &std::path::Path, id: u8) -> MailboxProcessConfig {
    let mailbox = MailboxId::from_bytes([id; 32]);
    let epoch = ExecutionEpoch::new(u64::from(id)).unwrap();
    let mut grant = MailboxGrant {
        mailbox,
        epoch,
        authority_key: authority_key_for(home, &mailbox, epoch).unwrap().to_bytes(),
        local_service: None,
    };
    // Derive exactly the established per-mailbox loopback identities.
    let keys = derive_launch_keys(home, &grant, &Key::random()).unwrap();
    // This is an explicit component fixture; standard installed launch
    // still refuses the unimplemented complete ReliableV1 service.
    grant.local_service = Some(local_service::MailboxLocalServiceGrant::reliable_v1());
    MailboxProcessConfig {
        grant,
        keys,
        socket: "/test/fixture".into(),
        route: HostDialRoute::PortSocket("/test/fixture".into()),
        vm_state_dir: "/test".into(),
    }
}
#[test]
fn independent_original_development_keys_carry_exact_bytes_and_refuse_swaps() {
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::signing::{sign_plan, verify_plan};
    let home = tempfile::tempdir().unwrap();
    crate::audit::host_keypair::load_or_init_at(home.path()).unwrap();
    let mut a = config(home.path(), 7);
    let mut b = config(home.path(), 11);
    let aowner = owner(7);
    let bowner = owner(11);
    let ak = SigningKey::from_bytes(&a.keys.authority);
    let bk = SigningKey::from_bytes(&b.keys.authority);
    assert_ne!(ak.verifying_key(), bk.verifying_key());
    let scope = |cfg: &MailboxProcessConfig| {
        let mut g = cfg.keys.template.capability.clone();
        g.address.tenant = TenantId::from_bytes([25; 32]);
        g.address.authorization_domain = AuthorizationDomainId::from_bytes([26; 32]);
        g.message_kinds = vec![MailboxMessageKind::Cast];
        g
    };
    let am = mailbox::sign_capability(scope(&a), &ak).unwrap();
    let mut rr = scope(&b);
    rr.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    rr.subject = rr.address.recipient;
    let receive = mailbox::sign_capability(rr, &bk).unwrap();
    let mut sr = scope(&b);
    sr.subject = am.grant.subject;
    sr.capability_id = CapabilityId::from_bytes([71; 32]);
    sr.revocation_id = RevocationId::from_bytes([72; 32]);
    sr.minimum_execution_epoch = a.grant.epoch;
    sr.maximum_execution_epoch = a.grant.epoch;
    let send = mailbox::sign_capability(sr, &bk).unwrap();
    let g = AddressedCastGrants {
        source_scope: &am,
        send: &send,
        receive: &receive,
    };
    let bad = mailbox::sign_capability(am.grant.clone(), &bk).unwrap();
    let now = super::super::now_unix_ms();
    assert!(
        prepare_at(
            home.path(),
            a.grant,
            &aowner,
            EndpointRole::Source,
            &bad,
            now
        )
        .is_err()
    );
    let (sa, mut original_a) = prepare_at(
        home.path(),
        a.grant,
        &aowner,
        EndpointRole::Source,
        &am,
        now,
    )
    .unwrap();
    let (db, mut original_b) = prepare_at(
        home.path(),
        b.grant,
        &bowner,
        EndpointRole::Destination,
        &receive,
        now,
    )
    .unwrap();
    assert!(a.keys.development_cast.is_none() && b.keys.development_cast.is_none());
    let src = sa.policy().clone();
    let dest = db.policy().clone();
    assert_ne!(b.keys.template.header.tenant, dest.expected_tenant);
    let k = SigningKey::from_bytes(&[48; 32]);
    let vk = k.verifying_key();
    let trust = [("dev", &vk)];
    let now = super::super::now_unix_ms();
    let plan = |name, grant| {
        let mut p = mvm_core::plan::test_support::PlanFixture::new()
            .workload(name)
            .validity(
                chrono::DateTime::from_timestamp_millis(now - 2500).unwrap(),
                chrono::DateTime::from_timestamp_millis(now + 25_000).unwrap(),
            )
            .build();
        p.mailbox = Some(grant);
        sign_plan(&p, &k, "dev")
    };
    let left = plan("source", a.grant);
    let right = plan("destination", b.grant);
    let ids = (
        verify_plan(&left, &trust).unwrap().plan_id,
        verify_plan(&right, &trust).unwrap().plan_id,
    );
    let chan = CastChannel::from_signed_pair(
        &left,
        &right,
        &trust,
        (&ids.0, &ids.1),
        db.greeting(),
        src.expected_sender,
        dest.expected_recipient,
        now,
    )
    .unwrap();
    let offer = issue_with_policy(
        &chan,
        sa,
        db,
        g,
        &src,
        &dest,
        now,
        Some(destination::policy_digest(&src, &dest).unwrap()),
    )
    .unwrap();
    original_b.setup.destination = Some(Box::new(
        destination::PrivateDestination::new(&offer, &left, &right, &trust, g, &src, &dest)
            .unwrap(),
    ));
    original_a.setup.source = Some(Box::new(original_b.setup.destination.as_ref().unwrap().for_source(&offer.source)));
    assert_ne!(offer.source.0, offer.destination.0);
    let d = &offer.direction;
    let public = d
        .original_deliver_enrollment(&aowner, &bowner, g, now)
        .unwrap();
    assert_eq!(
        public,
        (d.commitment(), d.destination_greeting(), d.fields.end)
    );
    assert!(
        d.original_deliver_enrollment(&bowner, &aowner, g, now)
            .is_err()
    );
    assert!(
        d.original_deliver_enrollment(&aowner, &bowner, g, d.fields.end)
            .is_err()
    );
    assert!(
        d.original_deliver_enrollment(
            &aowner,
            &bowner,
            AddressedCastGrants {
                send: &receive,
                ..g
            },
            now
        )
        .is_err()
    );

    let public = original_b
        .setup
        .destination
        .as_ref()
        .unwrap()
        .public_control();
    let bytes = serde_json::to_vec(&public).unwrap();
    let public: control::PublicCastControl = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(public.commitment().unwrap(), d.commitment());
    public.binds(&aowner, &bowner).unwrap();
    assert!(public.binds(&bowner, &aowner).is_err());
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc.as_object().unwrap().len(), 4);
    for raw in ["capsule", "wrapping", "authorities"] {
        assert!(doc.get(raw).is_none());
    }
    original_a.bind(d).unwrap();
    original_b.bind(d).unwrap();
    assert!(original_a.bind(d).is_err());
    assert!(original_a.binds_boot(d.commitment(), EndpointRole::Source));
    assert!(original_b.binds_boot(d.commitment(), EndpointRole::Destination));
    assert!(!original_a.binds_boot(d.commitment(), EndpointRole::Destination));
    assert!(!original_b.binds_boot([37; 32], EndpointRole::Destination));
    assert!(
        original_a
            .check_recipient(&bowner, Some(d.commitment()))
            .is_err()
    );
    assert!(original_a.check_recipient(&aowner, Some([37; 32])).is_err());
    original_a
        .check_recipient(&aowner, Some(d.commitment()))
        .unwrap();
    original_a.install(&mut a, &aowner).unwrap();
    original_b.install(&mut b, &bowner).unwrap();
    let mut dst = PrivateSlot::new(&mut b, &bowner).unwrap();
    let mut src_slot = PrivateSlot::new(&mut a, &aowner).unwrap();
    assert!(
        dst.accept(d, EndpointRole::Source, &bowner, &offer.source, now)
            .is_err()
    );
    assert!(
        dst.accept(
            d,
            EndpointRole::Destination,
            &aowner,
            &offer.destination,
            now
        )
        .is_err()
    );
    assert!(
        dst.accept(d, EndpointRole::Destination, &bowner, &offer.source, now)
            .is_err()
    );
    assert!(
        dst.accept(
            d,
            EndpointRole::Destination,
            &bowner,
            &offer.destination,
            d.fields.end
        )
        .is_err()
    );
    let mut corrupt = offer.destination.0;
    corrupt[17] ^= 1;
    assert!(
        dst.accept(
            d,
            EndpointRole::Destination,
            &bowner,
            &Capsule(corrupt),
            now
        )
        .is_err()
    );
    let ingress = dst
        .open_immutable_destination(&bowner, &b.grant)
        .unwrap()
        .unwrap();
    assert!(
        dst.accept(
            d,
            EndpointRole::Destination,
            &bowner,
            &offer.destination,
            now
        )
        .is_err()
    );
    let source_role = src_slot.open_immutable_role(&aowner, &a.grant, EndpointRole::Source).unwrap().unwrap();
    let first = src_slot
        .installed(d, EndpointRole::Source, &aowner)
        .unwrap();
    let second = dst
        .installed(d, EndpointRole::Destination, &bowner)
        .unwrap();
    assert_eq!(first.context(), second.context());
    let bytes = b"\0A\xffB\0";
    use local::{LocalDirection, LocalFrame, LocalSubmit};
    use mailbox::frame::{cast::source::SourceCastSlot, local::encode_local_frame};
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    let original = encode_local_frame(
        &LocalFrame::Submit(Box::new(LocalSubmit {
            originating_binding: d.source_greeting().binding,
            request_id: 1,
            kind: MailboxMessageKind::Cast,
            recipient: dest.expected_recipient,
            content_type: src.accepted_content_types[0].clone(),
            expires_at_unix_ms: now + 1000,
            timeout_ms: 0,
            correlation: CorrelationId::from_bytes([0; 32]),
            causation: CausationId::from_bytes([0; 32]),
            reply_token: vec![],
            body: bytes.to_vec(),
        })),
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &a.grant.local_service.unwrap().limits,
    )
    .unwrap();
    let observed=crate::mailbox_process::source_ingress::qualify(&source_role, first, &a.keys, &original, a.grant.local_service.unwrap().limits);
    crate::mailbox_process::destination_ingress::qualify(&ingress, &b.keys, second, &observed, bytes);
    let mut sealer = a.keys.trust().1;
    // A fixture credit is sufficient for this source/crypto component;
    // BoundSourceGeneration obtains an actual shared ledger reservation.
    let mut slot = SourceCastSlot::new(
        (),
        usize::try_from(a.grant.local_service.unwrap().limits.retained_host_bytes).unwrap(),
    );
    let mut source_policy = src.clone();
    source_policy.now_unix_ms = now;
    let mut receiving = dest.clone();
    receiving.expected_sender = src.expected_sender;
    receiving.acting_principal = src.acting_principal;
    receiving.current_execution_epoch = src.current_execution_epoch;
    receiving.now_unix_ms = now;
    let role = || VerifiedSourceRole {
        channel: &chan,
        grants: g,
        direction: d,
        key: first,
    };
    let start = std::time::Instant::now();
    let source_cpu = thread_cpu();
    let mut src_view = sealer.enrolled_addressed_source(role(), &mut slot).unwrap();
    let env = src_view
        .prepare(&original, &source_policy, &receiving)
        .unwrap();
    let encoded = mailbox::encode_envelope(env).unwrap();
    let source_cpu = thread_cpu() - source_cpu;
    let (mut left, mut right) = UnixStream::pair().unwrap();
    left.write_all(&encoded).unwrap();
    let mut received = vec![0; encoded.len()];
    right.read_exact(&mut received).unwrap();
    assert_eq!(received, encoded);
    let mut replay = mailbox::InMemoryReplayProtector::default();
    let before = thread_cpu();
    let proof = b
        .keys
        .open_original_cast(
            &chan,
            mailbox::decode_envelope(&received).unwrap(),
            g,
            second,
            &source_policy,
            &receiving,
            &mut replay,
            1.try_into().unwrap(),
        )
        .unwrap();
    let open_cpu = thread_cpu() - before;
    let (host, guest) = UnixStream::pair().unwrap();
    for stream in [&host, &guest] {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
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
        let workload = scope.spawn(|| {
            let begin = thread_cpu();
            let mut inbox = chan.inbox();
            chan.receive_on(&mut guest, || now, &mut inbox).unwrap();
            let read = inbox
                .consume_with(|v| Ok::<_, ()>(v.body.clone()))
                .unwrap()
                .unwrap();
            (read, thread_cpu() - begin, guest.read, guest.written)
        });
        let begin = thread_cpu();
        let ack = proof
            .dispatch_on(&chan, &mut host, || Ok((&source_policy, &receiving)))
            .unwrap();
        let host_cpu = thread_cpu() - begin;
        assert_eq!(ack.disposition, local::LocalInboxDisposition::Accepted);
        let (read, guest_cpu, read_role, wrote_role) = workload.join().unwrap();
        assert_eq!((host.written, host.read), (read_role, wrote_role));
        assert_eq!(read, bytes);
        eprintln!(
            "DEVELOPMENT_CAST payload={} envelope_socket_forward={} envelope_socket_reverse=0 role_forward={} role_reverse={} prepare_cpu_ns={} open_cpu_ns={} dispatch_cpu_ns={} guest_cpu_ns={} prepare_through_verified_readback_ns={}",
            read.len(),
            received.len(),
            host.written,
            host.read,
            source_cpu,
            open_cpu,
            host_cpu,
            guest_cpu,
            start.elapsed().as_nanos()
        );
    });
    let retry = sealer
        .enrolled_addressed_source(role(), &mut slot)
        .unwrap()
        .prepare(&original, &source_policy, &receiving)
        .unwrap()
        .clone();
    assert_eq!(mailbox::encode_envelope(&retry).unwrap(), encoded);
    // A reseal from the authorized signer with an unrelated boot is
    // rejected before B consumes the original replay identity.
    let signed = mailbox::open_verified_envelope(
        &retry,
        g.send,
        &receiving,
        second.key(),
        &sealer.sender_key.verifying_key(),
        &bk.verifying_key(),
        &mut mailbox::InMemoryReplayProtector::default(),
    )
    .unwrap();
    let mut wrong_header = signed.header().clone();
    wrong_header.sender_boot = BootId::from_bytes([99; 32]);
    let bad = mailbox::seal_envelope(
        mailbox::SealRequest {
            routing: retry.routing.clone(),
            header: wrong_header,
            plaintext: bytes,
        },
        first.key(),
        &sealer.sender_key,
    )
    .unwrap();
    let mut fresh = mailbox::InMemoryReplayProtector::default();
    assert!(
        b.keys
            .open_original_cast(
                &chan,
                bad,
                g,
                second,
                &source_policy,
                &receiving,
                &mut fresh,
                1.try_into().unwrap()
            )
            .is_err()
    );
    assert!(
        b.keys
            .open_original_cast(
                &chan,
                retry.clone(),
                g,
                second,
                &source_policy,
                &receiving,
                &mut fresh,
                1.try_into().unwrap()
            )
            .is_ok()
    );
    crate::mailbox_process::destination_ingress::qualify(&ingress, &b.keys, second, &retry, bytes);
    let mut revoked = receiving.clone();
    revoked
        .revoked_capabilities
        .push(g.receive.grant.revocation_id);
    assert!(
        b.keys
            .open_original_cast(
                &chan,
                retry,
                g,
                second,
                &source_policy,
                &revoked,
                &mut mailbox::InMemoryReplayProtector::default(),
                1.try_into().unwrap()
            )
            .is_err()
    );
    let aad = b"development synthetic object";
    let sealed = mvm_core::crypto::aead::seal(first.key(), bytes, aad);
    assert_eq!(
        mvm_core::crypto::aead::open(second.key(), &sealed, aad).unwrap(),
        bytes
    );
    assert!(mvm_core::crypto::aead::open(&b.keys.trust().0.encryption_key, &sealed, aad).is_err());
    assert!(mvm_core::crypto::aead::open(&a.keys.trust().0.encryption_key, &sealed, aad).is_err());
}
