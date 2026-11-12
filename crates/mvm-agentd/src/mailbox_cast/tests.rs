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

thread_local! { pub(super) static ACK_READ: std::cell::Cell<usize> = const {std::cell::Cell::new(0)}; }
thread_local! { static ACCEPTED_WRITES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

pub(super) fn record_write(n: usize) {
    ACCEPTED_WRITES.with(|v| v.set(v.get().checked_add(n).unwrap()));
}

fn cpu_ns() -> u64 {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: a successful clock_gettime initializes exactly one timespec.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, time.as_mut_ptr()) },
        0
    );
    let time = unsafe { time.assume_init() };
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn workload_payload() -> Vec<u8> {
    let mut bytes: Vec<_> = (0..257).map(|i| (i * 43) as u8).collect();
    bytes[255..].fill(0);
    bytes
}

/// Original workload fd crosses an actual exec as stdin. The child reads from
/// the production workload API and returns its positive canonical receipt.
#[test]
fn original_cast_crosses_process_boundary_with_verified_callback_and_role_counters() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::AsFd;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    const CONTEXT: &str = "MVM_TEST_ORIGINAL_CAST_WORKLOAD_CONTEXT";
    const SELECTOR: &str = "mailbox_cast::tests::original_cast_crosses_process_boundary_with_verified_callback_and_role_counters";
    if let Some(config) = std::env::var_os(CONTEXT) {
        let config = serde_json::from_slice(config.as_encoded_bytes()).unwrap();
        let fd = std::io::stdin().as_fd().try_clone_to_owned().unwrap();
        let mut reader = CastWorkloadReader::from_launch_fd(fd, config).unwrap();
        let expected = workload_payload();
        println!("CAST_WORKLOAD_READY");
        std::io::stdout().flush().unwrap();
        let start = Instant::now();
        let cpu = cpu_ns();
        ACCEPTED_WRITES.with(|n| n.set(0));
        assert!(
            reader
                .receive_with(|item| {
                    assert_eq!(item.delivery_sequence, 1);
                    assert_eq!(item.message_id, MessageId::from_bytes([2; 32]));
                    assert_eq!(item.body, expected);
                    Ok(())
                })
                .unwrap()
        );
        let cpu = cpu_ns() - cpu;
        let wall = start.elapsed().as_nanos();
        println!(
            "CAST_WORKLOAD_RESULT {}",
            serde_json::json!({
                "verified_payload_bytes":expected.len(), "expected_and_verified_digest":mvm_core::crypto::image_verify::sha256_generated_bytes(&expected).unwrap(),
                "workload_cpu_ns":cpu,"workload_wait_and_callback_wall_ns":wall,"workload_to_agent_accepted_bytes":ACCEPTED_WRITES.with(|n|n.get()),
            })
        );
        return;
    }
    let start = Instant::now();
    let (mut guest, reader, hello, mut item) = fixture();
    item.body = workload_payload();
    assert_eq!(
        admit(&mut guest, hello, &item),
        LocalInboxDisposition::Accepted
    );
    guest
        .workload
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (fd, config) = reader.into_launch_fd().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SELECTOR, "--nocapture", "--test-threads=1"])
        .env(CONTEXT, serde_json::to_string(&config).unwrap())
        .stdin(Stdio::from(fd))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    // Child either reports readiness, exits with a diagnostic, or reaches its
    // bounded socket read. No network or second helper is created by this test.
    loop {
        line.clear();
        if output.read_line(&mut line).unwrap() == 0 {
            panic!("workload exited before readiness: {:?}", child.wait());
        }
        if line.trim_end().ends_with("CAST_WORKLOAD_READY") {
            break;
        }
    }
    let setup = start.elapsed();
    ACCEPTED_WRITES.with(|n| n.set(0));
    let transfer = Instant::now();
    let cpu = cpu_ns();
    let confirmed = guest.offer_to_workload();
    let cpu = cpu_ns() - cpu;
    let wall = transfer.elapsed().as_nanos();
    let total = start.elapsed().as_nanos();
    let mut trailing = String::new();
    output.take(8192).read_to_string(&mut trailing).unwrap();
    assert!(child.wait().unwrap().success(), "{trailing}");
    assert!(confirmed.unwrap());
    assert!(!guest.offer_to_workload().unwrap());
    let data = trailing
        .lines()
        .find_map(|line| line.strip_prefix("CAST_WORKLOAD_RESULT "))
        .unwrap();
    let mut measurements = serde_json::from_str::<serde_json::Value>(data).unwrap();
    measurements["setup_through_workload_ready_wall_ns"] =
        u64::try_from(setup.as_nanos()).unwrap().into();
    measurements["agent_to_workload_accepted_bytes"] = ACCEPTED_WRITES.with(|n| n.get()).into();
    measurements["agent_cpu_ns"] = cpu.into();
    measurements["offer_through_confirmed_ack_wall_ns"] = u64::try_from(wall).unwrap().into();
    measurements["start_through_confirmed_ack_wall_ns"] = u64::try_from(total).unwrap().into();
    println!("CAST_COMPONENT {}", measurements);
}

/// Run explicitly in a private Linux PID+mount namespace as unprivileged
/// PID 1 with the real installed OCI wrapper and example application.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires namespace PID 1 and a prepared canonical OCI root"]
fn original_worker_oci_exec_reads_exact_cast_alongside_standard_pipes() {
    use crate::{
        entrypoint::EntrypointPolicy,
        worker_pool::{SlotSnapshot, WorkerPool},
    };
    assert_eq!(std::process::id(), 1);
    let start = std::time::Instant::now();
    let cpu = cpu_ns();
    let (mut endpoint, reader, greeting, mut item) = fixture();
    item.body = workload_payload();
    let (fd, context) = reader.into_launch_fd().unwrap();
    exec::queue_context(&endpoint.workload, &context).unwrap();
    endpoint
        .workload
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    assert_eq!(
        admit(&mut endpoint, greeting, &item),
        LocalInboxDisposition::Accepted
    );
    let entry = EntrypointPolicy::production().validate().unwrap();
    let cfg = serde_json::from_str(
        r#"{"max_calls_per_worker":1,"max_rss_mb":64,"pool_size":1,"in_process":"serial"}"#,
    )
    .unwrap();
    let pool = WorkerPool::start_original_cast(cfg, std::sync::Arc::new(entry), fd).unwrap();
    pool.mark_ready();
    let setup = start.elapsed().as_nanos();
    let caller = {
        let pool = pool.clone();
        std::thread::spawn(move || pool.dispatch(b"ordinary-stdin".to_vec(),4,Vec::new()).unwrap())
    };
    assert!(endpoint.offer_to_workload().unwrap());
    let out=caller.join().unwrap();
    assert_eq!(
        out.stdout,
        [item.body.as_slice(), b"ordinary-stdin"].concat()
    );
    assert_eq!(
        out.outcome,
        crate::worker_protocol::WorkerOutcome::Exit { code: 0 }
    );
    assert_eq!(pool.snapshot(), vec![SlotSnapshot::Dead]);
    let mut metrics: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    metrics["agent_thread_cpu_ns"] = (cpu_ns() - cpu).into();
    metrics["total_wall_ns"] = (start.elapsed().as_nanos() as u64).into();
    metrics["setup_wall_ns"] = (setup as u64).into();
    metrics["verified_cast_bytes"] = item.body.len().into();
    metrics["agent_to_workload_cast_accepted_bytes"] = ACCEPTED_WRITES.with(|n| n.get()).into();
    metrics["workload_to_agent_cast_read_bytes"] = ACK_READ.with(|n| n.get()).into();
    metrics["context_datagram_bytes"] = serde_json::to_vec(&context).unwrap().len().into();
    println!("ORIGINAL_OCI_CAST_RESULT {metrics}");
}

#[test]
fn original_boot_grant_binds_delivery_to_workload_owner_direction_and_root() {
    use ed25519_dalek::Signer;
    use mvm_core::plan::{Nonce, VerbGrant};
    let (endpoint, _, _, _) = fixture();
    let mut projection = endpoint
        .channel
        .guest_enrollment(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [10; 32],
            Some([6; 32]),
            "dest".into(),
        )
        .unwrap();
    let anchor = SigningKey::from_bytes(&[7; 32]);
    let nonce = Nonce::from_bytes([8; 16]);
    let now = chrono::Utc::now();
    let mut grant = VerbGrant {
        session_id: "dest".into(),
        plan_nonce: nonce.clone(),
        not_after: now + chrono::Duration::minutes(2),
        verbs: vec![],
        drive: None,
        application_terminal: None,
        cast_delivery_v1: Some(projection.commitment().unwrap()),
        sig: Vec::new(),
    };
    grant.sig = anchor.sign(&grant.signing_bytes()).to_bytes().to_vec();
    let stored = mvm_core::vm_backend::VerbGrantEnvelope {
        pubkey_hex: "07".repeat(32),
        plan_nonce_hex: nonce.as_hex().to_string(),
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant: grant.clone(),
        cast_delivery_v1: Some(projection.clone()),
    };
    let compact = mvm_core::vm_backend::encode_verb_grant_cmdline(&stored).unwrap();
    let boot = mvm_core::vm_backend::decode_verb_grant_cmdline(
        compact.strip_prefix("mvm.verb_grant=").unwrap(),
    )
    .unwrap();
    assert!(boot.cast_delivery_v1.is_none());
    assert_eq!(
        boot.grant.cast_delivery_v1,
        Some(projection.commitment().unwrap())
    );
    assert!(serde_json::to_vec(&stored).unwrap().len() > compact.len());
    assert!(
        projection
            .open_original(
                &boot.grant,
                &anchor.verifying_key(),
                "dest",
                &nonce,
                Some([6; 32]),
                [11; 32],
                now
            )
            .is_err()
    );
    let open = |value: &mvm_core::mailbox::frame::cast::enrollment::DeliverEnrollmentV1,
                w: &str,
                n: &Nonce,
                root: Option<[u8; 32]>,
                k: &ed25519_dalek::VerifyingKey| {
        value.open_original(&grant, k, w, n, root, [10; 32], now)
    };
    let vk = anchor.verifying_key();
    assert!(open(&projection, "dest", &nonce, Some([6; 32]), &vk).is_ok());
    assert!(open(&projection, "other", &nonce, Some([6; 32]), &vk).is_err());
    assert!(
        open(
            &projection,
            "dest",
            &Nonce::from_bytes([9; 16]),
            Some([6; 32]),
            &vk
        )
        .is_err()
    );
    assert!(open(&projection, "dest", &nonce, None, &vk).is_err());
    assert!(
        open(
            &projection,
            "dest",
            &nonce,
            Some([6; 32]),
            &SigningKey::from_bytes(&[9; 32]).verifying_key()
        )
        .is_err()
    );
    assert!(
        projection
            .open_original(
                &grant,
                &vk,
                "dest",
                &nonce,
                Some([6; 32]),
                [10; 32],
                now + chrono::Duration::hours(1)
            )
            .is_err()
    );
    for change in [
        "destination_owner",
        "source_plan",
        "destination_plan",
        "pair_commitment",
        "image_sha256",
        "mount_commitment",
        "binding",
        "generation",
        "workload",
    ] {
        let mut altered = serde_json::to_value(&projection).unwrap();
        altered[change] = match change {
            "generation" => 999.into(),
            "workload" => "another".into(),
            _ => serde_json::to_value([9u8; 32]).unwrap(),
        };
        let altered = serde_json::from_value(altered).unwrap();
        assert!(
            open(&altered, "dest", &nonce, Some([6; 32]), &vk).is_err(),
            "{change}"
        );
    }
    projection.verity_root = None;
    grant.cast_delivery_v1 = Some(projection.commitment().unwrap());
    grant.sig = anchor.sign(&grant.signing_bytes()).to_bytes().to_vec();
    assert!(
        projection
            .open_original(&grant, &vk, "dest", &nonce, None, [10; 32], now)
            .is_ok()
    );
    grant.cast_delivery_v1 = None;
    grant.sig = anchor.sign(&grant.signing_bytes()).to_bytes().to_vec();
    assert!(
        projection
            .open_original(&grant, &vk, "dest", &nonce, None, [10; 32], now)
            .is_err()
    );
    let legacy = String::from_utf8(grant.signing_bytes()).unwrap();
    assert!(!legacy.contains("cast_delivery_v1"));
}
