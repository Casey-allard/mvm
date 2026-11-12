use super::*;
use ed25519_dalek::{Signer, SigningKey};
use mvm_contract::protocol::mailbox::{MessageId, local_service::MailboxLocalServiceGrant};
use mvm_core::{
    mailbox::frame::{
        cast::submit_enrollment::SubmitEnrollmentV1,
        local::{LOCAL_GREETING_BYTES, encode_local_greeting},
    },
    plan::{Nonce, VerbGrant},
};
use std::{
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};

fn authority() -> (SubmitEnrollmentV1, VerbGrant, SigningKey) {
    let now = chrono::Utc::now();
    let p = SubmitEnrollmentV1 {
        source_plan: [1; 32],
        destination_plan: [2; 32],
        source_owner: [3; 32],
        pair_commitment: [4; 32],
        image_sha256: [5; 32],
        mount_commitment: [6; 32],
        verity_root: Some([7; 32]),
        workload: "original-a".into(),
        binding: [8; 32],
        generation: 9,
        service_generation: [10; 32],
        recipient: PrincipalId::from_bytes([11; 32]),
        content_type: ContentType::parse("a/b", 1).unwrap(),
        limits: MailboxLocalServiceGrant::reliable_v1().limits,
        max_payload: 1024,
        valid_from: now.timestamp_millis() - 1000,
        valid_until: now.timestamp_millis() + 60000,
    };
    let signer = SigningKey::from_bytes(&[12; 32]);
    let mut g = VerbGrant {
        session_id: "original-a".into(),
        plan_nonce: Nonce::from_bytes([13; 16]),
        not_after: now + chrono::Duration::minutes(2),
        verbs: vec![],
        drive: None,
        application_terminal: None,
        cast_delivery_v1: None,
        cast_submit_v1: Some(p.commitment().unwrap()),
        sig: vec![],
    };
    g.sig = signer.sign(&g.signing_bytes()).to_bytes().to_vec();
    (p, g, signer)
}
fn fixture() -> (GuestSubmitEndpoint, OwnedFd) {
    let (p, g, k) = authority();
    let original = p
        .open_original(
            &g,
            &k.verifying_key(),
            "original-a",
            &g.plan_nonce,
            p.verity_root,
            p.mount_commitment,
            chrono::Utc::now(),
        )
        .unwrap();
    GuestSubmitEndpoint::prepare_original_worker(original).unwrap()
}
fn serve_host(
    mut s: UnixStream,
    expected: Vec<u8>,
    nth: u8,
    encoded_hello: [u8; LOCAL_GREETING_BYTES],
    limits: MailboxLocalLimits,
) -> (usize, usize) {
    s.write_all(&encoded_hello).unwrap();
    let mut echo = [0; LOCAL_GREETING_BYTES];
    s.read_exact(&mut echo).unwrap();
    assert_eq!(echo, encoded_hello);
    let mut got = vec![0; expected.len()];
    s.read_exact(&mut got).unwrap();
    assert_eq!(got, expected);
    let inbound = got.len() + echo.len();
    if nth == 0 {
        return (inbound, encoded_hello.len());
    }
    let r = LocalSubmitResult {
        request_id: 1,
        semantic_digest: local_request_digest(&got, &limits).unwrap(),
        disposition: LocalDisposition::AcceptedEphemeral,
        message_id: MessageId::from_bytes([15; 32]),
        correlation: CorrelationId::from_bytes([0; 32]),
        service_generation: if nth == 1 { [31; 32] } else { [10; 32] },
    };
    let reply = encode_local_frame(
        &LocalFrame::SubmitResult(r),
        LocalRole::Submit,
        LocalDirection::HostToGuest,
        &limits,
    )
    .unwrap();
    s.write_all(&reply).unwrap();
    (inbound, encoded_hello.len() + reply.len())
}
#[test]
fn original_submit_requires_signed_boot_role_generation_mount_and_grant_time() {
    let (mut p, mut g, k) = authority();
    let open = |p: &SubmitEnrollmentV1, g: &VerbGrant| {
        p.open_original(
            g,
            &k.verifying_key(),
            "original-a",
            &g.plan_nonce,
            Some([7; 32]),
            [6; 32],
            chrono::Utc::now(),
        )
    };
    assert!(open(&p, &g).is_ok());
    p.service_generation = [33; 32];
    assert!(open(&p, &g).is_err());
    p.service_generation = [10; 32];
    p.mount_commitment = [34; 32];
    assert!(open(&p, &g).is_err());
    p.mount_commitment = [6; 32];
    g.cast_delivery_v1 = Some([3; 32]);
    g.sig = k.sign(&g.signing_bytes()).to_bytes().to_vec();
    assert!(open(&p, &g).is_err());
    g.cast_delivery_v1 = None;
    p.valid_until = chrono::Utc::now().timestamp_millis() - 1;
    g.cast_submit_v1 = Some(p.commitment().unwrap());
    g.sig = k.sign(&g.signing_bytes()).to_bytes().to_vec();
    assert!(open(&p, &g).is_err());
}
#[test]
fn submit_retries_one_workload_claim_across_eof_and_wrong_incarnation() {
    let (mut e, fd) = fixture();
    let workload = UnixDatagram::from(fd);
    let mut bootstrap = [0; BOOTSTRAP + 1];
    let n = receive(&workload, &mut bootstrap).unwrap();
    let ctx: WorkloadSubmit = serde_json::from_slice(&bootstrap[..n]).unwrap();
    let expected = ctx.encode(&[0, 1, 255, 0]).unwrap();
    send(&workload, &expected).unwrap();
    let hello = encode_local_greeting(&e.origin.greeting()).unwrap();
    for nth in 0..3 {
        let (host, mut guest) = UnixStream::pair().unwrap();
        let b = expected.clone();
        let limits = ctx.limits;
        let thread = std::thread::spawn(move || serve_host(host, b, nth, hello, limits));
        assert_eq!(e.exchange(&mut guest).is_ok(), nth == 2);
        thread.join().unwrap();
        assert!(e.pending.is_some());
        assert_eq!(e.accepted.is_some(), nth == 2);
    }
    let mut reply = [0; RESULT_MAX + 1];
    let n = receive(&workload, &mut reply).unwrap();
    let LocalFrame::SubmitResult(r) = decode_local_frame(
        &reply[..n],
        LocalRole::Submit,
        LocalDirection::HostToGuest,
        &ctx.limits,
    )
    .unwrap() else {
        panic!("missing actual SubmitResult")
    };
    assert_eq!(r.message_id.as_bytes(), &[15; 32]);
    assert_eq!(
        r.semantic_digest,
        local_request_digest(&expected, &ctx.limits).unwrap()
    );
    let (foreign, _) = UnixStream::pair().unwrap();
    assert!(e.forward_on_host_port(foreign.into()).is_err());
}
#[test]
#[ignore = "requires namespace PID 1, original OCI wrapper and source workload image"]
fn original_submit_oci_dispatch_reads_binary_body_from_the_ordinary_call() {
    use crate::{
        entrypoint::EntrypointPolicy, worker_pool::WorkerPool, worker_protocol::WorkerOutcome,
    };
    assert_eq!(std::process::id(), 1);
    let (mut e, fd) = fixture();
    let cfg = serde_json::from_str(
        r#"{"max_calls_per_worker":1,"max_rss_mb":64,"pool_size":1,"in_process":"serial"}"#,
    )
    .unwrap();
    let pool = WorkerPool::start_original_cast(
        cfg,
        Arc::new(EntrypointPolicy::production().validate().unwrap()),
        fd,
    )
    .unwrap();
    pool.mark_ready();
    let body: Vec<u8> = (0..257).map(|i| ((i * 203) % 256) as u8).collect();
    let expected = e.context.encode(&body).unwrap();
    let hello = encode_local_greeting(&e.origin.greeting()).unwrap();
    let (host, mut guest) = UnixStream::pair().unwrap();
    let limits = e.context.limits;
    let cpu = cpu_time();
    let start = Instant::now();
    let app = std::thread::spawn(move || pool.dispatch(body, 5, Vec::new()).unwrap());
    let host = std::thread::spawn(move || serve_host(host, expected, 2, hello, limits));
    e.exchange(&mut guest).unwrap();
    let (direction, reverse) = host.join().unwrap();
    let output = app.join().unwrap();
    assert_eq!(output.outcome, WorkerOutcome::Exit { code: 0 });
    assert_eq!(output.stdout, [15; 32]);
    let app_times: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(e.pending.is_some());
    println!(
        "ORIGINAL_OCI_SUBMIT {}",
        serde_json::json!({"payload_bytes":257,"guest_to_host_bytes":direction,"host_to_guest_bytes":reverse,
        "application_result_bytes":output.stdout.len(),"dispatch_through_result_wall_ns":start.elapsed().as_nanos() as u64,"source_workload":app_times,"agent_thread_cpu_ns":cpu_time()-cpu})
    );
}
fn cpu_time() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) },
        0
    );
    Duration::new(t.tv_sec as u64, t.tv_nsec as u32).as_nanos() as u64
}
