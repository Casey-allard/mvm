//! Explicit inter-repository component: real destination worker process and
//! guest agent. The host fixture has no recipient V2. It must never see an ACK.
use super::*;
use mvm_agentd::worker_protocol::{
    WorkerCallRequest, WorkerCallResponse, WorkerOutcome, read_pipe_frame, write_pipe_frame,
};
use mvm_core::mailbox::reader_wire::ObjectSubmissionV1;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, Stdio};

#[test]
#[ignore = "requires explicit private Linux mount namespace and external SpiralCore worker binaries"]
fn worker_holds_computed_reply_across_indeterminate_submission() {
    let mount = std::fs::metadata("/proc/self/ns/mnt").unwrap();
    assert_ne!(
        mount.ino(),
        std::fs::metadata("/proc/1/ns/mnt").unwrap().ino()
    );
    assert!(
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|l| l.split_whitespace().nth(4) == Some("/run")
                && l.contains(" - tmpfs spiralcore-worker-test "))
    );
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("call.json");
    let mut input = vec![];
    let f = selected_call(|pair| {
        let generator = std::env::var_os("SC_TEST_PRODUCER").unwrap();
        let status = Command::new(generator)
            .args([
                "--ignored",
                "--exact",
                "object_exchange::tests::emit_first_object_call_for_guest_component",
            ])
            .env(
                "SC_TEST_ORIGINAL_PAIR",
                pair.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
            .env("SC_TEST_CALL_FIXTURE", &path)
            .status()
            .unwrap();
        assert!(status.success());
        let value: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(&path).unwrap()).unwrap();
        input = serde_json::to_vec(&value["input"]).unwrap();
        (
            serde_json::from_value(value["message"].clone()).unwrap(),
            serde_json::from_value(value["correlation"].clone()).unwrap(),
            serde_json::from_value(value["payload"].clone()).unwrap(),
        )
    });
    let dir = Path::new("/run/mvm");
    std::fs::create_dir(dir).unwrap();
    let mail = dir.join("mailbox");
    std::fs::create_dir(&mail).unwrap();
    let public = dir.join(mvm_core::mailbox::reader::MAILBOX_READER_BOOT_FILE);
    std::fs::write(&public, serde_json::to_vec(&f.boot).unwrap()).unwrap();
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o444)).unwrap();
    let pending = start(
        f.boot.clone(),
        Box::leak(Box::new(Zeroizing::new(f.guest.to_bytes()))),
        Some(f.role.clone()),
    )
    .unwrap();
    let mut worker = Command::new(std::env::var_os("SC_TEST_WORKER").unwrap())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut seen = 0;
    let mut auth = 0;
    let mut submissions = 0;
    let mut last = None;
    std::thread::scope(|scope| {
        let calls = scope.spawn(|| {
            let input = WorkerCallRequest {
                stdin: input,
                timeout_secs: 4,
                env: vec![],
            };
            for attempt in 0..2 {
                write_pipe_frame(worker.stdin.as_mut().unwrap(), &input).unwrap();
                let r: WorkerCallResponse =
                    read_pipe_frame(worker.stdout.as_mut().unwrap()).unwrap();
                assert_ne!(r.outcome, WorkerOutcome::Exit { code: 0 });
                let public = String::from_utf8(r.stderr).unwrap();
                assert!(public.contains("worker_cumulative"));
                if attempt == 1 {
                    assert!(public.contains("original Reply was refused"));
                    assert!(public.contains("\"this_invocation\":[0,0,0,0,0,0]"));
                }
                eprintln!("worker_control={public}");
            }
            worker.stdin.take();
            assert!(worker.wait().unwrap().success());
        });
        while submissions < 2 {
            let request = pending.recv_timeout(Duration::from_secs(5)).unwrap();
            let (mut host, mut guest) = UnixStream::pair().unwrap();
            let actor = scope.spawn(move || exchange(&mut guest, request).unwrap());
            let req = read_request(&mut host).unwrap();
            let reply = match req {
                ReaderRequest::ReceiveObjectPairV1 { pair } => {
                    assert_eq!(pair, f.pair);
                    assert_eq!(seen, 0);
                    seen += 1;
                    let challenge = [49; 32];
                    write_response(
                        &mut host,
                        &ReaderResponse::Challenge {
                            enrollment: Box::new(f.signed_enrollment.clone()),
                            capability: Box::new(f.receive_cap.clone()),
                            challenge,
                        },
                    )
                    .unwrap();
                    let ReaderRequest::Possession { signature } = read_request(&mut host).unwrap()
                    else {
                        panic!("missing original guest possession")
                    };
                    verify_reader_possession(
                        &f.signed_enrollment,
                        &challenge,
                        &signature,
                        &f.guest.verifying_key(),
                    )
                    .unwrap();
                    ReaderResponse::ObjectDeliveryV1 {
                        lease: Box::new(f.lease.clone()),
                        header: Box::new(f.header.clone()),
                        payload: f.payload.clone(),
                    }
                }
                ReaderRequest::AuthorizeObjectCallV1 {
                    pair,
                    lease,
                    challenge,
                } => {
                    assert_eq!(pair, f.pair);
                    assert_eq!(*lease, f.lease);
                    assert_ne!(challenge, [0; 32]);
                    f.role.verify(&f.boot, now_unix_ms().unwrap()).unwrap();
                    mvm_core::mailbox::reader::verify_object_delivery_projection(
                        &pair,
                        &f.header,
                        &f.payload,
                        &lease,
                        &VerifyingKey::from_bytes(&f.boot.authority_key).unwrap(),
                    )
                    .unwrap();
                    auth += 1;
                    ReaderResponse::ObjectRoleV1 {
                        signed: Box::new(f.role.clone()),
                    }
                }
                ReaderRequest::SubmitObjectV1 { pair, submission } => {
                    assert_eq!(pair, f.pair);
                    let ObjectSubmissionV1::Reply {
                        original_call,
                        payload,
                        ..
                    } = &*submission
                    else {
                        panic!("expected computed Reply")
                    };
                    assert_eq!(**original_call, f.lease);
                    assert_eq!(payload.get(..8), Some(b"SCMOBJ01".as_slice()));
                    assert_eq!(payload[8], 101);
                    if let Some(ref first) = last {
                        assert_eq!(first, &submission)
                    } else {
                        last = Some(submission)
                    }
                    submissions += 1;
                    if submissions == 1 {
                        drop(host);
                        actor.join().unwrap();
                        continue;
                    }
                    // No destination journal was started in this fixture.
                    ReaderResponse::Refused {
                        reason: Refusal::NotAuthorized,
                    }
                }
                _ => panic!("unexpected guest request or premature ACK"),
            };
            write_response(&mut host, &reply).unwrap();
            actor.join().unwrap();
        }
        calls.join().unwrap();
    });
    assert!(auth >= 4);
    assert_eq!(seen, 1);
    eprintln!(
        "destination_worker input_frame_bytes={} original_calls={} authorization_checks={} identical_reply_submissions={} acknowledgments=0 elapsed_ns={}",
        f.payload.len(),
        seen,
        auth,
        submissions,
        start.elapsed().as_nanos()
    );
}
