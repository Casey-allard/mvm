// Included inside mailbox_workers::tests to exercise the real registry and Child.
use std::time::Duration;
fn handoff_cpu_ns() -> u64 {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: a successful call initializes the writable timespec.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, time.as_mut_ptr()) },
        0
    );
    let time = unsafe { time.assume_init() };
    (time.tv_sec as u64) * 1_000_000_000 + time.tv_nsec as u64
}
struct SocketHelper {
    dir: std::path::PathBuf,
}

impl MailboxWorkerFactory for SocketHelper {
    fn spawn(
        &self,
        request: &MailboxWorkerRequest,
        _: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker> {
        let (control, child_control) = UnixStream::pair()?;
        let child = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("broker::mailbox_workers::tests::original_socket_helper_process")
            .arg("--nocapture")
            .arg("--quiet")
            .env("MVM_TEST_CAST_SOCKET", self.dir.join(&request.vm_id))
            .stdin(Stdio::piped())
            .stderr(Stdio::from(OwnedFd::from(child_control)))
            .stdout(Stdio::null())
            .spawn()?;
        Ok(SpawnedMailboxWorker {
            child,
            control,
            parent_lease: None,
        })
    }
}

#[test]
fn original_socket_helper_process() {
    use std::io::{BufRead, Read, Write};
    let Some(path) = std::env::var_os("MVM_TEST_CAST_SOCKET") else {
        return;
    };
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let mut input = std::io::stdin().lock();
    let mut owner = String::new();
    input.read_line(&mut owner).unwrap();
    let original = serde_json::from_str(&owner).unwrap();
    use crate::mailbox_process::owned_wire::OwnedStatusV1;
    let status = if std::path::Path::new(&path).ends_with("a") {
        OwnedStatusV1::ReadyCastSourceV1 {
            owner: original,
            direction_commitment: [42; 32],
        }
    } else {
        OwnedStatusV1::ReadyCastDestinationV1 {
            owner: original,
            direction_commitment: [42; 32],
        }
    };
    // Only this child has the write half of the private status socket.
    let body = serde_json::to_vec(&status).unwrap();
    let mut status_io = std::io::stderr().lock();
    status_io
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    status_io.write_all(&body).unwrap();
    drop(status_io);
    listener.set_nonblocking(true).unwrap();
    let limit = Instant::now() + Duration::from_secs(8);
    loop {
        let peer = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < limit => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(_) => return,
        };
        let mut data = crate::mailbox_process::owned_wire::DeadlineStream::new(&peer, limit);
        let cpu = handoff_cpu_ns();
        let mut size = [0; 4];
        if data.read_exact(&mut size).is_err() {
            continue;
        }
        let n = u32::from_be_bytes(size) as usize;
        assert!(n <= 8192);
        let mut bytes = vec![0; n];
        data.read_exact(&mut bytes).unwrap();
        if bytes == [0x7e] {
            data.write_all(br#"{"Ok":null}"#).unwrap();
            continue;
        }
        assert_eq!(bytes, (0..=255).chain([0]).collect::<Vec<u8>>());
        let elapsed = handoff_cpu_ns() - cpu;
        // Close with no verdict after exact readback, prior to reporting.
        drop(peer);
        std::fs::write(
            std::path::Path::new(&path).with_extension("cpu"),
            elapsed.to_be_bytes(),
        )
        .unwrap();
        let pending = std::path::Path::new(&path).with_extension("partial");
        std::fs::write(&pending, &bytes).unwrap();
        std::fs::rename(pending, std::path::Path::new(&path).with_extension("read")).unwrap();
        break;
    }
    // Lost reply, still holding the original process and its work until EOF.
    let mut end = [0; 1];
    assert_eq!(input.read(&mut end).unwrap(), 0);
    let _ = std::io::stdout().flush();
}

#[test]
fn lost_peer_reply_keeps_cast_workspace_until_the_original_child_exits() {
    use crate::mailbox_process::installed_profile::{MailboxPair, development_cast_capacity};
    use mvm_contract::protocol::mailbox::local_service::MailboxLocalServiceGrant;
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let cap = development_cast_capacity(&MailboxPair::new(["a", "b"]).unwrap());
    let budget = MailboxWorkerBudget::new(cap.worker).unwrap();
    let registry = MailboxWorkers::new(
        "local",
        budget.clone(),
        Arc::new(SocketHelper {
            dir: dir.path().into(),
        }),
    )
    .unwrap();
    let make = |vm: &str, nonce: u8| {
        let mut r = request(&budget, "local");
        r.vm_id = vm.into();
        r.workload_id = vm.into();
        r.request_nonce = [nonce; 32];
        r.mailbox_grant.local_service = Some(MailboxLocalServiceGrant::reliable_v1());
        let owner = registry.handle(&r).unwrap().0.owner;
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        };
        let (_, input) = registry.handle(&r).unwrap();
        let mut input = std::fs::File::from(input.unwrap());
        serde_json::to_writer(&mut input, &owner).unwrap();
        input.write_all(b"\n").unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let slots = lock(&registry.slots).unwrap();
            let mut slot = lock(&slots[vm]).unwrap();
            let worker = slot.worker.as_mut().unwrap();
            if let Some(ingress) = crate::mailbox_process::owned_wire::poll_ready(
                &mut worker.control,
                &mut worker.ready,
                &owner,
            )
            .unwrap()
            {
                worker.ingress = ingress;
                slot.state = MailboxWorkerState::Serving;
                break;
            }
            drop(slot);
            drop(slots);
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(1));
        }
        (owner, input)
    };
    let (a, a_input) = make("a", 1);
    let (b, b_input) = make("b", 2);
    let base = budget.usage().unwrap();
    let participants = (("a", &a), ("b", &b));
    assert!(registry.claim_original_cast_turn(participants.0,participants.1,[43;32],[1;32]).is_err());
    registry.claim_original_cast_turn(participants.0,participants.1,[42;32],[1;32]).unwrap();
    assert!(registry.claim_original_cast_turn(participants.0,participants.1,[42;32],[1;32]).is_err());
    assert!(registry.claim_original_cast_turn(participants.0,participants.1,[42;32],[2;32]).is_err());
    let wrong_source = UnixStream::connect(dir.path().join("b")).unwrap();
    assert!(
        registry
            .retain_original_source(participants.0, participants.1, &wrong_source, [42; 32])
            .is_err()
    );
    drop(wrong_source);
    let first_source = UnixStream::connect(dir.path().join("a")).unwrap();
    assert!(
        registry
            .retain_original_source(participants.0, participants.1, &first_source, [43; 32])
            .is_err()
    );
    assert_eq!(budget.usage().unwrap(), base);
    registry
        .retain_original_source(participants.0, participants.1, &first_source, [42; 32])
        .unwrap();
    drop(first_source);
    let reopened = UnixStream::connect(dir.path().join("a")).unwrap();
    registry
        .retain_original_source(participants.0, participants.1, &reopened, [42; 32])
        .unwrap();
    drop(reopened);
    assert!(
        registry
            .reserve_cast_source(participants.0, participants.1)
            .is_err()
    );
    assert_eq!(
        budget.usage().unwrap().bytes,
        base.bytes + cast_credit::CAST_WORK_BYTES
    );
    let route = registry.reserve_cast(("a", &a), ("b", &b)).unwrap();
    let bytes = (0..=255).chain([0]).collect::<Vec<u8>>();
    let deadline = || Instant::now() + Duration::from_secs(3);
    // Correct path spelling and a valid direction do not replace peer identity.
    let mut foreign = UnixStream::connect(dir.path().join("a")).unwrap();
    assert!(
        route
            .exchange_with_original(&mut foreign, &bytes, [42; 32], deadline())
            .is_err()
    );
    drop(foreign);
    let mut wrong = UnixStream::connect(dir.path().join("b")).unwrap();
    assert!(
        route
            .exchange_with_original(&mut wrong, &bytes, [43; 32], deadline())
            .is_err()
    );
    drop(wrong);
    let mut complete = UnixStream::connect(dir.path().join("b")).unwrap();
    assert_eq!(
        route
            .exchange_with_original(&mut complete, &[0x7e], [42; 32], deadline())
            .unwrap(),
        Ok(())
    );
    let mut peer = UnixStream::connect(dir.path().join("b")).unwrap();
    let started = Instant::now();
    let cpu = handoff_cpu_ns();
    assert!(
        route
            .exchange_with_original(&mut peer, &bytes, [42; 32], deadline())
            .is_err()
    );
    let elapsed = started.elapsed();
    let sender_cpu = handoff_cpu_ns() - cpu;
    let until = deadline();
    while !dir.path().join("b.read").exists() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
    let receiver_cpu = u64::from_be_bytes(
        std::fs::read(dir.path().join("b.cpu"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(std::fs::read(dir.path().join("b.read")).unwrap(), bytes);
    drop(route);
    assert_eq!(
        budget.usage().unwrap().bytes,
        base.bytes + 2 * cast_credit::CAST_WORK_BYTES,
        "lost peer reply prematurely refunded the live original's workspace"
    );
    assert!(registry.reserve_cast(("a", &a), ("b", &b)).is_err());
    budget.charge("local", None).unwrap();
    budget.release_control("local");
    println!(
        "private_peer_loss body_bytes={} prefix_bytes=4 reply_bytes=0 charged_bytes={} through_eof_ns={} source_thread_cpu_ns={} receiver_thread_cpu_ns={}",
        bytes.len(),
        cast_credit::CAST_WORK_BYTES,
        elapsed.as_nanos(),
        sender_cpu,
        receiver_cpu
    );
    drop(b_input);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let slots = lock(&registry.slots).unwrap();
        let mut slot = lock(&slots["b"]).unwrap();
        if collect_child(slot.worker.as_mut().unwrap())
            .unwrap()
            .is_some()
        {
            break;
        }
        drop(slot);
        drop(slots);
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        budget.usage().unwrap().bytes,
        base.bytes + cast_credit::CAST_WORK_BYTES
    );
    let mut peer = UnixStream::connect(dir.path().join("a")).unwrap();
    peer.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&bytes).unwrap();
    drop(a_input);
    drop(peer);
    let until = deadline();
    loop {
        let slots = lock(&registry.slots).unwrap();
        let mut slot = lock(&slots["a"]).unwrap();
        if collect_child(slot.worker.as_mut().unwrap())
            .unwrap()
            .is_some()
        {
            break;
        }
        drop(slot);
        drop(slots);
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(budget.usage().unwrap(), base);
}
