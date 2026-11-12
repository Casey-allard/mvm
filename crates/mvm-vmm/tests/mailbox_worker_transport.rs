#![cfg(unix)]
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
use mvm_core::protocol::mailbox_worker_control::*;
use mvm_vmm::host::mailbox_worker_transport::{recv_response, send_response};
use std::{
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
fn fixture() -> (MailboxWorkerRequest, MailboxWorkerResult) {
    let owner = MailboxWorkerOwner {
        daemon_boot_nonce: [5; 32],
        lease: [6; 32],
        generation: 1,
        context_commitment: [7; 32],
    };
    let request = MailboxWorkerRequest {
        domain: MAILBOX_WORKER_DOMAIN.into(),
        version: 1,
        request_nonce: [1; 32],
        tenant: "tenant-1".into(),
        vm_id: "vm-1".into(),
        workload_id: "workload-1".into(),
        plan_commitment: [2; 32],
        mailbox_grant: MailboxGrant {
            mailbox: MailboxId::from_bytes([3; 32]),
            authority_key: [4; 32],
            epoch: ExecutionEpoch::new(7).unwrap(),
            local_service: None,
        },
        admission_expires_at_unix_ms: 20_000,
        deadline_unix_ms: 12_000,
        backend: MailboxWorkerBackend::Firecracker,
        operation: MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        },
    };
    let result = MailboxWorkerResult {
        request_nonce: request.request_nonce,
        owner,
        state: MailboxWorkerState::Starting,
        delegates_config: true,
    };
    (request, result)
}
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
#[cfg(target_os = "linux")]
#[test]
fn real_pipe_writer_handoff_is_cloexec_nonblocking_and_exact() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let (read, write) = pipe();
    let (request, result) = fixture();
    send_response(&mut a, &result, Some(write), deadline()).unwrap();
    let (_, fd) = recv_response(&mut b, &request, deadline()).unwrap();
    let fd = fd.unwrap();
    assert_ne!(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert_ne!(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
        0
    );
    let mut writer = std::fs::File::from(fd);
    writer.write_all(&[0, 255, 0, 42]).unwrap();
    drop(writer);
    let mut bytes = Vec::new();
    std::fs::File::from(read).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, [0, 255, 0, 42]);
}
#[test]
fn no_descriptor_for_query_and_wrong_fd_kind_rejected_before_send() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let (mut request, mut result) = fixture();
    request.operation = MailboxWorkerOperation::Query {
        owner: result.owner.clone(),
    };
    result.delegates_config = false;
    result.state = MailboxWorkerState::Reserved;
    send_response(&mut a, &result, None, deadline()).unwrap();
    assert!(
        recv_response(&mut b, &request, deadline())
            .unwrap()
            .1
            .is_none()
    );
    let (_, write) = pipe();
    assert!(send_response(&mut a, &result, Some(write), deadline()).is_err());
    let (read, _) = pipe();
    result.delegates_config = true;
    assert!(send_response(&mut a, &result, Some(read), deadline()).is_err());
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(send_response(&mut a, &result, Some(file.into()), deadline()).is_err());
}
#[test]
fn bad_marker_oversize_truncated_and_expired_frames_fail_closed() {
    for bytes in [
        vec![0x00],
        vec![0x4d, 0xff, 0xff, 0xff, 0xff],
        vec![0x4d, 0, 0, 0, 4, b'{'],
    ] {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&bytes).unwrap();
        drop(a);
        assert!(recv_response(&mut b, &fixture().0, deadline()).is_err());
    }
    let (_a, mut b) = UnixStream::pair().unwrap();
    assert!(recv_response(&mut b, &fixture().0, Instant::now()).is_err());
}
#[cfg(target_os = "linux")]
#[test]
fn mismatched_correlation_cannot_release_delegated_writer() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let (mut request, result) = fixture();
    let (read, write) = pipe();
    send_response(&mut a, &result, Some(write), deadline()).unwrap();
    request.request_nonce = [99; 32];
    assert!(recv_response(&mut b, &request, deadline()).is_err());
    let mut bytes = Vec::new();
    std::fs::File::from(read).read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty(), "refusal must close received writer");
}

fn raw_send(stream: &UnixStream, bytes: &[u8], fds: &[OwnedFd]) {
    let mut control = [0usize; 128];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        unsafe {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen =
                libc::CMSG_SPACE((fds.len() * std::mem::size_of::<libc::c_int>()) as _) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len =
                libc::CMSG_LEN((fds.len() * std::mem::size_of::<libc::c_int>()) as _) as _;
            for (i, fd) in fds.iter().enumerate() {
                libc::CMSG_DATA(c)
                    .cast::<libc::c_int>()
                    .add(i)
                    .write_unaligned(fd.as_raw_fd());
            }
        }
    }
    assert_eq!(
        unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) },
        bytes.len() as isize
    );
}
fn assert_pipe_closed(fd: OwnedFd) {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut b = [0];
    assert_eq!(
        std::fs::File::from(fd).read(&mut b).unwrap(),
        0,
        "rejected writer leaked"
    );
}
#[test]
fn excess_and_truncated_rights_are_all_closed() {
    for count in [2, 80] {
        let (a, mut b) = UnixStream::pair().unwrap();
        let pipes: Vec<_> = (0..count).map(|_| pipe()).collect();
        let (reads, writes): (Vec<_>, Vec<_>) = pipes.into_iter().unzip();
        raw_send(&a, &[0x4d], &writes);
        drop(writes);
        drop(a);
        assert!(recv_response(&mut b, &fixture().0, deadline()).is_err());
        for read in reads {
            assert_pipe_closed(read)
        }
    }
}
#[test]
fn rights_on_length_prefix_are_rejected_and_closed() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(&[0x4d]).unwrap();
    let (read, write) = pipe();
    raw_send(&a, &[0, 0, 0, 2], &[write]);
    drop(a);
    assert!(recv_response(&mut b, &fixture().0, deadline()).is_err());
    assert_pipe_closed(read);
}
#[test]
fn wrong_kind_from_untrusted_raw_sender_is_closed() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let (_, result) = fixture();
    let mut frame = vec![0x4d];
    let body = serde_json::to_vec(
        &mvm_core::protocol::broker_control::ControlResponse::MailboxWorkerV1(Box::new(result)),
    )
    .unwrap();
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    raw_send(
        &a,
        &frame,
        &[std::fs::File::open("/dev/null").unwrap().into()],
    );
    drop(a);
    assert!(recv_response(&mut b, &fixture().0, deadline()).is_err());
}
#[test]
fn partial_frame_cannot_restart_absolute_deadline() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let end = Instant::now() + Duration::from_millis(60);
    let sender = std::thread::spawn(move || {
        for byte in [0x4d, 0, 0, 0, 2, b'{', b'}'] {
            if a.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    });
    let start = Instant::now();
    assert!(recv_response(&mut b, &fixture().0, end).is_err());
    assert!(start.elapsed() < Duration::from_millis(500));
    drop(b);
    sender.join().unwrap();
}
#[cfg(target_os = "linux")]
#[test]
fn unexpected_kernel_credentials_ancillary_is_rejected() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let one: libc::c_int = 1;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                b.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of_val(&one) as _,
            )
        },
        0
    );
    let (read, write) = pipe();
    raw_send(&a, &[0x4d], &[write]);
    drop(a);
    assert!(recv_response(&mut b, &fixture().0, deadline()).is_err());
    assert_pipe_closed(read);
}
#[test]
fn first_delegation_without_descriptor_is_rejected() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let body = serde_json::to_vec(
        &mvm_core::protocol::broker_control::ControlResponse::MailboxWorkerV1(Box::new(
            fixture().1,
        )),
    )
    .unwrap();
    let mut frame = vec![0x4d];
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    raw_send(&a, &frame, &[]);
    drop(a);
    assert!(recv_response(&mut b, &fixture().0, deadline()).is_err());
}

#[test]
fn transferred_writer_is_closed_on_bad_marker_length_json_eof_and_timeout() {
    for bytes in [
        vec![0x00],
        vec![0x4d, 0xff, 0xff, 0xff, 0xff],
        vec![0x4d, 0, 0, 0, 2, b'x', b'x'],
        vec![0x4d, 0, 0, 0, 4, b'{'],
    ] {
        let (a, mut b) = UnixStream::pair().unwrap();
        let (read, write) = pipe();
        raw_send(&a, &bytes, &[write]);
        drop(a);
        assert!(recv_response(&mut b, &fixture().0, deadline()).is_err());
        assert_pipe_closed(read);
    }
    let (a, mut b) = UnixStream::pair().unwrap();
    let (read, write) = pipe();
    raw_send(&a, &[0x4d], &[write]);
    assert!(
        recv_response(
            &mut b,
            &fixture().0,
            Instant::now() + Duration::from_millis(25)
        )
        .is_err()
    );
    assert_pipe_closed(read);
    drop(a);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unqualified_platform_refuses_pipe_delegation_explicitly() {
    let (mut a, _) = UnixStream::pair().unwrap();
    let (_, write) = pipe();
    assert_eq!(
        send_response(&mut a, &fixture().1, Some(write), deadline())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
}
#[test]
fn new_wire_response_is_canonical_typed_control_variant() {
    use mvm_core::protocol::broker_control::ControlResponse;
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let (_, mut result) = fixture();
    result.delegates_config = false;
    result.state = MailboxWorkerState::Reserved;
    send_response(&mut a, &result, None, deadline()).unwrap();
    let mut marker = [0];
    b.read_exact(&mut marker).unwrap();
    assert_eq!(marker, [0x4d]);
    let mut size = [0; 4];
    b.read_exact(&mut size).unwrap();
    let mut body = vec![0; u32::from_be_bytes(size) as usize];
    b.read_exact(&mut body).unwrap();
    assert_eq!(
        serde_json::from_slice::<ControlResponse>(&body).unwrap(),
        ControlResponse::MailboxWorkerV1(Box::new(result))
    );
}

#[test]
fn delegated_config_refuses_a_regular_file_before_writing() {
    let file = tempfile::tempfile().unwrap();
    let writer = file.try_clone().unwrap().into();
    assert!(
        mvm_vmm::host::mailbox_worker_transport::write_config(writer, b"private", deadline())
            .is_err()
    );
    assert_eq!(file.metadata().unwrap().len(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn delegated_config_closes_after_exact_write_and_times_out_on_full_pipe() {
    use mvm_vmm::host::mailbox_worker_transport::write_config;
    let payload = vec![0x45; 65536];
    let (reader, writer) = pipe();
    let drain = std::thread::spawn(move || {
        let mut received = Vec::new();
        std::fs::File::from(reader)
            .read_to_end(&mut received)
            .unwrap();
        received
    });
    write_config(writer, &payload, deadline()).unwrap();
    assert_eq!(drain.join().unwrap(), payload);

    let (_reader, writer) = pipe();
    // Reduce capacity to one page so this write is guaranteed to stall.
    let capacity = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
    assert!((1..payload.len() as i32).contains(&capacity));
    assert_eq!(
        write_config(writer, &payload, Instant::now() + Duration::from_millis(50))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
}

#[test]
fn worker_request_uses_the_daemons_existing_length_and_signed_body() {
    use mvm_core::protocol::broker_control::{ControlRequest, sign};
    use mvm_vmm::host::mailbox_worker_transport::send_request;
    let (sender, mut receiver) = UnixStream::pair().unwrap();
    let signed = sign(
        ControlRequest::MailboxWorkerV1(Box::new(fixture().0)),
        &[9; 32],
    )
    .unwrap();
    send_request(&sender, &signed, deadline()).unwrap();
    drop(sender);
    let mut wire = Vec::new();
    receiver.read_to_end(&mut wire).unwrap();
    let expected = serde_json::to_vec(&signed).unwrap();
    assert_eq!(wire[..4], (expected.len() as u32).to_be_bytes());
    assert_eq!(wire[4..], expected);
}
