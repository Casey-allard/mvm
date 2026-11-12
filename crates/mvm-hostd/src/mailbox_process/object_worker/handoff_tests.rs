use super::*;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::{
    os::fd::AsFd,
    process::{Command, Stdio},
    time::Duration,
};

fn until() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn hands_off_both_original_handles_and_fences_exit_and_swapped_order() {
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let identity = [
        EndpointPid::of_child(std::process::id()),
        EndpointPid::of_child(child.id()),
    ];
    let fds =
        identity.map(|id| pidfd_open(Pid::from_raw(id.pid).unwrap(), PidfdFlags::empty()).unwrap());
    let (parent, worker) = UnixStream::pair().unwrap();
    send_originals(&parent, [fds[0].as_fd(), fds[1].as_fd()], until()).unwrap();
    let received = receive_originals(&worker, until()).unwrap();
    received.require_live(identity).unwrap();
    assert!(received.require_live([identity[1], identity[0]]).is_err());
    let mut stale = identity;
    stale[1].started = stale[1].started.map(|n| n ^ 1);
    assert!(received.require_live(stale).is_err());
    drop(child.stdin.take());
    child.wait().unwrap();
    assert!(received.require_live(identity).is_err());
}

#[test]
fn unrelated_open_files_and_partial_or_oversized_ancillary_messages_fail_closed() {
    let ordinary = std::fs::File::open("/dev/null").unwrap();
    let own = EndpointPid::of_child(std::process::id());
    for count in [1, 2, 3, 8] {
        let (parent, worker) = UnixStream::pair().unwrap();
        let fds = vec![ordinary.as_fd(); count];
        let mut mem = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut control = SendAncillaryBuffer::new(&mut mem);
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        sendmsg(
            &parent,
            &[IoSlice::new(&TAG)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        let received = receive_originals(&worker, until());
        if count == 2 {
            assert!(
                received
                    .unwrap()
                    .require_live([
                        own,
                        EndpointPid::of_child(
                            rustix::process::getppid().unwrap().as_raw_nonzero().get() as u32
                        )
                    ])
                    .is_err()
            );
        } else {
            assert!(received.is_err());
        }
    }
}

#[test]
fn absent_ancillary_data_eof_and_deadline_reject_before_bootstrap() {
    use std::io::Write;
    let (mut parent, worker) = UnixStream::pair().unwrap();
    assert!(receive_originals(&worker, Instant::now()).is_err());
    parent.write_all(&TAG).unwrap();
    assert!(receive_originals(&worker, until()).is_err());
    drop(parent);
    assert!(receive_originals(&worker, until()).is_err());
}

#[test]
fn bootstrap_body_is_bounded_and_requires_original_write_half_close() {
    use std::io::Write;
    let (mut parent, worker) = UnixStream::pair().unwrap();
    parent.write_all(b"{}").unwrap();
    assert!(read_body(&worker, 8, Instant::now() + Duration::from_millis(20)).is_err());
    let (mut parent, worker) = UnixStream::pair().unwrap();
    parent.write_all(b"abcdefg").unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(
        read_body(&worker, 7, until()).unwrap().as_slice(),
        b"abcdefg"
    );
    let (mut parent, worker) = UnixStream::pair().unwrap();
    parent.write_all(b"abcdefgh").unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(read_body(&worker, 7, until()).is_err());
}

#[test]
fn original_controller_is_the_parent_and_may_half_close_only_its_writes() {
    use std::os::fd::OwnedFd;
    const CHILD: &str = "MVM_OBJECT_WORKER_CONTROL_TEST";
    if std::env::var_os(CHILD).is_some() {
        let fd = std::io::stdin().as_fd().try_clone_to_owned().unwrap();
        let stream = UnixStream::from(fd);
        let controller = Controller::capture(&stream).unwrap();
        controller.require_live(&stream).unwrap();
        // Signal the actual launcher only after the parent's write-half close was accepted.
        let mut channel = &stream;
        std::io::Write::write_all(&mut channel, b"K").unwrap();
        let deadline = until();
        while controller.require_live(&stream).is_ok() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        return;
    }
    let (mut parent, worker) = UnixStream::pair().unwrap();
    assert!(Controller::capture(&parent).is_err());
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact","mailbox_process::object_worker::tests::original_controller_is_the_parent_and_may_half_close_only_its_writes"])
        .env(CHILD,"1").stdin(Stdio::from(OwnedFd::from(worker))).spawn().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut signal = [0];
    std::io::Read::read_exact(&mut parent, &mut signal).unwrap();
    assert_eq!(signal, *b"K");
    drop(parent);
    assert!(child.wait().unwrap().success());
}
