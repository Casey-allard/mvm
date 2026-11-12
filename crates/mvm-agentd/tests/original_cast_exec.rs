//! Descriptor hygiene for the admitted OCI mailbox workload.
#![cfg(target_os = "linux")]
use mvm_agentd::mailbox_cast::exec::{inherit_original_in_child, validate_original_parent};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::process::Command;

#[test]
fn passing_original_fd_does_not_change_the_parent_or_leak_a_sibling() {
    let (original, _other) = UnixDatagram::pair().unwrap();
    let (sibling, _unused) = UnixDatagram::pair().unwrap();
    let fd = original.as_raw_fd();
    let distractor = sibling.as_raw_fd();
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(format!(
        "test -S /proc/self/fd/{fd} && test ! -e /proc/self/fd/{distractor} && read word && echo \"$word\" && echo original-stderr >&2"
    ));
    use std::process::Stdio;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    mvm_agentd::fd_hygiene::configure_close_fds(&mut command, 3, None);
    inherit_original_in_child(&mut command, original.into()).unwrap();
    let mut child = command.spawn().unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"ordinary-stdin\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"ordinary-stdin\n");
    assert_eq!(result.stderr, b"original-stderr\n");
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
}

#[test]
fn workload_supplied_anonymous_socket_is_not_a_pid1_enrollment() {
    use std::os::fd::AsFd;
    let (socket, _other) = UnixDatagram::pair().unwrap();
    assert!(validate_original_parent(socket.as_fd()).is_err());
}
