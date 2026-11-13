use super::*;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::Duration;
use std::{fs::File, os::unix::fs::PermissionsExt};

fn lease(root: &std::path::Path) -> PreparedHostLifetimeLease {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = b"original admitted process state";
    std::fs::write(root.join("state.bin"), state).unwrap();
    std::fs::set_permissions(
        root.join("state.bin"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let holder = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("holder.lock"))
        .unwrap();
    PreparedHostLifetimeLease::bind(
        File::open(root).unwrap(),
        holder,
        mvm_core::host_lifetime::HostLeaseExpectation {
            state_name: "state.bin".into(),
            state_bytes: u16::try_from(state.len()).unwrap(),
            state_sha256: Sha256::digest(state).into(),
            absent_names: [".state.next".into(), ".state.intent".into()],
        },
    )
    .unwrap()
}

fn binding() -> HostLaunchBinding {
    HostLaunchBinding {
        installation: [1; 32],
        profile: [2; 32],
        generation: 3,
        grant_serial: 4,
        vm_name: "original-kernel-fixture".into(),
        backend: mvm_core::vm_backend::BackendKind::Firecracker,
        cpus: 1,
        memory_mib: 256,
    }
}

struct OriginalChild(Child);
impl Drop for OriginalChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn peer_child(listener: &UnixListener, path: &std::path::Path) -> (OriginalChild, UnixStream) {
    let mut command = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
    command
        .args([
            "host::fc_lifetime::tests::connected_peer_child",
            "--exact",
            "--ignored",
        ])
        .env("MVM_FC_LIFETIME_FIXTURE_SOCKET", path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = OriginalChild(command.spawn().unwrap());
    let mut event = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the listener and initialized single-entry buffer remain live.
    assert_eq!(unsafe { libc::poll(&mut event, 1, 3000) }, 1);
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut ready = [0];
    stream.read_exact(&mut ready).unwrap();
    assert_eq!(ready, [42]);
    (child, stream)
}

#[test]
#[ignore = "isolated child fixture, invoked by the owning process tests"]
fn connected_peer_child() {
    let path = std::env::var_os("MVM_FC_LIFETIME_FIXTURE_SOCKET").unwrap();
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(&[42]).unwrap();
    let mut stop = [0];
    assert_eq!(stream.read(&mut stop).unwrap(), 0);
}

#[test]
fn an_original_kernel_descriptor_survives_collection_without_a_pid_lookup() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let path = root.path().join("original.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (mut child, stream) = peer_child(&listener, &path);
    let original = OriginalProcess::observe(&mut child.0).unwrap();
    original.authenticate_config(&stream).unwrap();
    assert!(original.require_live().is_ok());
    assert_eq!(
        original.wait_exit(Instant::now()).unwrap(),
        ProcessExitWait::TimedOut
    );
    drop(stream);
    assert!(child.0.wait().unwrap().success());
    assert_eq!(
        original
            .wait_exit(Instant::now() + Duration::from_secs(1))
            .unwrap(),
        ProcessExitWait::Exited
    );
    assert!(original.require_live().is_err());
}

#[test]
fn a_foreign_connected_process_cannot_replace_the_original_child() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let a = root.path().join("a.sock");
    let b = root.path().join("b.sock");
    let (mut first, first_stream) = peer_child(&UnixListener::bind(&a).unwrap(), &a);
    let (mut second, second_stream) = peer_child(&UnixListener::bind(&b).unwrap(), &b);
    let original = OriginalProcess::observe(&mut first.0).unwrap();
    let refused = original.authenticate_config(&second_stream).is_err();
    drop(first_stream);
    drop(second_stream);
    assert!(first.0.wait().unwrap().success());
    assert!(second.0.wait().unwrap().success());
    assert!(refused);
}

#[test]
fn a_collected_original_child_uses_its_actual_status() {
    let mut command: Command = mvm_core::env_hygiene::helper_command("/bin/true");
    let mut child = OriginalChild(command.spawn().unwrap());
    assert!(child.0.wait().unwrap().success());
    let original = OriginalProcess::observe(&mut child.0).unwrap();
    assert_eq!(
        original.wait_exit(Instant::now()).unwrap(),
        ProcessExitWait::Exited
    );
    assert!(original.require_live().is_err());
}

#[test]
fn retirement_preserves_original_lease_and_can_finish_after_admission_closes() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let lease = lease(root.path());
    let original_holder = lease.holder_object_id();
    let original_directory = lease.directory_object_id();
    let mut command = mvm_core::env_hygiene::helper_command("/bin/cat");
    command.stdin(Stdio::piped()).stdout(Stdio::null());
    let mut child = OriginalChild(command.spawn().unwrap());
    let process = OriginalProcess::observe(&mut child.0).unwrap();
    let mut original = OriginalLifetime::from_observed(binding(), lease, process);
    assert!(original.confirm_exit(Instant::now()).is_err());
    std::fs::write(root.path().join(".state.intent"), b"admission now closed").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    let proof = original
        .confirm_exit(Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(proof.binding(), &binding());
    assert_eq!(proof.lease().holder_object_id(), original_holder);
    assert_eq!(proof.lease().directory_object_id(), original_directory);
    assert!(proof.lease().verify_current().is_err());
    assert!(original.confirm_exit(Instant::now()).is_err());
}
