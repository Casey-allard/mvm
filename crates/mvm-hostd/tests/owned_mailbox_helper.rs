//! Exercise the private lifetime channel on the shipped mailbox binary.
#![cfg(unix)]

use std::io::{self, Write};
use std::os::{
    fd::AsRawFd,
    unix::{net::UnixStream, process::CommandExt},
};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mvm_contract::protocol::{
    mailbox::{ExecutionEpoch, MailboxGrant, MailboxId},
    mailbox_worker::MailboxWorkerOwner,
};
use mvm_core::vm_backend::HostDialRoute;
use mvm_hostd::{
    mailbox_launch::authority_key_for,
    mailbox_process::{
        build_config,
        owned_wire::{PrepareOwnedV1, read_ready, write_prepare},
    },
    mailbox_service,
};

struct OriginalChild(Child);

impl Drop for OriginalChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Meter {
    stream: UnixStream,
    written: usize,
    read: usize,
}

impl io::Read for Meter {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = io::Read::read(&mut self.stream, bytes)?;
        self.read += n;
        Ok(n)
    }
}

impl Write for Meter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(bytes)?;
        self.written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn transfer(socket: &std::path::Path, port: &std::path::Path, deadline: Instant) -> (u64, u64) {
    use mvm_core::mailbox::frame::{OutboxMessage, send_outbox_message};
    let guest = std::os::unix::net::UnixListener::bind(port).unwrap();
    guest.set_nonblocking(true).unwrap();
    let stream = loop {
        match guest.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("guest dial: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut io = Meter {
        stream,
        written: 0,
        read: 0,
    };
    let message = OutboxMessage {
        recipient: mvm_contract::protocol::mailbox::PrincipalId::from_bytes([1; 32]),
        body: (0..4096).map(|n| (n % 255) as u8).chain([0, 0]).collect(),
    };
    let started = Instant::now();
    send_outbox_message(&mut io, &message).unwrap();
    let stored = mailbox_service::recv(socket).unwrap();
    let actual = hex::decode(stored.message.unwrap()).unwrap();
    assert_eq!(actual, message.body);
    eprintln!(
        "owned mailbox payload={} guest_to_helper={} helper_to_guest={} send_to_verified_readback_us={}",
        actual.len(),
        io.written,
        io.read,
        started.elapsed().as_micros()
    );
    (io.written as u64, io.read as u64)
}

fn run(mismatch: bool, measured: bool) {
    let state = tempfile::tempdir_in("/tmp").unwrap();
    let keys = tempfile::tempdir().unwrap();
    mvm_hostd::audit::host_keypair::load_or_init_at(keys.path()).unwrap();
    let mailbox = MailboxId::from_bytes([1; 32]);
    let epoch = ExecutionEpoch::new(1).unwrap();
    let grant = MailboxGrant {
        mailbox,
        epoch,
        local_service: None,
        authority_key: authority_key_for(keys.path(), &mailbox, epoch)
            .unwrap()
            .to_bytes(),
    };
    let route = HostDialRoute::PortSocket(state.path().join("guest.sock"));
    let config = build_config(keys.path(), &grant, state.path(), route.clone()).unwrap();
    let (parent, helper) = UnixStream::pair().unwrap();
    let fd = helper.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_mvm-mailbox"));
    command.arg("--owned-v1").env_clear().stdin(Stdio::piped());
    let (reader, writer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    if measured {
        command
            .env(mailbox_service::guest_io::ENABLE_ENV, "1")
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)));
    }
    let mut independent_counts = None;
    // SAFETY: the closure uses only async-signal-safe descriptor operations,
    // and helper remains live through spawn. Other descriptors are CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 3) != 3 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    use mvm_vmm::host::installed_owner::{
        HolderLease, InstallationKey, InstallationOwner, spawn_with_resource_lease,
    };
    use std::os::unix::fs::PermissionsExt as _;
    let installation_dir = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(
        installation_dir.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let root = installation_dir.path().join("owner");
    let key = InstallationKey {
        installation: [4; 32],
        profile: [5; 32],
    };
    let mut installation = InstallationOwner::initialize(&root, key).unwrap();
    let epoch = installation.begin().unwrap();
    let lease = HolderLease::acquire(&root, key, epoch.generation()).unwrap();
    let (child, parent_lease) = spawn_with_resource_lease(command, lease).unwrap();
    let mut child = OriginalChild(child);
    drop(helper);
    let deadline = Instant::now() + Duration::from_secs(5);
    let prepare = PrepareOwnedV1 {
        owner: MailboxWorkerOwner {
            daemon_boot_nonce: [1; 32],
            lease: [2; 32],
            generation: 1,
            context_commitment: [3; 32],
        },
        grant,
        socket: config.socket.clone(),
        route: if mismatch {
            HostDialRoute::Mux(state.path().join("guest.sock"))
        } else {
            route
        },
        vm_state_dir: state.path().to_owned(),
        expected_parent: std::process::id(),
    };
    write_prepare(&parent, &prepare, deadline).unwrap();
    let mut input = child.0.stdin.take().unwrap();
    serde_json::to_writer(&mut input, &config).unwrap();
    input.flush().unwrap();
    drop(input);
    let status = read_ready(&parent, &prepare.owner, deadline);
    if mismatch {
        assert_eq!(status.unwrap_err().to_string(), "owned helper failed");
        assert!(!config.socket.exists());
    } else {
        status.unwrap();
        independent_counts = Some(transfer(
            &config.socket,
            &state.path().join("guest.sock"),
            deadline,
        ));
        assert!(
            mailbox_service::recv(&config.socket)
                .unwrap()
                .message
                .is_none()
        );
    }
    // Keep the state directory and launcher alive. FD3 closure alone must stop serving.
    drop(parent);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "helper failed to exit after owner closed"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.success(), !mismatch);
    if measured {
        let report = mailbox_service::guest_io::receive_original(&reader, &prepare.owner).unwrap();
        let (written, read) = independent_counts.unwrap();
        assert!(written > 0 && read > 0);
        assert_eq!(
            (
                report.guest_to_host_read_bytes,
                report.host_to_guest_write_accepted_bytes
            ),
            (written, read)
        );
        assert!(!report.overflow);
    }
    drop(parent_lease);
    installation.finish(epoch).unwrap();
    assert!(!config.socket.exists());
}

#[test]
fn owned_mailbox_binds_reports_ready_and_retires_on_parent_eof() {
    run(false, false);
}

#[test]
fn owned_mailbox_refuses_mismatched_backend_route_before_bind() {
    run(true, false);
}

#[test]
fn original_helper_post_io_matches_independent_guest_meter_and_excludes_host_receive() {
    run(false, true);
}
