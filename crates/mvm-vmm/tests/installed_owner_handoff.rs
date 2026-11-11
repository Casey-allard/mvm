#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mvm_vmm::host::installed_owner::{
    HolderLease, InstallationKey, InstallationOwner, OwnerError, receive_resource_lease_at_startup,
    spawn_with_resource_lease,
};

const MARKER: &str = "MVM_RESOURCE_LEASE_V1";
const FIXTURE: &str = "MVM_RESOURCE_LEASE_TEST_CHILD";
const WATCHDOG: Duration = Duration::from_secs(10);

fn key() -> InstallationKey {
    InstallationKey {
        installation: [0x35; 32],
        profile: [0x61; 32],
    }
}

struct OwnedFixture {
    child: Child,
    input: Option<ChildStdin>,
    reader: Option<std::thread::JoinHandle<()>>,
    events: mpsc::Receiver<String>,
    collected: bool,
}

impl OwnedFixture {
    fn start(lease: HolderLease) -> (Self, HolderLease) {
        Self::start_with_fault(lease, None, None)
    }

    fn start_with_fault(
        lease: HolderLease,
        fault: Option<&str>,
        foreign_lock: Option<&std::fs::File>,
    ) -> (Self, HolderLease) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "handoff_runtime_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(FIXTURE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(fault) = fault {
            command.env("MVM_RESOURCE_LEASE_TEST_FAULT", fault);
        }
        if let Some(file) = foreign_lock {
            command.env(
                "MVM_RESOURCE_LEASE_TEST_FOREIGN_FD",
                file.as_raw_fd().to_string(),
            );
            mvm_vmm::host::restore_image::inherit_descriptors(&mut command, vec![file.as_raw_fd()]);
        }
        let (mut child, parent_lease) = spawn_with_resource_lease(command, lease).unwrap();
        let input = child.stdin.take();
        let output = child.stdout.take().unwrap();
        let (send, events) = mpsc::sync_channel(4);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else {
                    break;
                };
                if let Some(at) = line.find("LEASE_EVENT ") {
                    let _ = send.try_send(line[at..].to_owned());
                }
            }
        });
        (
            Self {
                child,
                input,
                reader: Some(reader),
                events,
                collected: false,
            },
            parent_lease,
        )
    }

    fn event(&self, expected: &str) {
        assert_eq!(self.next_event(), expected);
    }

    fn next_event(&self) -> String {
        self.events.recv_timeout(WATCHDOG).unwrap()
    }

    fn finish(&mut self) {
        self.input.take();
        let deadline = Instant::now() + WATCHDOG;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.collected = true;
                assert!(status.success(), "fixture failed: {status}");
                break;
            }
            assert!(Instant::now() < deadline, "fixture collection watchdog");
            std::thread::yield_now();
        }
        self.reader.take().unwrap().join().unwrap();
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        self.input.take();
        if !self.collected {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn handoff_runtime_entry() {
    if std::env::var_os(FIXTURE).is_none() {
        return;
    }
    let mut metadata: serde_json::Value =
        serde_json::from_str(&std::env::var(MARKER).unwrap()).unwrap();
    let original_directory = metadata["directory_fd"].as_i64().unwrap() as i32;
    let original_holder = metadata["holder_fd"].as_i64().unwrap() as i32;
    let fault = std::env::var("MVM_RESOURCE_LEASE_TEST_FAULT").ok();
    if let Some(fault) = &fault {
        match fault.as_str() {
            "version" => metadata["version"] = 2.into(),
            "epoch" => {
                metadata["generation"] = metadata["generation"]
                    .as_u64()
                    .unwrap()
                    .checked_add(1)
                    .unwrap()
                    .into()
            }
            "standard-stream" => metadata["holder_fd"] = 1.into(),
            "aliased-descriptors" => metadata["holder_fd"] = original_directory.into(),
            "foreign-lock" => {
                metadata["holder_fd"] = std::env::var("MVM_RESOURCE_LEASE_TEST_FOREIGN_FD")
                    .unwrap()
                    .parse::<i32>()
                    .unwrap()
                    .into()
            }
            "same-inode-ex" => {}
            "wrong-digest" => {
                metadata["state_sha256"][0] =
                    ((metadata["state_sha256"][0].as_u64().unwrap() + 1) & 255).into()
            }
            "wrong-installation" => metadata["installation"][0] = 0.into(),
            "unknown-field" => metadata["unexpected"] = true.into(),
            "oversized" => metadata["unexpected"] = "x".repeat(8192).into(),
            _ => panic!("unknown test fault"),
        }
        // SAFETY: this isolated exact fixture has no concurrent environment use.
        unsafe { std::env::set_var(MARKER, serde_json::to_string(&metadata).unwrap()) };
    }
    // SAFETY: this separately exec'd, exactly selected fixture has no other
    // environment readers or writers; the inherited descriptors have no owners
    // in this fresh process. No subprocess is started before adoption.
    let received = unsafe { receive_resource_lease_at_startup() };
    if fault.is_some() {
        if fault.as_deref() == Some("same-inode-ex") && received.is_ok() {
            assert!(std::env::var_os(MARKER).is_none());
            println!("LEASE_EVENT UNEXPECTEDLY_ACCEPTED");
            std::io::stdout().flush().unwrap();
            return;
        }
        assert!(received.is_err(), "malformed handoff must refuse startup");
        assert!(std::env::var_os(MARKER).is_none());
        println!("LEASE_EVENT REFUSED");
        std::io::stdout().flush().unwrap();
        return;
    }
    let lease = received.unwrap().unwrap();
    assert!(std::env::var_os(MARKER).is_none());
    for fd in [original_directory, original_holder] {
        // SAFETY: F_GETFD only checks whether the consumed descriptor is open.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    }
    let handoff = lease.prepare_handoff().unwrap();
    for fd in [handoff.directory.as_raw_fd(), handoff.holder.as_raw_fd()] {
        // SAFETY: these borrowed descriptors remain owned by the live handoff.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    drop(handoff);
    println!("LEASE_EVENT HELD");
    std::io::stdout().flush().unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
    drop(lease);
    println!("LEASE_EVENT RELEASED");
    std::io::stdout().flush().unwrap();
}

#[test]
fn actual_child_retains_its_own_epoch_after_parent_guard_drops() {
    let base = tempfile::tempdir().unwrap();
    std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.path().join("resources");
    let mut owner = InstallationOwner::initialize(&root, key()).unwrap();
    let epoch = owner.begin().unwrap();
    let lease = HolderLease::acquire(&root, key(), epoch.generation()).unwrap();
    let (mut fixture, parent_lease) = OwnedFixture::start(lease);
    fixture.event("LEASE_EVENT HELD");
    drop(parent_lease);
    assert!(
        matches!(owner.finish(epoch), Err(OwnerError::Busy)),
        "actual child must block retirement"
    );
    fixture.finish();
    fixture.event("LEASE_EVENT RELEASED");
    owner.finish(epoch).unwrap();
}

#[test]
fn malformed_handoff_refuses_before_work_and_never_releases_parent_lease() {
    for fault in [
        "version",
        "epoch",
        "standard-stream",
        "aliased-descriptors",
        "foreign-lock",
        "same-inode-ex",
        "wrong-digest",
        "wrong-installation",
        "unknown-field",
        "oversized",
    ] {
        let base = tempfile::tempdir().unwrap();
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.path().join("resources");
        let mut owner = Some(InstallationOwner::initialize(&root, key()).unwrap());
        let epoch = owner.as_mut().unwrap().begin().unwrap();
        let lease = HolderLease::acquire(&root, key(), epoch.generation()).unwrap();
        let same_inode_ex_pin = (fault == "same-inode-ex").then(|| {
            // Remove only the owner's independently opened supervisor SH. The
            // original typed lease and its exported holder are aliases of one
            // open description, which the parent now pins EX until collection.
            drop(owner.take());
            let handoff = lease.prepare_handoff().unwrap();
            handoff.holder.try_lock().unwrap();
            handoff
        });
        let foreign_path = base.path().join("foreign.lock");
        let foreign_lock = (fault == "foreign-lock").then(|| {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&foreign_path)
                .unwrap();
            file.try_lock().unwrap();
            file
        });
        let (mut fixture, parent_lease) =
            OwnedFixture::start_with_fault(lease, Some(fault), foreign_lock.as_ref());
        let same_inode_event = if same_inode_ex_pin.is_some() {
            Some(fixture.next_event())
        } else {
            fixture.event("LEASE_EVENT REFUSED");
            None
        };
        fixture.finish();
        if let Some(event) = &same_inode_event {
            eprintln!("same-inode-ex: child outcome={event}");
        }
        if foreign_lock.is_some() || same_inode_ex_pin.is_some() {
            let probe_path = if same_inode_ex_pin.is_some() {
                root.join("holders.lock")
            } else {
                foreign_path.clone()
            };
            let probe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(probe_path)
                .unwrap();
            // SAFETY: this freshly opened probe is independently owned. The
            // parent's EX descriptor remains live; a refused child must not
            // downgrade the inherited shared open-description lock at all.
            let result = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
            let probe_error = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(
                result, -1,
                "{fault}: receiver changed the parent's original EX lock"
            );
            assert_eq!(probe_error, Some(libc::EWOULDBLOCK));
        }
        if let Some(event) = same_inode_event {
            assert_eq!(
                event, "LEASE_EVENT REFUSED",
                "same-inode EX cannot admit a fresh independent SH"
            );
        }
        if let Some(owner) = owner.as_mut() {
            assert!(
                matches!(owner.finish(epoch), Err(OwnerError::Busy)),
                "{fault} released the original parent lease"
            );
        }
        drop(parent_lease);
        if let Some(owner) = owner.as_mut() {
            owner.finish(epoch).unwrap();
        }
        drop(foreign_lock);
        drop(same_inode_ex_pin);
    }
}
