#![cfg(target_os = "linux")]

use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
        io::AsRawFd,
    },
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "mvm-host-lease-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let mut state = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(root.join("state.bin"))
            .unwrap();
        state.write_all(b"abc").unwrap();
        drop(
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(root.join("holders.lock"))
                .unwrap(),
        );
        Self { root }
    }
    fn files(&self) -> (File, File) {
        (
            File::open(&self.root).unwrap(),
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.root.join("holders.lock"))
                .unwrap(),
        )
    }
    fn bind(&self) -> anyhow::Result<PreparedHostLifetimeLease> {
        let (directory, holder) = self.files();
        PreparedHostLifetimeLease::bind(directory, holder, expected())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn expected() -> HostLeaseExpectation {
    // SHA-256 of the three public fixture bytes, not a credential.
    HostLeaseExpectation {
        state_name: "state.bin".into(),
        state_bytes: 3,
        state_sha256: [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
        absent_names: [".state.intent".into(), ".state.next".into()],
    }
}
fn try_ex(file: &File) -> bool {
    // SAFETY: borrowed live fixture FD; nonblocking acquisition has no wait.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        true
    } else {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
        false
    }
}

#[test]
fn bind_pins_the_original_holder_description_instead_of_its_replaced_path() {
    let fixture = Fixture::new();
    let (_, original) = fixture.files();
    let lease = fixture.bind().unwrap();
    fs::rename(
        fixture.root.join("holders.lock"),
        fixture.root.join("original-holder"),
    )
    .unwrap();
    let replacement = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(fixture.root.join("holders.lock"))
        .unwrap();
    assert!(!try_ex(&original));
    assert!(try_ex(&replacement));
    drop(lease);
    assert!(try_ex(&original));
}

#[test]
fn bind_refuses_invalid_expectations_modes_and_nonregular_resources() {
    for name in [
        "".to_owned(),
        ".".into(),
        "..".into(),
        "a/b".into(),
        "a b".into(),
        "a;id".into(),
        "é".into(),
        "x".repeat(65),
    ] {
        let fixture = Fixture::new();
        let (directory, holder) = fixture.files();
        let mut expectation = expected();
        expectation.state_name = name.clone();
        assert!(
            PreparedHostLifetimeLease::bind(directory, holder, expectation).is_err(),
            "name={name:?}"
        );
    }
    for case in [
        "zero-length",
        "oversized",
        "duplicate-marker",
        "state-is-marker",
        "invalid-marker",
        "directory-mode",
        "holder-mode",
        "regular-directory",
        "directory-holder",
    ] {
        let fixture = Fixture::new();
        let (mut directory, mut holder) = fixture.files();
        let mut expectation = expected();
        match case {
            "zero-length" => expectation.state_bytes = 0,
            "oversized" => expectation.state_bytes = 4097,
            "duplicate-marker" => expectation.absent_names[1] = expectation.absent_names[0].clone(),
            "state-is-marker" => expectation.absent_names[0] = expectation.state_name.clone(),
            "invalid-marker" => expectation.absent_names[0] = "../escape".into(),
            "directory-mode" => {
                fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o750)).unwrap()
            }
            "holder-mode" => holder
                .set_permissions(fs::Permissions::from_mode(0o640))
                .unwrap(),
            "regular-directory" => directory = holder.try_clone().unwrap(),
            "directory-holder" => holder = directory.try_clone().unwrap(),
            _ => unreachable!(),
        }
        assert!(
            PreparedHostLifetimeLease::bind(directory, holder, expectation).is_err(),
            "{case}"
        );
    }
    let fixture = Fixture::new();
    let (directory, holder) = fixture.files();
    let mut expectation = expected();
    expectation.state_name = "x".repeat(64);
    expectation.state_bytes = 4096;
    drop(PreparedHostLifetimeLease::bind(directory, holder, expectation).unwrap());
}

const CHILD_MODE: &str = "MVM_HOST_LEASE_TEST_TARGET";
const WATCHDOG: Duration = Duration::from_secs(5);
struct Target {
    child: Child,
    input: ChildStdin,
    events: mpsc::Receiver<String>,
    reader: Option<JoinHandle<()>>,
    reaped: bool,
}
impl Target {
    fn spawn(fixture: &Fixture, lease: &PreparedHostLifetimeLease) -> Self {
        let target_test = format!(
            "{}::fake_exec_target",
            module_path!().split_once("::").unwrap().1
        );
        let script = format!(
            "set -euo pipefail\n{}\nexec \"$1\" --exact \"$2\" --nocapture --test-threads=1\n",
            preflight(lease)
        );
        let mut child = Command::new("/bin/bash")
            .args(["-c", &script, "host-lease-test"])
            .arg(std::env::current_exe().unwrap())
            .arg(target_test)
            .env(CHILD_MODE, fixture.root.join("target-executed"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (send, events) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if let Some(start) = line.find("EVENT ")
                    && send.try_send(line[start..].to_owned()).is_err()
                {
                    return;
                }
            }
            let _ = send.try_send("EVENT EOF".into());
        });
        Self {
            child,
            input,
            events,
            reader: Some(reader),
            reaped: false,
        }
    }
    fn event(&self, expected: &str) {
        assert_eq!(
            self.events
                .recv_timeout(WATCHDOG)
                .expect("owned target watchdog"),
            expected
        );
    }
    fn finish(mut self, accepted: bool) {
        if accepted {
            self.input.write_all(b"exit\n").unwrap();
            self.input.flush().unwrap();
            self.event("EVENT EXIT");
        }
        self.event("EVENT EOF");
        let status = self.child.wait().unwrap();
        self.reaped = true;
        assert_eq!(status.success(), accepted, "fixed preflight exit: {status}");
        self.reader.take().unwrap().join().unwrap();
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn fake_exec_target() {
    let Some(marker) = std::env::var_os(CHILD_MODE) else {
        return;
    };
    let mut marker = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(marker)
        .unwrap();
    marker.write_all(b"executed").unwrap();
    println!("EVENT READY");
    std::io::stdout().flush().unwrap();
    let mut command = String::new();
    std::io::stdin().read_line(&mut command).unwrap();
    assert_eq!(command, "exit\n");
    println!("EVENT EXIT");
    std::io::stdout().flush().unwrap();
}

#[test]
fn fixed_preflight_retains_original_sh_through_exec_after_parent_lease_drop() {
    let fixture = Fixture::new();
    let (_, original) = fixture.files();
    let lease = fixture.bind().unwrap();
    let target = Target::spawn(&fixture, &lease);
    target.event("EVENT READY");
    assert_eq!(
        fs::read(fixture.root.join("target-executed")).unwrap(),
        b"executed"
    );
    drop(lease);
    assert!(
        !try_ex(&original),
        "the actual exec target must retain SH without the parent lease"
    );
    target.finish(true);
    assert!(try_ex(&original));
}

#[test]
fn fixed_preflight_refuses_stale_state_and_markers_before_any_target_exec() {
    for case in [
        "hash",
        "length",
        "intent",
        "dangling-next",
        "state-symlink",
        "state-mode",
    ] {
        let fixture = Fixture::new();
        let lease = fixture.bind().unwrap();
        match case {
            "hash" => fs::write(fixture.root.join("state.bin"), b"abd").unwrap(),
            "length" => fs::write(fixture.root.join("state.bin"), b"abcd").unwrap(),
            "intent" => fs::write(fixture.root.join(".state.intent"), b"").unwrap(),
            "dangling-next" => symlink("missing", fixture.root.join(".state.next")).unwrap(),
            "state-symlink" => {
                fs::rename(
                    fixture.root.join("state.bin"),
                    fixture.root.join("saved-state"),
                )
                .unwrap();
                symlink("saved-state", fixture.root.join("state.bin")).unwrap();
            }
            "state-mode" => fs::set_permissions(
                fixture.root.join("state.bin"),
                fs::Permissions::from_mode(0o640),
            )
            .unwrap(),
            _ => unreachable!(),
        }
        Target::spawn(&fixture, &lease).finish(false);
        assert!(!fixture.root.join("target-executed").exists(), "{case}");
    }
}
