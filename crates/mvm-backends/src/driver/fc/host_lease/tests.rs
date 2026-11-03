#![cfg(target_os = "linux")]

use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{atomic::{AtomicU64, Ordering}, mpsc},
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Fixture { root: PathBuf }
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!("mvm-host-lease-{}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let mut state = OpenOptions::new().create_new(true).write(true).mode(0o600).open(root.join("state.bin")).unwrap();
        state.write_all(b"abc").unwrap();
        drop(OpenOptions::new().create_new(true).read(true).write(true).mode(0o600).open(root.join("holders.lock")).unwrap());
        Self {root}
    }
    fn files(&self) -> (File, File) {
        (File::open(&self.root).unwrap(), OpenOptions::new().read(true).write(true).open(self.root.join("holders.lock")).unwrap())
    }
    fn bind(&self) -> anyhow::Result<PreparedHostLifetimeLease> {
        let (directory, holder) = self.files();
        PreparedHostLifetimeLease::bind(directory, holder, expected())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
}
fn expected() -> HostLeaseExpectation {
    // SHA-256 of the three public fixture bytes, not a credential.
    HostLeaseExpectation {
        state_name: "state.bin".into(), state_bytes: 3,
        state_sha256: [0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad],
        absent_names: [".state.intent".into(), ".state.next".into()],
    }
}
fn try_ex(file: &File) -> bool {
    // SAFETY: borrowed live fixture FD; nonblocking acquisition has no wait.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 { true } else {
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EWOULDBLOCK));
        false
    }
}

#[test]
fn bind_pins_the_original_holder_description_instead_of_its_replaced_path() {
    let fixture = Fixture::new();
    let (_, original) = fixture.files();
    let lease = fixture.bind().unwrap();
    fs::rename(fixture.root.join("holders.lock"), fixture.root.join("original-holder")).unwrap();
    let replacement = OpenOptions::new().create_new(true).read(true).write(true).mode(0o600).open(fixture.root.join("holders.lock")).unwrap();
    assert!(!try_ex(&original));
    assert!(try_ex(&replacement));
    drop(lease);
    assert!(try_ex(&original));
}
