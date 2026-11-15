use super::*;
use std::{fs, io::Read, os::unix::fs::PermissionsExt as _, path::PathBuf};

struct Fixture {
    home: tempfile::TempDir,
    parent: PathBuf,
    state: PathBuf,
    parent_file: File,
    state_file: File,
}
impl Fixture {
    fn new() -> Self {
        let home = tempfile::Builder::new()
            .prefix("runtime-state-protection-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let parent = home.path().join("vms");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let state = parent.join("synthetic");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let parent_file = File::open(&parent).unwrap();
        let state_file = File::open(&state).unwrap();
        Self {
            home,
            parent,
            state,
            parent_file,
            state_file,
        }
    }
    fn acquire(&self) -> io::Result<RuntimeStateProtection> {
        RuntimeStateProtection::acquire(&self.parent, &self.parent_file)
    }
}

#[test]
fn clean_original_state_passes_without_changing_files() {
    let fixture = Fixture::new();
    fs::write(fixture.state.join("synthetic-console"), b"unchanged").unwrap();
    let guard = fixture.acquire().unwrap();
    guard
        .check_state(&fixture.state, &fixture.state_file)
        .unwrap();
    guard
        .check_removal_allowed(&fixture.state, &fixture.state_file)
        .unwrap();
    assert_eq!(
        fs::read(fixture.state.join("synthetic-console")).unwrap(),
        b"unchanged"
    );
}

#[test]
fn independent_same_process_open_cannot_bypass_lock() {
    let fixture = Fixture::new();
    let original = fixture.acquire().unwrap();
    assert_eq!(
        fixture.acquire().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    original
        .check_state(&fixture.state, &fixture.state_file)
        .unwrap();
    drop(original);
    fixture
        .acquire()
        .unwrap()
        .check_state(&fixture.state, &fixture.state_file)
        .unwrap();
}

#[test]
fn telemetry_or_markers_refuse_even_without_a_valid_retention_marker() {
    for name in [
        RETAINED_TELEMETRY_MARKER_FILE,
        TELEMETRY_RECORDS_FILE,
        TELEMETRY_RECORDS_KEY_FILE,
        TELEMETRY_COLLECTOR_STATUS_FILE,
        crate::host_lifetime::INSTALLED_NATIVE_CUSTODY_MARKER,
    ] {
        let fixture = Fixture::new();
        let guard = fixture.acquire().unwrap();
        let entry = fixture.state.join(name);
        fs::write(&entry, b"synthetic malformed retained evidence").unwrap();
        assert!(
            guard
                .check_removal_allowed(&fixture.state, &fixture.state_file)
                .is_err()
        );
        assert_eq!(
            fs::read(entry).unwrap(),
            b"synthetic malformed retained evidence"
        );
    }
}

#[test]
fn malformed_evidence_symlink_and_directory_are_also_denials() {
    for directory in [false, true] {
        let fixture = Fixture::new();
        let guard = fixture.acquire().unwrap();
        let evidence = fixture.state.join(TELEMETRY_RECORDS_FILE);
        if directory {
            fs::create_dir(&evidence).unwrap();
        } else {
            std::os::unix::fs::symlink("missing", &evidence).unwrap();
        }
        assert!(
            guard
                .check_removal_allowed(&fixture.state, &fixture.state_file)
                .is_err()
        );
        assert!(fs::symlink_metadata(evidence).is_ok());
    }
}

#[test]
fn replacement_state_is_refused_before_removal() {
    let fixture = Fixture::new();
    let guard = fixture.acquire().unwrap();
    fs::rename(&fixture.state, fixture.parent.join("original")).unwrap();
    fs::create_dir(&fixture.state).unwrap();
    fs::write(fixture.state.join("foreign"), b"keep replacement").unwrap();
    assert!(
        guard
            .check_state(&fixture.state, &fixture.state_file)
            .is_err()
    );
    assert_eq!(
        fs::read(fixture.state.join("foreign")).unwrap(),
        b"keep replacement"
    );
}

#[test]
fn replaced_parent_and_lock_are_refused() {
    let fixture = Fixture::new();
    let guard = fixture.acquire().unwrap();
    fs::rename(&fixture.parent, fixture.home.path().join("original-parent")).unwrap();
    fs::create_dir(&fixture.parent).unwrap();
    assert!(
        guard
            .check_state(&fixture.state, &fixture.state_file)
            .is_err()
    );
    assert!(fixture.acquire().is_err());

    let fixture = Fixture::new();
    let guard = fixture.acquire().unwrap();
    fs::remove_file(fixture.parent.join(RUNTIME_STATE_PROTECTION_LOCK_FILE)).unwrap();
    fs::write(
        fixture.parent.join(RUNTIME_STATE_PROTECTION_LOCK_FILE),
        b"replacement",
    )
    .unwrap();
    assert!(
        guard
            .check_state(&fixture.state, &fixture.state_file)
            .is_err()
    );
}

#[test]
fn lock_symlink_hardlink_mode_and_type_are_not_adopted() {
    for kind in 0..4 {
        let fixture = Fixture::new();
        let lock = fixture.parent.join(RUNTIME_STATE_PROTECTION_LOCK_FILE);
        match kind {
            0 => std::os::unix::fs::symlink("absent", &lock).unwrap(),
            1 => {
                let original = fixture.home.path().join("original-lock");
                fs::write(&original, b"").unwrap();
                fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
                fs::hard_link(original, &lock).unwrap();
            }
            2 => {
                fs::write(&lock, b"").unwrap();
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
            }
            3 => fs::create_dir(&lock).unwrap(),
            _ => unreachable!(),
        }
        assert!(fixture.acquire().is_err(), "invalid lock was adopted");
        assert!(fs::symlink_metadata(lock).is_ok());
    }
}

#[test]
fn writable_parent_or_state_refuses_without_chmod() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(fixture.acquire().is_err());
    assert_eq!(
        fs::metadata(&fixture.parent).unwrap().permissions().mode() & 0o777,
        0o777
    );
    fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(0o755)).unwrap();
    let guard = fixture.acquire().unwrap();
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        guard
            .check_state(&fixture.state, &fixture.state_file)
            .is_err()
    );
}

#[test]
fn fresh_check_detects_marker_published_after_initial_check() {
    let fixture = Fixture::new();
    let guard = fixture.acquire().unwrap();
    guard
        .check_removal_allowed(&fixture.state, &fixture.state_file)
        .unwrap();
    fs::write(
        fixture.state.join(RETAINED_TELEMETRY_MARKER_FILE),
        b"synthetic",
    )
    .unwrap();
    assert!(
        guard
            .check_removal_allowed(&fixture.state, &fixture.state_file)
            .is_err()
    );
}

#[test]
fn independent_original_child_is_denied_while_guard_is_held() {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    use std::process::{Command, Stdio};
    use std::time::Duration;
    let fixture = Fixture::new();
    let guard = fixture.acquire().unwrap();
    let (mut reader, writer) = UnixStream::pair().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "runtime_state_protection::tests::lock_contention_child",
            "--exact",
            "--nocapture",
        ])
        .env("MVM_STATE_PROTECTION_TEST_PARENT", &fixture.parent)
        .stdout(Stdio::from(OwnedFd::from(writer)));
    let mut child = command.spawn().unwrap();
    drop(command);
    let mut output = Vec::new();
    if let Err(error) = reader.read_to_end(&mut output) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("original contention child did not finish: {error}");
    }
    assert!(
        child.wait().unwrap().success(),
        "{}",
        String::from_utf8_lossy(&output)
    );
    guard
        .check_state(&fixture.state, &fixture.state_file)
        .unwrap();
}

#[test]
fn lock_contention_child() {
    let Some(parent) = std::env::var_os("MVM_STATE_PROTECTION_TEST_PARENT") else {
        return;
    };
    let path = PathBuf::from(parent);
    let original = File::open(&path).unwrap();
    assert_eq!(
        RuntimeStateProtection::acquire(&path, &original)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn exact_absence_is_distinct_from_replacement_or_symlink() {
    let fixture = Fixture::new();
    let guard = fixture.acquire().unwrap();
    assert!(guard.check_missing_state(&fixture.state).is_err());
    let absent = fixture.parent.join("absent");
    guard.check_missing_state(&absent).unwrap();
    std::os::unix::fs::symlink("missing", &absent).unwrap();
    assert!(guard.check_missing_state(&absent).is_err());
    assert!(
        guard
            .check_missing_state(&fixture.parent.join("../escape"))
            .is_err()
    );
}
