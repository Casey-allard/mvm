//! Actual-child parent ownership tests. The fixture does NOT qualify inherited
//! CLI lease handoff or host-crash recovery; that requires the real CLI adapter.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mvm_hostd::watcher_jobs::WatcherJobOwner;
use mvm_vmm::host::installed_owner::{HolderLease, InstallationKey, InstallationOwner};

fn private_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let initial = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
    eprintln!("WATCHER_FIXTURE_INITIAL_MODE={initial:o}");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    dir
}

struct ReleaseFixture(PathBuf);
impl Drop for ReleaseFixture {
    fn drop(&mut self) {
        let _ = fs::write(&self.0, b"release");
    }
}
fn fixture_command(ready: &Path, release: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "watcher_job_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MVM_WATCHER_JOB_READY", ready)
        .env("MVM_WATCHER_JOB_RELEASE", release)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}
fn wait_ready(ready: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = fs::read_to_string(ready)
            && let Ok(pid) = text.parse()
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "actual fixture did not become ready"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn original_job_slot_survives_timeout_and_stop_until_child_collection() {
    let dir = private_fixture();
    let root = dir.path().join("owner");
    let key = InstallationKey {
        installation: [21; 32],
        profile: [22; 32],
    };
    let mut installation = InstallationOwner::initialize(&root, key).unwrap();
    let epoch = installation.begin().unwrap();
    let lease = || HolderLease::acquire(&root, key, epoch.generation()).unwrap();
    let ready = dir.path().join("ready");
    let release = dir.path().join("release");
    let release_fixture = ReleaseFixture(release.clone());
    let jobs = WatcherJobOwner::new();
    assert!(!jobs.has_inflight_job().unwrap());
    jobs.try_spawn(fixture_command(&ready, &release), lease())
        .unwrap();
    let pid = wait_ready(&ready);
    assert!(jobs.has_inflight_job().unwrap());
    let rejected = dir.path().join("rejected-ready");
    assert!(
        jobs.try_spawn(fixture_command(&rejected, &release), lease())
            .is_err()
    );
    assert!(
        !rejected.exists(),
        "busy slot must refuse before a second spawn"
    );
    jobs.request_stop();
    assert!(
        jobs.drain(Some(Instant::now() + Duration::from_millis(20)))
            .is_err()
    );
    assert!(jobs.has_inflight_job().unwrap());
    assert!(
        installation.finish(epoch).is_err(),
        "timeout must retain the job's parent-held SH lease"
    );
    assert!(!rejected.exists());
    drop(release_fixture);
    let receipt = jobs
        .drain(Some(Instant::now() + Duration::from_secs(10)))
        .unwrap();
    assert_eq!(
        receipt.collected_jobs(),
        1,
        "receipt requires original Child collection"
    );
    assert_eq!(receipt.spawn_failures(), 0);
    assert!(!jobs.has_inflight_job().unwrap());
    #[cfg(target_os = "linux")]
    assert!(
        !PathBuf::from(format!("/proc/{pid}/stat")).exists(),
        "collected fixture must not remain a zombie"
    );
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
    assert!(
        jobs.try_spawn(fixture_command(&rejected, &release), lease())
            .is_err()
    );
    assert!(
        !rejected.exists(),
        "stopped job owner must never restart work"
    );
    installation.finish(epoch).unwrap();
}

#[test]
fn watcher_job_fixture() {
    let Some(ready) = std::env::var_os("MVM_WATCHER_JOB_READY") else {
        return;
    };
    let release = PathBuf::from(std::env::var_os("MVM_WATCHER_JOB_RELEASE").unwrap());
    fs::write(ready, std::process::id().to_string()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !release.exists() {
        assert!(Instant::now() < deadline, "fixture release deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn isolated_guard_error_retains_original_job_and_lease() {
    run_guard_fixture(false);
}

#[test]
fn explicit_retry_collects_same_original_job_after_guard_restore() {
    run_guard_fixture(true);
}

fn run_guard_fixture(retry: bool) {
    let dir = private_fixture();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "guard_error_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MVM_WATCHER_GUARD_DIR", dir.path())
        .env("MVM_WATCHER_RETRY", if retry { "1" } else { "0" })
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated guard fixture failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let marker = if retry {
        "WATCHER_GUARD_RETRY_SAME_CHILD_COLLECTED"
    } else {
        "WATCHER_GUARD_REFUSED_RESTORED_UNCOLLECTED"
    };
    assert!(String::from_utf8_lossy(&output.stderr).contains(marker));
    eprintln!("{marker}");
}

#[test]
fn guard_error_fixture() {
    let Some(base) = std::env::var_os("MVM_WATCHER_GUARD_DIR") else {
        return;
    };
    let base = PathBuf::from(base);
    let root = base.join("guard-owner");
    let key = InstallationKey {
        installation: [31; 32],
        profile: [32; 32],
    };
    let mut installation = InstallationOwner::initialize(&root, key).unwrap();
    let epoch = installation.begin().unwrap();
    let lease = HolderLease::acquire(&root, key, epoch.generation()).unwrap();
    let ready = base.join("guard-ready");
    let release = base.join("guard-release");
    let release_fixture = ReleaseFixture(release.clone());
    let jobs = WatcherJobOwner::new();
    jobs.try_spawn(fixture_command(&ready, &release), lease)
        .unwrap();
    let original_pid = wait_ready(&ready);
    struct Restore(libc::sigaction);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: only the dedicated exec fixture changes its disposition;
            // restore the exact queried original action before this test exits.
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGCHLD, &self.0, std::ptr::null_mut()) },
                0
            );
        }
    }
    extern "C" fn no_reaper(_: libc::c_int) {}
    // SAFETY: this test branch is separately exec'd and owns its signal state.
    // The no-op handler does not reap, ignore children, or set SA_NOCLDWAIT.
    let restore = unsafe {
        let mut previous = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        assert_eq!(
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), previous.as_mut_ptr()),
            0
        );
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = no_reaper as *const () as libc::sighandler_t;
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(
            libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()),
            0
        );
        Restore(previous.assume_init())
    };
    assert!(mvm_vmm::host::process_exit::require_owned_child_custody().is_err());
    drop(release_fixture);
    jobs.request_stop();
    let deadline = Instant::now() + Duration::from_secs(10);
    assert_eq!(
        jobs.drain(Some(deadline)).unwrap_err(),
        mvm_hostd::watcher_jobs::WatcherDrainError::Unresolved
    );
    assert!(
        jobs.has_inflight_job().unwrap(),
        "unresolved child is still inflight, never idle"
    );
    assert!(
        installation.finish(epoch).is_err(),
        "guard failure must retain the original parent lease"
    );
    drop(restore);
    mvm_vmm::host::process_exit::require_owned_child_custody().unwrap();
    if std::env::var("MVM_WATCHER_RETRY").as_deref() == Ok("1") {
        jobs.retry_cleanup().unwrap();
        let receipt = jobs.drain(Some(deadline)).unwrap();
        assert_eq!(receipt.collected_jobs(), 1);
        assert_eq!(receipt.spawn_failures(), 0);
        assert!(!jobs.has_inflight_job().unwrap());
        assert_eq!(
            fs::read_to_string(&ready).unwrap(),
            original_pid.to_string(),
            "retry must not launch a replacement fixture"
        );
        #[cfg(target_os = "linux")]
        assert!(
            !PathBuf::from(format!("/proc/{original_pid}/stat")).exists(),
            "original fixture must actually be collected"
        );
        installation.finish(epoch).unwrap();
        eprintln!("WATCHER_GUARD_RETRY_SAME_CHILD_COLLECTED");
        return;
    }
    // This first component witness intentionally does not claim retry or child
    // collection. The fixture process exits with retained custody; its parent
    // collects that fixture before removing the owned temporary namespace.
    eprintln!("WATCHER_GUARD_REFUSED_RESTORED_UNCOLLECTED");
}
