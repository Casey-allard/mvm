#![cfg(unix)]

use mvm_core::host_lifetime::{HostLeaseExpectation, PreparedHostLifetimeLease};
use mvm_hostd::supervisor::caller_registration::{adopt_startup_files, preflight_startup_files};
use mvm_vmm::host::hvf_supervisor::{HostLifetimeFds, HvfSupervisorConfig};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, IntoRawFd},
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
};

fn config() -> HvfSupervisorConfig {
    serde_json::from_value(serde_json::json!({
        "console_capture":"encrypted", "vm_name":"installed-fd-unit",
        "kernel":"/unused/kernel", "console_log":"/unused/console",
        "pid_file":"/unused/pid", "workload_exit":"/unused/exit", "timeout_secs":0
    }))
    .unwrap()
}

#[test]
fn original_hvf_holder_adoption_keeps_same_shared_lock_and_refuses_alias_before_ownership() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.path().join(".state"), b"a").unwrap();
    std::fs::set_permissions(
        root.path().join(".state"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let holder_path = root.path().join("holders.lock");
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&holder_path)
        .unwrap();
    let original = PreparedHostLifetimeLease::bind(
        File::open(root.path()).unwrap(),
        holder,
        HostLeaseExpectation {
            state_name: ".state".into(),
            state_bytes: 1,
            state_sha256: hex::decode(
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            absent_names: [".state.intent".into(), ".state.next".into()],
        },
    )
    .unwrap();
    let directory = original.directory().try_clone().unwrap();
    let holder = original.holder().try_clone().unwrap();
    let mut cfg = config();
    cfg.host_lifetime_fds = Some(HostLifetimeFds {
        directory: directory.as_raw_fd(),
        holder: directory.as_raw_fd(),
        expected: original.expectation().clone(),
    });
    assert!(preflight_startup_files(&cfg).is_err());
    assert!(
        directory.metadata().unwrap().is_dir(),
        "refusal must not adopt/close aliases"
    );
    cfg.host_lifetime_fds = Some(HostLifetimeFds {
        directory: directory.into_raw_fd(),
        holder: holder.into_raw_fd(),
        expected: original.expectation().clone(),
    });
    let mut files = adopt_startup_files(&cfg).unwrap();
    let inherited = files.take_host_lifetime().unwrap();
    assert_eq!(inherited.holder_object_id(), original.holder_object_id());
    inherited.verify_current().unwrap();
    assert!(files.take_host_lifetime().is_none());
    drop(original);
    let independent = OpenOptions::new()
        .read(true)
        .write(true)
        .open(holder_path)
        .unwrap();
    assert_ne!(
        unsafe { libc::flock(independent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    drop(inherited);
    assert_eq!(
        unsafe { libc::flock(independent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
}
