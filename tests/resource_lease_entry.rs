#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use mvm_vmm::host::installed_owner::{
    HolderLease, InstallationKey, InstallationOwner, spawn_with_resource_lease,
};

fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    home
}

fn version_command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mvmctl"));
    command
        .args(["--version"])
        .env("MVM_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn malformed_inherited_resource_metadata_refuses_before_cli_dispatch() {
    let home = private_home();
    let output = version_command(home.path())
        .env("MVM_RESOURCE_LEASE_V1", "{}")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "malformed handoff must refuse even --version dispatch"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid inherited resource lease"));
    assert!(output.stdout.is_empty());
}

#[test]
fn version_without_a_resource_handoff_preserves_normal_cli_behavior() {
    let home = private_home();
    let output = version_command(home.path())
        .env_remove("MVM_RESOURCE_LEASE_V1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("mvm"));
}

#[test]
fn actual_cli_accepts_and_releases_an_exact_typed_resource_handoff() {
    let home = private_home();
    let root = home.path().join("resource-owner");
    let key = InstallationKey {
        installation: [0x55; 32],
        profile: [0x67; 32],
    };
    let mut owner = InstallationOwner::initialize(&root, key).unwrap();
    let epoch = owner.begin().unwrap();
    let lease = HolderLease::acquire(&root, key, epoch.generation()).unwrap();
    let (child, parent_lease) =
        spawn_with_resource_lease(version_command(home.path()), lease).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("mvm"));
    drop(parent_lease);
    owner.finish(epoch).unwrap();
}
