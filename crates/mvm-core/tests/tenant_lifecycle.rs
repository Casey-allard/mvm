#![cfg(unix)]

use std::path::Path;
use std::time::{Duration, Instant};

use mvm_core::config;
use mvm_core::private_fs::create_owned_private_dir;
use mvm_core::tenant_lifecycle::TenantLifecycleGate;
use mvm_core::util::atomic_io::write_private;

fn tenant_dir(home: &Path) -> std::path::PathBuf {
    create_owned_private_dir(home).expect("private home");
    create_owned_private_dir(config::host_agent_root_at(home)).expect("private agent root");
    let dir = config::host_agent_dir_at(home, "tenant-a");
    create_owned_private_dir(&dir).expect("private tenant directory");
    write_private(&dir.join("lifecycle.lock"), b"").expect("private stable lock fixture");
    dir
}

fn reserve(home: &Path) -> anyhow::Result<()> {
    let gate = TenantLifecycleGate::new(home, "tenant-a")?;
    let _reservation = gate.reserve_launch(
        "vm-a",
        "plan-a",
        Instant::now() + Duration::from_millis(100),
    )?;
    Ok(())
}

#[test]
fn a_client_cannot_initialize_missing_lifecycle_as_active() {
    let home = tempfile::tempdir().expect("home");
    let dir = tenant_dir(home.path());
    assert!(reserve(home.path()).is_err());
    assert!(
        !dir.join("lifecycle.json").exists(),
        "a client reservation must never create an Active daemon generation"
    );
}

#[test]
fn malformed_and_oversize_lifecycle_metadata_never_become_zero_work() {
    let home = tempfile::tempdir().expect("home");
    let dir = tenant_dir(home.path());
    for bytes in [b"{".to_vec(), vec![b' '; 65_537]] {
        write_private(&dir.join("lifecycle.json"), &bytes).expect("fixture metadata");
        assert!(reserve(home.path()).is_err());
        assert_eq!(
            std::fs::read(dir.join("lifecycle.json")).expect("retained refusal evidence"),
            bytes,
            "malformed metadata must not be reset or repaired by a client"
        );
    }
}

#[test]
fn lifecycle_symlinks_are_refused_without_changing_the_target() {
    use std::os::unix::fs::symlink;

    let home = tempfile::tempdir().expect("home");
    let dir = tenant_dir(home.path());
    let target = home.path().join("foreign-state");
    write_private(&target, b"original").expect("target");
    symlink(&target, dir.join("lifecycle.json")).expect("symlink");
    assert!(reserve(home.path()).is_err());
    assert_eq!(
        std::fs::read(target).expect("target unchanged"),
        b"original"
    );
}

#[test]
fn tenant_path_components_cannot_select_another_gate() {
    let home = tempfile::tempdir().expect("home");
    tenant_dir(home.path());
    for tenant in ["", ".", "..", "../tenant-a", "/tenant-a", "tenant/a"] {
        assert!(
            TenantLifecycleGate::new(home.path(), tenant).is_err(),
            "invalid tenant must be refused: {tenant:?}"
        );
    }
}

#[test]
fn replacing_the_lock_between_turns_fences_the_original_gate() {
    use std::os::unix::fs::MetadataExt as _;

    let home = tempfile::tempdir().expect("home");
    let dir = tenant_dir(home.path());
    // A file-coordination fixture only; these bytes confer no launch authority.
    let lock_metadata =
        std::fs::metadata(dir.join("lifecycle.lock")).expect("fixture lock identity");
    let state = serde_json::json!({
        "version": 1,
        "tenant": "tenant-a",
        "generation": { "boot": vec![7_u8; 32], "sequence": 1 },
        "revision": 1,
        "lock_identity": { "device": lock_metadata.dev(), "inode": lock_metadata.ino() },
        "phase": "Active",
        "unresolved": false,
        "max_pending": 256,
        "pending": [],
    });
    write_private(
        &dir.join("lifecycle.json"),
        &serde_json::to_vec(&state).expect("fixture serialization"),
    )
    .expect("fixture state");
    let gate = TenantLifecycleGate::new(home.path(), "tenant-a").expect("original gate");
    let _original_reservation = gate
        .reserve_launch(
            "vm-before",
            "plan-before",
            Instant::now() + Duration::from_secs(1),
        )
        .expect("original lock turn");
    let lock = dir.join("lifecycle.lock");
    let original = std::fs::metadata(&lock).expect("original lock identity");
    write_private(&lock, b"").expect("replace lock inode between turns");
    let replacement = std::fs::metadata(&lock).expect("replacement identity");
    assert_ne!(
        (original.dev(), original.ino()),
        (replacement.dev(), replacement.ino()),
        "the regression requires actual inode replacement"
    );
    let before = std::fs::read(dir.join("lifecycle.json")).expect("original rows");
    assert!(
        gate.reserve_launch(
            "vm-after",
            "plan-after",
            Instant::now() + Duration::from_secs(1)
        )
        .is_err(),
        "a gate must not switch to a different coordination lock inode"
    );
    assert_eq!(
        std::fs::read(dir.join("lifecycle.json")).expect("rows unchanged"),
        before
    );
}
