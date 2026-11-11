#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;

use mvm_vmm::host::installed_owner::{
    HolderLease, InstallationKey, InstallationOwner, OwnerError, OwnerSnapshot, Phase, Recovery,
};

fn key() -> InstallationKey {
    InstallationKey {
        installation: [0x45; 32],
        profile: [0x81; 32],
    }
}

fn shared_probe(file: &File) -> bool {
    // SAFETY: nonblocking lock on this test's independently opened descriptor.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
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
fn already_clean_recovery_retains_both_original_exclusions_until_guard_drop() {
    let base = tempfile::tempdir().unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.path().canonicalize().unwrap().join("installation");
    let mut owner = InstallationOwner::initialize(&root, key()).unwrap();
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("holders.lock"))
        .unwrap();
    let original = fs::read(root.join("state.bin")).unwrap();
    let guard = owner.reconcile_with_exclusion().unwrap();
    assert_eq!(guard.recovery(), Recovery::AlreadyClean);
    guard.revalidate().unwrap();
    assert!(!shared_probe(&probe), "Clean must also retain holders EX");
    assert!(matches!(
        InstallationOwner::open(&root, key()),
        Err(OwnerError::Busy)
    ));
    assert_eq!(fs::read(root.join("state.bin")).unwrap(), original);
    drop(guard);
    assert!(shared_probe(&probe));
    drop(probe);
    let epoch = owner.begin().unwrap();
    owner.finish(epoch).unwrap();
}

#[test]
fn active_recovery_refuses_live_holders_then_retains_exclusion_after_retirement() {
    let base = tempfile::tempdir().unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.path().canonicalize().unwrap().join("installation");
    let mut owner = InstallationOwner::initialize(&root, key()).unwrap();
    let epoch = owner.begin().unwrap();
    let holder = HolderLease::acquire(&root, key(), epoch.generation()).unwrap();
    drop(owner);
    let mut owner = InstallationOwner::open(&root, key()).unwrap();
    assert!(matches!(
        owner.reconcile_with_exclusion(),
        Err(OwnerError::Busy)
    ));
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Active);
    drop(holder);
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("holders.lock"))
        .unwrap();
    let guard = owner.reconcile_with_exclusion().unwrap();
    assert_eq!(
        guard.recovery(),
        Recovery::Retired {
            epoch: epoch.generation()
        }
    );
    guard.revalidate().unwrap();
    assert!(!shared_probe(&probe));
    drop(guard);
    assert!(shared_probe(&probe));
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Clean);
}

#[test]
fn retained_exclusion_revalidates_original_namespace_without_releasing_its_locks() {
    let base = tempfile::tempdir().unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let base_path = base.path().canonicalize().unwrap();
    let root = base_path.join("installation");
    let mut owner = InstallationOwner::initialize(&root, key()).unwrap();
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("holders.lock"))
        .unwrap();
    let guard = owner.reconcile_with_exclusion().unwrap();
    fs::rename(&root, base_path.join("preserved")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(guard.revalidate().is_err());
    assert!(
        !shared_probe(&probe),
        "validation refusal cannot release original EX"
    );
    drop(guard);
    assert!(shared_probe(&probe));
}

#[test]
fn original_predecessor_distinguishes_bootstrap_from_retired_and_already_clean_epochs() {
    let base = tempfile::tempdir().unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.path().canonicalize().unwrap().join("installation");
    let mut owner = InstallationOwner::initialize(&root, key()).unwrap();
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("holders.lock"))
        .unwrap();
    {
        let guard = owner.reconcile_with_exclusion().unwrap();
        let original = fs::read(root.join("state.bin")).unwrap();
        assert_eq!(
            guard.original_predecessor().unwrap(),
            OwnerSnapshot {
                phase: Phase::Clean,
                epoch: 0
            }
        );
        guard.revalidate_for(&root, key()).unwrap();
        assert!(
            guard
                .revalidate_for(&base.path().join("wrong-root"), key())
                .is_err()
        );
        let mut wrong = key();
        wrong.profile[0] ^= 1;
        assert!(guard.revalidate_for(&root, wrong).is_err());
        guard.revalidate_for(&root, key()).unwrap();
        assert_eq!(fs::read(root.join("state.bin")).unwrap(), original);
        assert!(!base.path().join("wrong-root").exists());
        assert!(
            !shared_probe(&probe),
            "wrong-scope refusal cannot release original exclusion"
        );
    }
    let epoch = owner.begin().unwrap();
    {
        let guard = owner.reconcile_with_exclusion().unwrap();
        assert_eq!(
            guard.recovery(),
            Recovery::Retired {
                epoch: epoch.generation()
            }
        );
        assert_eq!(
            guard.original_predecessor().unwrap(),
            OwnerSnapshot {
                phase: Phase::Active,
                epoch: epoch.generation()
            }
        );
        guard.revalidate_for(&root, key()).unwrap();
        assert!(!shared_probe(&probe));
    }
    {
        let guard = owner.reconcile_with_exclusion().unwrap();
        assert_eq!(guard.recovery(), Recovery::AlreadyClean);
        assert_eq!(
            guard.original_predecessor().unwrap(),
            OwnerSnapshot {
                phase: Phase::Clean,
                epoch: epoch.generation()
            }
        );
        guard.revalidate_for(&root, key()).unwrap();
        assert!(!shared_probe(&probe));
    }
    assert!(shared_probe(&probe));
}
