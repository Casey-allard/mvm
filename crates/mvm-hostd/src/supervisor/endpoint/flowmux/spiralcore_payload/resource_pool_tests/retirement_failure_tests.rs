//! Real final-directory refusal after the claimed codec has retired its files.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::Ordering;

#[cfg(target_os = "linux")]
#[test]
fn parent_fsync_refusal_after_rmdir_retains_original_lease_lock_and_debit() {
    let pending = super::owner_mode_tests::pending_installed_store_with_parent(|path| {
        std::fs::File::from(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .expect("original path-only parent"),
        )
    });
    // O_PATH supports the original relative operations but cannot be fsynced.
    // Keep it from preparation onward; never replace or invalidate a live FD.
    let fixture = super::claim_installed_store(pending);
    let before = fixture.pool.snapshot().expect("original debit");
    assert_eq!((before.active, before.resident_charge), (1, fixture.charge));
    let (slots, capacity, carrier) = {
        let ledger = fixture
            .pool
            .inner
            .ledger
            .lock()
            .expect("prepared retention");
        assert!(ledger.stores.is_empty());
        (
            ledger.stores.as_ptr(),
            ledger.stores.capacity(),
            ledger.carrier_used,
        )
    };
    assert_eq!(capacity, 1);
    let owner = fixture
        .contender
        .metadata()
        .expect("original owner identity");
    assert_eq!(owner.nlink(), 1);
    let Some(OwnedPayloadStore::Installed(store)) = fixture.permit.store.as_ref() else {
        panic!("missing original claimed store");
    };
    let parent = Arc::clone(&store.parent);
    assert!(
        rustix::fs::fcntl_getfl(parent.as_ref())
            .expect("original flags")
            .contains(rustix::fs::OFlags::PATH)
    );
    let name = store.name.clone();
    let inode = store.created_inode.expect("original child inode");
    let directory = Arc::clone(store.directory.as_ref().expect("original child"));
    let child = directory.metadata().expect("original child identity");
    assert_eq!(child.ino(), inode);
    assert!(child.nlink() > 0);
    assert!(store.lease.is_some());
    // Probe only fsync, without removing anything. Drop below must encounter
    // the final sync refusal on its first and only store-cleanup attempt.
    let error = parent.sync_all().expect_err("path-only parent cannot sync");
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    assert!(fixture.path.is_dir());
    assert_eq!(
        fixture
            .contender
            .metadata()
            .expect("still named owner")
            .nlink(),
        1
    );
    assert_eq!(fixture.pool.snapshot().expect("debit before drop"), before);
    let clock = Instant::now();
    drop(fixture.permit);
    let cleanup_drop_wall_ns = clock.elapsed().as_nanos();
    assert!(
        std::fs::symlink_metadata(&fixture.path)
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    );
    let removed_child = directory.metadata().expect("held unlinked child");
    assert_eq!(
        (removed_child.dev(), removed_child.ino()),
        (child.dev(), child.ino())
    );
    assert_eq!(removed_child.nlink(), 0);
    let removed_owner = fixture.contender.metadata().expect("held unlinked owner");
    assert_eq!(
        (removed_owner.dev(), removed_owner.ino()),
        (owner.dev(), owner.ino())
    );
    assert_eq!(removed_owner.nlink(), 0);
    assert!(matches!(
        fixture.contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    fixture.pool.close_admission().expect("close original pool");
    assert!(
        !fixture
            .pool
            .drained()
            .expect("retained debit prevents drain")
    );
    let expected = PayloadPoolSnapshot {
        quarantined: before.quarantined + 1,
        ..before
    };
    assert_eq!(
        fixture.pool.snapshot().expect("quarantined debit"),
        expected
    );
    assert!(fixture.pool.inner.fenced.load(Ordering::Acquire));
    let ledger = fixture
        .pool
        .inner
        .ledger
        .lock()
        .expect("original quarantine");
    assert_eq!(ledger.stores.as_ptr(), slots);
    assert_eq!(ledger.stores.capacity(), capacity);
    assert_eq!(ledger.used, expected);
    assert_eq!(ledger.carrier_used, carrier);
    let [OwnedPayloadStore::Installed(retained)] = ledger.stores.as_slice() else {
        panic!("original removed store not retained");
    };
    assert!(Arc::ptr_eq(&retained.parent, &parent));
    assert_eq!(retained.name, name);
    assert_eq!(retained.created_inode, Some(inode));
    assert!(Arc::ptr_eq(
        retained.directory.as_ref().expect("retained child"),
        &directory
    ));
    assert!(retained.lease.is_some());
    assert_eq!(
        retained.named().expect_err("original name removed").kind(),
        io::ErrorKind::NotFound
    );
    assert!(
        rustix::fs::fcntl_getfl(retained.parent.as_ref())
            .expect("retained flags")
            .contains(rustix::fs::OFlags::PATH)
    );
    assert!(matches!(
        fixture.contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    assert!(!fixture.observation.called.load(Ordering::Acquire));
    assert!(fixture.root.path().is_dir());
    eprintln!(
        "PARENT_FSYNC_REFUSAL errno_probe={} first_cleanup_is_permit_drop=true child_links=0 owner_links=0 original_lock_retained=true original_lease_retained=true quarantined={} active={} resident_bytes={} disk_bytes={} carrier_bytes={carrier} cleanup_drop_wall_ns={cleanup_drop_wall_ns} network_bytes=0 scope=funded_pool_fixture_no_registered_child",
        libc::EBADF,
        ledger.used.quarantined,
        ledger.used.active,
        ledger.used.resident_charge,
        ledger.used.disk_charge
    );
}

struct ParentPermissions {
    directory: Arc<std::fs::File>,
    original: std::fs::Permissions,
}

impl ParentPermissions {
    fn deny_removal(directory: Arc<std::fs::File>) -> Self {
        let original = directory.metadata().expect("held parent").permissions();
        assert_eq!(original.mode() & 0o7777, 0o700);
        let guard = Self {
            directory,
            original,
        };
        guard
            .directory
            .set_permissions(std::fs::Permissions::from_mode(0o500))
            .expect("deny writes through the original parent");
        assert_eq!(
            guard.directory.metadata().expect("mutated parent").mode() & 0o7777,
            0o500
        );
        guard
    }
}

impl Drop for ParentPermissions {
    fn drop(&mut self) {
        self.directory
            .set_permissions(self.original.clone())
            .expect("restore fixture parent through its original FD");
    }
}

#[test]
#[ignore = "requires explicit unprivileged native execution for real directory write refusal"]
fn final_rmdir_refusal_retains_unlinked_owner_lease_and_original_debit() {
    assert!(
        !rustix::process::geteuid().is_root(),
        "explicit unprivileged actor required"
    );
    super::installed_store_destruction_precedes_returned_credit();
    let mut fixture = super::claimed_installed_store();
    let before = fixture.pool.snapshot().expect("original debit");
    let (slots, capacity) = {
        let ledger = fixture
            .pool
            .inner
            .ledger
            .lock()
            .expect("prepared retention");
        assert!(ledger.stores.is_empty());
        (ledger.stores.as_ptr(), ledger.stores.capacity())
    };
    assert_eq!(capacity, 1);
    assert_eq!((before.active, before.resident_charge), (1, fixture.charge));
    let carrier = fixture
        .pool
        .inner
        .ledger
        .lock()
        .expect("original carrier ledger")
        .carrier_used;
    let owner = fixture.contender.metadata().expect("original owner inode");
    assert_eq!(owner.nlink(), 1);
    let Some(OwnedPayloadStore::Installed(store)) = fixture.permit.store.as_mut() else {
        panic!("missing original claimed store");
    };
    let parent = Arc::clone(&store.parent);
    let name = store.name.clone();
    let inode = store.created_inode.expect("original child inode");
    let directory = Arc::clone(store.directory.as_ref().expect("held original child"));
    let child = rustix::fs::fstat(directory.as_ref()).expect("original child metadata");
    assert_eq!(child.st_ino, inode);
    assert_eq!(child.st_mode & 0o7777, 0o700);
    assert!(fixture.path.join(".owner").is_file());
    let context = spiralcore_transfer::wan::context([9; 32]);
    let namespace = fixture
        .path
        .join(hex::encode(context.namespace().expect("fixture namespace")));
    assert_eq!(
        std::fs::read_dir(namespace)
            .expect("accepted publication namespace")
            .count(),
        1
    );

    let permissions = ParentPermissions::deny_removal(Arc::clone(&parent));
    let clock = Instant::now();
    let error = store
        .cleanup(&fixture.pool.inner)
        .expect_err("final directory removal must refuse");
    let refusal_wall_ns = clock.elapsed().as_nanos();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    assert_eq!(
        std::fs::read_dir(&fixture.path)
            .expect("original child still named")
            .count(),
        0,
        "core cleanup must finish before the final parent-relative refusal"
    );
    assert_eq!(
        fixture
            .contender
            .metadata()
            .expect("unlinked owner")
            .nlink(),
        0
    );
    assert!(matches!(
        fixture.contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    assert!(store.lease.is_some());
    assert_eq!(fixture.pool.snapshot().expect("debit before drop"), before);

    drop(fixture.permit);
    // Restoring the test parent's permissions cannot recover ownership or credit.
    drop(permissions);
    let expected = PayloadPoolSnapshot {
        quarantined: before.quarantined + 1,
        ..before
    };
    assert_eq!(
        fixture.pool.snapshot().expect("quarantined debit"),
        expected
    );
    assert!(fixture.pool.inner.fenced.load(Ordering::Acquire));
    match fixture
        .pool
        .reserve_installed_profile(spiralcore_transfer::resource_profile::ResourceProfile::SmallV1)
    {
        Ok(_) => panic!("quarantined credit was reused"),
        Err(error) => {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "payload pool fenced");
        }
    }
    let ledger = fixture.pool.inner.ledger.lock().expect("quarantine ledger");
    assert_eq!(ledger.stores.as_ptr(), slots);
    assert_eq!(ledger.stores.capacity(), capacity);
    assert_eq!(ledger.used, expected);
    assert_eq!(ledger.carrier_used, carrier);
    let [OwnedPayloadStore::Installed(retained)] = ledger.stores.as_slice() else {
        panic!("original retired store not quarantined");
    };
    assert!(Arc::ptr_eq(&retained.parent, &parent));
    assert_eq!(retained.name, name);
    assert_eq!(retained.created_inode, Some(inode));
    assert!(Arc::ptr_eq(
        retained.directory.as_ref().expect("retained child"),
        &directory
    ));
    assert!(retained.lease.is_some());
    let named = retained.named().expect("same original child remains named");
    assert_eq!((named.st_dev, named.st_ino), (child.st_dev, child.st_ino));
    let unlinked = fixture.contender.metadata().expect("held original owner");
    assert_eq!((unlinked.dev(), unlinked.ino()), (owner.dev(), owner.ino()));
    assert_eq!(unlinked.nlink(), 0);
    assert!(matches!(
        fixture.contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    assert!(!fixture.observation.called.load(Ordering::Acquire));
    assert!(fixture.path.is_dir() && fixture.root.path().is_dir());
    eprintln!(
        "FINAL_RMDIR_REFUSAL owner_links=0 original_lock_retained=true original_child_retained=true quarantined={} active={} resident_bytes={} disk_bytes={} carrier_bytes={carrier} refusal_wall_ns={refusal_wall_ns} network_bytes=0",
        ledger.used.quarantined,
        ledger.used.active,
        ledger.used.resident_charge,
        ledger.used.disk_charge
    );
}
