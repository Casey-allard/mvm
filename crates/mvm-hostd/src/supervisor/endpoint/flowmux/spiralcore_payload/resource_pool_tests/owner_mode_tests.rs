//! Real directory metadata refusals; the pool is a funded fixture, not a VM.

use super::*;
use spiralcore_transfer::{
    resource_profile::ResourceProfile,
    v1::{OwnedLaneNamespaces, OwnedStorePolicy},
    wan,
};
use std::os::unix::fs::PermissionsExt;

pub(super) struct PendingInstalledStore {
    pub(super) root: tempfile::TempDir,
    pub(super) path: std::path::PathBuf,
    pub(super) pool: PayloadResourcePool,
    pub(super) permit: PayloadResourcePermit,
    pub(super) policy: OwnedStorePolicy,
    pub(super) charge: u64,
}

pub(super) fn pending_installed_store() -> PendingInstalledStore {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private original parent");
    let parent = Arc::new(std::fs::File::open(root.path()).expect("original parent FD"));
    let name = format!("flow-{}", hex::encode([9u8; 32]));
    let path = root.path().join(&name);
    let profile = ResourceProfile::SmallV1;
    let limits = profile.receiver_limits();
    let context = wan::context([9; 32]);
    let charge = profile.operation_charge().expect("engine bytes")
        + SpiralCorePayloadFactory::owned_store_requirements()
            .expect("filesystem work")
            .workspace_bytes;
    let pool = PayloadResourcePool::new(
        PayloadResourceLimits {
            max_active: 1,
            resident_bytes: charge,
            disk_bytes: 32 << 20,
        },
        None,
        1 << 20,
    )
    .expect("fixture ledger");
    let mut permit = pool
        .reserve_installed_profile(profile)
        .expect("fixture debit");
    let policy = OwnedStorePolicy::small_v1(
        &limits,
        permit.owned_store_visits().expect("booked visits"),
        OwnedLaneNamespaces::One(context.namespace().expect("fixture scope")),
        spiralcore_transfer::v1::OwnedWorkspaceFunding {
            heap_bytes: permit.owned_store_heap_bytes().expect("booked heap"),
            existing_stack_bytes: 2 << 20,
        },
    )
    .expect("policy");
    permit
        .begin_installed_store(parent, name)
        .expect("original directory");
    PendingInstalledStore {
        root,
        path,
        pool,
        permit,
        policy,
        charge,
    }
}

struct OriginalMetadata {
    directory: std::fs::File,
    before: rustix::fs::Stat,
    permissions: std::fs::Permissions,
    restore_owner: bool,
}

impl OriginalMetadata {
    fn hold(permit: &PayloadResourcePermit) -> Self {
        let Some(OwnedPayloadStore::Installed(store)) = permit.store.as_ref() else {
            panic!("missing original installed store");
        };
        let directory = std::fs::File::from(
            rustix::fs::openat(
                store.parent.as_ref(),
                store.name.as_str(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .expect("hold original directory before mutation"),
        );
        let before = rustix::fs::fstat(&directory).expect("original metadata");
        assert_eq!(
            before.st_ino,
            store.created_inode.expect("created identity")
        );
        assert_eq!(before.st_uid, rustix::process::geteuid().as_raw());
        assert_eq!(before.st_mode & 0o7777, 0o700);
        let permissions = directory
            .metadata()
            .expect("original permissions")
            .permissions();
        Self {
            directory,
            before,
            permissions,
            restore_owner: false,
        }
    }

    fn assert_metadata(&self, uid: u32, mode: u32) {
        use std::os::unix::fs::MetadataExt;
        let held = rustix::fs::fstat(&self.directory).expect("held mutated directory");
        assert_eq!(
            (held.st_dev, held.st_ino, held.st_gid),
            (self.before.st_dev, self.before.st_ino, self.before.st_gid)
        );
        assert_eq!(held.st_uid, uid);
        assert_eq!(
            self.directory.metadata().expect("actual mode").mode() & 0o7777,
            mode
        );
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(held.st_mode),
            rustix::fs::FileType::Directory
        );
    }
}

impl Drop for OriginalMetadata {
    fn drop(&mut self) {
        if self.restore_owner {
            rustix::fs::fchown(
                &self.directory,
                Some(rustix::process::Uid::from_raw(self.before.st_uid)),
                None,
            )
            .expect("restore fixture owner through original FD");
        }
        self.directory
            .set_permissions(self.permissions.clone())
            .expect("restore fixture permissions through original FD");
    }
}

fn capture_refusal_retains_original(
    mut fixture: PendingInstalledStore,
    original: OriginalMetadata,
) {
    let before = fixture.pool.snapshot().expect("original debit");
    assert_eq!((before.active, before.resident_charge), (1, fixture.charge));
    let carrier_before = fixture
        .pool
        .inner
        .ledger
        .lock()
        .expect("ledger")
        .carrier_used;
    let Some(OwnedPayloadStore::Installed(store)) = fixture.permit.store.as_mut() else {
        panic!("missing original installed store");
    };
    assert!(store.directory.is_none() && store.lease.is_none());
    let parent = Arc::clone(&store.parent);
    let name = store.name.clone();
    let error = match store.capture(fixture.policy) {
        Ok(_) => panic!("changed installed identity accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        error.to_string(),
        "original installed store identity differs"
    );
    assert!(store.lease.is_none());
    assert_eq!(fixture.pool.snapshot().expect("retained debit"), before);
    assert_eq!(
        std::fs::read_dir(&fixture.path)
            .expect("empty original")
            .count(),
        0
    );
    drop(fixture.permit);
    let ledger = fixture.pool.inner.ledger.lock().expect("quarantine ledger");
    assert_eq!(
        ledger.used,
        PayloadPoolSnapshot {
            quarantined: before.quarantined + 1,
            ..before
        }
    );
    assert_eq!(ledger.carrier_used, carrier_before);
    let [OwnedPayloadStore::Installed(store)] = ledger.stores.as_slice() else {
        panic!("original store not retained in quarantine");
    };
    assert!(Arc::ptr_eq(&parent, &store.parent));
    assert_eq!(store.name, name);
    assert_eq!(store.created_inode, Some(original.before.st_ino));
    assert!(store.lease.is_none());
    let retained = rustix::fs::fstat(store.directory.as_ref().expect("captured FD").as_ref())
        .expect("retained original identity");
    let named = store.named().expect("original name still present");
    assert_eq!(
        (retained.st_dev, retained.st_ino, named.st_dev, named.st_ino),
        (
            original.before.st_dev,
            original.before.st_ino,
            original.before.st_dev,
            original.before.st_ino,
        )
    );
    assert_eq!(
        std::fs::read_dir(&fixture.path)
            .expect("still empty")
            .count(),
        0
    );
    assert!(fixture.root.path().is_dir());
    drop(ledger);
    drop(original);
}

#[test]
fn broad_mode_capture_refuses_and_retains_original_store_and_debit() {
    super::installed_store_destruction_precedes_returned_credit();
    let fixture = pending_installed_store();
    let original = OriginalMetadata::hold(&fixture.permit);
    original
        .directory
        .set_permissions(std::fs::Permissions::from_mode(0o750))
        .expect("broaden only the original fixture mode");
    original.assert_metadata(rustix::process::geteuid().as_raw(), 0o750);
    capture_refusal_retains_original(fixture, original);
}

#[test]
#[ignore = "requires explicit native root execution to mutate the fixture UID"]
fn foreign_uid_capture_refuses_and_retains_original_store_and_debit() {
    assert!(
        rustix::process::geteuid().is_root(),
        "explicit root actor required"
    );
    super::installed_store_destruction_precedes_returned_credit();
    let fixture = pending_installed_store();
    let mut original = OriginalMetadata::hold(&fixture.permit);
    original.restore_owner = true;
    let foreign = rustix::process::Uid::from_raw(65534);
    rustix::fs::fchown(&original.directory, Some(foreign), None)
        .expect("change only the original fixture UID");
    original.assert_metadata(foreign.as_raw(), 0o700);
    capture_refusal_retains_original(fixture, original);
}
