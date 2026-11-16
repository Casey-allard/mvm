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

pub(super) fn seed_original_object(endpoint: &mut ObjectEndpoint<wan::BenchAuthority>) {
    use spiralcore_transfer::{protocol::Frame, v1::ObjectMode};
    let context = wan::context([9; 32]);
    let bytes = b"original installed custody: exact retained object".to_vec();
    let mut sender = ObjectSender::new_with_resource_profile(
        ObjectMode::Raw,
        &context,
        None,
        endpoint.profile(),
        ResourceProfile::SmallV1,
    )
    .expect("canonical fixture sender");
    let clock = Instant::now();
    let (mut requests, mut replies) = (0usize, 0usize);
    let receipt = sender
        .send(&context, bytes.clone(), [31; 32], false, |frames| {
            frames
                .iter()
                .map(|frame| {
                    let encoded = frame.encode()?;
                    requests += encoded.len();
                    let reply = endpoint.handle(&context, &Frame::decode(&encoded)?, 0)?;
                    let encoded = reply.encode()?;
                    replies += encoded.len();
                    Frame::decode(&encoded)
                })
                .collect()
        })
        .expect("publish original object");
    assert_eq!(receipt.object, spiralcore_transfer::object_id(&bytes));
    assert_eq!(
        endpoint
            .read_object(&context, receipt.object)
            .expect("exact readback"),
        bytes
    );
    eprintln!(
        "STORE_FIXTURE_OBJECT exact_bytes={} serialized_in_memory_request_bytes={requests} serialized_in_memory_reply_bytes={replies} verified_wall_ns={} network_bytes=0",
        bytes.len(),
        clock.elapsed().as_nanos()
    );
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FileRecord {
    relative: std::path::PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    directory: bool,
    bytes: Vec<u8>,
}

pub(super) fn snapshot_files(root: &std::path::Path) -> Vec<FileRecord> {
    fn walk(
        root: &std::path::Path,
        relative: &std::path::Path,
        depth: u8,
        rows: &mut Vec<FileRecord>,
    ) {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        assert!(depth <= 2, "fixture directory depth");
        let mut entries: Vec<_> = std::fs::read_dir(root.join(relative))
            .expect("fixture entries")
            .take(9)
            .map(|entry| entry.expect("fixture entry").file_name())
            .collect();
        assert!(entries.len() <= 8, "fixture entry bound");
        entries.sort();
        for name in entries {
            let relative = relative.join(name);
            let named = std::fs::symlink_metadata(root.join(&relative)).expect("named fixture");
            assert!(
                named.is_dir() || named.is_file(),
                "no fixture symlinks/special files"
            );
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(root.join(&relative))
                .expect("original fixture file");
            let meta = file.metadata().expect("held fixture metadata");
            assert_eq!((meta.dev(), meta.ino()), (named.dev(), named.ino()));
            let mut bytes = Vec::new();
            if meta.is_file() {
                assert!(meta.len() <= 4096, "fixture file byte bound");
                std::io::Read::by_ref(&mut file)
                    .take(4097)
                    .read_to_end(&mut bytes)
                    .expect("original bytes");
                assert_eq!(
                    u64::try_from(bytes.len()).expect("fixture length"),
                    meta.len()
                );
                assert!(bytes.len() <= 4096);
            }
            rows.push(FileRecord {
                relative: relative.clone(),
                device: meta.dev(),
                inode: meta.ino(),
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode(),
                links: meta.nlink(),
                directory: meta.is_dir(),
                bytes,
            });
            assert!(rows.len() <= 8, "fixture total entry bound");
            if meta.is_dir() {
                walk(root, &relative, depth + 1, rows);
            }
        }
    }
    let mut rows = Vec::new();
    walk(root, std::path::Path::new(""), 0, &mut rows);
    assert!(rows.iter().any(
        |row| row.relative.extension().is_some_and(|ext| ext == "object") && !row.bytes.is_empty()
    ));
    rows
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

    fn broaden_mode(&self) {
        self.directory
            .set_permissions(std::fs::Permissions::from_mode(0o750))
            .expect("broaden only the original fixture mode");
        self.assert_metadata(rustix::process::geteuid().as_raw(), 0o750);
    }

    fn change_owner(&mut self) {
        self.restore_owner = true;
        let foreign = rustix::process::Uid::from_raw(65534);
        rustix::fs::fchown(&self.directory, Some(foreign), None)
            .expect("change only the original fixture UID");
        self.assert_metadata(foreign.as_raw(), 0o700);
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
    original.broaden_mode();
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
    original.change_owner();
    capture_refusal_retains_original(fixture, original);
}

fn retirement_refusal_retains_original(
    mut fixture: ClaimedInstalledStore,
    original: OriginalMetadata,
    contents: Vec<FileRecord>,
) {
    use std::sync::atomic::Ordering;
    let before = fixture.pool.snapshot().expect("original debit");
    let carrier_before = fixture
        .pool
        .inner
        .ledger
        .lock()
        .expect("ledger")
        .carrier_used;
    assert_eq!(snapshot_files(&fixture.path), contents);
    let Some(OwnedPayloadStore::Installed(store)) = fixture.permit.store.as_mut() else {
        panic!("missing claimed store");
    };
    let parent = Arc::clone(&store.parent);
    let name = store.name.clone();
    let error = store
        .cleanup(&fixture.pool.inner)
        .expect_err("identity refusal");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        error.to_string(),
        "original installed store identity differs"
    );
    assert_eq!(fixture.pool.snapshot().expect("debit before drop"), before);
    assert_eq!(snapshot_files(&fixture.path), contents);
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
        panic!("original claimed store not retained");
    };
    assert!(Arc::ptr_eq(&parent, &store.parent));
    assert_eq!(store.name, name);
    assert_eq!(store.created_inode, Some(original.before.st_ino));
    assert!(store.directory.is_some() && store.lease.is_some());
    let held = rustix::fs::fstat(
        store
            .directory
            .as_ref()
            .expect("retained directory")
            .as_ref(),
    )
    .expect("held original identity");
    let named = store.named().expect("original name retained");
    assert_eq!(
        (held.st_dev, held.st_ino, named.st_dev, named.st_ino),
        (
            original.before.st_dev,
            original.before.st_ino,
            original.before.st_dev,
            original.before.st_ino
        )
    );
    store.check_child().expect_err("metadata still refuses");
    assert_eq!(snapshot_files(&fixture.path), contents);
    assert!(matches!(
        fixture.contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    assert!(!fixture.observation.called.load(Ordering::Acquire));
    assert!(fixture.root.path().is_dir());
    drop(ledger);
    drop(original);
}

#[test]
fn broad_mode_retirement_refuses_and_retains_original_lease_lock_and_debit() {
    super::installed_store_destruction_precedes_returned_credit();
    let fixture = super::claimed_installed_store();
    let contents = snapshot_files(&fixture.path);
    let original = OriginalMetadata::hold(&fixture.permit);
    original.broaden_mode();
    retirement_refusal_retains_original(fixture, original, contents);
}

#[test]
#[ignore = "requires explicit native root execution to mutate the fixture UID"]
fn foreign_uid_retirement_refuses_and_retains_original_lease_lock_and_debit() {
    assert!(
        rustix::process::geteuid().is_root(),
        "explicit root actor required"
    );
    super::installed_store_destruction_precedes_returned_credit();
    let fixture = super::claimed_installed_store();
    let contents = snapshot_files(&fixture.path);
    let mut original = OriginalMetadata::hold(&fixture.permit);
    original.change_owner();
    retirement_refusal_retains_original(fixture, original, contents);
}
