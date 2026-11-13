//! Component fixtures only: no native admission, resource credit or retirement.
use super::*;
use std::{
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU8, AtomicUsize},
};

struct Parent(Arc<AtomicBool>);
impl CoreCurrentParentPermit for Parent {
    fn check_current(&self, _: &HostLaunchBinding) -> Result<()> {
        ensure!(self.0.load(Ordering::Acquire), "fixture parent closed");
        Ok(())
    }
}
struct DefaultGuard;
impl EndpointPartitionGuard for DefaultGuard {
    fn check_current(&self, _: &EndpointPartitionProjection) -> Result<()> {
        Ok(())
    }
}
struct Guard {
    current: AtomicBool,
    parent: Arc<AtomicBool>,
    calls: AtomicUsize,
    mode: AtomicU8,
    expected: EndpointPartitionProjection,
    path: PathBuf,
    fd: i32,
    id: (u64, u64),
}
impl EndpointPartitionGuard for Guard {
    fn check_current(&self, projection: &EndpointPartitionProjection) -> Result<()> {
        ensure!(projection == &self.expected, "fixture projection differs");
        ensure!(self.current.load(Ordering::Acquire), "fixture guard closed");
        Ok(())
    }
    fn prepare_retained_telemetry(
        &self,
        projection: &EndpointPartitionProjection,
        state_path: &Path,
        state_directory: &File,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        ensure!(projection == &self.expected, "fixture projection differs");
        ensure!(state_path == self.path, "fixture path differs");
        ensure!(state_directory.as_raw_fd() == self.fd, "borrow changed");
        let held = state_directory.metadata()?;
        let named = fs::symlink_metadata(state_path)?;
        ensure!(held.is_dir() && named.is_dir(), "fixture directory differs");
        ensure!(
            (held.dev(), held.ino()) == self.id && (named.dev(), named.ino()) == self.id,
            "fixture original directory replaced"
        );
        match self.mode.load(Ordering::Acquire) {
            1 => self.current.store(false, Ordering::Release),
            2 => self.parent.store(false, Ordering::Release),
            3 => anyhow::bail!("fixture owner refuses preparation"),
            _ => {}
        }
        Ok(())
    }
}
struct Fixture {
    home: tempfile::TempDir,
    path: PathBuf,
    directory: File,
    parent: Arc<AtomicBool>,
    projection: EndpointPartitionProjection,
}
impl Fixture {
    fn new() -> Self {
        let home = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = home.path().join("state-directory");
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let directory = File::open(&path).unwrap();
        let projection = EndpointPartitionProjection {
            version: 1,
            binding: HostLaunchBinding {
                installation: [1; 32],
                profile: [2; 32],
                generation: 1,
                grant_serial: 3,
                vm_name: "retained-core-fixture".into(),
                backend: BackendKind::Firecracker,
                cpus: 1,
                memory_mib: 1,
            },
            admitted_plan_id: "fixture-only".into(),
            session: [4; 32],
            partition_serial: 5,
            profile: 1,
            store: None,
            limits: EndpointPartitionLimits {
                host_plaintext_bytes: 1,
                host_codec_bytes: 0,
                host_carrier_bytes: 0,
                host_metadata_bytes: 0,
                host_stack_bytes: 0,
                cache_disk_bytes: 0,
                staging_disk_bytes: 0,
                workers: 1,
                max_streams: 1,
            },
        };
        Self {
            home,
            path,
            directory,
            parent: Arc::new(AtomicBool::new(true)),
            projection,
        }
    }
    fn guard(&self) -> Arc<Guard> {
        let m = self.directory.metadata().unwrap();
        Arc::new(Guard {
            current: AtomicBool::new(true),
            parent: self.parent.clone(),
            calls: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
            expected: self.projection.clone(),
            path: self.path.clone(),
            fd: self.directory.as_raw_fd(),
            id: (m.dev(), m.ino()),
        })
    }
    fn handoff(&self, guard: Arc<dyn EndpointPartitionGuard>) -> PreparedEndpointHandoff {
        let root = self.home.path().join("installation");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::write(root.join("state"), b"live").unwrap();
        fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("holders"))
            .unwrap();
        let lease = PreparedHostLifetimeLease::bind(
            File::open(&root).unwrap(),
            holder,
            HostLeaseExpectation {
                state_name: "state".into(),
                state_bytes: 4,
                state_sha256: Sha256::digest(b"live").into(),
                absent_names: ["next".into(), "intent".into()],
            },
        )
        .unwrap();
        let anchor = Arc::new(HostLifetimeAnchor {
            lease,
            binding: self.projection.binding.clone(),
            _parent_owner: Box::new(()),
            portable_archive: None,
            canonical: None,
            root_copy_claimed: AtomicBool::new(false),
            admitted: Mutex::new(None),
            current_parent: Mutex::new(Some(Arc::new(Parent(self.parent.clone())))),
            native_claimed: AtomicBool::new(false),
            endpoint_claimed: AtomicBool::new(true),
            startup_claimed: AtomicBool::new(false),
            startup_complete: AtomicBool::new(false),
        });
        PreparedEndpointHandoff {
            partition: PreparedEndpointPartition::new(self.projection.clone(), guard).unwrap(),
            holder: anchor.lease.duplicate().unwrap(),
            anchor,
        }
    }
}

#[test]
fn default_retained_provider_refuses_without_effects() {
    let f = Fixture::new();
    let handoff = f.handoff(Arc::new(DefaultGuard));
    let error = handoff
        .prepare_retained_telemetry(&f.path, &f.directory)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 0);
}

#[test]
fn same_guard_receives_original_borrow_and_refuses_foreign_or_replaced_directory() {
    let f = Fixture::new();
    let guard = f.guard();
    let handoff = f.handoff(guard.clone());
    handoff
        .prepare_retained_telemetry(&f.path, &f.directory)
        .unwrap();
    assert_eq!(guard.calls.load(Ordering::Acquire), 1);
    let foreign = f.home.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    assert!(
        handoff
            .prepare_retained_telemetry(&foreign, &File::open(&foreign).unwrap())
            .is_err()
    );
    fs::rename(&f.path, f.home.path().join("original-state")).unwrap();
    fs::create_dir(&f.path).unwrap();
    assert!(
        handoff
            .prepare_retained_telemetry(&f.path, &f.directory)
            .is_err()
    );
    assert_eq!(guard.calls.load(Ordering::Acquire), 3);
}

#[test]
fn fresh_parent_and_guard_checks_surround_callback_and_refusals_remain_errors() {
    for mode in 0..=4 {
        let f = Fixture::new();
        let guard = f.guard();
        let handoff = f.handoff(guard.clone());
        if mode == 0 {
            guard.current.store(false, Ordering::Release);
        }
        if mode == 4 {
            f.parent.store(false, Ordering::Release);
        }
        guard.mode.store(mode, Ordering::Release);
        assert!(
            handoff
                .prepare_retained_telemetry(&f.path, &f.directory)
                .is_err()
        );
        assert_eq!(
            guard.calls.load(Ordering::Acquire),
            usize::from(mode != 0 && mode != 4)
        );
    }
}

// The fixture owner models only original callback custody. It is not the Root
// catalog, key validation, actual managed credit or a production file policy.
struct FilesGuard {
    original: Arc<Guard>,
    prepared: AtomicBool,
    calls: AtomicUsize,
    mode: AtomicU8,
    ids: [(u64, u64); 2],
    fds: [i32; 2],
    retained: Mutex<Option<[File; 2]>>,
}
impl FilesGuard {
    fn new(fixture: &Fixture, files: &[File; 2]) -> Arc<Self> {
        Arc::new(Self {
            original: fixture.guard(),
            prepared: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
            ids: files.each_ref().map(|file| {
                let meta = file.metadata().unwrap();
                (meta.dev(), meta.ino())
            }),
            fds: files.each_ref().map(|file| file.as_raw_fd()),
            retained: Mutex::new(None),
        })
    }
}
impl EndpointPartitionGuard for FilesGuard {
    fn check_current(&self, projection: &EndpointPartitionProjection) -> Result<()> {
        self.original.check_current(projection)
    }
    fn prepare_retained_telemetry(
        &self,
        projection: &EndpointPartitionProjection,
        state_path: &Path,
        state_directory: &File,
    ) -> Result<()> {
        self.original
            .prepare_retained_telemetry(projection, state_path, state_directory)?;
        self.prepared.store(true, Ordering::Release);
        Ok(())
    }
    fn bind_retained_telemetry_files(
        &self,
        projection: &EndpointPartitionProjection,
        state_path: &Path,
        state_directory: &File,
        records_file: &File,
        wrapped_key_file: &File,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.original.check_current(projection)?;
        ensure!(
            self.prepared.load(Ordering::Acquire),
            "fixture not prepared"
        );
        ensure!(state_path == self.original.path, "fixture path differs");
        let directory = state_directory.metadata()?;
        let named_directory = fs::symlink_metadata(state_path)?;
        ensure!(
            state_directory.as_raw_fd() == self.original.fd
                && directory.is_dir()
                && named_directory.is_dir()
                && (directory.dev(), directory.ino()) == self.original.id
                && (named_directory.dev(), named_directory.ino()) == self.original.id,
            "fixture original directory differs"
        );
        for (i, (name, file)) in [
            ("telemetry-records.jsonl", records_file),
            ("telemetry-records.key", wrapped_key_file),
        ]
        .into_iter()
        .enumerate()
        {
            let held = file.metadata()?;
            let named = fs::symlink_metadata(state_path.join(name))?;
            ensure!(
                file.as_raw_fd() == self.fds[i]
                    && held.is_file()
                    && named.is_file()
                    && held.nlink() == 1
                    && named.nlink() == 1
                    && held.mode() & 0o7777 == 0o600
                    && named.mode() & 0o7777 == 0o600
                    && (held.dev(), held.ino()) == self.ids[i]
                    && (named.dev(), named.ino()) == self.ids[i],
                "fixture original files differ"
            );
        }
        ensure!(
            self.mode.load(Ordering::Acquire) != 3,
            "fixture owner refusal"
        );
        *self.retained.lock().unwrap() =
            Some([records_file.try_clone()?, wrapped_key_file.try_clone()?]);
        match self.mode.load(Ordering::Acquire) {
            1 => self.original.current.store(false, Ordering::Release),
            2 => self.original.parent.store(false, Ordering::Release),
            _ => {}
        }
        Ok(())
    }
}
fn records_fixture(fixture: &Fixture) -> [File; 2] {
    ["telemetry-records.jsonl", "telemetry-records.key"].map(|name| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.path.join(name))
            .unwrap()
    })
}

#[test]
fn default_file_binding_is_typed_unsupported_and_keeps_borrowed_files_live() {
    let f = Fixture::new();
    let files = records_fixture(&f);
    let handoff = f.handoff(Arc::new(DefaultGuard));
    let error = handoff
        .bind_retained_telemetry_files(&f.path, &f.directory, &files[0], &files[1])
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert!(files.iter().all(|file| file.metadata().unwrap().len() == 0));
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 2);
}

#[test]
fn file_binding_requires_preparation_and_original_borrows_and_refuses_replacement() {
    let f = Fixture::new();
    let files = records_fixture(&f);
    let guard = FilesGuard::new(&f, &files);
    let handoff = f.handoff(guard.clone());
    assert!(
        handoff
            .bind_retained_telemetry_files(&f.path, &f.directory, &files[0], &files[1],)
            .is_err()
    );
    handoff
        .prepare_retained_telemetry(&f.path, &f.directory)
        .unwrap();
    let foreign = tempfile::tempfile().unwrap();
    assert!(
        handoff
            .bind_retained_telemetry_files(&f.path, &f.directory, &foreign, &files[1],)
            .is_err()
    );
    assert!(guard.retained.lock().unwrap().is_none());
    handoff
        .bind_retained_telemetry_files(&f.path, &f.directory, &files[0], &files[1])
        .unwrap();
    let retained = guard.retained.lock().unwrap();
    assert!(retained.as_ref().unwrap().iter().zip(&files).all(|(a, b)| {
        let a = a.metadata().unwrap();
        let b = b.metadata().unwrap();
        (a.dev(), a.ino()) == (b.dev(), b.ino())
    }));
    drop(retained);
    fs::rename(
        f.path.join("telemetry-records.key"),
        f.path.join("original-key"),
    )
    .unwrap();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(f.path.join("telemetry-records.key"))
        .unwrap();
    assert!(
        handoff
            .bind_retained_telemetry_files(&f.path, &f.directory, &files[0], &files[1],)
            .is_err()
    );
}

#[test]
fn file_binding_freshness_checks_refuse_before_callback_and_after_retaining_files() {
    for mode in 0..=4 {
        let f = Fixture::new();
        let files = records_fixture(&f);
        let guard = FilesGuard::new(&f, &files);
        let handoff = f.handoff(guard.clone());
        handoff
            .prepare_retained_telemetry(&f.path, &f.directory)
            .unwrap();
        if mode == 0 {
            guard.original.current.store(false, Ordering::Release);
        }
        if mode == 4 {
            f.parent.store(false, Ordering::Release);
        }
        guard.mode.store(mode, Ordering::Release);
        assert!(
            handoff
                .bind_retained_telemetry_files(&f.path, &f.directory, &files[0], &files[1],)
                .is_err()
        );
        assert_eq!(
            guard.calls.load(Ordering::Acquire),
            usize::from(mode != 0 && mode != 4)
        );
        assert_eq!(
            guard.retained.lock().unwrap().is_some(),
            mode == 1 || mode == 2
        );
    }
}
