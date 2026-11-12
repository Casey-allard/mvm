//! Durable locator for the original installed mailbox provider and helper.
//! A Pending reservation may have reached the daemon. Preserve it on uncertain
//! delivery or restart. Only the original daemon's Stop can prove collection.
use anyhow::{Context, Result, bail, ensure};
use mvm_core::protocol::{broker_control::SignedControl, mailbox_worker_control::*};
use mvm_hostd::{
    mailbox_process::owned_client::{InstalledMailboxClient, InstalledMailboxPeer},
    plan_admission::AdmittedPlan,
};
use mvm_runtime::AnyBackend;
use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

pub trait InstalledMailboxProvisioner: Send + Sync {
    /// Pin the installed peer before issuing an operation that can create a slot.
    fn original_peer(
        &self,
        plan: &AdmittedPlan,
        backend: &AnyBackend,
        request: &MailboxWorkerRequest,
    ) -> anyhow::Result<Arc<InstalledMailboxPeer>>;

    fn provision(
        &self,
        plan: &AdmittedPlan,
        backend: &AnyBackend,
        request: &MailboxWorkerRequest,
    ) -> anyhow::Result<Arc<InstalledMailboxPeer>>;
    /// Resolve the original daemon from trusted installation custody.
    fn resolve_original(
        &self,
        locator: &SignedControl,
    ) -> anyhow::Result<Arc<InstalledMailboxPeer>>;
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
enum Record {
    // Older unsigned records remain fail-closed. They cannot authorize lookup.
    Pending { acquire: Box<MailboxWorkerRequest> },
    PendingV1 { lookup: Box<SignedControl> },
    Owned { stop: Box<SignedControl> },
}

const MAX_RECORD: usize = 64 * 1024;
fn deadline() -> Instant {
    Instant::now() + Duration::from_millis(MAX_WORKER_OPERATION_MS)
}

fn at(dir: &File, name: &str, flags: OFlags) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat(
        dir,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )?))
}
fn unlink(dir: &File, name: &str) -> io::Result<()> {
    Ok(rustix::fs::unlinkat(dir, name, AtFlags::empty())?)
}

fn directory(file: &File, private: bool) -> Result<()> {
    let meta = file.metadata()?;
    mvm_core::private_fs::require_current_owner(&meta)?;
    ensure!(
        meta.is_dir() && meta.mode() & (if private { 0o077 } else { 0o022 }) == 0,
        "unsafe mailbox owner directory"
    );
    Ok(())
}
fn regular(file: &File) -> Result<()> {
    let meta = file.metadata()?;
    mvm_core::private_fs::require_current_owner(&meta)?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o777 == 0o600,
        "unsafe mailbox owner file"
    );
    Ok(())
}

fn store(home: &Path, create: bool) -> Result<Option<File>> {
    if create && !home.try_exists()? {
        mvm_core::private_fs::create_owned_private_dir(home)?;
        if let Some(parent) = home.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    let mut parent = match File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(home)
    {
        Ok(f) => f,
        Err(e) if !create && e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    directory(&parent, false)?;
    for (component, private) in [("state", false), ("mailbox-owners-v1", true)] {
        if create {
            match rustix::fs::mkdirat(&parent, component, Mode::RWXU) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match at(&parent, component, OFlags::DIRECTORY | OFlags::RDONLY) {
            Ok(child) => {
                directory(&child, private)?;
                if create {
                    parent.sync_all()?;
                }
                parent = child;
            }
            Err(e) if !create && e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Some(parent))
}

struct Claim {
    dir: File,
    _lock: File,
    name: String,
}
impl Claim {
    fn acquire(home: &Path, name: &str, create: bool) -> Result<Option<Self>> {
        mvm_core::naming::validate_vm_name(name)?;
        let Some(dir) = store(home, create)? else {
            return Ok(None);
        };
        // This directory lock covers only opening/removing the named lock
        // inode. The per-name lock spans the lifecycle, including remote I/O.
        dir.lock()?;
        let lock = at(&dir, &format!("{name}.lock"), OFlags::CREATE | OFlags::RDWR)?;
        regular(&lock)?;
        lock.try_lock()
            .context("another operation owns this VM's mailbox")?;
        dir.unlock()?;
        Ok(Some(Self {
            dir,
            _lock: lock,
            name: name.into(),
        }))
    }
    fn record_name(&self) -> String {
        format!("{}.json", self.name)
    }
    fn read(&self) -> Result<Option<Record>> {
        let f = match at(&self.dir, &self.record_name(), OFlags::RDONLY) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        regular(&f)?;
        ensure!(
            f.metadata()?.len() <= MAX_RECORD as u64,
            "oversized mailbox owner record"
        );
        let mut data = Vec::new();
        f.take((MAX_RECORD + 1) as u64).read_to_end(&mut data)?;
        ensure!(data.len() <= MAX_RECORD, "oversized mailbox owner record");
        Ok(Some(
            serde_json::from_slice(&data).context("invalid mailbox owner record")?,
        ))
    }
    fn write(&self, record: &Record) -> Result<()> {
        let data = serde_json::to_vec(record)?;
        ensure!(data.len() <= MAX_RECORD, "oversized mailbox owner record");
        let tmp = format!("{}.next", self.name);
        // An interrupted predecessor may have left this unpublished regular
        // file. Nobody else can publish it once this claim has been acquired.
        match at(&self.dir, &tmp, OFlags::RDONLY) {
            Ok(stale) => {
                regular(&stale)?;
                unlink(&self.dir, &tmp)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut out = at(
            &self.dir,
            &tmp,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY,
        )?;
        out.write_all(&data)?;
        out.sync_all()?;
        rustix::fs::renameat(
            &self.dir,
            tmp.as_str(),
            &self.dir,
            self.record_name().as_str(),
        )?;
        self.dir.sync_all()?;
        Ok(())
    }
    fn remove(&self) -> Result<()> {
        unlink(&self.dir, &self.record_name())?;
        self.dir.sync_all()?;
        Ok(())
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if self.dir.lock().is_ok() {
            let _ = unlink(&self.dir, &format!("{}.lock", self.name));
            let _ = self.dir.unlock();
        }
    }
}

pub(crate) fn refuse_existing(name: &str) -> Result<()> {
    if let Some(claim) = Claim::acquire(&mvm_core::config::mvm_home_strict()?, name, false)? {
        ensure!(
            claim.read()?.is_none(),
            "original mailbox owner is still recorded"
        );
    }
    Ok(())
}

/// Exclusive claim held from preflight through the admitted start. Consuming it
/// transfers exactly that name lock into the mailbox worker lifecycle.
pub(crate) struct VacantOwner(Claim);
impl VacantOwner {
    pub(crate) fn claim(name: &str) -> Result<Self> {
        let claim = Claim::acquire(&mvm_core::config::mvm_home_strict()?, name, true)?
            .context("mailbox owner store unavailable")?;
        ensure!(
            claim.read()?.is_none(),
            "original mailbox owner is still recorded"
        );
        Ok(Self(claim))
    }
}
/// Serialize a destructive operation on legacy VM state with acquisition and stop.
pub(crate) fn without_owner<T>(name: &str, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let _vacant = VacantOwner::claim(name)?;
    action()
}

pub(crate) struct OwnedLaunch {
    claim: Claim,
    client: InstalledMailboxClient,
    rollback_on_drop: bool,
}
impl OwnedLaunch {
    pub(crate) fn begin(
        provisioner: &dyn InstalledMailboxProvisioner,
        admitted: &AdmittedPlan,
        backend: &AnyBackend,
        vacant: VacantOwner,
    ) -> Result<Self> {
        let VacantOwner(claim) = vacant;
        let mut client = InstalledMailboxClient::prepare(admitted, backend, &claim.name)?;
        let original = provisioner.original_peer(admitted, backend, client.acquire_request())?;
        client.bind_acquire_peer(original.clone())?;
        // The original issuer and acquisition nonce are covered by the host
        // signature. No reservation can be made before this record is durable.
        claim.write(&Record::PendingV1 {
            lookup: Box::new(client.signed_pending_locator()?),
        })?;
        let mut launch = Self {
            claim,
            client,
            rollback_on_drop: true,
        };
        let peer = provisioner.provision(admitted, backend, launch.client.acquire_request())?;
        ensure!(
            Arc::ptr_eq(&original, &peer),
            "mailbox provisioner changed original daemon"
        );
        launch.client.acquire(deadline())?;
        launch.claim.write(&Record::Owned {
            stop: Box::new(launch.client.signed_stop_locator()?),
        })?;
        Ok(launch)
    }
    pub(crate) fn start_native<T>(&self, start: impl FnOnce() -> Result<T>) -> Result<T> {
        self.client.start_native(start)
    }
    pub(crate) fn settle_native_start(&self) -> Result<()> {
        self.client.settle_native_start()
    }
    pub(crate) fn configure_and_wait(&self, backend: &AnyBackend) -> Result<()> {
        self.client.configure_and_wait(backend, deadline())
    }
    pub(crate) fn commit(mut self) {
        self.rollback_on_drop = false;
    }
    /// Caller has established that the VMM never started or has been aborted.
    pub(crate) fn rollback_after_abort(
        &mut self,
        cleanup: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.rollback_on_drop = false;
        collect(&self.client)?;
        cleanup()?;
        self.claim.remove()
    }
}
impl Drop for OwnedLaunch {
    fn drop(&mut self) {
        if self.rollback_on_drop && self.client.owner().is_some() {
            // No backend-cleanup receipt on implicit Drop. Keep the durable
            // locator for the fresh client's stop/recovery even after Stop.
            if let Err(error) = collect(&self.client) {
                tracing::warn!(%error,"original mailbox stop remains unresolved");
            }
        }
    }
}
fn collect(client: &InstalledMailboxClient) -> Result<()> {
    client.settle_native_start()?;
    let until = deadline();
    match client.stop(until)? {
        MailboxWorkerState::Collected { .. } => Ok(()),
        MailboxWorkerState::Reserved | MailboxWorkerState::Unresolved => {
            ensure!(
                client.release_unstarted(until)? == MailboxWorkerState::ReleasedBeforeSpawn,
                "original mailbox reservation release is unresolved"
            );
            Ok(())
        }
        _ => bail!("original mailbox worker collection is unresolved"),
    }
}
pub(crate) fn stop_with<T>(
    name: &str,
    provisioner: Option<&dyn InstalledMailboxProvisioner>,
    cleanup: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let claim = Claim::acquire(&mvm_core::config::mvm_home_strict()?, name, true)?
        .context("mailbox owner store unavailable")?;
    stop_claim(&claim, name, provisioner, cleanup)
}

fn stop_claim<T>(
    claim: &Claim,
    name: &str,
    provisioner: Option<&dyn InstalledMailboxProvisioner>,
    cleanup: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let client = match claim.read()? {
        None => return cleanup(),
        Some(Record::Pending { .. }) => {
            bail!("unsigned pending mailbox record cannot prove original ownership")
        }
        Some(Record::PendingV1 { lookup }) => {
            let mut client = InstalledMailboxClient::from_pending_locator(name, &lookup)?;
            let resolver = provisioner.context("original installed mailbox daemon unavailable")?;
            client.bind_peer(resolver.resolve_original(&lookup)?)?;
            // The recovery operation can look up ONLY the original reservation.
            // An unknown slot or foreign daemon leaves the Pending record intact.
            client.recover_owner(deadline())?;
            let stop = client.signed_stop_locator()?;
            claim.write(&Record::Owned {
                stop: Box::new(stop),
            })?;
            client
        }
        Some(Record::Owned { stop }) => {
            let mut client = InstalledMailboxClient::from_stop_locator(name, &stop)?;
            let resolver = provisioner.context("original installed mailbox daemon unavailable")?;
            client.bind_peer(resolver.resolve_original(&stop)?)?;
            client
        }
    };
    collect(&client)?;
    let value = cleanup()?;
    claim.remove()?;
    Ok(value)
}
pub(crate) fn stop_if_present(
    name: &str,
    provisioner: Option<&dyn InstalledMailboxProvisioner>,
) -> Result<()> {
    stop_with(name, provisioner, || Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn pending() -> Record {
        Record::Pending {
            acquire: Box::new(MailboxWorkerRequest {
                domain: MAILBOX_WORKER_DOMAIN.into(),
                version: 1,
                request_nonce: [2; 32],
                tenant: "local".into(),
                vm_id: "test".into(),
                workload_id: "test".into(),
                plan_commitment: [3; 32],
                mailbox_grant: MailboxGrant {
                    mailbox: MailboxId::from_bytes([4; 32]),
                    authority_key: [5; 32],
                    epoch: ExecutionEpoch::new(1).unwrap(),
                    local_service: None,
                },
                admission_expires_at_unix_ms: 12345,
                deadline_unix_ms: 0,
                backend: MailboxWorkerBackend::Firecracker,
                operation: MailboxWorkerOperation::Acquire,
            }),
        }
    }
    #[test]
    fn original_claim_excludes_same_name_and_allows_another_vm() {
        let home = tempfile::tempdir().unwrap();
        let active = Claim::acquire(home.path(), "first", true).unwrap().unwrap();
        assert!(Claim::acquire(home.path(), "first", true).is_err());
        let second = Claim::acquire(home.path(), "second", true)
            .unwrap()
            .unwrap();
        assert!(second.read().unwrap().is_none());
        drop(active);
        assert!(
            Claim::acquire(home.path(), "first", true)
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn independent_process_cannot_claim_active_vm() {
        const CHILD_HOME: &str = "MVM_TEST_MAILBOX_OWNER_CONTENDER_HOME";
        if let Some(home) = std::env::var_os(CHILD_HOME) {
            let error = Claim::acquire(Path::new(&home), "same-vm", false)
                .err()
                .expect("second process took active name lock");
            assert!(error.to_string().contains("another operation owns"));
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let claim = Claim::acquire(home.path(), "same-vm", true)
            .unwrap()
            .unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "launch::mailbox_owner::tests::independent_process_cannot_claim_active_vm",
                "--exact",
                "--test-threads=1",
            ])
            .env(CHILD_HOME, home.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "contender failed: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed; 0 failed"));
        drop(claim);
        assert!(
            Claim::acquire(home.path(), "same-vm", true)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn uncertain_acquire_survives_reopen_and_prevents_runtime_deletion() {
        let home = tempfile::tempdir().unwrap();
        let active = Claim::acquire(home.path(), "test", true).unwrap().unwrap();
        active.write(&pending()).unwrap();
        drop(active);
        let reopened = Claim::acquire(home.path(), "test", false).unwrap().unwrap();
        assert!(
            stop_claim(&reopened, "test", None, || -> Result<()> {
                panic!("pending owner allowed cleanup")
            })
            .is_err()
        );
        assert!(matches!(
            reopened.read().unwrap(),
            Some(Record::Pending { .. })
        ));
    }
    #[test]
    fn malformed_or_linked_locator_never_allows_cleanup() {
        let home = tempfile::tempdir().unwrap();
        let active = Claim::acquire(home.path(), "test", true).unwrap().unwrap();
        let record = home.path().join("state/mailbox-owners-v1/test.json");
        std::fs::write(&record, b"{").unwrap();
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            stop_claim(&active, "test", None, || -> Result<()> {
                panic!("malformed locator allowed cleanup")
            })
            .is_err()
        );
        std::fs::remove_file(&record).unwrap();
        let other = home.path().join("other");
        std::fs::write(&other, b"original").unwrap();
        symlink(&other, &record).unwrap();
        assert!(active.read().is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"original");
    }
    #[test]
    fn forged_stop_locator_remains_on_disk_and_cannot_authorize_vm_cleanup() {
        use mvm_core::protocol::broker_control::{self, ControlRequest};
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        mvm_hostd::audit::host_keypair::load_or_init_at(&home.path().join("keys")).unwrap();
        let Record::Pending { mut acquire } = pending() else {
            unreachable!()
        };
        let ctx = context_commitment(&acquire).unwrap();
        acquire.operation = MailboxWorkerOperation::Stop {
            owner: MailboxWorkerOwner {
                daemon_boot_nonce: [7; 32],
                lease: [8; 32],
                generation: 1,
                context_commitment: ctx,
            },
        };
        let foreign =
            broker_control::sign(ControlRequest::MailboxWorkerV1(acquire), &[0x88; 32]).unwrap();
        let claim = Claim::acquire(home.path(), "test", true).unwrap().unwrap();
        claim
            .write(&Record::Owned {
                stop: Box::new(foreign),
            })
            .unwrap();
        drop(claim);
        assert!(
            stop_with("test", None, || -> Result<()> {
                panic!("forged locator allowed VM deletion")
            })
            .is_err()
        );
        let claim = Claim::acquire(home.path(), "test", false).unwrap().unwrap();
        assert!(matches!(claim.read().unwrap(), Some(Record::Owned { .. })));
    }
    #[test]
    fn refuses_linked_state_directory_and_claim_file() {
        let home = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        symlink(foreign.path(), home.path().join("state")).unwrap();
        assert!(Claim::acquire(home.path(), "test", true).is_err());
        assert!(std::fs::read_dir(foreign.path()).unwrap().next().is_none());
        std::fs::remove_file(home.path().join("state")).unwrap();
        drop(Claim::acquire(home.path(), "test", true).unwrap());
        let unsafe_lock = home.path().join("state/mailbox-owners-v1/test.lock");
        symlink(home.path().join("absent"), &unsafe_lock).unwrap();
        assert!(Claim::acquire(home.path(), "test", true).is_err());
    }
    #[test]
    fn absent_owner_stop_preserves_legacy_result_under_name_lock() {
        let home = tempfile::tempdir().unwrap();
        let claim = Claim::acquire(home.path(), "test", true).unwrap().unwrap();
        for _ in 0..2 {
            let observed = stop_claim(&claim, "test", None, || {
                assert!(Claim::acquire(home.path(), "test", true).is_err());
                Ok(17)
            })
            .unwrap();
            assert_eq!(observed, 17);
        }
    }
}
