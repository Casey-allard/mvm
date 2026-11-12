//! Durable locator for the original installed mailbox provider and helper.
//! A Pending reservation may have reached the daemon. Preserve it on uncertain
//! delivery or restart. Only the original daemon can prove collection or release.
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
    /// An explicitly installed two-VM development ceremony. Ordinary installed
    /// workers use the legacy one-VM lifecycle.
    fn original_cast_pair(&self) -> Option<&super::cast_rendezvous::OriginalCastPair> {
        None
    }
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
    fn marker_name(&self) -> String {
        format!("{}.retiring", self.name)
    }
    fn read_state(&self) -> Result<(Option<Record>, bool)> {
        let active = self.read_at(&self.record_name())?;
        let retired = self.read_at(&self.marker_name())?;
        ensure!(
            active.is_none() || retired.is_none(),
            "conflicting active and retiring mailbox owners"
        );
        if let Some(record) = retired {
            ensure!(
                matches!(record, Record::Owned { .. }),
                "retirement marker requires original signed Stop"
            );
            return Ok((Some(record), true));
        }
        Ok((active, false))
    }
    fn read(&self) -> Result<Option<Record>> {
        Ok(self.read_state()?.0)
    }
    fn read_at(&self, name: &str) -> Result<Option<Record>> {
        let f = match at(&self.dir, name, OFlags::RDONLY) {
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
    fn retire(&self, original: &InstalledMailboxClient, already_renamed: bool) -> Result<()> {
        let (Some(Record::Owned { stop }), renamed) = self.read_state()? else {
            bail!("original signed mailbox locator unavailable for retirement");
        };
        ensure!(
            renamed == already_renamed,
            "original mailbox retirement position changed"
        );
        let recorded = InstalledMailboxClient::from_stop_locator(&self.name, &stop)?;
        ensure!(
            recorded.owner() == original.owner()
                && recorded.acquire_request() == original.acquire_request(),
            "original signed mailbox locator changed before retirement"
        );
        self.retire_with(already_renamed, File::sync_all)
    }
    fn retire_with(
        &self,
        already_renamed: bool,
        sync_rename: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<()> {
        let marker = self.marker_name();
        if !already_renamed {
            rustix::fs::renameat(
                &self.dir,
                self.record_name().as_str(),
                &self.dir,
                marker.as_str(),
            )?;
        }
        // Once the rename is durable, the active locator is retired. If marker
        // deletion then fails, retry only housekeeping with the original proof.
        sync_rename(&self.dir)?;
        unlink(&self.dir, &marker)?;
        if let Err(error) = self.dir.sync_all() {
            // Only the inert marker can reappear after a crash. Reporting an
            // uncertain VM stop here would invite destructive replay by name.
            tracing::warn!(%error, "retired mailbox marker deletion not durably confirmed");
        }
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
    client: Arc<InstalledMailboxClient>,
    cast_role: Option<mvm_hostd::mailbox_launch::cast_pair::development::PreparedRole>,
    original_peer: Arc<InstalledMailboxPeer>,
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
        let mut client = if let Some(pair)=provisioner.original_cast_pair(){
            pair.index(&claim.name)?;
            InstalledMailboxClient::prepare_cast_reservation(admitted,backend,&claim.name)?
        } else {InstalledMailboxClient::prepare(admitted, backend, &claim.name)?};
        let original = provisioner.original_peer(admitted, backend, client.acquire_request())?;
        client.bind_acquire_peer(original.clone())?;
        // The original issuer and acquisition nonce are covered by the host
        // signature. No reservation can be made before this record is durable.
        claim.write(&Record::PendingV1 {
            lookup: Box::new(client.signed_pending_locator()?),
        })?;
        let mut launch = Self {
            claim,
            client: Arc::new(client),
            cast_role: None,
            original_peer: original.clone(),
            rollback_on_drop: true,
        };
        let peer = provisioner.provision(admitted, backend, launch.client.acquire_request())?;
        ensure!(
            Arc::ptr_eq(&original, &peer),
            "mailbox provisioner changed original daemon"
        );
        Arc::get_mut(&mut launch.client)
            .context("unreleased original before Acquire")?
            .acquire(deadline())?;
        launch.claim.write(&Record::Owned {
            stop: Box::new(launch.client.signed_stop_locator()?),
        })?;
        Ok(launch)
    }
    pub(crate) fn bind_original_cast(
        &mut self,
        pair: &super::cast_rendezvous::OriginalCastPair,
        admission: Arc<AdmittedPlan>,
        config: Arc<mvm_core::vm_backend::VmStartConfig>,
    ) -> Result<()> {
        let mut cancellation = pair.cancel_on_drop(&self.claim.name);
        let (prepared, until) = pair.admit(super::cast_rendezvous::ReservedLaunch {
            plan: admission,
            worker: self.client.clone(),
            config: config.clone(),
        })?;
        self.client
            .check_prepared_development_role(&prepared.role)?;
        let (prior, bytes) =
            prepared
                .boot
                .into_bytes_for_original(&self.client, &config, deadline().min(until))?;
        let path = mvm_core::config::vm_state_dir(&self.claim.name).join("verb-grant.json");
        stage_pair_boot(&path, &prior, &bytes, || {
            pair.published(&self.claim.name, until)
        })?;
        self.client.mark_cast_published(&prepared.role)?;
        self.cast_role = Some(prepared.role);
        cancellation.disarm();
        Ok(())
    }
    pub(crate) fn broker_binding(&self) -> Result<mvm_core::vm_backend::InstalledBrokerBinding> {
        Ok(mvm_core::vm_backend::InstalledBrokerBinding {
            plan_commitment: self.client.acquire_request().plan_commitment,
            owner: self
                .client
                .owner()
                .context("installed mailbox owner missing after acquisition")?
                .clone(),
            peer: self.original_peer.clone(),
        })
    }
    pub(crate) fn start_native<T>(&self, start: impl FnOnce() -> Result<T>) -> Result<T> {
        self.client.start_native(start)
    }
    pub(crate) fn settle_native_start(&self) -> Result<()> {
        self.client.settle_native_start()
    }
    pub(crate) fn configure_and_wait(&mut self, backend: &AnyBackend) -> Result<()> {
        if let Some(role) = self.cast_role.take() {
            return self
                .client
                .configure_development_cast(backend, deadline(), role);
        }
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
        self.client
            .finish_installed_cleanup(false, cleanup, || self.claim.retire(&self.client, false))
    }
}
/// With the per-name claim held, restore the initial grant on a pre-boot peer
/// refusal. If an external writer has replaced it, retain the differing record.
fn stage_pair_boot(
    path: &Path,
    prior: &[u8],
    bound: &[u8],
    peer: impl FnOnce() -> Result<()>,
) -> Result<()> {
    mvm_core::atomic_io::write_private_ephemeral(path, bound)?;
    if let Err(error) = peer() {
        let mut actual = Vec::new();
        File::open(path)?
            .take((bound.len() + 1) as u64)
            .read_to_end(&mut actual)?;
        ensure!(
            actual == bound,
            "original boot file changed during cancelled pair publication"
        );
        mvm_core::atomic_io::write_private_ephemeral(path, prior)?;
        return Err(error);
    }
    Ok(())
}
impl Drop for OwnedLaunch {
    fn drop(&mut self) {
        if self.rollback_on_drop && self.client.owner().is_some() {
            // No backend-cleanup receipt on implicit Drop. Keep the durable
            // locator for the fresh client's stop/recovery even after Stop.
            if let Err(error) = self.client.collect_original_worker() {
                tracing::warn!(%error,"original mailbox stop remains unresolved");
            }
        }
    }
}
pub(crate) fn stop_with(
    name: &str,
    provisioner: Option<&dyn InstalledMailboxProvisioner>,
    cleanup: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let claim = Claim::acquire(&mvm_core::config::mvm_home_strict()?, name, true)?
        .context("mailbox owner store unavailable")?;
    stop_claim(&claim, name, provisioner, cleanup)
}

fn stop_claim(
    claim: &Claim,
    name: &str,
    provisioner: Option<&dyn InstalledMailboxProvisioner>,
    cleanup: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let (record, retiring) = claim.read_state()?;
    let client = match record {
        None => return cleanup(),
        Some(Record::Pending { .. }) => {
            bail!("unsigned pending mailbox record cannot prove original ownership")
        }
        Some(Record::PendingV1 { lookup }) => {
            let mut client = InstalledMailboxClient::from_pending_locator(name, &lookup)?;
            let resolver = provisioner.context("original installed mailbox daemon unavailable")?;
            let original = resolver.resolve_original(&lookup)?;
            client.bind_peer(original.clone())?;
            // The recovery operation can look up ONLY the original reservation.
            // An unknown slot or foreign daemon leaves the Pending record intact.
            client.recover_owner(deadline())?;
            let stop = client.signed_stop_locator()?;
            let mut stopping = InstalledMailboxClient::from_stop_locator(name, &stop)?;
            stopping.bind_peer(original)?;
            claim.write(&Record::Owned {
                stop: Box::new(stop),
            })?;
            stopping
        }
        Some(Record::Owned { stop }) => {
            let mut client = InstalledMailboxClient::from_stop_locator(name, &stop)?;
            let resolver = provisioner.context("original installed mailbox daemon unavailable")?;
            client.bind_peer(resolver.resolve_original(&stop)?)?;
            client
        }
    };
    client.finish_installed_cleanup(retiring, cleanup, || claim.retire(&client, retiring))
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
    fn failed_pair_publication_restores_only_its_own_boot_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("verb-grant.json");
        std::fs::write(&file, b"original").unwrap();
        let result = stage_pair_boot(&file, b"original", b"bound", || {
            assert_eq!(std::fs::read(&file)?, b"bound");
            bail!("peer stopped")
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"original");
        let result = stage_pair_boot(&file, b"original", b"bound", || {
            std::fs::write(&file, b"replacement")?;
            bail!("peer stopped")
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"replacement");
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
    fn interrupted_directory_sync_retains_marker_and_prevents_unowned_backend_cleanup() -> Result<()>
    {
        use mvm_core::protocol::broker_control::{self, ControlRequest};
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir()?;
        env.set("MVM_HOME", home.path());
        let Record::Pending { mut acquire } = pending() else {
            unreachable!()
        };
        let commitment = context_commitment(&acquire)?;
        acquire.operation = MailboxWorkerOperation::Stop {
            owner: MailboxWorkerOwner {
                daemon_boot_nonce: [7; 32],
                lease: [8; 32],
                generation: 1,
                context_commitment: commitment,
            },
        };
        let stored = broker_control::sign(ControlRequest::MailboxWorkerV1(acquire), &[8; 32])?;
        let claim = Claim::acquire(home.path(), "test", true)?.unwrap();
        claim.write(&Record::Owned {
            stop: Box::new(stored),
        })?;
        let error = claim
            .retire_with(false, |_| {
                Err(io::Error::other("directory fsync unavailable"))
            })
            .unwrap_err();
        ensure!(error.to_string().contains("directory fsync unavailable"));
        drop(claim);
        let claim = Claim::acquire(home.path(), "test", false)?.unwrap();
        let (record, retiring) = claim.read_state()?;
        ensure!(retiring && matches!(record, Some(Record::Owned { .. })));
        ensure!(
            stop_claim(&claim, "test", None, || -> Result<()> {
                panic!("retirement marker authorized destructive replay")
            })
            .is_err()
        );
        Ok(())
    }
    // This peer uses real framed control I/O and deliberately drops its Acquire
    // response. The callback is the fault injector, not a production daemon.
    fn lost_ack_peer() -> Result<()> {
        use mvm_vmm::host::mailbox_worker_transport::send_response;
        use std::os::unix::net::UnixListener;

        let path = mvm_core::config::host_agent_control_socket("local");
        std::fs::create_dir_all(path.parent().unwrap())?;
        let listener = UnixListener::bind(path)?;
        let key =
            mvm_hostd::audit::host_keypair::load_or_init_at(&mvm_core::config::mvm_keys_dir())?;
        let record = mvm_core::config::mvm_home_strict()?.join("state/mailbox-owners-v1/test.json");
        let mut acquisition = None;
        let mut owner = None;
        for step in 0..5 {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            let mut length = [0; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            ensure!(length <= MAX_WORKER_CONTROL_BYTES);
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body)?;
            let signed: SignedControl = serde_json::from_slice(&body)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
                .try_into()?;
            if step == 4 {
                use mvm_core::protocol::broker_control::{self, ControlRequest, ControlResponse};
                ensure!(
                    matches!(broker_control::verify(&signed, &key.verifying)?, ControlRequest::Deregister(request)
                    if request.vm_id == "test" && request.mailbox_owner_v1 == owner)
                );
                let body = serde_json::to_vec(&ControlResponse::Ok)?;
                stream.write_all(&(body.len() as u32).to_be_bytes())?;
                stream.write_all(&body)?;
                continue;
            }
            let req = verify_request(&signed, &key.verifying, now)?;
            let current: Record = serde_json::from_slice(&std::fs::read(&record)?)?;
            let state = match (&req.operation, step, current) {
                (MailboxWorkerOperation::Acquire, 0, Record::PendingV1 { lookup }) => {
                    let original = verify_pending_locator(&lookup, &key.verifying, "test")?;
                    ensure!(
                        original.request_nonce == req.request_nonce
                            && context_commitment(original)? == context_commitment(req)?
                    );
                    acquisition = Some(req.request_nonce);
                    owner = Some(MailboxWorkerOwner {
                        daemon_boot_nonce: [7; 32],
                        lease: [8; 32],
                        generation: 1,
                        context_commitment: context_commitment(req)?,
                    });
                    continue; // Simulate committed reservation, then loss of its reply.
                }
                (MailboxWorkerOperation::LookupExistingV1, 1, Record::PendingV1 { .. }) => {
                    ensure!(Some(req.request_nonce) == acquisition);
                    MailboxWorkerState::Reserved
                }
                (MailboxWorkerOperation::Stop { owner }, 2, Record::Owned { stop }) => {
                    let stored = verify_stop_locator(&stop, &key.verifying, "test")?;
                    ensure!(
                        matches!(&stored.operation, MailboxWorkerOperation::Stop { owner: original } if original == owner)
                    );
                    ensure!(stored.request_nonce == acquisition.unwrap());
                    MailboxWorkerState::Reserved
                }
                (MailboxWorkerOperation::ReleaseUnstartedV1 { .. }, 3, Record::Owned { .. }) => {
                    MailboxWorkerState::ReleasedBeforeSpawn
                }
                _ => bail!("unexpected operation or durable owner phase for step {step}"),
            };
            let result = MailboxWorkerResult {
                request_nonce: req.request_nonce,
                owner: owner.clone().unwrap(),
                state,
                delegates_config: false,
            };
            send_response(&mut stream, &result, None, deadline())?;
        }
        if std::env::var_os("MVM_TEST_EXPIRED_HELPER_RECEIPT").is_some() {
            // Simulate complete removal of every server-side control receipt:
            // the live original process will accept no further wire operation.
            drop(listener);
            let mut release = [0];
            io::stdin().read_exact(&mut release)?;
            ensure!(release == [1]);
        }
        Ok(())
    }

    struct FixtureInstallation(Arc<InstalledMailboxPeer>);
    impl InstalledMailboxProvisioner for FixtureInstallation {
        fn original_peer(
            &self,
            _: &AdmittedPlan,
            _: &AnyBackend,
            _: &MailboxWorkerRequest,
        ) -> Result<Arc<InstalledMailboxPeer>> {
            Ok(self.0.clone())
        }
        fn provision(
            &self,
            _: &AdmittedPlan,
            _: &AnyBackend,
            _: &MailboxWorkerRequest,
        ) -> Result<Arc<InstalledMailboxPeer>> {
            Ok(self.0.clone())
        }
        fn resolve_original(&self, _: &SignedControl) -> Result<Arc<InstalledMailboxPeer>> {
            Ok(self.0.clone())
        }
    }
    struct TestProcess(std::process::Child);
    impl Drop for TestProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    fn lost_acquire_reply_recovers_only_original_and_persists_stop_before_cleanup() -> Result<()> {
        run_lost_acquire(false, Duration::ZERO)
    }

    #[test]
    fn confirmed_services_resume_after_receipt_eviction_without_new_wire_operations() -> Result<()>
    {
        run_lost_acquire(true, Duration::ZERO)
    }

    #[test]
    #[ignore = "61-second native terminal-retention qualification"]
    fn confirmed_services_resume_beyond_sixty_seconds_without_reacquisition() -> Result<()> {
        run_lost_acquire(true, Duration::from_secs(61))
    }

    fn run_lost_acquire(retry_after_retirement: bool, delay: Duration) -> Result<()> {
        use crate::admission::{admit_plan_for_boot, admit_plan_tests::pinning_params};
        use mvm_hostd::plan_admission::InMemoryNonceLedger;
        use std::process::Command;

        const WORKER: &str = "MVM_TEST_OWNER_LOST_ACK_WORKER";
        if std::env::var_os(WORKER).is_some() {
            return lost_ack_peer();
        }
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir_in("/tmp")?;
        env.set("MVM_HOME", home.path());
        mvm_hostd::audit::host_keypair::load_or_init_at(&home.path().join("keys"))?;
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"synthetic mailbox fixture")?;
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.vm_name = "test";
        let Record::Pending { acquire } = pending() else {
            unreachable!()
        };
        params.mailbox = Some(acquire.mailbox_grant);
        let admitted = admit_plan_for_boot(params)?;
        let selector = if retry_after_retirement {
            "launch::mailbox_owner::tests::confirmed_services_resume_after_receipt_eviction_without_new_wire_operations"
        } else {
            "launch::mailbox_owner::tests::lost_acquire_reply_recovers_only_original_and_persists_stop_before_cleanup"
        };
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", selector, "--test-threads=1"])
            .env(WORKER, "1");
        if retry_after_retirement {
            command
                .env("MVM_TEST_EXPIRED_HELPER_RECEIPT", "1")
                .stdin(std::process::Stdio::piped());
        }
        let mut worker = TestProcess(command.spawn()?);
        let original =
            FixtureInstallation(Arc::new(InstalledMailboxPeer::from_child(&mut worker.0)?));
        let socket = mvm_core::config::host_agent_control_socket("local");
        let until = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            ensure!(
                Instant::now() < until && worker.0.try_wait()?.is_none(),
                "fixture listener unavailable"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let result = OwnedLaunch::begin(
            &original,
            &admitted.admitted,
            &AnyBackend::from_hypervisor("firecracker"),
            VacantOwner::claim("test")?,
        );
        ensure!(result.is_err(), "lost Acquire reply reported success");
        drop(result);
        let claim = Claim::acquire(home.path(), "test", false)?.unwrap();
        ensure!(matches!(claim.read()?, Some(Record::PendingV1 { .. })));
        drop(claim);

        let mut other = TestProcess(Command::new("sleep").arg("20").spawn()?);
        let replacement =
            FixtureInstallation(Arc::new(InstalledMailboxPeer::from_child(&mut other.0)?));
        let err = stop_with("test", Some(&replacement), || -> Result<()> {
            panic!("wrong original allowed cleanup")
        })
        .unwrap_err();
        ensure!(
            err.to_string().contains("issuer differs"),
            "unexpected refusal: {err}"
        );
        let claim = Claim::acquire(home.path(), "test", false)?.unwrap();
        ensure!(matches!(claim.read()?, Some(Record::PendingV1 { .. })));
        drop(claim);

        if retry_after_retirement {
            let record = home.path().join("state/mailbox-owners-v1/test.json");
            let unavailable = home.path().join("temporarily-unavailable-locator");
            // Complete the local operation, then fault the original removal.
            // Restoring precisely that same file leaves only the final ack to retry.
            let failure = stop_with("test", Some(&original), || {
                std::fs::rename(&record, &unavailable)?;
                Ok(())
            });
            ensure!(
                failure.is_err(),
                "injected owner retirement failure was lost"
            );
            std::fs::rename(&unavailable, &record)?;
            let claim = Claim::acquire(home.path(), "test", false)?.unwrap();
            ensure!(matches!(claim.read()?, Some(Record::Owned { .. })));
            drop(claim);
            std::thread::sleep(delay);
        }
        stop_with("test", Some(&original), || {
            ensure!(
                !retry_after_retirement,
                "destructive backend cleanup was replayed"
            );
            ensure!(
                refuse_existing("test").is_err(),
                "cleanup ran without original claim"
            );
            Ok(())
        })?;
        if retry_after_retirement {
            worker
                .0
                .stdin
                .take()
                .context("missing original fixture pipe")?
                .write_all(&[1])?;
        }
        ensure!(
            worker.0.wait()?.success(),
            "fixture refused recovery sequence"
        );
        let claim = Claim::acquire(home.path(), "test", false)?.unwrap();
        ensure!(claim.read()?.is_none());
        Ok(())
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
            stop_claim(&claim, "test", None, || {
                assert!(Claim::acquire(home.path(), "test", true).is_err());
                Ok(())
            })
            .unwrap();
        }
    }
}
