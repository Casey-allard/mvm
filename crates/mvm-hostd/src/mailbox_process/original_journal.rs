//! Custody of a live destination helper for an explicitly paired local journal.
//! Only the canonical production launch can give a caller this handle. It
//! retains the original Child until collection. A pidfile cannot recreate it.

pub mod authorization;
#[cfg(test)]
mod paired_process_tests;
pub mod relay;
mod stop;
pub use stop::{JournalOwner, JournalStopOutcome};
mod runtime_state;
pub use runtime_state::FreshState;

use super::{MailboxLaunchPosture, MailboxProcessConfig, spawn_with_original};
use anyhow::{Context, Result, ensure};
use mvm_agentd::vsock::connect_unix_before;
use mvm_contract::protocol::mailbox::{MailboxAddress, PrincipalId};
use mvm_core::mailbox::reader::MailboxReaderBootBinding;
use mvm_core::plan::{ExecutionPlan, Variant};
use mvm_core::util::atomic_io::FileLock;
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::host::uds_peer::connected_peer_pid;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use std::time::Instant;

/// The program which starts B owns its real process. Borrowing the handle
/// cannot transfer the mailbox keys, change its recipient, or reopen a PID.
pub struct OriginalJournalDestination {
    pub(super) incoming: Option<super::paired_incoming::EnrolledIncoming>,
    child: Child,
    readiness: Option<String>,
    stop: stop::StopCustody,
    _original: std::sync::Arc<LaunchClaim>,
    marker: OriginalMarker,
    socket: PathBuf,
    boot: MailboxReaderBootBinding,
    address: MailboxAddress,
    policy_epoch: u64,
    issuer: PrincipalId,
    keys_dir: PathBuf,
    name: String,
    revocations_path: PathBuf,
    inbound: mvm_core::mailbox::OpenContext,
    sender_key: ed25519_dalek::VerifyingKey,
}

impl OriginalJournalDestination {
    /// Select this launcher instead of the ordinary PID-only launcher when B
    /// is the destination of an installed pair. All canonical admission,
    /// retention and verified cold-boot checks still run.
    pub fn start(
        plan: &ExecutionPlan,
        backend: &AnyBackend,
        vm_name: &str,
        posture: &MailboxLaunchPosture,
    ) -> Result<Self> {
        let owner = Self::start_custodied(plan, backend, vm_name, posture)?;
        if let Err(err) = owner.require_ready() {
            // The convenience API cannot hand an unready endpoint to a caller.
            // Return its actual child as a typed error for explicit collection.
            return Err(IncompleteJournalStart::new(err, owner).into());
        }
        Ok(owner)
    }

    /// Return custody even on a post-exec configuration/readiness failure.
    /// Call require_ready before advertising the endpoint.
    pub fn start_custodied(
        plan: &ExecutionPlan,
        backend: &AnyBackend,
        vm_name: &str,
        posture: &MailboxLaunchPosture,
    ) -> Result<Self> {
        ensure!(
            posture.variant() == Variant::Prod,
            "paired journal requires production admission"
        );
        spawn_with_original(
            plan,
            backend,
            vm_name,
            Some(posture),
            true,
            |config, plan, guard| {
                Self::spawn(config, plan, backend, guard).map_err(std::io::Error::other)
            },
        )?
        .context("destination VM has no admitted mailbox")
    }

    fn spawn(
        config: &MailboxProcessConfig,
        plan: &ExecutionPlan,
        backend: &AnyBackend,
        guard: std::sync::Arc<LaunchClaim>,
    ) -> Result<Self> {
        let boot = config
            .reader_boot
            .clone()
            .context("guest reader boot is absent")?;
        boot.check_plan(plan)?;
        ensure!(
            config.grant.retention.is_some(),
            "destination has no admitted retention"
        );
        let (mut policy, sealer) = config.keys.trust();
        let current = &policy.context;
        let address = MailboxAddress {
            tenant: current.expected_tenant,
            authorization_domain: current.expected_authorization_domain,
            mailbox: config.grant.mailbox,
            recipient: current.expected_recipient,
        };
        let incoming = if config.grant.incoming_journal_policy_sha256_v1.is_some() {
            let posture = config
                .posture
                .as_ref()
                .context("missing original destination posture")?;
            let retained = crate::mailbox_custody::RetainedMailboxKeys::open_existing(
                &config.keys_dir,
                plan,
                &plan.image.name,
                posture,
                Some(boot.boot),
                address,
            )?;
            let signer = config.keys.durable_material().0;
            let reader = super::reader::load_or_enroll(
                &config.vm_state_dir,
                &config.grant,
                boot.clone(),
                &sealer.capability,
                &signer,
            )?;
            let enrolled = super::paired_incoming::EnrolledIncoming::open(
                &config.keys_dir,
                &config.grant,
                &retained,
                &boot,
                &reader,
            )?
            .context("B incoming policy absent")?;
            enrolled.apply(&mut policy)?;
            Some(enrolled)
        } else {
            None
        };
        let current = &policy.context;
        let stop = stop::StopCustody::capture(config, backend, &plan.image.name)?;
        let (mut child, marker) = spawn_claimed(&guard.owner_dir, super::serving_command()?)?;
        let readiness = super::configure_serving(config, &mut child)
            .err()
            .map(|e| e.to_string());
        Ok(Self {
            child,
            readiness,
            stop,
            incoming,
            _original: guard,
            marker,
            socket: config.socket.clone(),
            boot,
            address,
            policy_epoch: current.current_policy_epoch,
            issuer: current.expected_capability_issuer,
            keys_dir: config.keys_dir.clone(),
            name: plan.image.name.clone(),
            revocations_path: super::reader::revocations_path(&config.vm_state_dir),
            inbound: current.clone(),
            sender_key: policy.sender_key,
        })
    }

    pub(crate) fn peer_state(&self, name: &str) -> Result<PathBuf> {
        mvm_core::naming::validate_vm_name(name)?;
        let state = self
            .revocations_path
            .parent()
            .context("missing original VM state")?;
        Ok(state.with_file_name(name))
    }

    /// Before sending any credential or ciphertext, authenticate the connected
    /// kernel peer against the exclusively owned, still-live original Child.
    pub fn connect(&mut self, deadline: Instant) -> Result<UnixStream> {
        self.require_ready()?;
        authenticated_connect(&mut self.child, &self.socket, deadline)
    }

    /// Observe terminal status only by collecting the original Child.
    pub fn try_collect(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.marker.collect(&mut self.child)
    }

    /// Request termination through the retained original Child. The caller
    /// must first confirm VM stop and separately report assisted teardown.
    /// Only try_collect can clear this helper's persistent ownership record.
    pub fn request_original_exit_after_vm_stop(&mut self) -> std::io::Result<()> {
        request_original_exit(&mut self.child)
    }

    pub fn require_ready(&self) -> Result<()> {
        if let Some(e) = &self.readiness {
            anyhow::bail!("original B did not become ready: {e}");
        }
        Ok(())
    }

    pub fn binding(&self) -> &MailboxReaderBootBinding {
        &self.boot
    }
    pub fn address(&self) -> MailboxAddress {
        self.address
    }
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }
    pub fn issuer(&self) -> PrincipalId {
        self.issuer
    }
}

/// A convenience launch that crossed exec but failed its readiness handshake.
/// Retains the exact original owner for inspection, stop and collection.
pub struct IncompleteJournalStart<T> {
    reason: String,
    pub owner: std::sync::Mutex<T>,
}
impl<T> IncompleteJournalStart<T> {
    fn new(error: anyhow::Error, owner: T) -> Self {
        Self {
            reason: error.to_string(),
            owner: std::sync::Mutex::new(owner),
        }
    }
}
impl<T> std::fmt::Debug for IncompleteJournalStart<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}
impl<T> std::fmt::Display for IncompleteJournalStart<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}
impl<T> std::error::Error for IncompleteJournalStart<T> {}

fn spawn_claimed(
    dir: &std::path::Path,
    mut command: std::process::Command,
) -> std::io::Result<(Child, OriginalMarker)> {
    let mut marker = OriginalMarker::claim(dir)?;
    match command.spawn() {
        Ok(child) => Ok((child, marker)),
        Err(exec) => {
            marker.clear_original()?;
            Err(exec)
        }
    }
}

pub(super) struct LaunchClaim {
    _guard: FileLock,
    pub(super) owner_dir: PathBuf,
}

pub(super) fn owner_dir(keys_dir: &std::path::Path, name: &str) -> std::io::Result<PathBuf> {
    let root = keys_dir.join("mailbox-original-owners-v1");
    mvm_core::private_fs::ensure_private_dir(&root).map_err(std::io::Error::other)?;
    let dir = mvm_core::config::vm_mailbox_original_owner_at(keys_dir, name);
    mvm_core::private_fs::ensure_private_dir(&dir).map_err(std::io::Error::other)?;
    mvm_core::util::atomic_io::sync_dir(keys_dir).map_err(std::io::Error::other)?;
    mvm_core::util::atomic_io::sync_dir(&root).map_err(std::io::Error::other)?;
    Ok(dir)
}

pub(super) fn claim_launch(
    state: &std::path::Path,
    owner_dir: &std::path::Path,
    exclusive: bool,
) -> std::io::Result<std::sync::Arc<LaunchClaim>> {
    use std::io::{Error, ErrorKind};
    let guard = FileLock::try_acquire(&owner_dir.join("mailbox-launch"))
        .map_err(Error::other)?
        .ok_or_else(|| Error::new(ErrorKind::WouldBlock, "mailbox launch is owned"))?;
    let path = owner_dir.join(MARKER);
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => (),
        Err(e) => return Err(e),
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "original paired helper has unresolved custody",
            ));
        }
    }
    if exclusive {
        for path in [
            state.join(super::MAILBOX_PID_FILE),
            mvm_core::config::vm_mailbox_socket_at(state),
        ] {
            match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == ErrorKind::NotFound => (),
                Err(e) => return Err(e),
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        "existing mailbox original requires canonical retirement",
                    ));
                }
            }
        }
    }
    Ok(std::sync::Arc::new(LaunchClaim {
        _guard: guard,
        owner_dir: owner_dir.to_path_buf(),
    }))
}

/// Per-name exclusion held across lifecycle operations for ordinary and paired machines.
pub struct PairedBootReservation {
    _boot: FileLock,
    owner: PathBuf,
    state: PathBuf,
}

impl PairedBootReservation {
    /// Serialize mutations without granting access to a helper. The paired
    /// stop path must separately establish custody of its exact original Child.
    pub fn for_original_lifecycle(name: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        mvm_core::naming::validate_vm_name(name)?;
        let keys = mvm_core::config::mvm_keys_dir();
        let digest = Sha256::digest(name.as_bytes());
        let shard = u16::from_be_bytes([digest[0], digest[1]]) >> 4;
        let locks = keys.join("mailbox-sdk-locks-v1");
        mvm_core::private_fs::ensure_private_dir(&locks)?;
        let boot =
            FileLock::try_acquire(&locks.join(format!("{shard:03x}")))?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "machine lifecycle operation is already in progress",
                )
            })?;
        Ok(Self {
            _boot: boot,
            owner: keys
                .join("mailbox-original-owners-v1")
                .join(hex::encode(digest)),
            state: mvm_core::config::vm_state_dir(name),
        })
    }

    pub fn for_lifecycle_mutation(name: &str) -> Result<Self> {
        let reserved = Self::for_original_lifecycle(name)?;
        // Ordinary transient names take a bounded shard lock without creating
        // a permanent owner entry. Only an actual mailbox enrollment needs one.
        match std::fs::symlink_metadata(&reserved.owner) {
            Ok(_) => {
                let original = owner_dir(&mvm_core::config::mvm_keys_dir(), name)?;
                claim_launch(&reserved.state, &original, false)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        Ok(reserved)
    }

    pub fn require_name(&self, name: &str) -> Result<()> {
        mvm_core::naming::validate_vm_name(name)?;
        ensure!(
            self.state == mvm_core::config::vm_state_dir(name),
            "reservation is for a different machine or MVM home"
        );
        Ok(())
    }

    pub fn prepare_journal_runtime(&self, name: &str) -> Result<FreshState> {
        self.require_name(name)?;
        let home = mvm_core::config::mvm_home_strict()?;
        let state = mvm_core::config::vm_state_dir_at(&home, name);
        let original = owner_dir(&mvm_core::config::mvm_keys_dir(), name)?;
        let _claim = claim_launch(&state, &original, true)?;
        runtime_state::prepare(&home, name, || {
            ensure!(
                mvm_runtime::vm::reconcile::reap_unowned_state_dir(
                    &state,
                    &mvm_core::config::instance_dir(name)
                )
                .map_err(anyhow::Error::msg)?,
                "VM runtime is still owned"
            );
            Ok(())
        })
    }
}

fn request_original_exit(child: &mut std::process::Child) -> std::io::Result<()> {
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    Ok(())
}

pub(super) const MARKER: &str = mvm_core::config::ORIGINAL_MAILBOX_CLAIM;

/// Kept on disk through either launcher crash or an uncollected Child. The
/// ordinary Drop of Child/FileLock is never proof that a subprocess exited.
struct OriginalMarker {
    path: PathBuf,
    original: std::fs::File,
    token: [u8; 32],
    unlinked: bool,
    cleared: bool,
}

impl OriginalMarker {
    fn claim(state: &std::path::Path) -> std::io::Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = state.join(MARKER);
        let token: [u8; 32] = rand::random();
        let mut original = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        original.write_all(&token)?;
        original.sync_all()?;
        mvm_core::util::atomic_io::sync_dir(state).map_err(std::io::Error::other)?;
        Ok(Self {
            path,
            original,
            token,
            unlinked: false,
            cleared: false,
        })
    }

    fn collect(&mut self, child: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };
        self.clear_original()?;
        Ok(Some(status))
    }

    // Called only after collecting the actual Child, or after Command::spawn
    // returned Err before yielding a Child. A crash at any other point fences.
    fn clear_original(&mut self) -> std::io::Result<()> {
        if self.cleared {
            return Ok(());
        }
        if !self.unlinked {
            self.require_original()?;
            std::fs::remove_file(&self.path)?;
            self.unlinked = true;
        } else if !matches!(std::fs::symlink_metadata(&self.path), Err(e) if e.kind()==std::io::ErrorKind::NotFound)
        {
            return Err(std::io::Error::other(
                "original claim was replaced after unlink",
            ));
        }
        mvm_core::util::atomic_io::sync_dir(self.path.parent().unwrap())
            .map_err(std::io::Error::other)?;
        self.cleared = true;
        Ok(())
    }

    fn require_original(&self) -> std::io::Result<()> {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let original = self.original.metadata()?;
        let named = std::fs::symlink_metadata(&self.path)?;
        let mut token = [0u8; 32];
        self.original.read_exact_at(&mut token, 0)?;
        if (original.dev(), original.ino()) != (named.dev(), named.ino())
            || named.nlink() != 1
            || named.len() != 32
            || token != self.token
        {
            return Err(std::io::Error::other("original marker was replaced"));
        }
        Ok(())
    }
}

fn authenticated_connect(
    child: &mut Child,
    path: &std::path::Path,
    deadline: Instant,
) -> Result<UnixStream> {
    ensure!(
        child.try_wait()?.is_none(),
        "original journal helper exited"
    );
    let socket = connect_unix_before(path, deadline)?;
    let peer = u32::try_from(connected_peer_pid(&socket)?)?;
    ensure!(
        peer == child.id() && child.try_wait()?.is_none(),
        "connected journal endpoint does not belong to the original live helper"
    );
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn original_exec_refusal_releases_only_its_unstarted_claim() {
        let dir = tempfile::tempdir().unwrap();
        let missing = std::process::Command::new(dir.path().join("no-executable"));
        let Err(error) = spawn_claimed(dir.path(), missing) else {
            panic!("unexpected exec");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!dir.path().join(MARKER).exists());
        let mut command = std::process::Command::new("sleep");
        command.arg("15");
        let (mut child, mut marker) = spawn_claimed(dir.path(), command).unwrap();
        assert!(marker.collect(&mut child).unwrap().is_none());
        assert!(dir.path().join(MARKER).is_file());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(marker.collect(&mut child).unwrap().is_some());
    }

    #[test]
    fn unpaired_names_leave_only_bounded_lock_shards() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        let keys = mvm_core::config::mvm_keys_dir();
        for i in 0..128 {
            let name = format!("ephemeral-{i}");
            let reservation = PairedBootReservation::for_lifecycle_mutation(&name).unwrap();
            assert!(reservation.require_name("another-name").is_err());
        }
        assert!(!keys.join("mailbox-original-owners-v1").exists());
        for shard in std::fs::read_dir(keys.join("mailbox-sdk-locks-v1")).unwrap() {
            let path = shard.unwrap().path();
            assert_eq!(path.extension().unwrap(), "lock");
            let stem = path.file_stem().unwrap().to_str().unwrap();
            assert_eq!(stem.len(), 3);
            assert!(u16::from_str_radix(stem, 16).unwrap() < 4096);
        }
    }

    #[test]
    fn paired_sdk_reap_preserves_owned_state_and_serializes_starts() {
        let root = tempfile::Builder::new()
            .prefix("sc")
            .tempdir_in("/tmp")
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        let name = "short";
        let owner = owner_dir(&mvm_core::config::mvm_keys_dir(), name).unwrap();
        let state = mvm_core::config::vm_state_dir(name);
        let instance = mvm_core::config::instance_dir(name);
        mvm_core::private_fs::ensure_private_dir(state.parent().unwrap()).unwrap();
        mvm_core::private_fs::ensure_private_dir(&state).unwrap();
        let sample = state.join("preserved");
        std::fs::write(&sample, b"original").unwrap();
        let mut marker = OriginalMarker::claim(&owner).unwrap();
        assert!(PairedBootReservation::for_lifecycle_mutation(name).is_err());
        assert_eq!(std::fs::read(&sample).unwrap(), b"original");
        let mut child = std::process::Command::new("true").spawn().unwrap();
        child.wait().unwrap();
        assert!(marker.collect(&mut child).unwrap().is_some());
        let first = PairedBootReservation::for_lifecycle_mutation(name).unwrap();
        let live = mvm_runtime::vm::instance_snapshot::try_lock_resume_in(&instance)
            .unwrap()
            .unwrap();
        assert!(first.prepare_journal_runtime(name).is_err());
        assert!(sample.exists());
        drop(live);
        first.prepare_journal_runtime(name).unwrap().commit();
        assert!(!sample.exists());
        assert!(PairedBootReservation::for_lifecycle_mutation(name).is_err());
        drop(first);
        PairedBootReservation::for_lifecycle_mutation(name).unwrap();
    }

    #[test]
    fn journal_peer_child() {
        let Some(path) = std::env::var_os("MVM_TEST_ORIGINAL_JOURNAL_SOCKET") else {
            return;
        };
        let _listener = UnixListener::bind(path).unwrap();
        println!("journal-child-listening");
        std::io::stdout().flush().unwrap();
        let mut done = String::new();
        std::io::stdin().lock().read_line(&mut done).unwrap();
    }

    fn listener(path: &Path) -> Child {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "mailbox_process::original_journal::tests::journal_peer_child",
                "--exact",
                "--nocapture",
            ])
            .env("MVM_TEST_ORIGINAL_JOURNAL_SOCKET", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = std::io::BufReader::new(child.stdout.as_mut().unwrap());
        assert!(
            output
                .lines()
                .map_while(std::result::Result::ok)
                .any(|l| l.contains("journal-child-listening"))
        );
        child
    }

    #[test]
    fn a_second_launcher_cannot_rotate_a_live_original_or_adopt_stale_state() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let original = claim_launch(dir.path(), dir.path(), true).unwrap();
        assert!(claim_launch(dir.path(), dir.path(), false).is_err());
        assert!(claim_launch(dir.path(), dir.path(), true).is_err());
        drop(original);
        let path = dir.path().join(super::super::MAILBOX_PID_FILE);
        std::fs::write(&path, "original marker").unwrap();
        assert!(claim_launch(dir.path(), dir.path(), true).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original marker");
    }

    #[test]
    fn dropping_original_custody_keeps_both_normal_and_paired_starts_fenced() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let guard = claim_launch(dir.path(), dir.path(), true).unwrap();
        let mut marker = OriginalMarker::claim(dir.path()).unwrap();
        let socket = dir.path().join("peer");
        let mut child = listener(&socket);
        assert!(marker.collect(&mut child).unwrap().is_none());
        drop(marker);
        drop(guard);
        assert!(child.try_wait().unwrap().is_none());
        assert!(claim_launch(dir.path(), dir.path(), false).is_err());
        assert!(claim_launch(dir.path(), dir.path(), true).is_err());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert!(claim_launch(dir.path(), dir.path(), false).is_err());
    }

    #[test]
    fn assisted_stop_targets_only_the_held_child_and_still_requires_collection() {
        let directory = tempfile::tempdir().unwrap();
        let mut marker = OriginalMarker::claim(directory.path()).unwrap();
        let mut first = std::process::Command::new("sleep")
            .arg("15")
            .spawn()
            .unwrap();
        let mut second = std::process::Command::new("sleep")
            .arg("15")
            .spawn()
            .unwrap();
        request_original_exit(&mut first).unwrap();
        assert!(marker.path.exists());
        assert!(second.try_wait().unwrap().is_none());
        let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let status = loop {
            if let Some(status) = marker.collect(&mut first).unwrap() {
                break status;
            }
            assert!(std::time::Instant::now() < until);
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert!(!status.success());
        assert!(!marker.path.exists());
        second.kill().unwrap();
        second.wait().unwrap();
    }

    #[test]
    fn definitive_original_collection_is_idempotent_and_protects_the_marker() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mut marker = OriginalMarker::claim(dir.path()).unwrap();
        let mut child = listener(&dir.path().join("peer"));
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert!(marker.collect(&mut child).unwrap().unwrap().success());
        assert!(marker.collect(&mut child).unwrap().unwrap().success());
        let mut other = OriginalMarker::claim(dir.path()).unwrap();
        std::fs::rename(&other.path, dir.path().join("original")).unwrap();
        std::fs::write(&other.path, [0; 32]).unwrap();
        assert!(other.collect(&mut child).is_err());
        assert!(other.path.is_file());
    }

    #[test]
    fn crash_before_child_publication_preserves_unresolved_custody() {
        const CHILD: &str = "MVM_TEST_CRASH_BEFORE_ORIGINAL_JOURNAL_SPAWN";
        if let Some(path) = std::env::var_os(CHILD) {
            let path = Path::new(&path);
            let _guard = claim_launch(path, path, true).unwrap();
            let _marker = OriginalMarker::claim(path).unwrap();
            std::process::exit(71);
        }
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let status = Command::new(std::env::current_exe().unwrap()).args([
            "mailbox_process::original_journal::tests::crash_before_child_publication_preserves_unresolved_custody",
            "--exact"
        ]).env(CHILD,dir.path()).stdout(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(71));
        assert!(claim_launch(dir.path(), dir.path(), false).is_err());
        assert!(claim_launch(dir.path(), dir.path(), true).is_err());
    }

    #[test]
    fn only_original_kernel_peer_can_receive_the_direction() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let socket = dir.path().join("b.sock");
        let mut original = listener(&socket);
        let deadline = || Instant::now() + Duration::from_secs(2);
        assert!(authenticated_connect(&mut original, &socket, deadline()).is_ok());
        std::fs::remove_file(&socket).unwrap();
        let mut replacement = listener(&socket);
        assert!(authenticated_connect(&mut original, &socket, deadline()).is_err());
        drop(original.stdin.take());
        assert!(original.wait().unwrap().success());
        assert!(authenticated_connect(&mut original, &socket, deadline()).is_err());
        drop(replacement.stdin.take());
        assert!(replacement.wait().unwrap().success());
    }
}
