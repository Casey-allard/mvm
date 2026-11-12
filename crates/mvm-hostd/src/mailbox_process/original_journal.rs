//! Custody of a live destination helper for an explicitly paired local journal.
//! Only the canonical production launch can give a caller this handle. It
//! retains the original Child until collection. A pidfile cannot recreate it.

pub mod authorization;
pub mod relay;

use super::{MailboxLaunchPosture, MailboxProcessConfig, spawn_serving, spawn_with_original};
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
    child: Child,
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
            |config, plan, guard| Self::spawn(config, plan, guard).map_err(std::io::Error::other),
        )?
        .context("destination VM has no admitted mailbox")
    }

    fn spawn(
        config: &MailboxProcessConfig,
        plan: &ExecutionPlan,
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
        let (policy, _) = config.keys.trust();
        let current = &policy.context;
        let address = MailboxAddress {
            tenant: current.expected_tenant,
            authorization_domain: current.expected_authorization_domain,
            mailbox: config.grant.mailbox,
            recipient: current.expected_recipient,
        };
        let marker = OriginalMarker::claim(&guard.owner_dir)?;
        let child = spawn_serving(config, &config.vm_state_dir)?;
        Ok(Self {
            child,
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

    /// Before sending any credential or ciphertext, authenticate the connected
    /// kernel peer against the exclusively owned, still-live original Child.
    pub fn connect(&mut self, deadline: Instant) -> Result<UnixStream> {
        authenticated_connect(&mut self.child, &self.socket, deadline)
    }

    /// Observe terminal status only by collecting the original Child.
    pub fn try_collect(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.marker.collect(&mut self.child)
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

pub(super) struct LaunchClaim {
    _guard: FileLock,
    pub(super) owner_dir: PathBuf,
}

pub(super) fn owner_dir(keys_dir: &std::path::Path, name: &str) -> std::io::Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let root = keys_dir.join("mailbox-original-owners-v1");
    mvm_core::private_fs::ensure_private_dir(&root).map_err(std::io::Error::other)?;
    let dir = root.join(hex::encode(Sha256::digest(name.as_bytes())));
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

pub(super) const MARKER: &str = "mailbox-paired-original-v1";

/// Kept on disk through either launcher crash or an uncollected Child. The
/// ordinary Drop of Child/FileLock is never proof that a subprocess exited.
struct OriginalMarker {
    path: PathBuf,
    original: std::fs::File,
    token: [u8; 32],
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
            cleared: false,
        })
    }

    fn collect(&mut self, child: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };
        if !self.cleared {
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
            std::fs::remove_file(&self.path)?;
            mvm_core::util::atomic_io::sync_dir(self.path.parent().unwrap())
                .map_err(std::io::Error::other)?;
            self.cleared = true;
        }
        Ok(Some(status))
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
