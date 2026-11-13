//! An installed controller may re-exec its collected journal helper for the same
//! still-running VM. Its launch claim and durable marker never change owners.
use super::super::{MailboxProcessConfig, OriginalJournalStartup};
use super::{LaunchClaim, OriginalMarker, relay::OriginalJournalSourceHost, stop::StopCustody};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::{
        fd::OwnedFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    process::{Child, ExitStatus, Stdio},
    time::Instant,
};

struct SocketOriginal {
    #[cfg(target_os = "linux")]
    file: File,
}
impl SocketOriginal {
    fn capture(path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let file = File::options()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                .open(path)?;
            if !file.metadata()?.file_type().is_socket() {
                return Err(io::Error::other("original socket is not a socket"));
            }
            Ok(Self { file })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if !std::fs::symlink_metadata(path)?.file_type().is_socket() {
                return Err(io::Error::other("original socket is not a socket"));
            }
            Ok(Self {})
        }
    }
    fn retire(&self, path: &Path, until: Instant) -> io::Result<()> {
        if Instant::now() >= until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
            #[cfg(target_os = "linux")]
            Ok(named)
                if same_inode(&self.file.metadata()?, &named)
                    && named.file_type().is_socket()
                    && named.nlink() == 1 =>
            {
                let probe = mvm_agentd::vsock::connect_unix_before(path, until);
                match probe {
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::ConnectionRefused) =>
                    {
                        ()
                    }
                    _ => {
                        return Err(io::Error::other(
                            "original socket still accepts or is uncertain",
                        ));
                    }
                }
                if !same_inode(&self.file.metadata()?, &std::fs::symlink_metadata(path)?) {
                    return Err(io::Error::other("stale socket was replaced"));
                }
                std::fs::remove_file(path)
            }
            Ok(_) => Err(io::Error::other(
                "occupied socket cannot be proved original",
            )),
        }
    }
}
fn same_inode(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}

// The controller and root are trusted. A sticky root-owned directory allows
// other UIDs to create names, but not to replace the next trusted component.
fn require_trusted_image(path: &Path) -> Result<std::fs::Metadata> {
    ensure!(path.is_absolute(), "helper executable path is relative");
    let current = rustix::process::geteuid().as_raw();
    for parent in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir()
                && (m.uid() == current || m.uid() == 0)
                && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0)),
            "untrusted directory on helper executable path"
        );
    }
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && (m.uid() == 0 || m.uid() == current)
            && m.mode() & 0o022 == 0
            && m.mode() & 0o111 != 0,
        "untrusted helper executable"
    );
    Ok(m)
}

pub(super) struct RestartInput {
    config: MailboxProcessConfig,
    image: File,
    image_change: (i64, i64),
    reader_digest: Option<[u8; 32]>,
    program: PathBuf,
    owner: File,
    keys_dir: File,
    socket: Option<SocketOriginal>,
}
impl RestartInput {
    pub(super) fn capture(
        config: &MailboxProcessConfig,
        bin: &OsStr,
        owner_dir: &Path,
    ) -> Result<Self> {
        let program = std::fs::canonicalize(bin)?;
        let named = require_trusted_image(&program)?;
        let image = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&program)?;
        ensure!(
            same_inode(&image.metadata()?, &named),
            "installed helper changed at capture"
        );
        let image_meta = image.metadata()?;
        let image_change = (image_meta.ctime(), image_meta.ctime_nsec());
        let open_dir = |path: &Path| {
            File::options()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)
        };
        let owner = open_dir(owner_dir)?;
        let keys_dir = open_dir(&config.keys_dir)?;
        Ok(Self {
            config: config.clone(),
            image,
            image_change,
            reader_digest: None,
            program,
            owner,
            keys_dir,
            socket: None,
        })
    }
    pub(super) fn capture_socket(&mut self) -> io::Result<()> {
        let digest = super::super::reader::original_enrollment_digest(&self.config.vm_state_dir)?;
        if self
            .reader_digest
            .is_some_and(|expected| expected != digest)
        {
            return Err(io::Error::other("original reader enrollment changed"));
        }
        self.reader_digest = Some(digest);
        self.socket = Some(SocketOriginal::capture(&self.config.socket)?);
        Ok(())
    }
    fn current(
        &self,
        guard: &LaunchClaim,
        marker: &OriginalMarker,
        stop: &mut StopCustody,
        until: Instant,
    ) -> Result<super::super::lifetime::OriginalVmm> {
        ensure!(
            Instant::now() < until,
            "original helper reconnect deadline elapsed"
        );
        for (held, path) in [
            (&self.owner, &guard.owner_dir),
            (&self.keys_dir, &self.config.keys_dir),
        ] {
            let m = held.metadata()?;
            ensure!(
                m.mode() & 0o022 == 0
                    && m.uid() == rustix::process::geteuid().as_raw()
                    && same_inode(&m, &std::fs::symlink_metadata(path)?),
                "original owner or key directory changed"
            );
        }
        marker.require_original()?;
        let c = &self.config;
        let original = stop.live_for_reconnect(&c.vm_state_dir)?;
        let plan = super::super::load_admitted_plan(&c.vm_state_dir)?;
        let boot = c.reader_boot.as_ref().context("missing original boot")?;
        ensure!(
            plan.plan_id == mvm_core::plan::compute_plan_id(&plan)
                && plan.mailbox == Some(c.grant)
                && super::super::load_reader_boot_for_plan(&c.vm_state_dir, &plan)?.as_ref()
                    == Some(boot),
            "original grant, plan or boot changed"
        );
        c.posture
            .as_ref()
            .context("absent original launch posture")?
            .verify(&plan, &plan.image.name, Some(boot.boot))?;
        ensure!(
            self.reader_digest
                == Some(super::super::reader::original_enrollment_digest(
                    &c.vm_state_dir
                )?),
            "original reader enrollment changed"
        );
        self.command()?;
        Ok(original)
    }

    pub(super) fn command(&self) -> Result<std::process::Command> {
        let image = self.image.metadata()?;
        let named = require_trusted_image(&self.program)?;
        ensure!(
            (image.ctime(), image.ctime_nsec()) == self.image_change && same_inode(&image, &named),
            "installed helper executable changed"
        );
        Ok(super::super::command(&self.program))
    }
    fn replace(
        &mut self,
        child: &mut Child,
        readiness: &mut Option<String>,
        original: super::super::lifetime::OriginalVmm,
        until: Instant,
    ) -> Result<ExitStatus> {
        let previous = child
            .try_wait()?
            .context("original helper is still running")?;
        // Keep a previously failed/ambiguous replacement fenced until its
        // own Child is definitively collected; never touch a substitute name.
        if let Some(socket) = &self.socket {
            socket.retire(&self.config.socket, until)?;
        } else {
            ensure!(
                matches!(std::fs::symlink_metadata(&self.config.socket),Err(e) if e.kind()==io::ErrorKind::NotFound),
                "unconfirmed helper socket is occupied"
            );
        }
        *readiness = Some("replacement readiness unconfirmed".into());
        let (mut private, peer) = UnixStream::pair()?;
        let mut command = self.command()?;
        command
            .arg(super::super::ORIGINAL_JOURNAL_V1)
            .stdin(Stdio::from(OwnedFd::from(peer.try_clone()?)))
            .stdout(Stdio::from(OwnedFd::from(peer)));
        ensure!(
            Instant::now() < until,
            "original helper reconnect deadline elapsed"
        );
        *child = command.spawn()?;
        drop(command);
        self.socket = None;
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&OriginalJournalStartup {
            config: &self.config,
            original_vmm_v1: original,
            required_reader_sha256: self.reader_digest,
        })?);
        mvm_vmm::host::hvf_control_transport::write_all(&mut private, &bytes, until)?;
        private.shutdown(std::net::Shutdown::Write)?;
        let mut ready = [0; super::super::READY_MARKER.len()];
        mvm_vmm::host::hvf_control_transport::read_exact(&mut private, &mut ready, until)?;
        ensure!(
            &ready == super::super::READY_MARKER && child.try_wait()?.is_none(),
            "replacement helper not ready"
        );
        self.capture_socket()?;
        Ok(previous)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum JournalHelper {
    Source,
    Destination,
}

enum RecoveryAction {
    ReopenCollected,
    #[cfg(target_os = "linux")]
    InterruptOwned,
}

#[cfg(any(target_os = "linux", test))]
fn collect_interrupted_helper(
    child: &mut Child,
    readiness: &mut Option<String>,
    until: Instant,
) -> Result<ExitStatus> {
    use mvm_vmm::host::process_exit::{
        ProcessExitObserver, ProcessExitWait, collect_after_exit_event,
    };
    ensure!(
        Instant::now() < until,
        "helper interruption deadline elapsed"
    );
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    let observer = ProcessExitObserver::arm(libc::pid_t::try_from(child.id())?)?;
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    ensure!(
        Instant::now() < until,
        "helper interruption deadline elapsed"
    );
    *readiness = Some("original helper interruption awaits recovery".into());
    child.kill()?;
    ensure!(
        observer.wait_event(until)? == ProcessExitWait::Exited,
        "original helper exit is unconfirmed"
    );
    collect_after_exit_event(until, || child.try_wait())?
        .context("original helper status is uncollected")
}

impl OriginalJournalSourceHost {
    /// Re-exec a definitively collected helper under the same pair of live
    /// boots, current credentials and exclusive SDK launch claims.
    pub fn reconnect_helper(&mut self, which: JournalHelper, until: Instant) -> Result<ExitStatus> {
        self.recover_helper(which, until, RecoveryAction::ReopenCollected)
    }

    /// Interrupt and replace one owned Linux helper while both admitted VMs
    /// remain live. Outstanding operations require their original retry.
    /// Other platforms refuse before interrupting a helper.
    pub fn restart_helper(&mut self, which: JournalHelper, until: Instant) -> Result<ExitStatus> {
        #[cfg(target_os = "linux")]
        {
            self.recover_helper(which, until, RecoveryAction::InterruptOwned)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (which, until);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "controlled live helper restart requires pinned socket retirement",
            )
            .into())
        }
    }

    fn recover_helper(
        &mut self,
        which: JournalHelper,
        until: Instant,
        action: RecoveryAction,
    ) -> Result<ExitStatus> {
        #[cfg(not(target_os = "linux"))]
        let _ = action;
        self.require_original_relay()?;
        let until = until.min(Instant::now() + super::super::READY_TIMEOUT);
        let shared = self.destination.clone();
        let mut held = shared
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original destination busy"))?;
        let b = &mut *held;
        let a_vmm = self
            .restart
            .current(&self._guard, &self.marker, &mut self.stop, until)?;
        let b_vmm = b
            .restart
            .current(&b._original, &b.marker, &mut b.stop, until)?;
        b.check_current_credentials(&self.plan, &self.grants)?;
        #[cfg(target_os = "linux")]
        if matches!(action, RecoveryAction::InterruptOwned) {
            match which {
                JournalHelper::Source => {
                    collect_interrupted_helper(&mut self.source, &mut self.readiness, until)?;
                }
                JournalHelper::Destination => {
                    let destination = &mut *b;
                    collect_interrupted_helper(
                        &mut destination.child,
                        &mut destination.readiness,
                        until,
                    )?;
                }
            }
            self.restart
                .current(&self._guard, &self.marker, &mut self.stop, until)?;
            b.restart
                .current(&b._original, &b.marker, &mut b.stop, until)?;
            b.check_current_credentials(&self.plan, &self.grants)?;
        }
        let prior = match which {
            JournalHelper::Source => {
                self.restart
                    .replace(&mut self.source, &mut self.readiness, a_vmm, until)?
            }
            JournalHelper::Destination => {
                let dest = &mut *b;
                dest.restart
                    .replace(&mut dest.child, &mut dest.readiness, b_vmm, until)?
            }
        };
        self.restart
            .current(&self._guard, &self.marker, &mut self.stop, until)?;
        b.restart
            .current(&b._original, &b.marker, &mut b.stop, until)?;
        b.check_current_credentials(&self.plan, &self.grants)?;
        self.require_original_relay()?;
        ensure!(
            Instant::now() < until,
            "original helper reconnect deadline elapsed"
        );
        match which {
            JournalHelper::Source => self.readiness = None,
            JournalHelper::Destination => b.readiness = None,
        }
        Ok(prior)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn owned_helper() -> Child {
        mvm_core::env_hygiene::helper_command("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start owned helper fixture")
    }

    #[test]
    fn controlled_exit_collects_the_owned_child_and_keeps_readiness_fenced() {
        let mut child = owned_helper();
        let mut readiness = None;
        let until = Instant::now() + std::time::Duration::from_secs(3);
        let status = collect_interrupted_helper(&mut child, &mut readiness, until)
            .expect("collect original helper through its exit observer");
        assert!(!status.success());
        assert_eq!(
            child.try_wait().expect("original child status"),
            Some(status)
        );
        assert!(readiness.is_some());
        assert_eq!(
            collect_interrupted_helper(&mut child, &mut readiness, until)
                .expect("retry retains original status"),
            status
        );
    }

    #[test]
    fn expired_interruption_deadline_leaves_the_original_child_running() {
        let mut child = owned_helper();
        let mut readiness = None;
        let result = collect_interrupted_helper(&mut child, &mut readiness, Instant::now());
        assert!(result.is_err());
        assert!(child.try_wait().expect("original child status").is_none());
        assert!(readiness.is_none());
        child.kill().expect("clean up owned fixture");
        child.wait().expect("collect owned fixture");
    }

    #[test]
    fn recovered_socket_never_removes_a_substituted_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("mailbox.sock");
        let old = UnixListener::bind(&path).unwrap();
        let pin = SocketOriginal::capture(&path).unwrap();
        drop(old);
        std::fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        assert!(
            pin.retire(&path, Instant::now() + std::time::Duration::from_secs(1))
                .is_err()
        );
        assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
        drop(replacement);
        std::fs::remove_file(&path).unwrap();
        pin.retire(&path, Instant::now() + std::time::Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn group_writable_executable_or_parent_fences_the_private_configuration() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .unwrap();
        let bin = dir.path().join("helper");
        std::fs::write(&bin, b"fixture").unwrap();
        let bin = bin.canonicalize().unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(require_trusted_image(&bin).is_ok());
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o720)).unwrap();
        assert!(require_trusted_image(&bin).is_err());
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(require_trusted_image(&bin).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collected_helper_can_retire_only_its_original_stale_socket() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("original");
        let listener = UnixListener::bind(&path).unwrap();
        let pin = SocketOriginal::capture(&path).unwrap();
        assert!(
            pin.retire(&path, Instant::now() + std::time::Duration::from_secs(1))
                .is_err()
        );
        drop(listener);
        pin.retire(&path, Instant::now() + std::time::Duration::from_secs(1))
            .unwrap();
        assert!(!path.exists());
    }
}
