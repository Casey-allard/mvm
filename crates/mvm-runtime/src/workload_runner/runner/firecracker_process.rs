//! A post-boot rollback may signal only the original process behind the
//! Firecracker API socket. The lifetime descriptor is acquired before guest
//! activation and is reused on every attempt, including after the path changes.
use anyhow::{Context, Result, ensure};
use mvm_vmm::host::{process_identity::ProcessIdentity, uds_peer::connected_peer_pid};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{Signal, pidfd_send_signal};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) struct OriginalFirecracker {
    pub(crate) identity: ProcessIdentity,
    descriptor: OwnedFd,
}

impl OriginalFirecracker {
    pub(super) fn capture(vm: &dyn super::RunningVm, name: &str, state_dir: &Path) -> Result<Self> {
        ensure!(vm.id().0 == name, "driver returned a different original VM");
        let path = mvm_backends::fc::fc_api_socket_path(&state_dir.to_string_lossy());
        Self::from_original_peer(name, Path::new(&path), || {
            vm.process_identity()?
                .context("driver has no original Firecracker identity")
        })
    }

    fn from_original_peer(
        name: &str,
        socket: &Path,
        identity: impl Fn() -> Result<ProcessIdentity>,
    ) -> Result<Self> {
        let before = identity()?;
        ensure!(before.vm_id == name, "original VM name differs");
        let stream = mvm_agentd::vsock::connect_unix_before(
            socket,
            Instant::now() + Duration::from_secs(2),
        )?;
        ensure!(
            u32::try_from(connected_peer_pid(&stream)?)? == before.pid,
            "Firecracker API belongs to another process"
        );
        let descriptor = peer_pidfd(&stream)?;
        ensure!(
            identity()? == before,
            "original process changed during binding"
        );
        let pinned = Self {
            identity: before,
            descriptor,
        };
        ensure!(
            !pinned.exited_before(Instant::now())?,
            "original process exited during binding"
        );
        Ok(pinned)
    }

    fn exited_before(&self, until: Instant) -> Result<bool> {
        loop {
            let mut fds = [PollFd::new(&self.descriptor, PollFlags::IN)];
            let timeout = Timespec::try_from(until.saturating_duration_since(Instant::now()))?;
            match poll(&mut fds, Some(&timeout)) {
                Err(Errno::INTR) if Instant::now() < until => continue,
                Err(error) => return Err(error.into()),
                Ok(0) => return Ok(false),
                Ok(_) => {
                    let events = fds[0].revents();
                    ensure!(
                        events.contains(PollFlags::IN)
                            && !events.intersects(PollFlags::ERR | PollFlags::NVAL),
                        "unconfirmed original pidfd terminal events: {events:?}"
                    );
                    return Ok(true);
                }
            }
        }
    }

    pub(crate) fn verify_exit(&self) -> Result<()> {
        ensure!(
            self.exited_before(Instant::now())?,
            "original Firecracker exit is unconfirmed"
        );
        Ok(())
    }

    pub(super) fn stop(&self) -> Result<()> {
        if self.exited_before(Instant::now())? {
            return Ok(());
        }
        let start = Instant::now();
        for (signal, until) in [
            (Signal::TERM, start + Duration::from_secs(1)),
            (Signal::KILL, start + Duration::from_secs(4)),
        ] {
            match pidfd_send_signal(&self.descriptor, signal) {
                Ok(()) | Err(Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
            if self.exited_before(until)? {
                return Ok(());
            }
        }
        anyhow::bail!("original Firecracker pidfd did not report exit")
    }
}

/// Check kernel support before launching a VM. The actual authority is
/// obtained later from the original Firecracker socket, never from this pair.
pub(super) fn require_peer_pidfd() -> Result<()> {
    let (probe, _other) = UnixStream::pair()?;
    peer_pidfd(&probe)?;
    Ok(())
}

// Linux >= 6.5 supplies the lifetime descriptor directly from the connected
// socket. Unsupported kernels fail closed before the workload is activated.
fn peer_pidfd(stream: &UnixStream) -> Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of_val(&fd) as libc::socklen_t;
    // SAFETY: all pointers reference live buffers of the indicated size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("obtain original Firecracker API peer pidfd");
    }
    ensure!(fd >= 0, "invalid original API peer pidfd");
    // SAFETY: SO_PEERPIDFD installs a fresh caller-owned descriptor on success.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    ensure!(
        len as usize == std::mem::size_of::<libc::c_int>(),
        "invalid API peer pidfd size"
    );
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::process::{Child, Command, Stdio};

    const FIXTURE: &str = "workload_runner::runner::firecracker_process::tests::fixture_listener";
    #[test]
    #[ignore = "spawned by the original pidfd tests"]
    fn fixture_listener() {
        let _socket =
            UnixListener::bind(std::env::var_os("MVM_TEST_ORIGINAL_PIDFD_SOCKET").unwrap())
                .unwrap();
        loop {
            std::thread::park();
        }
    }
    struct OriginalChild(Child);
    impl Drop for OriginalChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn original(path: &Path) -> OriginalChild {
        let mut child = OriginalChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", FIXTURE])
                .env("MVM_TEST_ORIGINAL_PIDFD_SOCKET", path)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(child.0.try_wait().unwrap().is_none() && Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        child
    }
    #[test]
    fn changed_identity_and_missing_peer_retain_original_process() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fc.socket");
        let mut child = original(&path);
        let pid = child.0.id();
        let calls = std::cell::Cell::new(0);
        let capture = || {
            let mut identity = ProcessIdentity::capture("vm", pid)?;
            if calls.replace(1) != 0 {
                identity.start_ticks += 1;
            }
            Ok(identity)
        };
        assert!(OriginalFirecracker::from_original_peer("vm", &path, capture).is_err());
        assert!(
            OriginalFirecracker::from_original_peer("vm", &temp.path().join("absent"), || Ok(
                ProcessIdentity::capture("vm", pid)?
            ))
            .is_err()
        );
        assert!(child.0.try_wait().unwrap().is_none());
    }
    #[test]
    fn only_original_process_exits_even_after_socket_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fc.socket");
        let mut original_child = original(&path);
        let pid = original_child.0.id();
        let held = OriginalFirecracker::from_original_peer("vm", &path, || {
            Ok(ProcessIdentity::capture("vm", pid)?)
        })
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        let mut replacement = original(&path);
        assert!(
            OriginalFirecracker::from_original_peer("vm", &path, || Ok(ProcessIdentity::capture(
                "vm", pid
            )?))
            .is_err()
        );
        assert!(held.verify_exit().is_err());
        held.stop().unwrap();
        held.verify_exit().unwrap();
        held.stop().unwrap();
        assert!(!original_child.0.wait().unwrap().success());
        assert!(replacement.0.try_wait().unwrap().is_none());
    }
}
