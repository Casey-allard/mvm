//! Original Linux process observations and the lease retained through retirement.
use super::process_exit::{ProcessExitWait, require_owned_child_custody, wait_pidfd};
use anyhow::{Context, Result, ensure};
use mvm_core::host_lifetime::{HostLaunchBinding, PreparedHostLifetimeLease};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    process::{Child, ExitStatus},
    time::Instant,
};

pub mod worker_terms;

#[derive(Debug)]
enum OriginalExit {
    Kernel(OwnedFd),
    Collected { _status: ExitStatus },
}

/// Capture while the caller exclusively owns the unreaped original child.
/// The caller must preserve that custody and the default child disposition.
#[derive(Debug)]
pub struct OriginalProcess {
    pid: u32,
    exit: OriginalExit,
}
impl OriginalProcess {
    pub fn observe(child: &mut Child) -> Result<Self> {
        require_owned_child_custody()?;
        let pid = child.id();
        ensure!(pid > 1, "invalid original child identity");
        if let Some(status) = child.try_wait()? {
            return Ok(Self {
                pid,
                exit: OriginalExit::Collected { _status: status },
            });
        }
        // SAFETY: this is the still-owned unreaped child, with no competing
        // reaper or automatic reaping. Its PID cannot be recycled here.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let raw = i32::try_from(raw).context("original child descriptor out of range")?;
        // SAFETY: successful pidfd_open returns one fresh owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            pid,
            exit: OriginalExit::Kernel(descriptor),
        })
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn wait_exit(&self, until: Instant) -> Result<ProcessExitWait> {
        match &self.exit {
            OriginalExit::Kernel(fd) => Ok(wait_pidfd(fd.as_raw_fd(), until)?),
            OriginalExit::Collected { .. } => Ok(ProcessExitWait::Exited),
        }
    }
    pub fn require_live(&self) -> Result<()> {
        ensure!(
            self.wait_exit(Instant::now())? == ProcessExitWait::TimedOut,
            "original process has exited"
        );
        Ok(())
    }
    pub fn authenticate_config(&self, stream: &UnixStream) -> Result<()> {
        self.require_live()?;
        let peer = ConfigSessionOwner::capture(stream)?;
        ensure!(
            peer.pid() == self.pid,
            "config peer is not the original child"
        );
        self.require_live()?;
        peer.require_live()
    }
    /// Verify the actual child retained the explicitly inherited holder object.
    /// Descriptor inheritance preserves its lock description; object identity
    /// alone would not prove that an independently reopened file holds a lock.
    pub fn verify_inherited_holder(&self, lease: &PreparedHostLifetimeLease) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        self.require_live()?;
        let metadata = std::fs::metadata(format!(
            "/proc/{}/fd/{}",
            self.pid,
            lease.holder().as_raw_fd()
        ))
        .context("original child did not retain its inherited holder")?;
        ensure!(
            metadata.is_file()
                && (metadata.dev(), metadata.ino()) == lease.holder_object_id()
                && metadata.uid() == lease.owner_uid()
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1,
            "original child holder object differs from its retained lease"
        );
        self.require_live()
    }
    fn signal(&self, signal: libc::c_int) -> Result<()> {
        let OriginalExit::Kernel(fd) = &self.exit else {
            return Ok(());
        };
        // SAFETY: the retained pidfd identifies the original process; no PID
        // lookup or user-provided siginfo is used.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
        Ok(())
    }
    pub fn terminate(&self) -> Result<()> {
        self.signal(libc::SIGTERM)
    }
    pub fn kill(&self) -> Result<()> {
        self.signal(libc::SIGKILL)
    }
}

/// Kernel-owned peer observation from the actual connected config session.
#[derive(Debug)]
pub struct ConfigSessionOwner {
    pid: u32,
    descriptor: OwnedFd,
}
impl ConfigSessionOwner {
    pub fn capture(stream: &UnixStream) -> Result<Self> {
        let pid = super::uds_peer::connected_peer_pid(stream)?.try_into()?;
        let mut raw = -1_i32;
        let mut size = std::mem::size_of_val(&raw) as libc::socklen_t;
        // SAFETY: the connected socket and exact descriptor-sized output
        // buffer remain live; success installs one new descriptor.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut raw as *mut i32).cast(),
                &mut size,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        ensure!(raw >= 0, "config peer supplied no process descriptor");
        // SAFETY: successful SO_PEERPIDFD returned a fresh owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        ensure!(
            size as usize == std::mem::size_of_val(&raw),
            "invalid config peer process descriptor"
        );
        let peer = Self { pid, descriptor };
        peer.require_live()?;
        Ok(peer)
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
    pub fn require_live(&self) -> Result<()> {
        ensure!(
            wait_pidfd(self.descriptor.as_raw_fd(), Instant::now())? == ProcessExitWait::TimedOut,
            "original config peer has exited"
        );
        Ok(())
    }
}

/// Local custody, not launch authorization. Admission precedes process effects.
#[derive(Debug)]
pub struct OriginalLifetime {
    binding: HostLaunchBinding,
    lease: Option<PreparedHostLifetimeLease>,
    process: Option<OriginalProcess>,
}
impl OriginalLifetime {
    pub fn from_observed(
        binding: HostLaunchBinding,
        lease: PreparedHostLifetimeLease,
        process: OriginalProcess,
    ) -> Self {
        Self {
            binding,
            lease: Some(lease),
            process: Some(process),
        }
    }
    pub fn process(&self) -> Result<&OriginalProcess> {
        self.process
            .as_ref()
            .context("original lifetime already collected")
    }
    pub fn lease(&self) -> Result<&PreparedHostLifetimeLease> {
        self.lease
            .as_ref()
            .context("original lifetime already collected")
    }
    pub fn confirm_exit(&mut self, until: Instant) -> Result<ConfirmedExit> {
        ensure!(self.lease.is_some(), "original lifetime already collected");
        if self.process()?.wait_exit(until)? != ProcessExitWait::Exited {
            return Err(io::Error::from(io::ErrorKind::TimedOut).into());
        }
        Ok(ConfirmedExit {
            binding: self.binding.clone(),
            lease: self.lease.take().expect("checked original lease retained"),
            _process: self
                .process
                .take()
                .expect("checked original process retained"),
        })
    }
}

/// A positive original-process exit with its exact original lease retained.
/// No exit-code, signed receipt or resource-refund authority is implied.
#[derive(Debug)]
pub struct ConfirmedExit {
    binding: HostLaunchBinding,
    lease: PreparedHostLifetimeLease,
    _process: OriginalProcess,
}
impl ConfirmedExit {
    pub fn binding(&self) -> &HostLaunchBinding {
        &self.binding
    }
    pub fn lease(&self) -> &PreparedHostLifetimeLease {
        &self.lease
    }
}

#[cfg(test)]
mod tests;
