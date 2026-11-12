//! Observer for the UNIX stream used to configure and start the original VMM.
use anyhow::{Result, ensure};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

/// Two single-assignment observations shared only within one cold launch.
#[derive(Clone, Debug, Default)]
pub struct LaunchObservation {
    peer: std::sync::Arc<std::sync::OnceLock<ConfigSessionOwner>>,
    pub reader:
        std::sync::Arc<std::sync::OnceLock<mvm_core::mailbox::reader::MailboxReaderBootBinding>>,
}
impl LaunchObservation {
    pub(super) fn bind(&self, peer: ConfigSessionOwner) -> Result<()> {
        ensure!(
            self.reader.get().is_some(),
            "original guest identity drive has not been produced"
        );
        self.peer
            .set(peer)
            .map_err(|_| anyhow::anyhow!("original Firecracker config stream already bound"))
    }
    pub fn require_live(&self) -> Result<()> {
        self.peer
            .get()
            .ok_or_else(|| anyhow::anyhow!("original Firecracker config peer absent"))?
            .require_live()
    }
}

#[derive(Debug)]
pub struct ConfigSessionOwner {
    pid: u32,
    descriptor: OwnedFd,
}
impl ConfigSessionOwner {
    pub(super) fn capture(stream: &UnixStream) -> Result<Self> {
        let pid = mvm_vmm::host::uds_peer::connected_peer_pid(stream)?.try_into()?;
        let mut raw = -1_i32;
        let mut size = std::mem::size_of_val(&raw) as libc::socklen_t;
        // SAFETY: the kernel receives a live connected socket and an exact
        // descriptor-sized output buffer. The new fd is owned by this process.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut raw as *mut i32).cast(),
                &mut size,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        ensure!(
            raw >= 0,
            "Firecracker config peer supplied no lifetime descriptor"
        );
        // SAFETY: successful SO_PEERPIDFD installs a fresh fd.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        ensure!(
            size as usize == std::mem::size_of_val(&raw),
            "invalid config peer descriptor"
        );
        let owner = Self { pid, descriptor };
        owner.require_live()?;
        Ok(owner)
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn require_live(&self) -> Result<()> {
        let mut p = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: p remains live and exclusive during the zero-time poll.
        let ready = unsafe { libc::poll(&mut p, 1, 0) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        ensure!(
            ready == 0,
            "original Firecracker config peer is no longer live"
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests;
