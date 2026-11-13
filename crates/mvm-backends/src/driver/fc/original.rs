//! Observer for the UNIX stream used to configure and start the original VMM.
use anyhow::{Result, ensure};
pub use mvm_vmm::host::fc_lifetime::ConfigSessionOwner;
use std::os::fd::BorrowedFd;

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
    /// Borrow the Linux pidfd of the connected peer which accepted InstanceStart.
    pub fn original_peer(&self) -> Result<(u32, BorrowedFd<'_>)> {
        let owner = self
            .peer
            .get()
            .ok_or_else(|| anyhow::anyhow!("original config peer absent"))?;
        owner.require_live()?;
        Ok((owner.pid(), owner.descriptor()))
    }
    pub fn require_live(&self) -> Result<()> {
        self.peer
            .get()
            .ok_or_else(|| anyhow::anyhow!("original Firecracker config peer absent"))?
            .require_live()
    }
}

#[cfg(test)]
mod tests;
