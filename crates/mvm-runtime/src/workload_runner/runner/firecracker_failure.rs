//! Retain the original running instance and its supporting launch guards on
//! errors between driver boot and successful runtime registration.
use super::{ConsoleStreamer, RunningVm, firecracker_process::OriginalFirecracker};
use crate::{
    kernel_custody::KernelBoundLaunch, runtime_evidence::RuntimeLifecycleLease,
    workload_runner::claim::EndpointHandle,
};
use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::mailbox_worker::MailboxWorkerOwner;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct FirecrackerPostBootFailure {
    #[source]
    cause: anyhow::Error,
    held: Option<Box<Mutex<Held>>>,
}
struct Held {
    owner: MailboxWorkerOwner,
    process: Option<OriginalFirecracker>,
    vm: Box<dyn RunningVm>,
    _endpoint: EndpointHandle,
    console: Arc<dyn ConsoleStreamer>,
    lifetime: Option<(RuntimeLifecycleLease, KernelBoundLaunch)>,
}
impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held").finish_non_exhaustive()
    }
}
impl FirecrackerPostBootFailure {
    pub(super) fn new(
        cause: anyhow::Error,
        owner: MailboxWorkerOwner,
        process: Option<OriginalFirecracker>,
        vm: Box<dyn RunningVm>,
        endpoint: EndpointHandle,
        console: Arc<dyn ConsoleStreamer>,
    ) -> Self {
        Self {
            cause,
            held: Some(Box::new(Mutex::new(Held {
                owner,
                process,
                vm,
                _endpoint: endpoint,
                console,
                lifetime: None,
            }))),
        }
    }
    fn held(&mut self) -> Result<&mut Held> {
        self.held
            .as_mut()
            .context("original instance already released")?
            .get_mut()
            .map_err(|_| anyhow::anyhow!("original Firecracker custody is unavailable"))
    }
    pub(super) fn with_lifetime(
        mut self,
        lifecycle: RuntimeLifecycleLease,
        kernel: KernelBoundLaunch,
    ) -> Self {
        self.held
            .as_mut()
            .unwrap()
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lifetime = Some((lifecycle, kernel));
        self
    }
    pub fn retry_stop(&mut self, owner: &MailboxWorkerOwner) -> Result<()> {
        let held = self.held()?;
        ensure!(&held.owner == owner, "different installed mailbox owner");
        let (lifecycle, _) = held
            .lifetime
            .as_ref()
            .context("original runtime lifecycle guard missing")?;
        let process = held
            .process
            .as_ref()
            .context("original Firecracker peer lifetime was not captured")?;
        process.stop()?;
        crate::kernel_custody::release_after_original_firecracker_exit(lifecycle, process)?;
        lifecycle.release_installed_bundle_after_stop(&held.vm.id().0)?;
        held.console.stop(&held.vm.id().0);
        // Drop endpoint and the original runtime name lock only after exit and
        // generation-bound release have both succeeded.
        self.held.take();
        Ok(())
    }
}
impl Drop for FirecrackerPostBootFailure {
    fn drop(&mut self) {
        // A string-only caller must not release a live VM's guards. The owning
        // installed SDK keeps this typed error for a bounded retry.
        if let Some(held) = self.held.take() {
            std::mem::forget(held);
        }
    }
}
