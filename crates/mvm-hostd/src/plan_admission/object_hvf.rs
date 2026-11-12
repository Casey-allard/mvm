//! Original cold HVF custody shared by one SDK reservation and its mailbox.
//! The prepared handle is retained before native activation. No PID or name
//! lookup can construct or replace the native stop authority.
use super::*;
use anyhow::{Context, ensure};
use mvm_runtime::workload_runner::runner::OwnedRuntimeLaunch;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Default)]
pub(crate) struct OriginalHvf(Arc<Mutex<Slot>>);
#[derive(Default)]
struct Slot {
    original: Option<OwnedRuntimeLaunch>,
    spent: bool,
    unserved_rollback_pending: bool,
}
impl std::fmt::Debug for OriginalHvf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OriginalHvf")
    }
}
impl OriginalHvf {
    pub(crate) fn same_reservation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    fn lock(&self) -> Result<MutexGuard<'_, Slot>> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("original HVF slot poisoned"))
    }
    pub(crate) fn with_live<T>(
        &self,
        f: impl FnOnce(&OwnedRuntimeLaunch) -> Result<T>,
    ) -> Result<T> {
        let s = self.lock()?;
        let handle = s.original.as_ref().context("no original HVF owner")?;
        handle.validate_live()?;
        f(handle)
    }
    fn activate(&self, runtime: OwnedRuntimeLaunch) -> Result<VmId> {
        let mut s = self.lock()?;
        ensure!(!s.spent, "HVF reservation already consumed");
        s.spent = true;
        let id = runtime.vm_id()?.clone();
        let original = s.original.insert(runtime);
        if let Err(err) = original.activate() {
            // A failed spawn may have its own original rollback proof.
            let original = s.original.take().expect("original activated slot");
            if let Err(original) = original.release_if_child_free() {
                s.original = Some(*original);
                s.unserved_rollback_pending = true;
                if let Err(stop) = Self::stop_locked(&mut s) {
                    return Err(err.context(format!(
                        "original HVF activation rollback unresolved: {stop:#}"
                    )));
                }
            }
            return Err(err);
        }
        Ok(id)
    }
    fn stop_locked(s: &mut Slot) -> Result<()> {
        let original = s.original.as_mut().context("no original HVF to stop")?;
        original.stop()?;
        s.original = None;
        s.unserved_rollback_pending = false;
        Ok(())
    }
    pub(crate) fn stop(&self) -> Result<()> {
        Self::stop_locked(&mut *self.lock()?)
    }
    pub(crate) fn abort_unserved(&self) -> Result<()> {
        let mut s = self.lock()?;
        s.unserved_rollback_pending = true;
        Self::stop_locked(&mut s)
    }
    pub(crate) fn retry_unserved(&self) -> Result<()> {
        let mut s = self.lock()?;
        ensure!(
            s.unserved_rollback_pending,
            "no failed original HVF rollback"
        );
        Self::stop_locked(&mut s)
    }
}
impl AdmittedPlan {
    pub(crate) fn object_hvf(&self) -> Result<&OriginalHvf> {
        self.object_hvf
            .as_ref()
            .context("no original selected HVF admission")
    }
    pub fn abort_unserved_object(&self, backend: &AnyBackend, id: &VmId) -> Result<()> {
        ensure!(
            backend.kind() == BackendKind::Hvf && self.plan.image.name == id.0,
            "different original HVF admission"
        );
        self.object_hvf()?.abort_unserved()
    }
    pub(super) fn activate_object_hvf(
        &mut self,
        held: &OriginalHvf,
        backend: &AnyBackend,
        mut config: VmStartConfig,
        images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    ) -> Result<VmId> {
        ensure!(
            images.is_empty() && config.volumes.is_empty(),
            "selected HVF object profile requires a sealed role image without writable volume attachments"
        );
        let mut frozen = self
            .built_pack_boot_check()?
            .context("selected HVF requires authenticated registry/application boot images")?
            .freeze_native_boot(&mut config, backend.kind())?
            .context("missing original HVF image preparation")?;
        frozen.verify_config(&config)?;
        let runtime = backend.prepare_owned_launch(&config, frozen.take_boot_images()?)?;
        frozen.verify_config(runtime.config()?)?;
        self.object_hvf = Some(held.clone());
        held.activate(runtime)
    }
}
