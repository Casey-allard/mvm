//! Original in-process native custody. The table is only an index; every
//! operation uses one original slot, never a driver attachment reconstructed
//! from a persisted VM name. Unknown custody is retained on owner drop.

use super::*;
use mvm_core::host_lifetime::{HostLaunchBinding, HostLifetimeAnchor};
use std::sync::{Mutex, MutexGuard, TryLockError};

#[derive(Default)]
pub(super) struct InstalledSlots(Mutex<Vec<Arc<InstalledSlot>>>);

pub(super) struct InstalledSlot {
    id: VmId,
    owner: Arc<HostLifetimeAnchor>,
    state: Mutex<Option<Custody>>,
}

/// Linear local evidence of completed original native and supporting cleanup.
/// Retain this receipt through release of the actual parent resource grant.
/// It cannot be serialized, cloned, or reconstructed from a binding or PID.
#[must_use = "retain completed ownership through actual parent grant release"]
pub struct OwnedRetirement {
    owner: Arc<HostLifetimeAnchor>,
    endpoint: Option<mvm_vmm::host::network_endpoint_spawn::EndpointRetirement>,
}
impl OwnedRetirement {
    pub fn binding(&self) -> &HostLaunchBinding {
        self.owner.binding()
    }
    /// Move the original helper partition once for parent disk cleanup.
    /// None is not evidence that an expected helper/store has retired.
    pub fn take_endpoint_retirement(
        &mut self,
    ) -> Option<mvm_vmm::host::network_endpoint_spawn::EndpointRetirement> {
        self.endpoint.take()
    }
    /// Exact retained reservation identity; copied fields confer no ownership.
    pub fn retains_parent_permit(
        &self,
        permit: &Arc<dyn mvm_core::host_lifetime::CoreCurrentParentPermit>,
    ) -> bool {
        self.owner.retains_parent_permit(permit)
    }
}
impl std::fmt::Debug for OwnedRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedRetirement")
            .field("vm_name", &self.binding().vm_name)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
#[path = "installed/entrypoint.rs"]
mod entrypoint;

struct Custody {
    #[cfg(target_os = "linux")]
    entrypoint: Option<Box<dyn mvm_vmm::driver::OriginalEntrypointChannel>>,
    #[cfg(target_os = "linux")]
    entrypoint_busy: bool,
    vm: Option<Box<dyn RunningVm>>,
    failure: Option<anyhow::Error>,
    endpoint: Option<crate::workload_runner::claim::EndpointHandle>,
    endpoint_start_entered: bool,
    native_dispatch_entered: bool,
    #[cfg(target_os = "linux")]
    installed_kernel_released: bool,
    endpoint_retirement: Option<mvm_vmm::host::network_endpoint_spawn::EndpointRetirement>,
    broker: Option<BrokerGuard>,
    launch: Option<(
        crate::runtime_evidence::RuntimeLifecycleLease,
        crate::kernel_custody::KernelBoundLaunch,
    )>,
    retired: bool,
    exit: Option<mvm_vmm::driver::traits::KernelStopOutcome>,
}

impl InstalledSlots {
    pub(super) fn has_any(&self) -> Result<bool> {
        Ok(!self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("installed index poisoned"))?
            .is_empty())
    }
    pub(super) fn reserve(&self, owner: &Arc<HostLifetimeAnchor>) -> Result<Arc<InstalledSlot>> {
        let mut slots = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("installed index poisoned"))?;
        anyhow::ensure!(slots.len() < 2, "installed native slots full");
        anyhow::ensure!(
            !slots
                .iter()
                .any(|slot| slot.id.0 == owner.binding().vm_name),
            "installed VM identity already retained"
        );
        let slot = Arc::new(InstalledSlot {
            id: VmId(owner.binding().vm_name.clone()),
            owner: Arc::clone(owner),
            state: Mutex::new(Some(Custody {
                #[cfg(target_os = "linux")]
                entrypoint: None,
                #[cfg(target_os = "linux")]
                entrypoint_busy: false,
                vm: None,
                failure: None,
                endpoint: None,
                endpoint_start_entered: false,
                native_dispatch_entered: false,
                #[cfg(target_os = "linux")]
                installed_kernel_released: false,
                endpoint_retirement: None,
                broker: None,
                launch: None,
                retired: false,
                exit: None,
            })),
        });
        slots.push(Arc::clone(&slot));
        Ok(slot)
    }

    pub(super) fn find(&self, id: &VmId) -> Result<Option<Arc<InstalledSlot>>> {
        let slots = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("installed index poisoned"))?;
        Ok(slots.iter().find(|slot| slot.id == *id).cloned())
    }

    pub(super) fn take_retired(&self, slot: &Arc<InstalledSlot>) -> Result<OwnedRetirement> {
        let mut state = slot.access()?;
        let state = state.as_mut().context("installed custody unavailable")?;
        anyhow::ensure!(state.retired, "installed native custody has not retired");
        let mut slots = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("installed index poisoned"))?;
        let index = slots
            .iter()
            .position(|held| Arc::ptr_eq(held, slot))
            .context("original retirement record unavailable or already consumed")?;
        // All refusal paths precede removal. The receipt retains the same
        // original parent owner; no release/reacquire or history eviction.
        let receipt = OwnedRetirement {
            owner: Arc::clone(&slot.owner),
            endpoint: state.endpoint_retirement.take(),
        };
        slots.remove(index);
        Ok(receipt)
    }
}

impl InstalledSlot {
    fn retain_guard<T: Send + 'static>(
        &self,
        value: T,
    ) -> Result<(MutexGuard<'_, Option<Custody>>, T)> {
        match self.access() {
            Ok(guard) if guard.as_ref().is_some_and(|state| !state.retired) => Ok((guard, value)),
            result => {
                // Never let contention/poison destroy an original native or
                // supporting owner passed across a fallible phase boundary.
                std::mem::forget((Arc::clone(&self.owner), value));
                match result {
                    Err(error) => Err(error),
                    Ok(_) => anyhow::bail!("installed retention unavailable; custody quarantined"),
                }
            }
        }
    }
    fn access(&self) -> Result<MutexGuard<'_, Option<Custody>>> {
        let guard = self.state.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => anyhow::anyhow!("installed VM operation in progress"),
            TryLockError::Poisoned(_) => anyhow::anyhow!("installed VM custody poisoned"),
        })?;
        anyhow::ensure!(guard.is_some(), "original installed cleanup in progress");
        Ok(guard)
    }

    pub(super) fn matches(&self, owner: &Arc<HostLifetimeAnchor>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }

    pub(super) fn binding(&self) -> &HostLaunchBinding {
        self.owner.binding()
    }

    pub(super) fn view(self: &Arc<Self>) -> Box<dyn RunningVm> {
        Box::new(InstalledVmView(Arc::clone(self)))
    }

    pub(super) fn retain_start(
        &self,
        lifecycle: crate::runtime_evidence::RuntimeLifecycleLease,
        kernel: crate::kernel_custody::KernelBoundLaunch,
        outcome: Result<Box<dyn RunningVm>>,
    ) -> Result<Box<dyn RunningVm>> {
        let (mut guard, (lifecycle, kernel, outcome)) =
            self.retain_guard((lifecycle, kernel, outcome))?;
        let state = guard.as_mut().expect("checked original custody");
        if state.launch.is_some() || state.failure.is_some() {
            drop(guard);
            std::mem::forget((Arc::clone(&self.owner), lifecycle, kernel, outcome));
            anyhow::bail!("original installed launch already retained; custody quarantined");
        }
        state.launch = Some((lifecycle, kernel));
        match outcome {
            Ok(vm) => Ok(vm),
            Err(error) => {
                state.failure = Some(error);
                anyhow::bail!("installed native startup failed; original error retained")
            }
        }
    }

    #[cfg(test)]
    pub(super) fn endpoint_retained_for_test(&self) -> bool {
        self.access()
            .unwrap()
            .as_ref()
            .is_some_and(|state| state.endpoint.is_some())
    }

    pub(super) fn begin_endpoint_start(&self) -> Result<()> {
        let mut guard = self.access()?;
        let state = guard.as_mut().context("installed custody unavailable")?;
        anyhow::ensure!(
            !state.retired && state.launch.is_none() && !state.endpoint_start_entered,
            "original endpoint startup already attempted or unavailable"
        );
        state.endpoint_start_entered = true;
        Ok(())
    }

    pub(super) fn retain_endpoint(
        &self,
        endpoint: crate::workload_runner::claim::EndpointHandle,
    ) -> Result<()> {
        let (mut guard, endpoint) = self.retain_guard(endpoint)?;
        let state = guard.as_mut().expect("checked original custody");
        if !state.endpoint_start_entered || state.endpoint.is_some() {
            drop(guard);
            std::mem::forget((Arc::clone(&self.owner), endpoint));
            anyhow::bail!("original installed endpoint custody conflicts; endpoint quarantined");
        }
        state.endpoint = Some(endpoint);
        Ok(())
    }

    pub(super) fn begin_native_dispatch(&self) -> Result<()> {
        let mut guard = self.access()?;
        let state = guard.as_mut().context("installed custody unavailable")?;
        anyhow::ensure!(
            !state.retired
                && state.launch.is_none()
                && state.endpoint.is_some()
                && !state.native_dispatch_entered,
            "original installed native dispatch unavailable or already attempted"
        );
        state.native_dispatch_entered = true;
        Ok(())
    }

    pub(super) fn retain_broker(&self, broker: BrokerGuard) -> Result<()> {
        let (mut guard, broker) = self.retain_guard(broker)?;
        let state = guard.as_mut().expect("checked original custody");
        if state.broker.is_some() {
            drop(guard);
            std::mem::forget((Arc::clone(&self.owner), broker));
            anyhow::bail!("original installed broker already retained; custody quarantined");
        }
        state.broker = Some(broker);
        Ok(())
    }

    pub(super) fn broker_registration(
        &self,
    ) -> Result<Arc<mvm_vmm::host::host_agent_spawn::OwnedVmRegistration>> {
        let guard = self.access()?;
        let broker = guard
            .as_ref()
            .and_then(|state| state.broker.as_ref())
            .context("original installed broker registration missing")?;
        match &broker.0 {
            super::BrokerCustody::Installed(registration) => Ok(Arc::clone(registration)),
            _ => anyhow::bail!("legacy broker is not an installed registration"),
        }
    }

    pub(super) fn retain_vm(
        self: &Arc<Self>,
        vm: Box<dyn RunningVm>,
    ) -> Result<Box<dyn RunningVm>> {
        let (mut guard, vm) = self.retain_guard(vm)?;
        let state = guard.as_mut().context("installed custody unavailable")?;
        anyhow::ensure!(state.vm.is_none(), "installed native VM already retained");
        state.vm = Some(vm);
        anyhow::ensure!(
            state.vm.as_ref().is_some_and(|vm| vm.id() == &self.id),
            "native VM identity substitution; original retained"
        );
        Ok(Box::new(InstalledVmView(Arc::clone(self))))
    }

    pub(super) fn stop(&self, streamer: &dyn ConsoleStreamer) -> Result<()> {
        let mut guard = self.access()?;
        let state = guard.as_ref().context("installed custody unavailable")?;
        #[cfg(target_os = "linux")]
        anyhow::ensure!(
            !state.entrypoint_busy,
            "original entrypoint is still in use"
        );
        if state.retired {
            return Ok(());
        }
        anyhow::ensure!(
            state.launch.is_some(),
            "installed startup still in progress"
        );
        // Loan the original custody as one unit. Competing operations refuse
        // through access() until the exact state is restored.
        let mut state = guard.take().expect("checked original custody");
        drop(guard);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.stop_custody(&mut state, streamer)
        }));
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => {
                std::mem::forget((Arc::clone(&self.owner), state));
                anyhow::bail!("installed cleanup custody poisoned; original quarantined");
            }
        };
        if guard.is_some() {
            drop(guard);
            std::mem::forget((Arc::clone(&self.owner), state));
            anyhow::bail!("installed cleanup custody changed; original quarantined");
        }
        *guard = Some(state);
        drop(guard);
        result
            .map_err(|_| anyhow::anyhow!("original installed cleanup panicked; custody retained"))?
    }

    fn stop_custody(&self, state: &mut Custody, streamer: &dyn ConsoleStreamer) -> Result<()> {
        let (lifecycle, _kernel) = state
            .launch
            .as_ref()
            .context("installed launch custody unavailable")?;
        // The unused channel also retains original kernel and lease custody.
        // Close it before any disposal receipt can release this launch's debit.
        #[cfg(target_os = "linux")]
        drop(state.entrypoint.take());
        if !state.native_dispatch_entered {
            anyhow::ensure!(
                state.failure.is_some() && state.vm.is_none() && state.exit.is_none(),
                "original pre-dispatch failure proof unavailable"
            );
            #[cfg(target_os = "linux")]
            if self.binding().backend == BackendKind::Firecracker
                && self.owner.canonical_kernel().is_some()
            {
                if !state.installed_kernel_released {
                    _kernel.release_installed_kernel(lifecycle)?;
                    state.installed_kernel_released = true;
                }
            } else {
                anyhow::ensure!(
                    !crate::kernel_custody::has_retained_kernel(lifecycle)?,
                    "pre-dispatch kernel custody still requires native exit proof"
                );
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::ensure!(
                !crate::kernel_custody::has_retained_kernel(lifecycle)?,
                "pre-dispatch kernel custody still requires native exit proof"
            );
        }
        if state.endpoint_retirement.is_none() {
            if let Some(endpoint) = state.endpoint.as_mut() {
                endpoint.close_owned_admission()?;
            } else if let Some(failed) = state.failure.as_mut().and_then(|failure| {
                failure
                    .downcast_mut::<mvm_vmm::host::network_endpoint_spawn::OwnedEndpointSpawnError>(
                    )
            }) {
                failed.endpoint_mut().close_admission()?;
            } else {
                anyhow::ensure!(
                    !state.endpoint_start_entered,
                    "original attempted endpoint lacks cleanup evidence; custody retained"
                );
            }
        }
        #[cfg(target_os = "linux")]
        let never_spawned = if let Some(proof) = state.failure.as_ref().and_then(|error| {
            error.downcast_ref::<mvm_backends::driver::fc::OriginalFcNotSpawned>()
        }) {
            anyhow::ensure!(
                state.native_dispatch_entered
                    && state.vm.is_none()
                    && self.binding() == proof.binding(),
                "foreign pre-spawn refusal"
            );
            self.owner.check_original_lease(proof.lease())?;
            true
        } else {
            false
        };
        #[cfg(not(target_os = "linux"))]
        let never_spawned = false;
        if state.native_dispatch_entered && state.exit.is_none() && !never_spawned {
            let stopped = if let Some(vm) = state.vm.as_deref() {
                vm.terminate_with_kernel_exit()?
            } else {
                let failure = state
                    .failure
                    .as_mut()
                    .context("installed startup still in progress")?;
                #[cfg(target_os = "linux")]
                if let Some(failed) =
                    failure.downcast_mut::<mvm_backends::driver::fc::OwnedFcBootFailure>()
                {
                    let proof = failed.collect_original(Instant::now() + Duration::from_secs(2))?;
                    mvm_vmm::driver::traits::KernelStopOutcome {
                        fc_exit: Some(proof),
                        hvf_exit: None,
                        timing: None,
                    }
                } else {
                    failed_hvf_exit(failure)?
                }
                #[cfg(not(target_os = "linux"))]
                failed_hvf_exit(failure)?
            };
            match self.binding().backend {
                #[cfg(target_os = "linux")]
                BackendKind::Firecracker => {
                    let proof = stopped
                        .fc_exit
                        .as_ref()
                        .context("original Firecracker exit proof unavailable")?;
                    anyhow::ensure!(
                        proof.binding() == self.binding(),
                        "foreign Firecracker exit binding"
                    );
                    self.owner.check_original_lease(proof.lease())?;
                }
                BackendKind::Hvf => {
                    let proof =
                        match stopped.hvf_exit.as_ref() {
                            Some(proof) => proof,
                            None => failed_hvf_proof(state.failure.as_mut().context(
                                "original HVF exit proof unavailable; custody retained",
                            )?)?,
                        };
                    anyhow::ensure!(
                        proof.instance().vm_id == self.id.0,
                        "HVF exit belongs to another instance"
                    );
                    proof.verify_current()?;
                }
                _ => anyhow::bail!("installed backend has no native exit proof"),
            }
            state.exit = Some(stopped);
        }
        if state.endpoint_retirement.is_none() {
            if let Some(endpoint) = state.endpoint.as_mut() {
                endpoint.shutdown_owned()?;
                state.endpoint_retirement = endpoint.take_owned_retirement()?;
            } else if let Some(failed) = state.failure.as_mut().and_then(|failure| {
                failure
                    .downcast_mut::<mvm_vmm::host::network_endpoint_spawn::OwnedEndpointSpawnError>(
                    )
            }) {
                let endpoint = failed.endpoint_mut();
                endpoint.shutdown()?;
                state.endpoint_retirement = Some(endpoint.take_retirement()?);
            }
        }
        if let Some(broker) = state.broker.as_mut() {
            broker.shutdown_owned()?;
        }
        streamer.stop(&self.id.0);
        let (lifecycle, _kernel) = state
            .launch
            .as_ref()
            .context("original installed launch missing")?;
        let has_kernel = crate::kernel_custody::has_retained_kernel(lifecycle)?;
        #[cfg(target_os = "linux")]
        if self.binding().backend == BackendKind::Firecracker
            && self.owner.canonical_kernel().is_some()
            && !state.installed_kernel_released
        {
            anyhow::ensure!(
                !state.native_dispatch_entered
                    || never_spawned
                    || state
                        .exit
                        .as_ref()
                        .is_some_and(|exit| exit.fc_exit.is_some()),
                "original Firecracker disposal proof unavailable"
            );
            _kernel.release_installed_kernel(lifecycle)?;
            state.installed_kernel_released = true;
        }
        #[cfg(target_os = "linux")]
        let has_kernel = has_kernel && !state.installed_kernel_released;
        if has_kernel {
            let stopped = state
                .exit
                .as_ref()
                .context("original native exit missing")?;
            if let Some(proof) = stopped.hvf_exit.as_ref() {
                crate::kernel_custody::release_after_confirmed_exit(lifecycle, proof)?;
            } else if self.binding().backend == BackendKind::Hvf {
                let proof = failed_hvf_proof(
                    state
                        .failure
                        .as_mut()
                        .context("original HVF rollback missing")?,
                )?;
                crate::kernel_custody::release_after_confirmed_exit(lifecycle, proof)?;
            } else {
                #[cfg(target_os = "linux")]
                anyhow::ensure!(stopped.fc_exit.is_some(), "original native exit missing");
                crate::kernel_custody::release_after_process_exit(lifecycle)?;
            }
        }
        match std::fs::remove_file(marker(&self.id)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove installed refusal marker after exit"),
        }
        mvm_core::util::atomic_io::sync_dir(&vm_state_dir(&self.id.0))?;
        state.endpoint = None;
        state.broker = None;
        state.vm = None;
        state.failure = None;
        state.launch = None;
        state.retired = true;
        Ok(())
    }

    pub(super) fn with_vm<T>(&self, action: impl FnOnce(&dyn RunningVm) -> Result<T>) -> Result<T> {
        let guard = self.access()?;
        let state = guard.as_ref().context("installed custody unavailable")?;
        anyhow::ensure!(!state.retired, "installed VM has retired");
        action(
            state
                .vm
                .as_deref()
                .context("installed native startup incomplete")?,
        )
    }
}

fn failed_hvf_exit(
    error: &mut anyhow::Error,
) -> Result<mvm_vmm::driver::traits::KernelStopOutcome> {
    let failed = error
        .downcast_mut::<mvm_backends::driver::hvf::ColdHvfBootFailure>()
        .context("installed failed-start custody is not recoverable through a native owner")?;
    failed.retry_stop()?;
    failed
        .confirmed_exit()
        .context("native rollback unconfirmed")?
        .verify_current()?;
    Ok(mvm_vmm::driver::traits::KernelStopOutcome {
        #[cfg(target_os = "linux")]
        fc_exit: None,
        // Its non-Clone proof stays inside the original failed native owner.
        hvf_exit: None,
        timing: None,
    })
}

fn failed_hvf_proof(error: &mut anyhow::Error) -> Result<&mvm_vmm::host::hvf_stop::ConfirmedExit> {
    error
        .downcast_mut::<mvm_backends::driver::hvf::ColdHvfBootFailure>()
        .context("original failed HVF owner missing")?
        .confirmed_exit()
        .context("native rollback unconfirmed")
}

pub(super) fn marker(id: &VmId) -> PathBuf {
    vm_state_dir(&id.0).join(mvm_core::host_lifetime::INSTALLED_NATIVE_CUSTODY_MARKER)
}

pub(super) fn refuse_unowned(id: &VmId) -> Result<()> {
    mvm_core::host_lifetime::require_no_installed_native(&id.0)
}

impl Drop for InstalledSlot {
    fn drop(&mut self) {
        // A dropped controller is not evidence that a native process or any
        // helper exited. Retain the exact owner, resources, and native handle
        // until process exit. This bounded quarantine never marks Clean.
        let guard = self
            .state
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(state) = guard.take()
            && !state.retired
        {
            std::mem::forget((state, Arc::clone(&self.owner)));
        }
    }
}

struct InstalledVmView(Arc<InstalledSlot>);

#[cfg(test)]
#[path = "installed/retirement_tests.rs"]
mod retirement_tests;

impl RunningVm for InstalledVmView {
    fn id(&self) -> &VmId {
        &self.0.id
    }
    fn host_process_id(&self) -> Option<u32> {
        self.0.with_vm(|vm| Ok(vm.host_process_id())).ok().flatten()
    }
    fn wait(&self) -> Result<VmExitStatus> {
        // The compatibility trait has no cancellation/deadline. Holding the
        // original slot in an unbounded wait would prevent its owner stopping
        // it. Resident callers use application completion and explicit stop.
        anyhow::bail!(
            "installed blocking wait is unsupported; retain the original resident lifecycle"
        )
    }
    fn prepare_stop(&self) -> Result<()> {
        self.0.with_vm(|vm| vm.prepare_stop())
    }
    fn kill(&self) -> Result<()> {
        anyhow::bail!("installed VM must stop through its original runner custody")
    }
    fn authenticated_hvf_instance(
        &self,
    ) -> Result<Option<mvm_core::protocol::hvf_control::HvfInstance>> {
        self.0.with_vm(|vm| vm.authenticated_hvf_instance())
    }
    #[cfg(target_os = "linux")]
    fn open_owned_entrypoint(
        &self,
        anchor: Arc<HostLifetimeAnchor>,
        identity: mvm_vmm::driver::OriginalEntrypointIdentity,
        until: Instant,
    ) -> Result<Box<dyn mvm_vmm::driver::OriginalEntrypointChannel>> {
        self.0
            .with_vm(|vm| vm.open_owned_entrypoint(anchor, identity, until))
    }
    #[cfg(target_os = "linux")]
    fn check_original_firecracker_kernel(&self, anchor: &HostLifetimeAnchor) -> Result<()> {
        self.0
            .with_vm(|vm| vm.check_original_firecracker_kernel(anchor))
    }
    fn process_identity(&self) -> Result<Option<mvm_vmm::host::process_identity::ProcessIdentity>> {
        self.0.with_vm(|vm| vm.process_identity())
    }
    fn pause(&self) -> Result<()> {
        self.0.with_vm(|vm| vm.pause())
    }
    fn resume(&self) -> Result<()> {
        self.0.with_vm(|vm| vm.resume())
    }
    fn status(&self) -> Result<VmStatus> {
        self.0.with_vm(|vm| vm.status())
    }
    fn vsock_connect(&self, port: u32) -> Result<Box<dyn crate::driver::DuplexStream>> {
        self.0.with_vm(|vm| vm.vsock_connect(port))
    }
}
