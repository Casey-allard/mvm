//! Original process and installation custody retained after a failed cold boot.
use anyhow::{Context, Result};
use mvm_core::host_lifetime::{HostLaunchBinding, PreparedHostLifetimeLease};
use mvm_vmm::host::{
    fc_lifetime::{ConfirmedExit, OriginalLifetime, OriginalProcess},
    process_exit::{ProcessExitWait, collect_after_exit_event},
};
use std::{
    fmt,
    process::Child,
    sync::{Arc, Mutex},
    time::Instant,
};

/// The driver did not reach process creation; original custody is retained.
#[derive(Debug)]
pub struct OriginalFcNotSpawned {
    pub(super) binding: HostLaunchBinding,
    pub(super) lease: PreparedHostLifetimeLease,
    pub(super) error: anyhow::Error,
}
impl OriginalFcNotSpawned {
    pub fn binding(&self) -> &HostLaunchBinding {
        &self.binding
    }
    pub fn lease(&self) -> &PreparedHostLifetimeLease {
        &self.lease
    }
}
impl fmt::Display for OriginalFcNotSpawned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original Firecracker was not spawned: {}", self.error)
    }
}
impl std::error::Error for OriginalFcNotSpawned {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

#[derive(Debug)]
pub(crate) struct OwnedFcState {
    pub binding: HostLaunchBinding,
    pub lease: Option<PreparedHostLifetimeLease>,
    pub child: Option<Child>,
    pub lifetime: Option<OriginalLifetime>,
    pub spawn_attempted: bool,
    pub retired: bool,
    pub authenticated: bool,
    pub(super) exit_capture: Option<super::owned_capture::CaptureWorker>,
}

pub(super) fn boot(
    driver: &super::FcDriver,
    spec: &mvm_vmm::driver::spec::VmmSpec,
    files: mvm_vmm::driver::prepared_disks::PreparedBootFiles<'_>,
    lease: PreparedHostLifetimeLease,
    binding: &HostLaunchBinding,
) -> Result<Box<dyn mvm_vmm::driver::RunningVm>> {
    let original = Arc::new(Mutex::new(OwnedFcState {
        binding: binding.clone(),
        lease: Some(lease),
        child: None,
        lifetime: None,
        spawn_attempted: false,
        retired: false,
        authenticated: false,
        exit_capture: None,
    }));
    let launch = || {
        anyhow::ensure!(driver.owned.is_none(), "original lifetime already selected");
        anyhow::ensure!(
            binding.backend == mvm_core::vm_backend::BackendKind::Firecracker
                && binding.vm_name == spec.name
                && spec.vcpus > 0
                && spec.vcpus <= binding.cpus.min(super::MAX_VCPUS)
                && spec.memory_mib > 0
                && spec.memory_mib <= binding.memory_mib,
            "original lifetime differs from the requested Firecracker shape"
        );
        original
            .lock()
            .map_err(|_| anyhow::anyhow!("original Firecracker custody poisoned"))?
            .check_current()?;
        let mut selected = driver.clone();
        selected.owned = Some(Arc::clone(&original));
        mvm_vmm::driver::VmmDriver::boot_custodied(&selected, spec, files)
    };
    launch().map_err(|error| boot_failure(original, error))
}
impl OwnedFcState {
    pub fn check_current(&self) -> Result<()> {
        match &self.lifetime {
            Some(original) => {
                original.lease()?.verify_current()?;
                original.process()?.require_live()
            }
            None => self
                .lease
                .as_ref()
                .context("original lease absent")?
                .verify_current(),
        }
    }
    pub fn begin_spawn(&mut self) -> Result<()> {
        anyhow::ensure!(
            !self.spawn_attempted && self.child.is_none(),
            "original spawn already attempted"
        );
        self.check_current()?;
        self.spawn_attempted = true;
        Ok(())
    }
    pub fn record_spawn(
        &mut self,
        spawned: std::result::Result<
            (Child, OriginalProcess),
            mvm_core::spawn_scope::RetainedSpawnFailure<OriginalProcess>,
        >,
    ) -> Result<()> {
        use mvm_core::spawn_scope::RetainedSpawnFailure;
        let (child, observation, result) = match spawned {
            Ok((child, observation)) => (child, Some(observation), Ok(())),
            Err(RetainedSpawnFailure::NotSpawned(error)) => {
                self.spawn_attempted = false;
                return Err(error);
            }
            Err(RetainedSpawnFailure::Spawned {
                child,
                observation,
                error,
            }) => (child, observation, Err(error)),
        };
        self.child = Some(child);
        if let Some(process) = observation {
            let lease = self.lease.take().context("original spawn lease absent")?;
            self.lifetime = Some(OriginalLifetime::from_observed(
                self.binding.clone(),
                lease,
                process,
            ));
        }
        result
    }
    pub fn authenticate_config(&mut self, stream: &std::os::unix::net::UnixStream) -> Result<()> {
        self.check_current()?;
        self.lifetime
            .as_ref()
            .context("original lifetime absent")?
            .process()?
            .authenticate_config(stream)?;
        let lifetime = self.lifetime.as_ref().context("original lifetime absent")?;
        lifetime
            .process()?
            .verify_inherited_holder(lifetime.lease()?)?;
        self.authenticated = true;
        Ok(())
    }
    pub fn process(&self) -> Result<&OriginalProcess> {
        self.lifetime
            .as_ref()
            .context("original lifetime absent")?
            .process()
    }
    fn observe_original(&mut self) -> Result<()> {
        if self.lifetime.is_none() {
            let child = self
                .child
                .as_mut()
                .context("original spawned child absent")?;
            let process = OriginalProcess::observe(child)?;
            let lease = self.lease.take().context("original process lease absent")?;
            self.lifetime = Some(OriginalLifetime::from_observed(
                self.binding.clone(),
                lease,
                process,
            ));
        }
        Ok(())
    }
    pub fn stop_original(&mut self, until: Instant) -> Result<()> {
        self.observe_original()?;
        let process = self
            .lifetime
            .as_ref()
            .context("original lifetime absent")?
            .process()?;
        if process.wait_exit(Instant::now())? != ProcessExitWait::Exited {
            if Instant::now() >= until {
                return Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into());
            }
            process.terminate()?;
            let grace = until.min(Instant::now() + crate::driver::libkrun_process::STOP_TIMEOUT);
            if process.wait_exit(grace)? != ProcessExitWait::Exited {
                if Instant::now() >= until {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into());
                }
                process.kill()?;
                if process.wait_exit(until)? != ProcessExitWait::Exited {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into());
                }
            }
        }
        let child = self
            .child
            .as_mut()
            .context("original child custody absent")?;
        collect_after_exit_event(until, || child.try_wait())?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
        if let Some(worker) = &mut self.exit_capture {
            worker.stop(until)?;
        }
        Ok(())
    }
    pub fn collect_original(&mut self, until: Instant) -> Result<ConfirmedExit> {
        self.stop_original(until)?;
        anyhow::ensure!(
            self.authenticated,
            "original Firecracker config session was not authenticated; custody remains uncertain"
        );
        let proof = self
            .lifetime
            .as_mut()
            .context("original lifetime absent")?
            .confirm_exit(until)?;
        self.retired = true;
        Ok(proof)
    }
}
impl Drop for OwnedFcState {
    fn drop(&mut self) {
        if self.spawn_attempted && !self.retired {
            if let Some(child) = self.child.take() {
                std::mem::forget(child);
            }
            if let Some(lifetime) = self.lifetime.take() {
                std::mem::forget(lifetime);
            }
            if let Some(lease) = self.lease.take() {
                std::mem::forget(lease);
            }
            if let Some(worker) = self.exit_capture.take() {
                std::mem::forget(worker);
            }
        }
    }
}

/// A failed launch keeps the actual original child and its installation lease.
/// Unknown effects cannot become a no-spawn or positive retirement outcome.
#[derive(Debug)]
pub struct OwnedFcBootFailure {
    pub(super) original: Arc<Mutex<OwnedFcState>>,
    pub(super) error: anyhow::Error,
}
impl OwnedFcBootFailure {
    pub fn collect_original(&mut self, until: Instant) -> Result<ConfirmedExit> {
        self.original
            .lock()
            .map_err(|_| anyhow::anyhow!("original Firecracker custody poisoned"))?
            .collect_original(until)
    }
}

pub(super) fn boot_failure(
    original: Arc<Mutex<OwnedFcState>>,
    error: anyhow::Error,
) -> anyhow::Error {
    let unused = {
        match original.lock() {
            Ok(mut state)
                if !state.spawn_attempted && state.child.is_none() && state.lifetime.is_none() =>
            {
                state
                    .lease
                    .take()
                    .map(|lease| (state.binding.clone(), lease))
            }
            Ok(_) | Err(_) => None,
        }
    };
    if let Some((binding, lease)) = unused {
        OriginalFcNotSpawned {
            binding,
            lease,
            error,
        }
        .into()
    } else {
        OwnedFcBootFailure { original, error }.into()
    }
}

pub(super) fn set_vm_state(
    original: &Arc<Mutex<OwnedFcState>>,
    directory: &std::path::Path,
    state: &str,
) -> Result<()> {
    let mut original = original
        .lock()
        .map_err(|_| anyhow::anyhow!("original Firecracker custody poisoned"))?;
    let socket = crate::fc::fc_api_socket_path(&directory.to_string_lossy());
    let mut session = crate::fc::api_session(&socket)?;
    original.authenticate_config(session.connected_stream())?;
    session.call(
        "PATCH",
        "/vm",
        Some(&serde_json::json!({"state": state}).to_string()),
    )?;
    original.check_current()
}
impl fmt::Display for OwnedFcBootFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original Firecracker boot custody retained: {}",
            self.error
        )
    }
}
impl std::error::Error for OwnedFcBootFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

#[cfg(test)]
mod tests;
