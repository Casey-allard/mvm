//! Original process and installation custody retained after a failed cold boot.
use anyhow::{Context, Result};
use mvm_core::host_lifetime::{HostLaunchBinding, PreparedHostLifetimeLease};
use mvm_vmm::host::{
    fc_lifetime::{ConfirmedExit, OriginalLifetime, OriginalProcess},
    process_exit::{ProcessExitWait, collect_after_exit_event},
};
use std::{fmt, process::Child, sync::Mutex, time::Instant};

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
pub(super) struct OwnedFcState {
    pub binding: HostLaunchBinding,
    pub lease: Option<PreparedHostLifetimeLease>,
    pub child: Option<Child>,
    pub lifetime: Option<OriginalLifetime>,
}
impl OwnedFcState {
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
            process.terminate()?;
            let grace = until.min(Instant::now() + crate::driver::libkrun_process::STOP_TIMEOUT);
            if process.wait_exit(grace)? != ProcessExitWait::Exited {
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
        collect_after_exit_event(until, || child.try_wait())?;
        Ok(())
    }
    pub fn collect_original(&mut self, until: Instant) -> Result<ConfirmedExit> {
        self.stop_original(until)?;
        self.lifetime
            .as_mut()
            .context("original lifetime absent")?
            .confirm_exit(until)
    }
}

/// A failed launch keeps the actual original child and its installation lease.
/// Unknown effects cannot become a no-spawn or positive retirement outcome.
#[derive(Debug)]
pub struct OwnedFcBootFailure {
    pub(super) original: Mutex<OwnedFcState>,
    pub(super) error: anyhow::Error,
}
impl OwnedFcBootFailure {
    pub fn collect_original(&mut self, until: Instant) -> Result<ConfirmedExit> {
        self.original
            .get_mut()
            .map_err(|_| anyhow::anyhow!("original Firecracker custody poisoned"))?
            .collect_original(until)
    }
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
