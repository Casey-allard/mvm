//! Trusted parent resource admission for the original canonical installed boot.
//! This DI surface is never supplied by a guest, plan field or quota projection.

use crate::plan_admission::AdmittedPlan;
use anyhow::{Context, Result};
use mvm_core::{
    host_lifetime::{CoreCurrentParentPermit, HostLaunchBinding},
    vm_backend::{BackendKind, VmStartConfig},
};
use std::sync::{Arc, OnceLock};

pub trait ParentAdmissionProvider: Send + Sync {
    /// Bind one original pre-reserved parent grant to actual opaque admission.
    fn bind(
        &self,
        admitted: &AdmittedPlan,
        binding: &HostLaunchBinding,
    ) -> Result<Arc<dyn CoreCurrentParentPermit>>;
}

static INSTALLED: OnceLock<Arc<dyn ParentAdmissionProvider>> = OnceLock::new();

/// One resident process installs its original installation provider prelaunch.
pub fn install(provider: Arc<dyn ParentAdmissionProvider>) -> Result<()> {
    INSTALLED
        .set(provider)
        .map_err(|_| anyhow::anyhow!("installed parent provider already installed"))
}

pub fn require_installed() -> Result<&'static Arc<dyn ParentAdmissionProvider>> {
    INSTALLED
        .get()
        .context("installed launch requires the original parent admission provider")
}

pub(crate) fn bind_current(
    admitted: &AdmittedPlan,
    config: &VmStartConfig,
    backend: BackendKind,
) -> Result<()> {
    let Some(owner) = &config.host_lifetime else {
        return Ok(());
    };
    let provider = require_installed()?;
    owner.bind_admitted(config, backend, admitted.plan())?;
    let permit = provider.bind(admitted, owner.binding())?;
    owner.bind_parent_permit(config, backend, permit)
}
