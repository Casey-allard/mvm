//! Trusted parent resource admission for the original canonical installed boot.
//! This DI surface is never supplied by a guest, plan field or quota projection.

use crate::plan_admission::AdmittedPlan;
use anyhow::{Context, Result};
use mvm_core::{
    host_lifetime::{CoreCurrentParentPermit, HostLaunchBinding, HostLifetimeAnchor},
    plan::PlanArtifact,
    vm_backend::{BackendKind, VmStartConfig},
};
use std::sync::{Arc, OnceLock, Weak};

pub trait ParentAdmissionProvider: Send + Sync {
    /// Check that the exact owner already holds workspace qualified for the
    /// signed bundle. Do not open the bundle, bind admission or reserve again.
    fn check_portable_startup_workspace(
        &self,
        _owner: &Arc<HostLifetimeAnchor>,
        _pin: &PlanArtifact,
    ) -> Result<()> {
        anyhow::bail!("original parent portable startup workspace unavailable")
    }

    /// Bind one original pre-reserved parent grant to actual opaque admission.
    fn bind(
        &self,
        admitted: &AdmittedPlan,
        binding: &HostLaunchBinding,
    ) -> Result<Arc<dyn CoreCurrentParentPermit>>;

    /// The same opaque admission with its original verified launch anchor.
    /// Existing providers retain their prior behavior. Installed helper parents
    /// override this to bind actual config/anchor facts before registration.
    fn bind_config(
        &self,
        admitted: &AdmittedPlan,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<Arc<dyn CoreCurrentParentPermit>> {
        let owner = config
            .host_lifetime
            .as_ref()
            .context("installed launch original anchor missing")?;
        owner.verify_config(config, backend)?;
        self.bind(admitted, owner.binding())
    }
}

// The resident owns the provider. A permanent strong registration would retain
// its actual managed reservation after shutdown and prevent global drain.
// Expiry does not reset this OnceLock or permit another installation.
static INSTALLED: OnceLock<Weak<dyn ParentAdmissionProvider>> = OnceLock::new();

/// One resident process installs its original installation provider prelaunch.
/// The resident must retain a strong Arc through shutdown; registration is weak
/// and remains consumed after that original provider expires.
pub fn install(provider: Arc<dyn ParentAdmissionProvider>) -> Result<()> {
    INSTALLED
        .set(Arc::downgrade(&provider))
        .map_err(|_| anyhow::anyhow!("installed parent provider already installed"))
}

pub fn require_installed() -> Result<Arc<dyn ParentAdmissionProvider>> {
    INSTALLED
        .get()
        .and_then(Weak::upgrade)
        .context("installed launch requires the original parent admission provider")
}

pub(crate) fn check_portable_startup_workspace(
    config: &VmStartConfig,
    backend: BackendKind,
    pin: &PlanArtifact,
) -> Result<()> {
    let owner = config
        .host_lifetime
        .as_ref()
        .context("portable startup requires the original host lifetime owner")?;
    owner.verify_config(config, backend)?;
    require_installed()?.check_portable_startup_workspace(owner, pin)
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
    let permit = provider.bind_config(admitted, config, backend)?;
    owner.bind_parent_permit(config, backend, permit)
}
