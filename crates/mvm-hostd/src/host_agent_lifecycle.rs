//! Shared lifecycle coverage for original canonical plans. These classifications
//! coordinate owners; they grant no launch or mailbox authority.

use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;
use mvm_core::vm_backend::BackendKind;

/// Known original coverage; failed reads and unknown profiles remain errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleCoverage {
    Covered,
    KnownOther(BackendKind),
}

/// Classify an original admitted plan or a canonical persisted plan read by
/// checked inventory. No backend is instantiated and no host default is used.
/// This classification does not itself establish admission or collection.
pub fn classify_admitted_plan(plan: &ExecutionPlan) -> Result<LifecycleCoverage> {
    let backend = mvm_runtime::catalog::descriptor_for_selector(&plan.runtime_profile.0)
        .context("original admitted backend is unknown")?
        .kind;
    let reliable_owner = if let Some(service) = plan.mailbox.and_then(|grant| grant.local_service) {
        service.require_implemented()?;
        true
    } else {
        false
    };
    if crate::host_agent_sessions::host_agent_enforces_session_expiry(backend) || reliable_owner {
        return Ok(LifecycleCoverage::Covered);
    }
    match backend {
        BackendKind::Libkrun
        | BackendKind::Mock
        | BackendKind::Hvf
        | BackendKind::Wasm
        | BackendKind::WebLinux
        | BackendKind::AppleContainer => Ok(LifecycleCoverage::KnownOther(backend)),
        BackendKind::Firecracker | BackendKind::Qemu => {
            anyhow::bail!("covered backend lacks its canonical lifecycle owner")
        }
    }
}
