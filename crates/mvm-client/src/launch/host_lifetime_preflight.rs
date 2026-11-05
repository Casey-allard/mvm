//! Typed custody for the four pure installed-launch preflight refusals.
use mvm_core::{
    client::MvmError,
    host_lifetime::{HostLaunchBinding, PreparedHostLifetime},
};
use std::{fmt, sync::Arc};

/// The exact preparation returned before conversion or canonical invocation.
/// There is no public constructor, owner getter, serialization or Clone.
#[must_use = "retain for an explicit original-parent cancellation or retry"]
pub struct UnusedHostLifetimePreparation {
    lifetime: PreparedHostLifetime,
}
impl UnusedHostLifetimePreparation {
    pub fn binding(&self) -> &HostLaunchBinding {
        self.lifetime.binding()
    }
    pub fn retains_parent_owner<T: Send + Sync + 'static>(&self, original: &Arc<T>) -> bool {
        self.lifetime.retains_parent_owner(original)
    }
    /// Retry before cancelling the original parent; this grants no permission.
    pub fn into_prepared(self) -> PreparedHostLifetime {
        self.lifetime
    }
}
impl fmt::Debug for UnusedHostLifetimePreparation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnusedHostLifetimePreparation")
            .field("binding", self.binding())
            .finish_non_exhaustive()
    }
}

/// None means uncertain/converted, never a claim that no VM effects occurred.
#[derive(Debug)]
#[must_use = "preserve the original unused preparation or pending launch custody"]
pub struct HostLifetimeLaunchFailure {
    error: MvmError,
    unused: Option<Box<UnusedHostLifetimePreparation>>,
}
impl HostLifetimeLaunchFailure {
    pub(super) fn unused(error: MvmError, lifetime: PreparedHostLifetime) -> Self {
        Self {
            error,
            unused: Some(Box::new(UnusedHostLifetimePreparation { lifetime })),
        }
    }
    pub(super) fn converted(error: MvmError) -> Self {
        Self {
            error,
            unused: None,
        }
    }
    pub fn error(&self) -> &MvmError {
        &self.error
    }
    pub fn into_parts(self) -> (MvmError, Option<UnusedHostLifetimePreparation>) {
        (self.error, self.unused.map(|unused| *unused))
    }
    /// Legacy error handling discards preparation without issuing cleanup proof.
    pub fn into_error(self) -> MvmError {
        self.error
    }
}
impl fmt::Display for HostLifetimeLaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for HostLifetimeLaunchFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
