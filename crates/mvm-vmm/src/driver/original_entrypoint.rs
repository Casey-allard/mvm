//! Closed control operations on one retained original guest session.
use anyhow::Result;
use mvm_agentd::vsock::{EntrypointEvent, GuestRequest, GuestResponse};
use std::time::Instant;

/// Expected host identity from the original in-memory launch registration.
/// This is an identity expectation, not activation or execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalEntrypointIdentity {
    pub host: [u8; 32],
}

/// One activation, entrypoint and terminal flush on the same protected stream.
/// The caller retains signed-plan admission and current-policy enforcement.
/// A failed operation consumes this session; it cannot retry uncertain effects.
pub trait OriginalEntrypointChannel: Send {
    fn activate(&mut self, request: &GuestRequest, until: Instant) -> Result<GuestResponse>;
    fn entrypoint(
        &mut self,
        request: &GuestRequest,
        until: Instant,
        observer: &mut dyn FnMut(&EntrypointEvent),
    ) -> Result<EntrypointEvent>;
    fn sync_filesystems(&mut self, until: Instant) -> Result<()>;
}
