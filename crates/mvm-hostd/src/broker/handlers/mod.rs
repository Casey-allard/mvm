//! Concrete `ServiceHandler` implementations hosted by `mvm-broker`.
//!
//! Each submodule is one handler; the binary's `main` wires them into
//! the [`crate::broker::registry::Registry`] at startup.

pub mod host_assurance_v1;
pub mod host_audit_v1;
pub mod host_beacon_v1;
pub mod host_kv_v1;
pub mod host_time_v1;

use std::sync::Arc;

use mvm_core::protocol::broker::ServiceId;

use self::host_assurance_v1::HostAssuranceV1Handler;
use self::host_kv_v1::HostKvV1Handler;
use self::host_time_v1::HostTimeV1Handler;
use super::registry::Registry;

/// Handles for stateful handlers the caller has to drive after registration.
///
/// Most handlers are stateless and need nothing back. The assurance handler
/// does: a session has to be opened on it from an admitted plan before any
/// probe can land, so the registering caller keeps the `Arc`.
#[derive(Default)]
pub struct BoundHandlers {
    /// Present exactly when `host.assurance.v1` was bound and registered.
    pub assurance: Option<Arc<HostAssuranceV1Handler>>,
}

pub(crate) struct HandlerPublication<'a> {
    assurance: Option<crate::assurance_session::PlanePublicationReservation<'a>>,
}

impl HandlerPublication<'_> {
    pub(crate) fn commit(self) {
        if let Some(assurance) = self.assurance {
            // Already installed is canonical first-wins behavior, not refusal.
            let _installed = assurance.commit();
        }
    }
}

impl BoundHandlers {
    pub(crate) fn reserve_publication(
        &self,
    ) -> Result<HandlerPublication<'_>, crate::assurance_session::PlanePublicationError> {
        let assurance = self
            .assurance
            .as_ref()
            .map(crate::assurance_session::reserve_host_assurance_publication)
            .transpose()?;
        Ok(HandlerPublication { assurance })
    }

    /// Publish the original prepared plane only after its owning registration
    /// commits. This does not admit a session or replace an existing plane.
    pub(crate) fn publish(&self) {
        if let Some(handler) = &self.assurance {
            crate::assurance_session::install_host_assurance_plane(Arc::clone(handler));
        }
    }
}

/// Register stateless built-in handlers named by an admitted service binding.
/// Services absent from `bindings` remain unregistered and therefore fail with
/// `NotBound` at the registry gate.
pub fn register_bound_handlers(registry: &mut Registry, bindings: &[ServiceId]) -> BoundHandlers {
    let bound = build_bound_handlers(registry, bindings);
    bound.publish();
    bound
}

/// Build the same canonical handlers without making their assurance plane
/// visible process-wide. The owning registration explicitly publishes at commit.
pub(crate) fn build_bound_handlers(
    registry: &mut Registry,
    bindings: &[ServiceId],
) -> BoundHandlers {
    let mut bound = BoundHandlers::default();

    let host_time = ServiceId::parse("host.time.v1").expect("host.time.v1 is a valid ServiceId");
    if bindings.contains(&host_time) {
        registry.register(Arc::new(HostTimeV1Handler::new()));
    }

    let host_kv =
        ServiceId::parse(host_kv_v1::HOST_KV_SERVICE).expect("host.kv.v1 is a valid ServiceId");
    if bindings.contains(&host_kv) {
        registry.register(Arc::new(HostKvV1Handler::new()));
    }

    let host_assurance = ServiceId::parse(host_assurance_v1::HOST_ASSURANCE_SERVICE)
        .expect("host.assurance.v1 is a valid ServiceId");
    if bindings.contains(&host_assurance) {
        let handler = Arc::new(HostAssuranceV1Handler::new());
        let as_service: Arc<dyn mvm_core::protocol::handler::ServiceHandler> = handler.clone();
        registry.register(Arc::clone(&as_service));
        registry
            .register_capability(as_service, HostAssuranceV1Handler::capability_descriptor())
            .expect("built-in assurance capability descriptor is valid");
        bound.assurance = Some(handler);
    }

    bound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_assurance_plane_publication_is_explicit() {
        const CHILD: &str = "MVM_TEST_DEFERRED_ASSURANCE_PUBLICATION";
        if std::env::var_os(CHILD).is_none() {
            // A selected fresh process gives this test its own OnceLock. Other
            // broker tests may legitimately publish a plane in the parent.
            let status =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--exact",
                        "broker::handlers::tests::deferred_assurance_plane_publication_is_explicit",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .status()
                    .expect("run isolated publication fixture");
            assert!(status.success(), "isolated publication fixture failed");
            return;
        }

        assert!(crate::assurance_session::host_assurance_plane().is_none());
        let mut registry = Registry::new();
        let service = ServiceId::parse(host_assurance_v1::HOST_ASSURANCE_SERVICE)
            .expect("canonical assurance service");
        let bound = build_bound_handlers(&mut registry, &[service]);
        let original = bound.assurance.as_ref().expect("original bound handler");
        assert!(
            crate::assurance_session::host_assurance_plane().is_none(),
            "preparation must not publish the assurance plane before commit"
        );
        bound.publish();
        let published = crate::assurance_session::host_assurance_plane()
            .expect("explicit commit publishes the plane");
        assert!(
            Arc::ptr_eq(original, &published),
            "commit must publish the handler the prepared registry owns"
        );
    }
}
