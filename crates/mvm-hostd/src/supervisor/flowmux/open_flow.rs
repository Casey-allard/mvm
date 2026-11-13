//! The open-a-flow decision for one guest `OpenTcp`.
//!
//! A guest names a destination. This module decides first whether that
//! destination may be reached at all — the claim-10 gate, the single decision
//! point — and only then how the flow is served: terminated on the host so a
//! bound credential can be substituted into the request, relayed opaquely, or
//! refused. The order is the point. The shape of a flow is only ever chosen
//! against a destination admission has already allowed.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use mvm_vmm::vsock_egress_bridge::egress_gate::{EgressVerdict, Route};
use tracing::warn;

use super::socket::FlowSocket;
use super::tcp_relay::connect_first_admitted;
use super::wire::{lock_registry, parse_host_port};
use super::{FlowMuxError, FlowMuxSession, registry};
use crate::supervisor::audit_recorder::EventCategory;
use crate::supervisor::network_endpoint_proxy::TerminationMode;
use crate::supervisor::terminator;
use mvm_contract::protocol::network_flow::open_tcp::{OpenTcpPayloadError, decode_open_tcp};

/// One `OpenTcp` the claim-10 gate admitted: what the guest named, and what
/// the gate decided about it. Carried between admission and whichever way the
/// flow is then served, so neither half re-derives the other's facts.
struct AdmittedFlow {
    /// The `host:port` exactly as the guest wrote it, for the audit label.
    target: String,
    /// The host half of that target — what a secret binding is checked
    /// against, and the authority a terminated request must agree with.
    host: String,
    /// Which policy namespace decided the flow. Kept typed rather than as its
    /// label, because one of the two values decides whether the flow may be
    /// terminated at all.
    route: Route,
    /// Every address the gate admitted, in its order.
    ips: Vec<IpAddr>,
    /// The admitted port, which the gate may have chosen rather than taken
    /// from the target.
    port: u16,
    requested_port: u16,
}

enum RelayAdmission {
    Proceed(Option<OwnedRelayAdmission>),
    Refused,
}
struct OwnedRelayAdmission {
    reservation: super::owned_relays::RelayReservation,
    deadline: std::time::Instant,
}

impl AdmittedFlow {
    /// Render the admitted addresses as one audit label value.
    fn resolved_ips(&self) -> String {
        FlowMuxSession::format_ips(&self.ips)
    }

    /// The audit-label form of the route.
    fn route_label(&self) -> String {
        self.route.as_str().to_string()
    }

    fn allowed_tcp_labels(&self, stream_id: u32) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("stream_id".to_string(), stream_id.to_string()),
            ("class".to_string(), "tcp".to_string()),
            ("route".to_string(), self.route_label()),
            ("target".to_string(), self.target.clone()),
            ("resolved_ips".to_string(), self.resolved_ips()),
        ])
    }

    /// Whether this flow may be served by terminating it on the host.
    ///
    /// Only an egress-routed flow may. A peer route's admitted address *is*
    /// the translation — the gate rewrites `<name>.mvm.peer:<port>` to the
    /// peer's local ingress mapping, and the name resolves nowhere — so a
    /// terminated peer flow would discard the one fact that made it
    /// reachable and re-originate by an unresolvable name. A peer flow
    /// therefore falls through to the opaque path, where a bound destination
    /// is refused at open.
    fn may_terminate(&self) -> bool {
        matches!(self.route, Route::Egress)
    }
}

/// How a terminated flow was terminated, as an audit label. Metadata about
/// which flow was decided and how, never anything from inside it.
fn termination_label(mode: TerminationMode) -> &'static str {
    match mode {
        TerminationMode::Tls => "tls",
        TerminationMode::Cleartext => "cleartext",
    }
}

impl FlowMuxSession {
    fn reserve_owned_tcp_relay(
        &mut self,
        stream_id: u32,
        flow: &AdmittedFlow,
    ) -> Result<RelayAdmission, FlowMuxError> {
        let reservation = self
            .owned_tcp_relays
            .as_ref()
            .map(|owned| {
                let deadline = std::time::Instant::now()
                    .checked_add(self.connect_timeout)
                    .ok_or_else(|| std::io::Error::other("owned flow deadline overflow"))?;
                owned
                    .reserve_until(deadline)
                    .map(|reservation| OwnedRelayAdmission {
                        reservation,
                        deadline,
                    })
            })
            .transpose();
        match reservation {
            Ok(reservation) => Ok(RelayAdmission::Proceed(reservation)),
            Err(_) => {
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_refused(stream_id, "owned relay capacity unavailable")?;
                self.deny_flow(stream_id, flow, "relay_capacity_unavailable");
                Ok(RelayAdmission::Refused)
            }
        }
    }

    /// Serve one guest `OpenTcp`.
    ///
    /// Admission first — rate, then the claim-10 gate, which is the single
    /// decision point about whether this destination may be reached at all.
    /// Only then does the flow's *shape* get decided: a destination carrying a
    /// bound secret is terminated on the host so the credential can be
    /// substituted into the request, and everything else is relayed opaquely.
    /// A bound destination this endpoint cannot terminate stays refused rather
    /// than being relayed, because relaying it would put a placeholder on the
    /// wire to a real upstream. A peer-routed flow is never terminated at all —
    /// see [`AdmittedFlow::may_terminate`].
    pub(super) fn handle_open_tcp(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        let Some(flow) = self.admit_open_tcp(stream_id, payload_len)? else {
            return Ok(());
        };
        let termination = if flow.may_terminate() {
            self.substitution
                .as_ref()
                .and_then(|service| service.terminable(&flow.host, flow.port))
        } else {
            None
        };
        let Some(mode) = termination else {
            if let Some(refusal) = self
                .substitution
                .as_ref()
                .and_then(|service| service.route_refusal(&flow.host, flow.port))
            {
                self.send_refused(
                    stream_id,
                    "destination has endpoint rules; the plan must grant interception to enforce them",
                )?;
                self.deny_route_flow(stream_id, &flow, &refusal.route_id, refusal.reason);
                return Ok(());
            }
            if let Some(reason) = self
                .substitution
                .as_ref()
                .and_then(|service| service.opaque_refusal_reason(&flow.host))
            {
                self.send_refused(stream_id, reason)?;
                self.deny_flow(stream_id, &flow, "typed_transform_required");
                return Ok(());
            }
            return self.open_opaque_flow(stream_id, &flow);
        };
        if self
            .payload_mapping
            .as_ref()
            .is_some_and(|mapping| mapping.selects(&flow.host, flow.requested_port))
        {
            self.send_refused(
                stream_id,
                "selected payload profile does not support this terminated transform path",
            )?;
            self.deny_flow(stream_id, &flow, "payload_transform_unsupported");
            return Ok(());
        }
        self.open_terminated_flow(stream_id, &flow, mode)
    }

    /// Parse, rate-limit, and gate one `OpenTcp` target.
    ///
    /// `Ok(None)` means the guest has already been answered with a refusal and
    /// the audit entry for it emitted.
    fn admit_open_tcp(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<Option<AdmittedFlow>, FlowMuxError> {
        let target = match decode_open_tcp(self.frame_payload(payload_len)) {
            Ok(target) => target.to_string(),
            Err(OpenTcpPayloadError::LegacyBinding) => {
                self.send_refused(stream_id, "tool invocation bindings are not supported")?;
                self.deny_unrouted_flow(
                    stream_id,
                    registry::FlowClass::Tcp,
                    "legacy-binding",
                    "tool_binding_unsupported",
                );
                return Ok(None);
            }
            Err(error) => {
                self.send_refused(stream_id, &error.to_string())?;
                return Ok(None);
            }
        };

        let (host, requested_port) = match parse_host_port(&target) {
            Ok((host, port)) => (host.to_string(), port),
            Err(e) => {
                self.send_refused(stream_id, &format!("invalid OpenTcp target: {e}"))?;
                return Ok(None);
            }
        };

        if !self.check_connection_rate(registry::FlowClass::Tcp) {
            self.send_refused(stream_id, "rate limited")?;
            self.deny_unrouted_flow(stream_id, registry::FlowClass::Tcp, &target, "rate_limited");
            return Ok(None);
        }

        let decision = self.gate.decide_target(&host, requested_port);
        // Recorded on every audit entry this connect emits, so the chain says
        // which namespace authorized (or refused) the flow rather than leaving
        // a reader to infer it from the target's shape.
        let mut flow = AdmittedFlow {
            target,
            host,
            route: decision.route,
            ips: Vec::new(),
            port: requested_port,
            requested_port,
        };
        match decision.verdict {
            EgressVerdict::Allow { ips, port } => {
                flow.ips = ips;
                flow.port = port;
                Ok(Some(flow))
            }
            EgressVerdict::Deny(reason) => {
                self.send_refused(stream_id, &reason.to_string())?;
                self.deny_flow(stream_id, &flow, reason.audit_label());
                Ok(None)
            }
            EgressVerdict::Malformed => {
                self.send_refused(stream_id, "malformed destination")?;
                self.deny_flow(stream_id, &flow, "malformed");
                Ok(None)
            }
        }
    }

    /// Relay an admitted flow straight through to its destination.
    fn open_opaque_flow(
        &mut self,
        stream_id: u32,
        flow: &AdmittedFlow,
    ) -> Result<(), FlowMuxError> {
        // The selected installed profile requires its original cooperating
        // mapping. A policy admission alone cannot select an implicit raw
        // transport. General/legacy FlowMux retains its existing behavior.
        if self.installed_audit.is_some()
            && !self
                .payload_mapping
                .as_ref()
                .is_some_and(|mapping| mapping.selects(&flow.host, flow.requested_port))
        {
            self.send_refused(stream_id, "selected installed payload mapping required")?;
            self.deny_flow(stream_id, flow, "installed_payload_unmapped");
            return Ok(());
        }
        if !self.reserve_stream(stream_id, flow)? {
            return Ok(());
        }
        let owned = match self.reserve_owned_tcp_relay(stream_id, flow)? {
            RelayAdmission::Proceed(owned) => owned,
            RelayAdmission::Refused => return Ok(()),
        };
        let owned_deadline = owned.as_ref().map(|owned| owned.deadline);
        let reservation = owned.map(|owned| owned.reservation);

        let selected_mapping = if let Some(mapping) = self
            .payload_mapping
            .as_ref()
            .filter(|mapping| mapping.selects(&flow.host, flow.requested_port))
        {
            let deadline = if let Some(deadline) = owned_deadline {
                deadline
            } else {
                std::time::Instant::now()
                    .checked_add(self.connect_timeout)
                    .ok_or_else(|| std::io::Error::other("payload setup deadline overflow"))?
            };
            Some((Arc::clone(mapping), deadline))
        } else {
            None
        };

        let prepared_audit = if self.installed_audit.is_some() {
            self.check_installed_audit()?;
            let recorder = self.recorder.as_ref().ok_or_else(|| {
                FlowMuxError::FrameRefused("original installed recorder missing".into())
            })?;
            let deadline = owned_deadline.ok_or_else(|| {
                FlowMuxError::FrameRefused("original installed flow deadline missing".into())
            })?;
            Some(
                recorder
                    .preflight_installed_unbound(
                        EventCategory::Host,
                        "host.flow.allowed",
                        deadline,
                        || flow.allowed_tcp_labels(stream_id),
                    )
                    .map_err(|_| {
                        FlowMuxError::FrameRefused("installed flow audit preflight refused".into())
                    })?,
            )
        } else {
            None
        };
        let timeout = owned_deadline
            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()))
            .unwrap_or_else(|| {
                selected_mapping
                    .as_ref()
                    .map_or(self.connect_timeout, |(_, deadline)| {
                        deadline.saturating_duration_since(std::time::Instant::now())
                    })
            });
        let upstream = match connect_first_admitted(&flow.ips, flow.port, timeout) {
            Some(stream) => stream,
            None => {
                warn!(stream_id, target = %flow.target, "FlowMux TCP connect failed");
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_connect_failed(stream_id, "connection failed")?;
                self.deny_flow(stream_id, flow, "connect_failed");
                return Ok(());
            }
        };
        if let Some(prepared) = prepared_audit {
            let appended = (|| {
                self.check_installed_audit()?;
                let recorder = self.recorder.as_ref().ok_or_else(|| {
                    FlowMuxError::FrameRefused("original installed recorder missing".into())
                })?;
                let runtime = self.runtime_handle.as_ref().ok_or_else(|| {
                    FlowMuxError::FrameRefused("installed audit runtime missing".into())
                })?;
                runtime
                    .block_on(recorder.record_installed_prepared(prepared))
                    .map_err(|_| {
                        FlowMuxError::FrameRefused("installed flow audit append refused".into())
                    })?;
                self.check_installed_audit()
            })();
            if let Err(error) = appended {
                let _ = upstream.shutdown(std::net::Shutdown::Both);
                if let Some(audit) = &self.installed_audit {
                    audit.fence();
                }
                return Err(error);
            }
        }
        if let Some(reservation) = &reservation {
            let guest = self
                .owned_guest_control
                .clone()
                .ok_or_else(|| std::io::Error::other("owned guest control missing"))?;
            reservation.bind_setup(&upstream, guest)?;
        }

        let upstream = if let Some((mapping, deadline)) = selected_mapping {
            let guest_key = self
                .session
                .lock()
                .map_err(|_| std::io::Error::other("session poisoned"))?
                .peer_verifying_key()
                .to_bytes();
            let facts = super::payload_mapping::AdmittedTcpFacts {
                session_id: self.session_id(),
                guest_key,
                stream_id,
                requested_host: flow.host.clone(),
                requested_port: flow.requested_port,
                route: flow.route.as_str(),
                deadline,
                owned_relay: reservation
                    .as_ref()
                    .map(|reservation| reservation.witness())
                    .transpose()?,
            };
            match mapping.map(upstream, facts) {
                Ok(payload) => FlowSocket::mapped(payload),
                Err(error) => {
                    // A peer EOF alone is not evidence of an orderly local stop.
                    if error.kind() == std::io::ErrorKind::UnexpectedEof
                        && let Some(stopped) = self
                            .installed_session_control
                            .as_ref()
                            .and_then(|control| control.stop_error())
                        && let Some(reservation) = &reservation
                        && reservation.setup_was_stopped()?
                    {
                        return Err(stopped.into());
                    }
                    warn!(stream_id,error=%error,"required payload mapping refused");
                    let _ = lock_registry(&self.registry).retire(stream_id);
                    self.send_refused(
                        stream_id,
                        "required authenticated payload mapping unavailable",
                    )?;
                    self.deny_flow(stream_id, flow, "payload_mapping_unavailable");
                    return Ok(());
                }
            }
        } else {
            FlowSocket::from(upstream)
        };
        if owned_deadline.is_some_and(|until| std::time::Instant::now() >= until) {
            let _ = upstream.shutdown(std::net::Shutdown::Both);
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_refused(stream_id, "owned flow setup deadline")?;
            self.deny_flow(stream_id, flow, "owned_setup_deadline");
            return Ok(());
        }
        if !self.confirm_stream(stream_id)? {
            return Ok(());
        }
        self.send_opened(stream_id)?;
        self.spawn_tcp_relay(stream_id, upstream, reservation)?;
        if self.installed_audit.is_none() {
            self.emit_audit(
                EventCategory::Host,
                "host.flow.allowed",
                flow.allowed_tcp_labels(stream_id),
            );
        }
        Ok(())
    }

    /// Serve an admitted flow by terminating it on this host.
    ///
    /// The guest's half of the flow is one end of a local socket pair, so the
    /// relay and the credit accounting are exactly what they are for an opaque
    /// flow; the other end is driven by the terminator, which reads each
    /// request, puts it through the substitution pipeline, and writes the
    /// response back. Nothing dials the destination here — the forward leg
    /// inside that pipeline does.
    fn open_terminated_flow(
        &mut self,
        stream_id: u32,
        flow: &AdmittedFlow,
        mode: TerminationMode,
    ) -> Result<(), FlowMuxError> {
        let (Some(service), Some(runtime)) =
            (self.substitution.clone(), self.runtime_handle.clone())
        else {
            self.send_refused(stream_id, "termination unavailable on this endpoint")?;
            self.deny_flow(stream_id, flow, "termination_unavailable");
            return Ok(());
        };
        let reservation = match self.reserve_owned_tcp_relay(stream_id, flow)? {
            RelayAdmission::Proceed(owned) => owned.map(|owned| owned.reservation),
            RelayAdmission::Refused => return Ok(()),
        };

        // Claimed before anything is built, and held by the flow's thread for
        // its whole life. A terminated flow is several times the cost of an
        // opaque one, so it gets its own ceiling rather than sharing the
        // registry's.
        let Some(slot) = terminator::flow::FlowSlot::claim(&self.terminated_flows) else {
            self.send_refused(stream_id, "too many terminated flows")?;
            self.deny_flow(stream_id, flow, "termination_exhausted");
            return Ok(());
        };

        let terminated = match terminator::flow::TerminatedFlow::builder()
            .service(Arc::clone(&service))
            .runtime(runtime)
            .leaves(Arc::clone(&self.leaves))
            .authority(&flow.host, flow.port)
            .mode(mode)
            .build()
        {
            Ok(terminated) => terminated,
            Err(reason) => {
                warn!(stream_id, %reason, "FlowMux terminated flow is incomplete");
                self.send_refused(stream_id, reason)?;
                self.deny_flow(stream_id, flow, "termination_unavailable");
                return Ok(());
            }
        };

        if !self.reserve_stream(stream_id, flow)? {
            return Ok(());
        }

        let (endpoint_side, terminator_side) = match UnixStream::pair() {
            Ok(pair) => pair,
            Err(error) => {
                warn!(stream_id, %error, "FlowMux terminated flow has no transport");
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_connect_failed(stream_id, "termination setup failed")?;
                self.deny_flow(stream_id, flow, "termination_failed");
                return Ok(());
            }
        };

        if let Err(error) = terminator::flow::spawn(terminated, terminator_side, slot) {
            warn!(stream_id, %error, "FlowMux terminated flow could not start");
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_connect_failed(stream_id, "termination setup failed")?;
            self.deny_flow(stream_id, flow, "termination_failed");
            return Ok(());
        }

        if !self.confirm_stream(stream_id)? {
            return Ok(());
        }

        self.send_opened(stream_id)?;
        self.spawn_tcp_relay(stream_id, FlowSocket::from(endpoint_side), reservation)?;
        let mut labels = BTreeMap::from([
            ("stream_id".to_string(), stream_id.to_string()),
            ("class".to_string(), "tcp".to_string()),
            ("route".to_string(), flow.route_label()),
            ("target".to_string(), flow.target.clone()),
            ("resolved_ips".to_string(), flow.resolved_ips()),
            (
                "termination".to_string(),
                termination_label(mode).to_string(),
            ),
        ]);
        // The forward leg behind a terminated flow speaks the scheme the
        // terminator re-originates under, so the proxy read here is the exact
        // one the leg will make per request. An endpoint with no upstream
        // proxy records no label, keeping the entry's bytes what they were
        // before the label existed.
        if let Some(path) =
            service.forward_path_for(&flow.host, Some(matches!(mode, TerminationMode::Tls)))
        {
            labels.insert("via".to_string(), path.label().to_string());
        }
        self.emit_audit(EventCategory::Host, "host.flow.allowed", labels);
        Ok(())
    }

    /// Take a registry slot for an admitted flow. `Ok(false)` means the guest
    /// has been refused and the refusal audited.
    fn reserve_stream(
        &mut self,
        stream_id: u32,
        flow: &AdmittedFlow,
    ) -> Result<bool, FlowMuxError> {
        let open_err = lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Tcp)
            .err();
        if let Some(e) = open_err {
            self.send_refused(stream_id, &e.to_string())?;
            self.deny_flow(stream_id, flow, "resource_exhausted");
            return Ok(false);
        }
        Ok(true)
    }

    /// Move a reserved slot to live. `Ok(false)` means the guest has been
    /// refused and the slot released.
    fn confirm_stream(&mut self, stream_id: u32) -> Result<bool, FlowMuxError> {
        let confirm_err = lock_registry(&self.registry).confirm(stream_id).err();
        if let Some(e) = confirm_err {
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_refused(stream_id, &e.to_string())?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Audit a refusal of a flow the gate had already routed.
    fn deny_flow(&self, stream_id: u32, flow: &AdmittedFlow, reason: &str) {
        self.emit_audit(
            EventCategory::Host,
            "host.flow.denied",
            Self::flow_denial_labels(stream_id, flow, reason),
        );
    }

    fn deny_route_flow(&self, stream_id: u32, flow: &AdmittedFlow, route_id: &str, reason: &str) {
        let mut labels = Self::flow_denial_labels(stream_id, flow, reason);
        labels.insert("endpoint_route".into(), route_id.into());
        labels.insert("rule".into(), "not_evaluated".into());
        self.emit_audit(EventCategory::Host, "host.flow.denied", labels);
    }

    fn flow_denial_labels(
        stream_id: u32,
        flow: &AdmittedFlow,
        reason: &str,
    ) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("stream_id".to_string(), stream_id.to_string()),
            ("class".to_string(), "tcp".to_string()),
            ("route".to_string(), flow.route_label()),
            ("target".to_string(), flow.target.clone()),
            ("reason".to_string(), reason.to_string()),
        ])
    }

    /// Audit a refusal of a flow to `target` that carries no route: taken
    /// before the gate chose one, or decided for a datagram, which the gate
    /// never routes.
    pub(super) fn deny_unrouted_flow(
        &self,
        stream_id: u32,
        class: registry::FlowClass,
        target: &str,
        reason: &str,
    ) {
        self.emit_audit(
            EventCategory::Host,
            "host.flow.denied",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), class.to_string()),
                ("target".to_string(), target.to_string()),
                ("reason".to_string(), reason.to_string()),
            ]),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::thread;

    use mvm_contract::protocol::network_flow::Opcode;
    use mvm_contract::protocol::network_flow::hello::Handshake;
    use mvm_core::net::session::Session;
    use mvm_vmm::vsock_egress_bridge::egress_gate::EgressGate;

    use super::*;
    use crate::supervisor::flowmux::registry::RegistryLimits;
    use crate::supervisor::flowmux::tests::{
        fresh_keys, gate_allowing_addr, gate_pinning_name, local_test_ip, read_flowmux_frame,
        recorder_at, run_session, run_session_from, run_session_on_runtime, run_session_with,
        tcp_echo_server, write_frame,
    };
    use crate::supervisor::flowmux::{FlowMuxAccept, FlowMuxVmResources};

    #[test]
    fn authenticated_canonical_tcp_preserves_shared_whole_warm_runtime_and_combined() {
        use crate::supervisor::flowmux::{
            PayloadArtifact, PayloadScopeController, PreparedPayloadSession,
            SpiralCorePayloadFactory, accept_enrolled_payload,
        };
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use mvm_contract::peer::{PeerBinding, PeerName};
        use mvm_contract::policy::network_policy::{
            CooperatingPayloadPolicy, CooperatingTcpPeer, NetworkPolicy, PayloadMappingProfile,
        };
        use spiralcore_mvm_flowmux::{
            Role,
            scope::{PinnedScopePolicy, ScopeFacts},
            tls::{PinnedIdentity, TlsCarrier},
        };
        use spiralcore_transfer::{
            endpoint::Limits,
            shared_runtime::{OutputKind, Recipe, State},
            shared_transfer::PreparedPrediction,
            v1::{NegotiatedProfile, ObjectEndpoint, ObjectMode, ObjectSender},
        };
        use std::{
            io::{Read, Write},
            time::{Duration, Instant},
        };
        fn prediction() -> PreparedPrediction {
            PreparedPrediction::new(
                &State::seeded(48)
                    .expect("state")
                    .encode()
                    .expect("checkpoint"),
                &Recipe {
                    steps: 16,
                    payload: 1.25,
                    output: OutputKind::Trace,
                },
            )
            .expect("prediction")
        }
        fn limits() -> Limits {
            Limits {
                max_active: 1,
                max_states: 8,
                max_publications: 64,
                resident_bytes: 128 << 20,
                namespace_bytes: 128 << 20,
                cache_bytes: 16 << 20,
                graph_cache_bytes: 16 << 20,
                ..Limits::default()
            }
        }
        #[derive(Debug)]
        struct Controller {
            mode: ObjectMode,
            pool: crate::supervisor::flowmux::PayloadResourcePool,
            root: std::path::PathBuf,
            receiver: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<PreparedPayloadSession>>>,
        }
        impl PayloadScopeController for Controller {
            fn prepare(
                &self,
                request: &crate::supervisor::flowmux::AdmittedTcpPayload,
                facts: &ScopeFacts,
                profile: NegotiatedProfile,
                deadline: Instant,
            ) -> std::io::Result<PreparedPayloadSession> {
                assert!(Instant::now() < deadline);
                assert_eq!(facts.plan_id, request.plan().plan_id.0);
                assert_eq!(facts.requested_port, 443);
                assert_ne!(
                    facts.actual_peer.port(),
                    443,
                    "canonical peer route must retain its translated admitted TCP port"
                );
                let error = |e: spiralcore_transfer::Error| std::io::Error::other(e.to_string());
                let mapping_error =
                    |e: spiralcore_mvm_flowmux::Error| std::io::Error::other(e.to_string());
                // This General functional fixture explicitly reserves two
                // local engines before codec/storage setup. It is outside the
                // separate8MiB DEV envelope, not a production host grant.
                let left_resources = self.pool.reserve_shared_sender(self.mode)?;
                let right_resources = self.pool.reserve_shared_sender(ObjectMode::Whole)?;
                let policy = PinnedScopePolicy::new(2).map_err(mapping_error)?;
                policy
                    .enroll(
                        facts,
                        facts.acceptor_spki,
                        Role::Initiator,
                        Instant::now() + Duration::from_secs(5),
                    )
                    .map_err(mapping_error)?;
                policy
                    .enroll(
                        facts,
                        facts.initiator_spki,
                        Role::Acceptor,
                        Instant::now() + Duration::from_secs(5),
                    )
                    .map_err(mapping_error)?;
                let left = policy
                    .authorize_scope(facts, facts.acceptor_spki, Role::Initiator)
                    .map_err(mapping_error)?;
                let right = policy
                    .authorize_scope(facts, facts.initiator_spki, Role::Acceptor)
                    .map_err(mapping_error)?;
                let schema =
                    spiralcore_transfer::schema::fit(&[b"{\"value\":0}\n"]).map_err(error)?;
                let (sender, artifacts) = match self.mode {
                    ObjectMode::Whole => (
                        ObjectSender::new_with_profile(
                            ObjectMode::Whole,
                            left.context(),
                            None,
                            profile,
                        )
                        .map_err(error)?,
                        Vec::new(),
                    ),
                    ObjectMode::Warm => (
                        ObjectSender::new_with_profile(
                            ObjectMode::Warm,
                            left.context(),
                            Some(&schema),
                            profile,
                        )
                        .map_err(error)?,
                        vec![
                            PayloadArtifact::Schema,
                            PayloadArtifact::Base(
                                (0..8192).map(|i| ((i * 173 + i / 7) % 251) as u8).collect(),
                            ),
                        ],
                    ),
                    ObjectMode::Runtime => (
                        ObjectSender::with_runtime_profile(left.context(), prediction(), profile)
                            .map_err(error)?,
                        vec![PayloadArtifact::Checkpoint],
                    ),
                    ObjectMode::Combined => (
                        ObjectSender::with_combined_policy_and_profile(
                            left.context(),
                            prediction(),
                            &schema,
                            spiralcore_transfer::session::SelectionPolicy::Exhaustive,
                            profile,
                        )
                        .map_err(error)?,
                        vec![PayloadArtifact::Checkpoint, PayloadArtifact::Schema],
                    ),
                    ObjectMode::Raw => unreachable!("fixture selects four intended shared modes"),
                };
                let right_sender = ObjectSender::new_with_profile(
                    ObjectMode::Whole,
                    right.context(),
                    None,
                    profile,
                )
                .map_err(error)?;
                let right_endpoint = ObjectEndpoint::open(
                    &self.root.join("right"),
                    limits(),
                    right.clone(),
                    profile,
                )
                .map_err(error)?;
                let right = PreparedPayloadSession::new(
                    right,
                    right_sender,
                    right_endpoint,
                    right_resources.with_owned_store(self.root.join("right"))?,
                )?;
                self.receiver
                    .lock()
                    .expect("controller mutex")
                    .take()
                    .expect("one actual stream")
                    .send(right)
                    .map_err(|_| std::io::Error::other("receiver enrollment disappeared"))?;
                let endpoint =
                    ObjectEndpoint::open(&self.root.join("left"), limits(), left.clone(), profile)
                        .map_err(error)?;
                PreparedPayloadSession::new(
                    left,
                    sender,
                    endpoint,
                    left_resources.with_owned_store(self.root.join("left"))?,
                )?
                .with_artifacts(artifacts)
            }
        }
        for mode in [
            ObjectMode::Whole,
            ObjectMode::Warm,
            ObjectMode::Runtime,
            ObjectMode::Combined,
        ] {
            let stores = tempfile::tempdir().expect("stores");
            let server_key = ed25519_dalek::SigningKey::from_bytes(&[75; 32]);
            let server_identity = PinnedIdentity::from_pkcs8(
                server_key
                    .to_pkcs8_der()
                    .expect("PKCS8")
                    .as_bytes()
                    .to_vec(),
            )
            .expect("identity");
            let client_key = ed25519_dalek::SigningKey::from_bytes(&[76; 32]);
            let client_identity = PinnedIdentity::from_pkcs8(
                client_key
                    .to_pkcs8_der()
                    .expect("PKCS8")
                    .as_bytes()
                    .to_vec(),
            )
            .expect("identity");
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
            listener.set_nonblocking(true).expect("nonblocking");
            let address = listener.local_addr().expect("address");
            let target = "cooperator.mvm.peer";
            let policy = NetworkPolicy::deny_all()
                .with_peers(vec![PeerBinding {
                    name: PeerName::parse(target).expect("name"),
                    port: 443,
                    host_addr: address.ip().to_string(),
                    host_port: address.port(),
                }])
                .with_payload_mapping(Some(
                    CooperatingPayloadPolicy::new(vec![CooperatingTcpPeer {
                        host: target.into(),
                        port: 443,
                        server_name: target.into(),
                        spki_sha256: server_identity.spki_sha256(),
                        profile: PayloadMappingProfile::SpiralCoreObjectStreamV1,
                    }])
                    .expect("policy"),
                ));
            let binding = mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan {
                plan_id: mvm_core::plan::PlanId(format!("actual-{mode:?}-plan")),
                plan_version: 3,
                plan_nonce: mvm_core::plan::Nonce::from_bytes([10; 16]),
                bundle_sha256: "c".repeat(64),
                tenant_id: "tenant".into(),
                instance_id: "instance".into(),
                policy_sha256: mvm_core::policy::network_policy::content_sha256(&policy),
            };
            let (receiver_tx, receiver_rx) = std::sync::mpsc::sync_channel(1);
            let controller = Arc::new(Controller {
                mode,
                pool: crate::supervisor::flowmux::PayloadResourcePool::for_qualification(
                    crate::supervisor::flowmux::PayloadResourceLimits {
                        max_active: 2,
                        resident_bytes: 2 << 30,
                        disk_bytes: 5 << 30,
                    },
                )
                .expect("explicit General functional ledger"),
                root: stores.path().to_owned(),
                receiver: std::sync::Mutex::new(Some(receiver_tx)),
            });
            let factory = Arc::new(
                SpiralCorePayloadFactory::from_host_key(&client_key, controller.clone())
                    .expect("factory"),
            );
            let mapping = Arc::new(
                crate::supervisor::flowmux::PayloadMappingConfig::new(&policy, binding)
                    .expect("config")
                    .with_factory(factory),
            );
            let gate = crate::supervisor::network_endpoint::build_egress_gate(&policy);
            let mut bytes = if matches!(mode, ObjectMode::Runtime | ObjectMode::Combined) {
                prediction().prediction().to_vec()
            } else {
                (0..8192).map(|i| ((i * 173 + i / 7) % 251) as u8).collect()
            };
            let n = bytes.len();
            bytes[n / 2] ^= 7;
            let expected = bytes.clone();
            thread::scope(|scope| {
                let peer = scope.spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(3);
                    let (socket, _) = loop {
                        match listener.accept() {
                            Ok(pair) => break pair,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                assert!(Instant::now() < deadline);
                                thread::sleep(Duration::from_millis(1));
                            }
                            Err(e) => panic!("accept:{e}"),
                        }
                    };
                    let tls = TlsCarrier::accept(
                        socket,
                        &server_identity,
                        client_identity.spki_sha256(),
                        deadline,
                    )
                    .expect("TLS");
                    let prepared = receiver_rx
                        .recv_timeout(Duration::from_secs(2))
                        .expect("explicit receiver enrollment");
                    let mut stream = accept_enrolled_payload(tls, prepared, deadline)
                        .expect("enrolled acceptor");
                    let mut received = Vec::new();
                    stream.read_to_end(&mut received).expect("application read");
                    assert_eq!(
                        received, expected,
                        "artifact bytes cannot leak into application"
                    );
                    stream.write_all(&received).expect("reverse");
                    stream
                        .shutdown(std::net::Shutdown::Write)
                        .expect("reverse FIN");
                    received.len()
                });
                let (mut guest, mut session, host) =
                    run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
                        FlowMuxAccept::new(id, key, anchor, limits, gate)
                            .with_payload_mapping(Some(mapping))
                    });
                guest
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");
                write_frame(
                    &mut guest,
                    &mut session,
                    Opcode::OpenTcp,
                    1,
                    b"cooperator.mvm.peer:443",
                );
                let opened = read_flowmux_frame(&mut guest, &mut session);
                assert_eq!(
                    opened.0,
                    Opcode::Opened,
                    "{mode:?}:{}",
                    String::from_utf8_lossy(&opened.2)
                );
                assert_eq!(
                    controller.pool.snapshot().expect("live resources").active,
                    2,
                    "each local engine holds its reservation across mapped I/O clones"
                );
                write_frame(&mut guest, &mut session, Opcode::Data, 1, &bytes);
                write_frame(&mut guest, &mut session, Opcode::HalfClose, 1, b"");
                let mut actual = Vec::new();
                loop {
                    let (opcode, id, data) = read_flowmux_frame(&mut guest, &mut session);
                    assert_eq!(id, 1);
                    match opcode {
                        Opcode::WindowUpdate => {}
                        Opcode::Data => actual.extend_from_slice(&data),
                        Opcode::HalfClose => break,
                        other => panic!(
                            "{mode:?}:unexpected{other:?}:{}",
                            String::from_utf8_lossy(&data)
                        ),
                    }
                }
                assert_eq!(actual, bytes);
                drop(guest);
                host.join().expect("host join").expect("serve");
                assert_eq!(peer.join().expect("peer join"), bytes.len());
            });
            assert_eq!(
                controller.pool.snapshot().expect("joined resources").active,
                0
            );
            assert!(!stores.path().join("left").exists());
            assert!(!stores.path().join("right").exists());
        }
    }

    #[test]
    fn authenticated_payload_peer_without_enrolled_scope_is_refused_before_application() {
        use crate::supervisor::flowmux::{
            PayloadScopeController, PreparedPayloadSession, SpiralCorePayloadFactory,
        };
        use mvm_contract::peer::{PeerBinding, PeerName};
        use mvm_contract::policy::network_policy::{
            CooperatingPayloadPolicy, CooperatingTcpPeer, NetworkPolicy, PayloadMappingProfile,
        };
        use spiralcore_mvm_flowmux::{
            scope::ScopeFacts,
            tls::{PinnedIdentity, TlsCarrier},
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Debug)]
        struct DenyController(Arc<AtomicUsize>);
        impl PayloadScopeController for DenyController {
            fn prepare(
                &self,
                _: &crate::supervisor::flowmux::AdmittedTcpPayload,
                _: &ScopeFacts,
                _: spiralcore_transfer::v1::NegotiatedProfile,
                _: std::time::Instant,
            ) -> std::io::Result<PreparedPayloadSession> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "scope not enrolled",
                ))
            }
        }
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
        let server_identity = PinnedIdentity::from_pkcs8(
            server_key
                .to_pkcs8_der()
                .expect("PKCS8")
                .as_bytes()
                .to_vec(),
        )
        .expect("server TLS identity");
        let client_key = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
        let client_identity = PinnedIdentity::from_pkcs8(
            client_key
                .to_pkcs8_der()
                .expect("PKCS8")
                .as_bytes()
                .to_vec(),
        )
        .expect("client TLS identity");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let target = "cooperator.mvm.peer";
        let policy = NetworkPolicy::deny_all()
            .with_peers(vec![PeerBinding {
                name: PeerName::parse(target).expect("peer"),
                port: 443,
                host_addr: address.ip().to_string(),
                host_port: address.port(),
            }])
            .with_payload_mapping(Some(
                CooperatingPayloadPolicy::new(vec![CooperatingTcpPeer {
                    host: target.into(),
                    port: 443,
                    server_name: target.into(),
                    spki_sha256: server_identity.spki_sha256(),
                    profile: PayloadMappingProfile::SpiralCoreObjectStreamV1,
                }])
                .expect("policy"),
            ));
        let binding = mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan {
            plan_id: mvm_core::plan::PlanId("actual-plan".into()),
            plan_version: 1,
            plan_nonce: mvm_core::plan::Nonce::from_bytes([9; 16]),
            bundle_sha256: "b".repeat(64),
            tenant_id: "tenant".into(),
            instance_id: "instance".into(),
            policy_sha256: mvm_core::policy::network_policy::content_sha256(&policy),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let factory = Arc::new(
            SpiralCorePayloadFactory::from_host_key(
                &client_key,
                Arc::new(DenyController(calls.clone())),
            )
            .expect("factory"),
        );
        let mapping = Arc::new(
            crate::supervisor::flowmux::PayloadMappingConfig::new(&policy, binding)
                .expect("binding")
                .with_factory(factory),
        );
        let gate = crate::supervisor::network_endpoint::build_egress_gate(&policy);
        thread::scope(|scope| {
            let peer = scope.spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                let (socket, _) = loop {
                    match listener.accept() {
                        Ok(pair) => break pair,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline);
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                let mut tls = TlsCarrier::accept(
                    socket,
                    &server_identity,
                    client_identity.spki_sha256(),
                    deadline,
                )
                .expect("mutual TLS");
                tls.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .expect("timeout");
                match std::io::Read::read(&mut tls, &mut [0; 1]) {
                    Ok(0) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                        ) => {}
                    other => panic!("denied scope must close without application bytes: {other:?}"),
                }
            });
            let (mut guest, mut session, host) =
                run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
                    FlowMuxAccept::new(id, key, anchor, limits, gate)
                        .with_payload_mapping(Some(mapping))
                });
            guest
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("timeout");
            write_frame(
                &mut guest,
                &mut session,
                Opcode::OpenTcp,
                1,
                b"cooperator.mvm.peer:443",
            );
            let observed = read_flowmux_frame(&mut guest, &mut session).0;
            drop(guest);
            host.join().expect("host join").expect("serve");
            peer.join().expect("peer join");
            assert_eq!(observed, Opcode::Refused);
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "real authenticated peer reached explicit scope authority exactly once"
            );
        });
    }

    fn selected_mapping(target: &str) -> Arc<crate::supervisor::flowmux::PayloadMappingConfig> {
        use mvm_contract::policy::network_policy::{
            CooperatingPayloadPolicy, CooperatingTcpPeer, NetworkPolicy, PayloadMappingProfile,
        };
        let policy = NetworkPolicy::deny_all().with_payload_mapping(Some(
            CooperatingPayloadPolicy::new(vec![CooperatingTcpPeer {
                host: target.into(),
                port: 443,
                server_name: target.into(),
                spki_sha256: [7; 32],
                profile: PayloadMappingProfile::SpiralCoreObjectStreamV1,
            }])
            .expect("mapping"),
        ));
        let binding = mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan {
            plan_id: mvm_core::plan::PlanId("full-admitted-plan".into()),
            plan_version: 1,
            plan_nonce: mvm_core::plan::Nonce::from_bytes([9; 16]),
            bundle_sha256: "b".repeat(64),
            tenant_id: "test-tenant".into(),
            instance_id: "test-instance".into(),
            policy_sha256: mvm_core::policy::network_policy::content_sha256(&policy),
        };
        Arc::new(
            crate::supervisor::flowmux::PayloadMappingConfig::new(&policy, binding)
                .expect("mapping config"),
        )
    }
    #[test]
    fn selected_payload_mapping_never_bypasses_required_tcp_termination() {
        let target = "bound.example";
        let (service, _secrets) = substitution_binding(target, true);
        let gate = gate_pinning_name(target, local_test_ip(), 443);
        let mapping = selected_mapping(target);
        let (mut guest, mut session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_payload_mapping(Some(mapping))
            });
        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        write_frame(
            &mut guest,
            &mut session,
            Opcode::OpenTcp,
            1,
            b"bound.example:443",
        );
        let observed = read_flowmux_frame(&mut guest, &mut session).0;
        drop(guest);
        host.join().expect("join").expect("serve");
        assert_eq!(
            observed,
            Opcode::Refused,
            "selected required profile cannot silently become a plain terminated leg"
        );
    }
    #[test]
    fn selected_payload_mapping_never_bypasses_required_typed_http_mapping() {
        let target = "bound.example";
        let (service, _secrets) = substitution_binding(target, true);
        let gate = gate_pinning_name(target, local_test_ip(), 443);
        let mapping = selected_mapping(target);
        let (mut guest, mut session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_payload_mapping(Some(mapping))
            });
        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        write_frame(&mut guest, &mut session, Opcode::OpenHttp, 1, b"");
        assert_eq!(
            read_flowmux_frame(&mut guest, &mut session).0,
            Opcode::Opened
        );
        let head = mvm_core::substitution_wire::HttpFlowHead {
            method: "GET".into(),
            url: "https://bound.example/path".into(),
            headers: Vec::new(),
            body_len: 0,
        };
        write_frame(
            &mut guest,
            &mut session,
            Opcode::HttpRequestHead,
            1,
            &serde_json::to_vec(&head).expect("head"),
        );
        let observed = read_flowmux_frame(&mut guest, &mut session).0;
        drop(guest);
        host.join().expect("join").expect("serve");
        assert_eq!(
            observed,
            Opcode::Reset,
            "typed selected profile must refuse before an ordinary forward task"
        );
    }

    #[test]
    fn payload_mapping_required_unavailable_peer_never_falls_back_to_raw() {
        use crate::supervisor::flowmux::PayloadMappingConfig;
        use mvm_contract::peer::{PeerBinding, PeerName};
        use mvm_contract::policy::network_policy::{
            CooperatingPayloadPolicy, CooperatingTcpPeer, NetworkPolicy, PayloadMappingProfile,
        };
        use mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let target = "cooperator.mvm.peer";
        let policy = NetworkPolicy::deny_all()
            .with_peers(vec![PeerBinding {
                name: PeerName::parse(target).expect("name"),
                port: 443,
                host_addr: address.ip().to_string(),
                host_port: address.port(),
            }])
            .with_payload_mapping(Some(
                CooperatingPayloadPolicy::new(vec![CooperatingTcpPeer {
                    host: target.into(),
                    port: 443,
                    server_name: target.into(),
                    spki_sha256: [7; 32],
                    profile: PayloadMappingProfile::SpiralCoreObjectStreamV1,
                }])
                .expect("mapping"),
            ));
        let binding = AdmittedNetworkPlan {
            plan_id: mvm_core::plan::PlanId("full-admitted-plan".into()),
            plan_version: 1,
            plan_nonce: mvm_core::plan::Nonce::from_bytes([9; 16]),
            bundle_sha256: "b".repeat(64),
            tenant_id: "test-tenant".into(),
            instance_id: "test-instance".into(),
            policy_sha256: mvm_core::policy::network_policy::content_sha256(&policy),
        };
        let mapping =
            Arc::new(PayloadMappingConfig::new(&policy, binding).expect("matching full policy"));
        let gate = crate::supervisor::network_endpoint::build_egress_gate(&policy);
        thread::scope(|scope| {
            let peer = scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                runtime.block_on(async move {
                    use tokio::io::AsyncReadExt;
                    let listener = tokio::net::TcpListener::from_std(listener).expect("listener");
                    let (mut stream, _) =
                        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                            .await
                            .expect("bounded accept")
                            .expect("accept");
                    let mut byte = [0; 1];
                    assert_eq!(
                        tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            stream.read(&mut byte)
                        )
                        .await
                        .expect("bounded read")
                        .expect("read"),
                        0,
                        "required peer gets neither raw nor encoded payload without authentication"
                    );
                });
            });
            let (mut guest, mut session, host) =
                run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
                    FlowMuxAccept::new(id, key, anchor, limits, gate)
                        .with_payload_mapping(Some(mapping))
                });
            guest
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("read deadline");
            write_frame(
                &mut guest,
                &mut session,
                Opcode::OpenTcp,
                1,
                b"cooperator.mvm.peer:443",
            );
            assert_eq!(
                read_flowmux_frame(&mut guest, &mut session).0,
                Opcode::Refused
            );
            drop(guest);
            host.join().expect("join host").expect("serve");
            peer.join().expect("join peer");
        });
    }

    #[test]
    fn open_tcp_to_unknown_host_is_refused_by_default_deny_gate() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (mut guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            b"example.com:443",
        );

        let (opcode, _stream_id, payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        // The session stays alive; an unknown-stream frame afterward still
        // receives a GoAway rather than dropping the connection.
        write_frame(&mut guest_stream, &mut guest_session, Opcode::Data, 3, b"?");

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::GoAway);

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn parse_host_port_accepts_ipv4_and_names() {
        assert_eq!(
            parse_host_port("127.0.0.1:443").unwrap(),
            ("127.0.0.1", 443)
        );
        assert_eq!(
            parse_host_port("example.com:80").unwrap(),
            ("example.com", 80)
        );
    }

    #[test]
    fn parse_host_port_rejects_missing_port_and_empty_host() {
        assert!(parse_host_port("example.com").is_err());
        assert!(parse_host_port(":443").is_err());
        assert!(parse_host_port("example.com:99999").is_err());
    }

    #[test]
    fn open_tcp_to_allowed_local_addr_roundtrips_data() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        let payload = b"ping";
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, payload);
        let data = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            if opcode == Opcode::Data {
                break frame;
            }
            // WindowUpdate and other non-data frames are expected before the
            // upstream response reaches us.
        };
        assert_eq!(&data[..], payload);

        write_frame(&mut guest, &mut guest_session, Opcode::HalfClose, 1, b"");
        let opcode = loop {
            let (op, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
            if op == Opcode::HalfClose {
                break op;
            }
            // WindowUpdate may be in flight before the relay observes EOF.
            assert_eq!(op, Opcode::WindowUpdate);
        };
        assert_eq!(opcode, Opcode::HalfClose);

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// Every builder job — a flake build's fetches and a dependency install's
    /// alike — leaves the builder through its vsock egress client and is
    /// decided here, on the builder endpoint's gate. That gate is built by the
    /// endpoint's own `build_egress_gate` from the builder's egress policy,
    /// exactly as the builder spawns it. The policy is open, and open reaches
    /// only public addresses: a private range is refused as `private_range`
    /// and cloud metadata as `cloud_metadata`, each refusal audited, because a
    /// flake's fetcher is as able to aim at the host's LAN as any workload.
    #[test]
    fn builder_egress_refuses_private_ranges_and_metadata_and_audits_both() {
        const PRIVATE: &str = "10.255.0.1:80";
        const METADATA: &str = "169.254.169.254:80";
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let gate = crate::supervisor::network_endpoint::build_egress_gate(
            &mvm_build::builder_vm_transport::builder_egress_policy(),
        );
        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_recorder(Some(recorder))
            });

        for (stream, target) in [(1_u32, PRIVATE), (3, METADATA)] {
            write_frame(
                &mut guest,
                &mut guest_session,
                Opcode::OpenTcp,
                stream,
                target.as_bytes(),
            );
            let (opcode, stream_id) = loop {
                let (opcode, stream_id, _frame) =
                    read_flowmux_frame(&mut guest, &mut guest_session);
                if stream_id == stream {
                    break (opcode, stream_id);
                }
            };
            assert_eq!((opcode, stream_id), (Opcode::Refused, stream), "{target}");
        }

        drop(guest);
        host.join().unwrap().unwrap();

        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        let denied: Vec<&str> = chain
            .lines()
            .filter(|line| line.contains("host.flow.denied"))
            .collect();
        assert_eq!(denied.len(), 2, "{chain}");
        assert!(
            denied[0].contains(PRIVATE) && denied[0].contains("private_range"),
            "{chain}"
        );
        assert!(
            denied[1].contains(METADATA) && denied[1].contains("cloud_metadata"),
            "{chain}"
        );
        assert!(!chain.contains("host.flow.allowed"), "{chain}");
    }

    /// The default policy, projected the way the supervisor projects every
    /// admitted policy, refuses a flow no rule admits and leaves a
    /// chain-verified denial rather than an allow in the audit log.
    #[test]
    fn a_flow_no_rule_admits_is_refused_and_audited_under_the_default_policy() {
        const TARGET: &str = "example.com:443";
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let gate = crate::supervisor::network_endpoint::build_egress_gate(
            &mvm_core::policy::network_policy::NetworkPolicy::default(),
        );
        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_recorder(Some(recorder))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            TARGET.as_bytes(),
        );
        let (opcode, ..) = loop {
            let frame = read_flowmux_frame(&mut guest, &mut guest_session);
            if frame.1 == 1 {
                break frame;
            }
        };
        assert_eq!(opcode, Opcode::Refused);

        drop(guest);
        host.join().unwrap().unwrap();

        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        let denied: Vec<&str> = chain
            .lines()
            .filter(|line| line.contains("host.flow.denied"))
            .collect();
        assert_eq!(denied.len(), 1, "{chain}");
        assert!(
            denied[0].contains(TARGET) && denied[0].contains("policy_denied"),
            "{chain}"
        );
        assert!(!chain.contains("host.flow.allowed"), "{chain}");
    }

    #[test]
    fn open_tcp_to_denied_local_addr_is_refused() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        let denied_port = addr.port().wrapping_add(1);
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), denied_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// Build a substitution service binding one secret to `bound_host`, with
    /// or without the per-VM egress intermediate a terminated flow needs.
    ///
    /// Real registry, real resolver over a real encrypted secret store; only
    /// the forward leg is a double, and no test here reaches it.
    fn substitution_binding(
        bound_host: &str,
        with_intermediate: bool,
    ) -> (
        Arc<crate::supervisor::network_endpoint_proxy::SubstitutionService>,
        tempfile::TempDir,
    ) {
        substitution_binding_routed(bound_host, with_intermediate, Vec::new())
    }

    /// [`substitution_binding`] whose service gate carries `routes`.
    fn substitution_binding_routed(
        bound_host: &str,
        with_intermediate: bool,
        routes: Vec<mvm_contract::policy::routes::EgressRoute>,
    ) -> (
        Arc<crate::supervisor::network_endpoint_proxy::SubstitutionService>,
        tempfile::TempDir,
    ) {
        use crate::keyholder::substitution::SubstitutionRegistry;
        use crate::keyholder::{LocalResolver, SecretResolver};
        use crate::supervisor::network_endpoint_proxy::{
            ForwardError, ForwardResponse, Forwarder, PreparedRequest, SubstitutionService,
        };
        use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
        use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
        use secrecy::SecretBox;

        /// Never reached by these tests: both of them refuse or relay before
        /// any forward leg exists.
        struct UnusedForwarder;

        #[async_trait::async_trait]
        impl Forwarder for UnusedForwarder {
            async fn forward(
                &self,
                _req: PreparedRequest,
            ) -> Result<ForwardResponse, ForwardError> {
                Err(ForwardError::Failed("no forward leg in this test".into()))
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "model-api",
                &SecretBox::new(Box::new("sk-live-value".to_string())),
            )
            .expect("seed secret store");
        let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new(
            "local",
            Arc::new(store) as Arc<dyn SecretStore>,
        ));
        let mut registry = SubstitutionRegistry::new();
        let _placeholder = registry.mint(SecretRef {
            name: "model-api".into(),
            mount: SecretMount::Env {
                var: "API_KEY".into(),
            },
            auth_type: AuthType::Bearer,
            allowed_hosts: vec![bound_host.to_string()],
            sigv4: None,
            inject: Default::default(),
        });
        // Every flow in these tests is decided on the FlowMux connect path, by
        // the session's own gate, before any request reaches the service. Its
        // gate denies everything so a test that did reach it would fail rather
        // than forward.
        let mut service = SubstitutionService::new(
            Arc::new(registry),
            resolver,
            Arc::new(UnusedForwarder),
            Arc::new(EgressGate::default_deny().with_routes(
                mvm_contract::policy::routes::RouteSet::new(routes).expect("test routes validate"),
            )),
        );
        if with_intermediate {
            service = service.with_tls_intermediate(
                mvm_core::crypto::egress_ca::VmEgressCa::mint(&[bound_host])
                    .expect("mint the per-VM egress ca"),
            );
        }
        (Arc::new(service), dir)
    }

    /// A destination carrying a bound secret, on an endpoint with no egress
    /// intermediate, stays refused.
    ///
    /// The flow is admitted by the gate — this is not a policy denial. It is
    /// refused because the only honest way to serve it is to terminate it and
    /// substitute the credential, and this endpoint cannot. Relaying it
    /// instead would put a `mvm-secret-<hex>` placeholder on the wire to a real
    /// upstream, which is the failure the refusal exists to prevent.
    #[test]
    fn connect_to_bound_host_without_an_intermediate_is_refused() {
        let ip = local_test_ip();
        let (service, _dir) = substitution_binding(&ip.to_string(), false);
        let gate = gate_allowing_addr(ip, 443, None);
        let (mut guest, mut guest_session, host) =
            run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_substitution(Some(service))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{ip}:443").as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert_eq!(
            String::from_utf8_lossy(&payload),
            "destination requires secret substitution over typed HTTP",
            "the refusal must name the reason, not a generic failure"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// Real ClientHello bytes for `name`, produced by rustls rather than
    /// hand-assembled, so the terminator is answering a handshake a client
    /// would actually send.
    fn client_hello_for(name: &str) -> Vec<u8> {
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from(name)
            .expect("test name is a server name")
            .to_owned();
        let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)
            .expect("build a client connection");
        let mut hello = Vec::new();
        connection
            .write_tls(&mut hello)
            .expect("a fresh client connection has a ClientHello to write");
        hello
    }

    /// A flow to a destination carrying a bound secret is served by
    /// terminating it on the host, not by dialing the destination.
    ///
    /// The proof is the ServerHello: the pinned address has nothing listening
    /// on 443, so an opaque relay could only answer `ConnectFailed`, and
    /// nothing but a host-side terminator can answer a ClientHello with a TLS
    /// record. The audit entry then has to say so.
    #[test]
    fn a_bound_connect_is_terminated_on_the_host_rather_than_dialed() {
        const NAME: &str = "api.terminated.test";
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let (service, _secrets) = substitution_binding(NAME, true);
        let gate = gate_pinning_name(NAME, local_test_ip(), 443);

        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_recorder(Some(recorder))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{NAME}:443").as_bytes(),
        );
        let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::Opened,
            "a terminated flow opens without dialing: {}",
            String::from_utf8_lossy(&payload)
        );
        assert_eq!(stream_id, 1);

        let hello = client_hello_for(NAME);
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, &hello);
        let answer = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            match opcode {
                Opcode::Data => break frame,
                Opcode::WindowUpdate => {}
                other => panic!("unexpected {other:?}: {}", String::from_utf8_lossy(&frame)),
            }
        };
        assert_eq!(
            answer.first(),
            Some(&0x16),
            "only a host-side terminator can answer a ClientHello with a TLS handshake record"
        );

        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        assert!(
            chain.contains("host.flow.allowed"),
            "the open must be audited: {chain}"
        );
        assert!(
            chain.contains("\"termination\":\"tls\""),
            "the chain must say the flow was terminated and how: {chain}"
        );
        assert!(
            chain.contains(&format!("{NAME}:443")),
            "the entry names the target: {chain}"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// Open one terminated flow on an endpoint whose substitution service
    /// carries `proxy`, and return the verified chain text.
    ///
    /// The open alone is enough: the proxy attribution is written with the
    /// `host.flow.allowed` entry at open, before any request arrives.
    fn terminated_flow_chain(proxy: Option<mvm_http::ProxyConfig>) -> String {
        const NAME: &str = "api.terminated.test";
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let (service, _secrets) = substitution_binding(NAME, true);
        let service = Arc::new(
            Arc::try_unwrap(service)
                .ok()
                .expect("the test holds the only service reference")
                .with_proxy_config(proxy),
        );
        let gate = gate_pinning_name(NAME, local_test_ip(), 443);
        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_recorder(Some(recorder))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{NAME}:443").as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::Opened,
            "a terminated flow opens: {}",
            String::from_utf8_lossy(&payload)
        );

        drop(guest);
        host.join().unwrap().unwrap();
        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        std::fs::read_to_string(&audit_path).expect("read audit chain")
    }

    /// A terminated flow whose forward leg goes through the configured
    /// upstream proxy says so on its flow entry, next to the real destination.
    #[test]
    fn a_terminated_flow_through_the_upstream_proxy_is_audited_as_proxied() {
        let proxy = mvm_http::ProxyConfig::from_lookup(|key| {
            (key == "HTTPS_PROXY").then(|| "http://proxy.corp:3128".to_string())
        })
        .expect("proxy environment parses");
        let chain = terminated_flow_chain(proxy);
        assert!(chain.contains("host.flow.allowed"), "{chain}");
        assert!(chain.contains("api.terminated.test:443"), "{chain}");
        assert!(chain.contains(r#""via":"proxy""#), "{chain}");
    }

    /// A destination the proxy's `NO_PROXY` list excepts is recorded as a
    /// bypass, distinguishable from both a proxied leg and an unproxied host.
    #[test]
    fn a_terminated_flow_bypassed_by_no_proxy_is_audited_as_a_bypass() {
        let proxy = mvm_http::ProxyConfig::from_lookup(|key| match key {
            "HTTPS_PROXY" => Some("http://proxy.corp:3128".to_string()),
            "NO_PROXY" => Some("terminated.test".to_string()),
            _ => None,
        })
        .expect("proxy environment parses");
        let chain = terminated_flow_chain(proxy);
        assert!(chain.contains(r#""via":"no_proxy""#), "{chain}");
        assert!(!chain.contains(r#""via":"proxy""#), "{chain}");
    }

    /// A proxy configured only for plaintext carries no TLS flow: the
    /// terminated leg dials directly and the entry says `direct`.
    #[test]
    fn a_terminated_flow_whose_scheme_the_proxy_does_not_cover_is_audited_as_direct() {
        let proxy = mvm_http::ProxyConfig {
            https: None,
            http: Some(mvm_http::Proxy::parse("http://plain.corp:8080").expect("proxy parses")),
            no_proxy: mvm_http::NoProxy::default(),
        };
        let chain = terminated_flow_chain(Some(proxy));
        assert!(chain.contains(r#""via":"direct""#), "{chain}");
    }

    /// An endpoint with no upstream proxy records no label at all, so its
    /// entries keep the bytes they had before the label existed.
    #[test]
    fn a_terminated_flow_on_an_unproxied_endpoint_carries_no_proxy_label() {
        let chain = terminated_flow_chain(None);
        assert!(chain.contains("host.flow.allowed"), "{chain}");
        assert!(
            !chain.contains(r#""via""#),
            "no proxy decision, no label: {chain}"
        );
    }

    /// An opaque flow has no forward leg: it is a raw TCP relay the upstream
    /// proxy never carries, so its entry records no proxy label even on an
    /// endpoint that has one.
    #[test]
    fn an_opaque_flow_on_a_proxied_endpoint_carries_no_proxy_label() {
        let addr = tcp_echo_server();
        let (service, _dir) = substitution_binding("bound.example", true);
        let service = Arc::new(
            Arc::try_unwrap(service)
                .ok()
                .expect("the test holds the only service reference")
                .with_proxy_config(
                    mvm_http::ProxyConfig::from_lookup(|key| {
                        (key == "HTTPS_PROXY").then(|| "http://proxy.corp:3128".to_string())
                    })
                    .expect("proxy environment parses"),
                ),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let gate = gate_allowing_addr(addr.ip(), addr.port(), None);
        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_recorder(Some(recorder))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        drop(guest);
        host.join().unwrap().unwrap();
        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        assert!(chain.contains("host.flow.allowed"), "{chain}");
        assert!(!chain.contains(r#""via""#), "{chain}");
    }

    /// The terminated-flow ceiling and the leaf cache belong to the VM, not to
    /// a session.
    ///
    /// A per-session budget is multiplied by `MAX_CONCURRENT_FLOWMUX_SESSIONS`:
    /// a guest that reconnects sixteen times would reach sixteen times the
    /// intended ceiling and keep sixteen independent caches, which is exactly
    /// what `FlowMuxVmResources` exists to prevent. Two sessions built from one
    /// resources value must therefore look at the same counter and the same
    /// cache.
    #[test]
    fn the_terminated_flow_budget_and_leaf_cache_are_shared_across_a_vms_sessions() {
        let resources = Arc::new(FlowMuxVmResources::from_registry_limits(
            RegistryLimits::default(),
        ));
        let build = |resources: Arc<FlowMuxVmResources>| {
            let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();
            let (host_key, host_verify) = fresh_keys();
            let (guest_key, guest_verify) = fresh_keys();
            let accepted = thread::spawn(move || {
                FlowMuxSession::accept_with(
                    host_stream,
                    FlowMuxAccept::new(
                        "shared-session",
                        host_key,
                        guest_verify,
                        RegistryLimits::default(),
                        EgressGate::default_deny(),
                    )
                    .with_vm_resources(resources),
                )
                .unwrap()
            });
            let (guest_session, _id) =
                Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
            let session = accepted.join().unwrap();
            (session, guest_stream, guest_session)
        };

        let (first, _first_guest, _first_session) = build(Arc::clone(&resources));
        let (second, _second_guest, _second_session) = build(Arc::clone(&resources));

        assert!(
            Arc::ptr_eq(&first.terminated_flows, &second.terminated_flows),
            "a second session must spend the same budget, not a fresh one"
        );
        assert!(
            Arc::ptr_eq(&first.leaves, &second.leaves),
            "a second session must reuse the VM's minted leaves"
        );
        assert!(
            Arc::ptr_eq(&first.terminated_flows, &resources.terminated_flows),
            "the budget is the VM's, not one the session invented"
        );

        // And it is the budget the open path actually spends.
        let held = terminator::flow::FlowSlot::claim(&first.terminated_flows)
            .expect("a slot below the ceiling");
        assert_eq!(
            second
                .terminated_flows
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "a flow opened on one session is visible to the other"
        );
        drop(held);
    }

    /// A peer route is never terminated, even when its name carries a bound
    /// secret.
    ///
    /// The gate rewrites `<name>.mvm.peer:<port>` to the peer's local ingress
    /// mapping, and that rewrite *is* what makes the peer reachable — the name
    /// resolves nowhere. A terminated peer flow would throw the mapping away
    /// and re-originate by the unresolvable name with the real credential
    /// attached. So it falls through to the opaque path, where a bound
    /// destination is refused at open.
    #[test]
    fn a_peer_route_is_never_terminated_even_when_the_peer_name_is_bound() {
        use mvm_contract::peer::{PeerBinding, PeerName};

        let peer_target = "db.mvm.peer";
        let (service, _secrets) = substitution_binding(peer_target, true);
        // The dialed port and the mapped port differ, which is the rewrite
        // this guard exists for. The *mapped* port is the terminable one, so
        // `terminable` would say yes and only the route can refuse: with the
        // route check removed this test opens a terminated peer flow.
        let gate = EgressGate::default_deny().with_peers(vec![PeerBinding {
            name: PeerName::parse(peer_target).expect("peer name parses"),
            port: 8443,
            host_addr: local_test_ip().to_string(),
            host_port: 443,
        }]);

        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_substitution(Some(service))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{peer_target}:8443").as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::Refused,
            "a peer route must not be opened as a terminated flow"
        );
        assert_eq!(
            String::from_utf8_lossy(&payload),
            "destination requires secret substitution over typed HTTP",
            "the peer flow falls through to the opaque refusal"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// A destination with no bound secret is relayed opaquely even on an
    /// endpoint that could terminate, and the bytes cross unchanged.
    ///
    /// Mediating every flow was rejected: the host gains nothing from
    /// decrypting a destination it holds no credential for, and loses the
    /// guest's end-to-end TLS by doing it.
    #[test]
    fn an_unbound_connect_is_spliced_without_termination() {
        let addr = tcp_echo_server();
        let (service, _dir) = substitution_binding("bound.example", true);
        // What decides this flow is the binding, not the port: asserted at the
        // terminable port, where the port arm cannot be what refuses. Without
        // this the test would pass with the binding check inverted, because an
        // ephemeral port is not terminable either way.
        assert_eq!(
            service.terminable(&addr.ip().to_string(), 443),
            None,
            "an unbound destination is not terminable even on a terminable port"
        );
        let gate = gate_allowing_addr(addr.ip(), addr.port(), None);
        let (mut guest, mut guest_session, host) =
            run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_substitution(Some(service))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::Opened,
            "an unbound destination is opened, not refused"
        );

        // A TLS ClientHello prefix: an opaque relay must pass it through
        // verbatim, where a terminator would answer it with a ServerHello.
        let payload = b"\x16\x03\x01\x00\x05opaque";
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, payload);
        let data = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            if opcode == Opcode::Data {
                break frame;
            }
        };
        assert_eq!(
            &data[..],
            payload,
            "the echo server saw exactly what the guest sent"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// A destination whose route has endpoint rules, on a plan that does not
    /// grant interception, is refused at open rather than relayed opaquely:
    /// the rules could not be enforced on a flow the host never reads.
    #[test]
    fn an_opaque_flow_to_a_route_with_ungranted_rules_is_refused_and_audited() {
        let addr = tcp_echo_server();
        let route = mvm_contract::policy::routes::EgressRoute {
            id: "local".into(),
            host: addr.ip().to_string(),
            port: addr.port(),
            rules: vec![mvm_contract::policy::routes::EndpointRule {
                id: None,
                method: Some("GET".into()),
                path: "/**".into(),
                outcome: mvm_contract::policy::routes::RouteOutcome::Allow,
            }],
            otherwise: mvm_contract::policy::routes::RouteOutcome::Deny,
            intercept: false,
        };
        let (service, _dir) = substitution_binding_routed("bound.example", true, vec![route]);
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let gate = gate_allowing_addr(addr.ip(), addr.port(), None);
        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_recorder(Some(recorder))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);

        drop(guest);
        host.join().unwrap().unwrap();
        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        assert!(chain.contains("endpoint_rules_unenforceable"), "{chain}");
        assert!(chain.contains("\"endpoint_route\":\"local\""), "{chain}");
        assert!(chain.contains("\"rule\":\"not_evaluated\""), "{chain}");
        assert!(!chain.contains("host.flow.allowed"), "{chain}");
    }

    #[test]
    fn open_tcp_to_allowed_but_unbound_addr_is_refused_truthfully() {
        let ip = local_test_ip();
        // Bind briefly to let the OS assign a free port, then drop the
        // listener so the attempted connect fails with ECONNREFUSED.
        let free_port = std::net::TcpListener::bind(std::net::SocketAddr::new(ip, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(ip, free_port, None));
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", ip, free_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::ConnectFailed);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_connection_rate_limit_refuses_overflow() {
        let addr = tcp_echo_server();
        let limits = RegistryLimits {
            tcp_connect_rate: 1,
            ..Default::default()
        };
        let (mut guest, mut guest_session, host) =
            run_session_with(gate_allowing_addr(addr.ip(), addr.port(), None), limits);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            3,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(std::str::from_utf8(&payload).unwrap().contains("rate"));

        drop(guest);
        host.join().unwrap().unwrap();
    }
}
