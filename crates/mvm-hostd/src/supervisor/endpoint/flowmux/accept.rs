//! Authenticated session construction and original audit/cancellation custody.
use super::*;

/// What one accepted FlowMux session needs to serve.
///
/// A struct with a builder rather than a longer argument list: the optional
/// halves — the audit recorder and the substitution service — are exactly the
/// ones a caller is most likely to pass in the wrong order.
pub struct FlowMuxAccept {
    pub(super) session_id: String,
    pub(super) host_key: SigningKey,
    pub(super) guest_anchor: VerifyingKey,
    pub(super) limits: RegistryLimits,
    pub(super) gate: Arc<EgressGate>,
    pub(super) recorder: Option<Arc<Recorder>>,
    pub(super) substitution:
        Option<Arc<crate::supervisor::endpoint::network_endpoint_proxy::SubstitutionService>>,
    pub(super) vm_resources: Option<Arc<FlowMuxVmResources>>,
    pub(super) ingress_mappings: Vec<(u16, IngressFlowKind)>,
    pub(super) payload_mapping: Option<Arc<PayloadMappingConfig>>,
    pub(super) owned_tcp_relays: Option<Arc<OwnedTcpRelays>>,
    pub(super) installed_audit: Option<InstalledEndpointAudit>,
    pub(super) installed_session_control:
        Option<Arc<crate::installed_endpoint::InstalledSessionControl>>,
}

struct PendingInstalledAudit(Option<InstalledEndpointAudit>);
impl PendingInstalledAudit {
    fn check_current(&self) -> Result<(), FlowMuxError> {
        if let Some(audit) = &self.0 {
            audit.check_current().map_err(|_| {
                FlowMuxError::FrameRefused("installed audit authority unavailable".into())
            })?;
        }
        Ok(())
    }
}
impl Drop for PendingInstalledAudit {
    fn drop(&mut self) {
        if let Some(audit) = &self.0 {
            audit.fence();
        }
    }
}

impl FlowMuxAccept {
    /// The required half: who this session is, whose key signs it, and which
    /// single guest identity it will accept.
    #[must_use]
    pub fn new(
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: VerifyingKey,
        limits: RegistryLimits,
        gate: EgressGate,
    ) -> Self {
        Self::new_shared(session_id, host_key, guest_anchor, limits, Arc::new(gate))
    }

    /// Build from the endpoint's single shared claim-10 policy object.
    #[must_use]
    pub fn new_shared(
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: VerifyingKey,
        limits: RegistryLimits,
        gate: Arc<EgressGate>,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            host_key,
            guest_anchor,
            limits,
            gate,
            recorder: None,
            substitution: None,
            vm_resources: None,
            ingress_mappings: Vec::new(),
            payload_mapping: None,
            owned_tcp_relays: None,
            installed_audit: None,
            installed_session_control: None,
        }
    }

    /// Attach the chain-signed audit recorder.
    #[must_use]
    pub fn with_recorder(mut self, recorder: Option<Arc<Recorder>>) -> Self {
        self.recorder = recorder;
        self
    }

    #[must_use]
    pub fn with_owned_tcp_relays(mut self, owned: Option<Arc<OwnedTcpRelays>>) -> Self {
        self.owned_tcp_relays = owned;
        self
    }

    /// Bind the original private child audit capability. Acceptance requires
    /// the same actual resource partition, recorder, group and payload factory.
    #[must_use]
    pub fn with_installed_audit(mut self, audit: InstalledEndpointAudit) -> Self {
        self.installed_audit = Some(audit);
        self
    }

    pub(crate) fn with_installed_session_control(
        mut self,
        control: Arc<crate::installed_endpoint::InstalledSessionControl>,
    ) -> Self {
        self.installed_session_control = Some(control);
        self
    }

    #[must_use]
    pub fn with_payload_mapping(mut self, mapping: Option<Arc<PayloadMappingConfig>>) -> Self {
        self.payload_mapping = mapping;
        self
    }

    /// Attach the substitution service typed HTTP flows forward through.
    ///
    /// Without it an `OpenHttp` is refused: a flow that may name a
    /// `mvm-secret-<hex>` placeholder has nothing to resolve it, and
    /// forwarding it anyway would put the placeholder on the wire to a real
    /// upstream.
    #[must_use]
    pub fn with_substitution(
        mut self,
        substitution: Option<
            Arc<crate::supervisor::endpoint::network_endpoint_proxy::SubstitutionService>,
        >,
    ) -> Self {
        self.substitution = substitution;
        self
    }

    /// Attach the endpoint's VM-wide budget, rate guards, and session owner.
    #[must_use]
    pub fn with_vm_resources(mut self, resources: Arc<FlowMuxVmResources>) -> Self {
        self.vm_resources = Some(resources);
        self
    }

    /// Attach the signed ingress mapping IDs this session may open.
    #[must_use]
    pub fn with_ingress_mappings(mut self, mappings: impl IntoIterator<Item = u16>) -> Self {
        self.ingress_mappings = mappings
            .into_iter()
            .map(|mapping| (mapping, IngressFlowKind::Tcp))
            .collect();
        self
    }

    /// Attach signed ingress mapping IDs and their transport classes.
    #[must_use]
    pub fn with_ingress_transports(
        mut self,
        mappings: impl IntoIterator<Item = (u16, IngressFlowKind)>,
    ) -> Self {
        self.ingress_mappings = mappings.into_iter().collect();
        self
    }
}

impl FlowMuxSession {
    /// Accept one authenticated FlowMux session on `stream`.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept(
        stream: UnixStream,
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: &VerifyingKey,
        limits: RegistryLimits,
        gate: EgressGate,
    ) -> Result<Self, FlowMuxError> {
        Self::accept_with(
            stream,
            FlowMuxAccept::new(session_id, host_key, guest_anchor.to_owned(), limits, gate),
        )
    }

    /// Accept one authenticated FlowMux session with an optional audit
    /// recorder attached.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept_with(
        mut stream: UnixStream,
        params: FlowMuxAccept,
    ) -> Result<Self, FlowMuxError> {
        let FlowMuxAccept {
            session_id,
            host_key,
            guest_anchor,
            limits,
            gate,
            recorder,
            substitution,
            vm_resources,
            ingress_mappings,
            payload_mapping,
            owned_tcp_relays,
            installed_audit,
            installed_session_control,
        } = params;
        let session_id = session_id.as_str();
        let runtime_handle = tokio::runtime::Handle::try_current().ok();
        if owned_tcp_relays.is_some() && installed_audit.is_none() {
            return Err(FlowMuxError::FrameRefused(
                "original installed audit capability required".into(),
            ));
        }
        match (&owned_tcp_relays, &payload_mapping) {
            (Some(group), Some(mapping)) => mapping
                .check_owned_tcp_relays(
                    group,
                    session_id,
                    host_key.verifying_key().to_bytes(),
                    guest_anchor.to_bytes(),
                )
                .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?,
            (Some(_), None) => {
                return Err(FlowMuxError::FrameRefused(
                    "owned relay factory missing".into(),
                ));
            }
            (None, Some(mapping)) if mapping.requires_owned_tcp_relays() => {
                return Err(FlowMuxError::FrameRefused(
                    "original installed relay group required".into(),
                ));
            }
            _ => {}
        }
        let bound_guest = if let Some(audit) = &installed_audit {
            if !recorder
                .as_ref()
                .is_some_and(|recorder| recorder.has_installed_origin(audit))
                || substitution.is_some()
                || !runtime_handle.as_ref().is_some_and(|handle| {
                    handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread
                })
            {
                return Err(FlowMuxError::FrameRefused(
                    "installed audit recorder or profile unavailable".into(),
                ));
            }
            owned_tcp_relays
                .as_ref()
                .ok_or_else(|| {
                    FlowMuxError::FrameRefused("original installed relay group required".into())
                })?
                .check_installed_audit(audit)
                .map_err(|_| {
                    FlowMuxError::FrameRefused("original installed audit partition refused".into())
                })?;
            Some(audit.bind_guest_transport(&stream).map_err(|_| {
                FlowMuxError::FrameRefused("original guest cancellation refused".into())
            })?)
        } else {
            None
        };
        if let Some(control) = &installed_session_control {
            if !installed_audit
                .as_ref()
                .is_some_and(|audit| control.matches(audit))
            {
                control.fail();
                return Err(FlowMuxError::FrameRefused(
                    "original session stop partition differs".into(),
                ));
            }
            if let Some(stopped) = control.stop_error() {
                return Err(stopped.into());
            }
        }
        let mut pending_audit = PendingInstalledAudit(installed_audit);
        // Split the socket into independent read/write descriptors so the
        // main thread can block on guest frames while relay threads emit
        // upstream data back to the guest.
        let writer = stream.try_clone()?;
        let (session, _peer_key) =
            Session::host(&mut stream, session_id, host_key).map_err(|error| {
                if let Some(control) = &installed_session_control {
                    if error.is_peer_hangup()
                        && let Some(stopped) = control.stop_error()
                    {
                        return FlowMuxError::Transport(stopped);
                    }
                    control.fail();
                }
                FlowMuxError::Handshake(error.to_string())
            })?;

        if session.peer_verifying_key() != &guest_anchor {
            return Err(FlowMuxError::Handshake(
                "guest identity does not match pinned anchor".to_string(),
            ));
        }
        if let Some(control) = &installed_session_control
            && let Some(stopped) = control.stop_error()
        {
            return Err(stopped.into());
        }
        pending_audit.check_current().inspect_err(|_| {
            if let Some(control) = &installed_session_control {
                control.fail();
            }
        })?;
        let owned_guest_control = match bound_guest {
            Some(original) => Some(original),
            None if owned_tcp_relays.is_some() => {
                Some(Arc::new(InstalledGuestWake::new(stream.try_clone()?)))
            }
            None => None,
        };

        info!(session_id, "FlowMux handshake complete");

        let resources = vm_resources
            .unwrap_or_else(|| Arc::new(FlowMuxVmResources::from_registry_limits(limits)));
        Ok(Self {
            reader: stream,
            writer: Arc::new(SharedWriter::new(writer, pending_audit.0.clone())),
            session: Arc::new(Mutex::new(session)),
            validator: Arc::new(Mutex::new(SessionValidator::new(ingress_mappings))),
            registry: Arc::new(Mutex::new(StreamRegistry::with_budget(
                limits,
                Arc::clone(&resources.registry_budget),
            ))),
            streams: Arc::new(Mutex::new(BTreeMap::new())),
            pending_ingress: Arc::new(Mutex::new(BTreeMap::new())),
            icmp_rate: Arc::clone(&resources.icmp_rate),
            http_flows: BTreeMap::new(),
            http_cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            substitution,
            udp_associations: Arc::new(Mutex::new(BTreeMap::new())),
            gate,
            read_buf: Vec::with_capacity(4096),
            limits,
            connect_timeout: Duration::from_secs(30),
            recorder,
            runtime_handle,
            rate_limiter: Arc::clone(&resources.rate_limiter),
            terminated_flows: Arc::clone(&resources.terminated_flows),
            leaves: Arc::clone(&resources.leaves),
            payload_mapping,
            owned_tcp_relays,
            owned_guest_control,
            installed_audit: pending_audit.0.take(),
            installed_session_control,
        })
    }
}
