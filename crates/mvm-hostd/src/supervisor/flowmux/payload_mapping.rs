use mvm_contract::policy::network_policy::{CooperatingPayloadPolicy, CooperatingTcpPeer};
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan;
use std::{
    fmt::Debug,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::Arc,
    time::Instant,
};

/// Payload I/O still owned by the original admitted TCP connection.
pub trait AuthenticatedTcpPayloadIo: Read + Write + Send + Debug {
    fn try_clone(&self) -> io::Result<Box<dyn AuthenticatedTcpPayloadIo>>;
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

/// Trusted implementation authenticates the peer before creating codec state.
pub trait AuthenticatedTcpPayloadFactory: Send + Sync + Debug {
    fn map(
        &self,
        socket: TcpStream,
        request: AdmittedTcpPayload,
    ) -> io::Result<Box<dyn AuthenticatedTcpPayloadIo>>;
}

#[derive(Debug, Clone)]
pub struct AdmittedTcpPayload {
    plan: AdmittedNetworkPlan,
    session_id: String,
    guest_key: [u8; 32],
    stream_id: u32,
    requested_host: String,
    requested_port: u16,
    actual_peer: SocketAddr,
    route: &'static str,
    selected: CooperatingTcpPeer,
    deadline: Instant,
}
impl AdmittedTcpPayload {
    pub fn plan(&self) -> &AdmittedNetworkPlan {
        &self.plan
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn guest_key(&self) -> [u8; 32] {
        self.guest_key
    }
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
    pub fn requested_host(&self) -> &str {
        &self.requested_host
    }
    pub fn requested_port(&self) -> u16 {
        self.requested_port
    }
    pub fn actual_peer(&self) -> SocketAddr {
        self.actual_peer
    }
    pub fn route(&self) -> &'static str {
        self.route
    }
    pub fn selected(&self) -> &CooperatingTcpPeer {
        &self.selected
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

pub(super) struct AdmittedTcpFacts {
    pub session_id: String,
    pub guest_key: [u8; 32],
    pub stream_id: u32,
    pub requested_host: String,
    pub requested_port: u16,
    pub route: &'static str,
    pub deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct PayloadMappingConfig {
    policy: CooperatingPayloadPolicy,
    plan: AdmittedNetworkPlan,
    factory: Option<Arc<dyn AuthenticatedTcpPayloadFactory>>,
}
impl PayloadMappingConfig {
    pub fn new(policy: &NetworkPolicy, plan: AdmittedNetworkPlan) -> anyhow::Result<Self> {
        plan.validate_for(policy, &plan.tenant_id, &plan.instance_id)?;
        let selected = policy
            .payload_mapping()
            .ok_or_else(|| anyhow::anyhow!("payload mapping has no signed declaration"))?;
        Ok(Self {
            policy: selected.clone(),
            plan,
            factory: None,
        })
    }
    #[must_use]
    pub fn with_factory(mut self, factory: Arc<dyn AuthenticatedTcpPayloadFactory>) -> Self {
        self.factory = Some(factory);
        self
    }
    pub(super) fn selects(&self, host: &str, port: u16) -> bool {
        self.policy.select(host, port).is_some()
    }
    pub(super) fn map(
        &self,
        socket: TcpStream,
        facts: AdmittedTcpFacts,
    ) -> io::Result<Box<dyn AuthenticatedTcpPayloadIo>> {
        let selected = self
            .policy
            .select(&facts.requested_host, facts.requested_port)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "payload destination not selected",
                )
            })?;
        if Instant::now() >= facts.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "payload setup deadline",
            ));
        }
        let deadline = facts.deadline;
        let request = AdmittedTcpPayload {
            plan: self.plan.clone(),
            session_id: facts.session_id,
            guest_key: facts.guest_key,
            stream_id: facts.stream_id,
            requested_host: facts.requested_host,
            requested_port: facts.requested_port,
            actual_peer: socket.peer_addr()?,
            route: facts.route,
            selected,
            deadline,
        };
        let mapped = self
            .factory
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "required authenticated payload provider unavailable",
                )
            })?
            .map(socket, request)?;
        if Instant::now() >= deadline {
            let _ = mapped.shutdown(Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "payload setup deadline",
            ));
        }
        Ok(mapped)
    }
}
