//! Portable discovery DTOs for the single canonical guest control protocol.
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
/// Guest-agent control protocol capability. Closed enum so host and
/// guest fail loudly on drift instead of accepting arbitrary strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GuestCapability {
    Ping,
    /// Separately admitted, schema-bound owner application operations.
    OwnerAccessV1,
    /// Shared object-v1 payload mapping; permission still comes from the plan.
    OwnerAccessObjectV1,
    ResourceUsage,
    IntegrationStatus,
    EntrypointStatus,
    RunEntrypoint,
    /// `AgentPrompt`: one prompt to the image's resident agent.
    AgentPrompt,
    Drive,
    RunExtension,
    FilesystemRpc,
    ProcessRpc,
    /// Authenticated host decision required before a declared command spawn.
    MediatedExec,
    Console,
    /// Unix-domain socket forwarding (`StartUnixSocketForward`). Not an SSH
    /// session capability — no SSH client/server or key material crosses the
    /// guest boundary.
    UnixSocketForward,
    VolumeMount,
    UpdateIdleTimeout,
    /// `ReadinessStatus` returns
    /// `GuestResponse::ReadinessStatusReport(ReadinessReport)`.
    /// `mvmctl machine wait` / `mvmctl machine boot-report` require this capability.
    Readiness,
}

/// Required remediation for a host/guest protocol mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProtocolUpgradeAction {
    UpgradeHost,
    RebuildGuest,
    DowngradeHost,
}

pub const CONTROL_PROTOCOL_VERSION: u32 = 3;
pub const MIN_SUPPORTED_CONTROL_PROTOCOL_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlHello {
    pub host_protocol_version: u32,
    pub min_supported_version: u32,
    pub host_version: String,
    pub requested_capabilities: Vec<GuestCapability>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlHelloFrame {
    #[serde(rename = "ProtocolHello")]
    pub hello: ControlHello,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ControlHelloReply {
    ProtocolHelloAck {
        agent_protocol_version: u32,
        min_supported_version: u32,
        agent_version: String,
        capabilities: Vec<GuestCapability>,
    },
    ProtocolMismatch {
        host_protocol_version: u32,
        agent_protocol_version: u32,
        required_action: ProtocolUpgradeAction,
        message: String,
    },
    Error {
        message: String,
    },
}
