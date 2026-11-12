//! Inactive version-one host-signed mailbox child-owner control contract.
//! No key material, executable paths, or PID authority crosses this protocol.
use super::mailbox::MailboxGrant;
use alloc::string::String;
use serde::{Deserialize, Serialize};

pub const MAILBOX_WORKER_DOMAIN: &str = "mvm-mailbox-worker-v1";
pub const MAX_WORKER_CONTROL_BYTES: usize = 64 * 1024;
pub const MAX_WORKER_OPERATION_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxWorkerBackend {
    Firecracker,
    Hvf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxWorkerOwner {
    pub daemon_boot_nonce: [u8; 32],
    pub lease: [u8; 32],
    pub generation: u64,
    pub context_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MailboxWorkerOperation {
    Acquire,
    /// Read an existing slot by original nonce and exact admission context.
    LookupExistingV1,
    /// Host launcher's signed attestation of an already admitted local plan.
    /// An explicitly enabled worker reserves the original nonce and context.
    ProvisionAdmittedV1 { resource_epoch: u64 },
    DelegateConfig {
        owner: MailboxWorkerOwner,
    },
    Query {
        owner: MailboxWorkerOwner,
    },
    Stop {
        owner: MailboxWorkerOwner,
    },
    /// Explicit extension for aborting a reservation before any spawn attempt.
    /// Older peers reject the unknown operation.
    ReleaseUnstartedV1 {
        owner: MailboxWorkerOwner,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxWorkerRequest {
    pub domain: String,
    pub version: u16,
    pub request_nonce: [u8; 32],
    pub tenant: String,
    pub vm_id: String,
    pub workload_id: String,
    pub plan_commitment: [u8; 32],
    pub mailbox_grant: MailboxGrant,
    pub admission_expires_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub backend: MailboxWorkerBackend,
    pub operation: MailboxWorkerOperation,
}

/// Actual status returned by waiting the original child, never by observing a PID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MailboxWorkerExit {
    Code { code: i32 },
    Signal { signal: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MailboxWorkerState {
    Reserved,
    Starting,
    Serving,
    Stopping,
    Collected {
        exit: MailboxWorkerExit,
    },
    Unresolved,
    /// Returned exclusively to ReleaseUnstartedV1, never as a Child exit.
    ReleasedBeforeSpawn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxWorkerResult {
    pub request_nonce: [u8; 32],
    pub owner: MailboxWorkerOwner,
    pub state: MailboxWorkerState,
    /// True only for the first successful DelegateConfig: exactly one pipe writer.
    pub delegates_config: bool,
}
