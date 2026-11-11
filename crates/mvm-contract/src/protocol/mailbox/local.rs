//! Version-one local mailbox messages, separate from the canonical encrypted envelope.
//!
//! These values carry untrusted data until the original service owner admits
//! them. A decoded receipt is not proof that its signature was verified.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use super::{
    CausationId, ContentType, CorrelationId, MailboxMessageKind, MessageId, PrincipalId,
    SignedDestinationReceipt,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRole {
    Submit,
    Deliver,
    Control,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDirection {
    GuestToHost,
    HostToGuest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalGreeting {
    pub role: LocalRole,
    pub binding: [u8; 32],
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDisposition {
    AcceptedEphemeral,
    DuplicateEphemeral,
    Full,
    Backpressured,
    Unauthorized,
    Expired,
    Unavailable,
    ShuttingDown,
    Conflict,
    Retired,
    Cancelled,
    Deadline,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalInboxDisposition {
    Accepted,
    Full,
    Expired,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalControlOperation {
    Query,
    Cancel,
    Retire,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LocalSubmit {
    pub originating_binding: [u8; 32],
    pub request_id: u64,
    pub kind: MailboxMessageKind,
    pub recipient: PrincipalId,
    pub content_type: ContentType,
    pub expires_at_unix_ms: i64,
    pub timeout_ms: u32,
    pub correlation: CorrelationId,
    pub causation: CausationId,
    pub reply_token: Vec<u8>,
    pub body: Vec<u8>,
}
impl fmt::Debug for LocalSubmit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSubmit")
            .field("request_id", &self.request_id)
            .field("kind", &self.kind)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSubmitResult {
    pub request_id: u64,
    pub semantic_digest: [u8; 32],
    pub disposition: LocalDisposition,
    pub message_id: MessageId,
    pub correlation: CorrelationId,
    pub service_generation: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct LocalDelivery {
    pub delivery_sequence: u64,
    pub message_id: MessageId,
    pub correlation: CorrelationId,
    pub causation: CausationId,
    pub sender: PrincipalId,
    pub recipient: PrincipalId,
    pub kind: MailboxMessageKind,
    pub content_type: ContentType,
    pub expires_at_unix_ms: i64,
    pub reply_token: Vec<u8>,
    pub body: Vec<u8>,
}
impl fmt::Debug for LocalDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalDelivery")
            .field("delivery_sequence", &self.delivery_sequence)
            .field("kind", &self.kind)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDeliveryAck {
    pub delivery_sequence: u64,
    pub message_id: MessageId,
    pub disposition: LocalInboxDisposition,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalControlRequest {
    pub control_id: u64,
    pub operation: LocalControlOperation,
    pub target_request_id: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalControlResult {
    pub control_id: u64,
    pub target_request_id: u64,
    pub disposition: LocalDisposition,
    pub message_id: MessageId,
    pub correlation: CorrelationId,
    pub service_generation: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDestinationReceipt {
    pub request_id: u64,
    pub signed: SignedDestinationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalFrame {
    Submit(Box<LocalSubmit>),
    SubmitResult(LocalSubmitResult),
    Deliver(Box<LocalDelivery>),
    DeliveryAck(LocalDeliveryAck),
    ControlRequest(LocalControlRequest),
    ControlResult(LocalControlResult),
    DestinationReceipt(Box<LocalDestinationReceipt>),
}
