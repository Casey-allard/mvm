//! Versioned control frames for the on-demand guest reader exchange.
//!
//! The `MVMR` discriminator must be dispatched before the outbox decoder;
//! it is not itself a claim of reader authority.
//! Decoding never supplies authority: the destination must verify the signed
//! Receive capability, current boot, possession proof, lease and ACK against
//! its journal before releasing plaintext or committing an acknowledgement.
//! The discriminator is inspected only after the outer length has been bounded.

use std::io::{Read, Write};

use base64::Engine as _;
use mvm_contract::protocol::mailbox::{
    ContentType, SignedDestinationReceipt, SignedMailboxCapability, SignedMailboxDeliveryAck,
    SignedMailboxDeliveryLease, SignedMailboxGuestReaderEnrollment,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::frame::Refusal;

const READER_MAGIC: &[u8; 5] = b"MVMR\x01";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Guest-local socket for explicit application Receive and ACK-after-processing.
pub const GUEST_READER_SOCKET_PATH: &str = "/run/mvm/mailbox/receive.sock";

/// An application operation for one already selected durable object pair. The
/// original sender, recipient, signing keys and return route come from MVM's
/// retained owners. The application supplies only its own stable logical IDs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectSubmissionV1 {
    Call {
        message_id: mvm_contract::protocol::mailbox::MessageId,
        correlation_id: mvm_contract::protocol::mailbox::CorrelationId,
        #[serde(with = "payload_base64")]
        payload: Vec<u8>,
    },
    Reply {
        message_id: mvm_contract::protocol::mailbox::MessageId,
        original_call: Box<SignedMailboxDeliveryLease>,
        #[serde(with = "payload_base64")]
        payload: Vec<u8>,
    },
}
impl ObjectSubmissionV1 {
    pub fn message_id(&self) -> mvm_contract::protocol::mailbox::MessageId {
        match self {
            Self::Call { message_id, .. } | Self::Reply { message_id, .. } => *message_id,
        }
    }
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Call { payload, .. } | Self::Reply { payload, .. } => payload,
        }
    }
}
impl std::fmt::Debug for ObjectSubmissionV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(match self {
            Self::Call { .. } => "ObjectCallV1",
            Self::Reply { .. } => "ObjectReplyV1",
        })
        .field("payload_len", &self.payload().len())
        .finish_non_exhaustive()
    }
}

/// The original source custodian supplies these public identifiers from the
/// retained sealed request on its authenticated, host-CID connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalObjectSealV1 {
    pub pair: [u8; 32],
    pub sender_boot: mvm_contract::protocol::mailbox::BootId,
    pub intent_sha256: [u8; 32],
    pub delivery_id: mvm_contract::protocol::mailbox::DeliveryId,
    pub ciphertext_commitment: [u8; 32],
}

pub fn original_object_intent_digest(submission: &ObjectSubmissionV1) -> Result<[u8; 32], Refusal> {
    use sha2::{Digest, Sha256};
    if submission.payload().len() > MAX_REQUEST_BYTES {
        return Err(Refusal::Oversized(MAX_REQUEST_BYTES));
    }
    let serialized = serde_jcs::to_vec(submission).map_err(|_| Refusal::Malformed)?;
    if serialized.len() > MAX_REQUEST_BYTES {
        return Err(Refusal::Oversized(MAX_REQUEST_BYTES));
    }
    let mut h = Sha256::new();
    h.update(b"mvm.mailbox.original-object-intent.v1\0");
    h.update(serialized);
    Ok(h.finalize().into())
}

impl OriginalObjectSealV1 {
    /// Call with the source original's immutable retained envelope, independently
    /// of any returned receipt. This value confers no forward or receive authority.
    pub fn from_original(
        pair: [u8; 32],
        sender_boot: mvm_contract::protocol::mailbox::BootId,
        submission: &ObjectSubmissionV1,
        stored: &mvm_contract::protocol::mailbox::MailboxEnvelope,
    ) -> Result<Self, Refusal> {
        Ok(Self {
            pair,
            sender_boot,
            intent_sha256: original_object_intent_digest(submission)?,
            delivery_id: stored.routing.delivery_id,
            ciphertext_commitment: stored.ciphertext_commitment,
        })
    }
}

/// One on-demand guest request. `Possession` answers the immediately preceding
/// destination challenge on the same connection, not an arbitrary old one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReaderRequest {
    SenderOrdinalV1 {
        request: Box<super::sender_ordinal::SenderRequestV1>,
    },
    /// Fresh, read-only sample for the exact retained, unacknowledged Call.
    AuthorizeObjectCallV1 {
        pair: [u8; 32],
        lease: Box<SignedMailboxDeliveryLease>,
        challenge: [u8; 32],
    },
    GetObjectRoleV1 {
        pair: [u8; 32],
        boot: mvm_contract::protocol::mailbox::BootId,
    },
    Receive,
    SubmitObjectV1 {
        pair: [u8; 32],
        submission: Box<ObjectSubmissionV1>,
    },
    ReceiveObjectPairV1 {
        pair: [u8; 32],
    },
    Possession {
        signature: Vec<u8>,
    },
    Ack {
        signed: Box<SignedMailboxDeliveryAck>,
    },
}

/// The guest application asks for a delivery or explicitly acknowledges one
/// after processing. It never receives the per-boot ACK signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicationReaderRequest {
    SenderOrdinalV1 {
        request: Box<super::sender_ordinal::ApplicationSenderRequestV1>,
    },
    /// Fresh, read-only sample for the exact retained, unacknowledged Call.
    AuthorizeObjectCallV1 {
        pair: [u8; 32],
        lease: Box<SignedMailboxDeliveryLease>,
        challenge: [u8; 32],
    },
    ObjectSubmissionStatusV1 {
        pair: [u8; 32],
        message_id: mvm_contract::protocol::mailbox::MessageId,
    },
    StageObjectV1 {
        pair: [u8; 32],
        submission: Box<ObjectSubmissionV1>,
    },
    ReceiveObjectPairV1 {
        pair: [u8; 32],
    },
    /// Feature availability only. The guest verifies the same boot again on dispatch.
    CheckOutboundJournalV1 {
        commitment: [u8; 32],
        recipient: mvm_contract::protocol::mailbox::PrincipalId,
        payload_bytes: u32,
    },
    Receive,
    Ack {
        lease: Box<SignedMailboxDeliveryLease>,
    },
}

/// Destination response; a delivery is never sent before its lease is durable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReaderResponse {
    SenderPendingV1 {
        handle: super::sender_ordinal::SenderOrdinalV1,
    },
    SenderAcceptedV1 {
        handle: super::sender_ordinal::SenderOrdinalV1,
        receipt: Box<SignedDestinationReceipt>,
    },
    SenderSettledV1 {
        handle: super::sender_ordinal::SenderOrdinalV1,
        retired_through: u64,
    },
    /// Guest proof of a current check against its enrolled original host.
    ObjectCallAuthorityV1 {
        role: Box<super::object_pair::role::SignedObjectRoleV1>,
        enrollment: Box<SignedMailboxGuestReaderEnrollment>,
        capability: Box<SignedMailboxCapability>,
        signature: Vec<u8>,
    },
    /// Original source service -> guest agent only. Applications receive the verified V2.
    ObjectSealAcceptedV1 {
        original: OriginalObjectSealV1,
        receipt: Box<mvm_contract::protocol::mailbox::SignedDestinationReceipt>,
    },
    ObjectRoleV1 {
        signed: Box<super::object_pair::role::SignedObjectRoleV1>,
    },
    ObjectPendingV1 {
        pair: [u8; 32],
        message_id: mvm_contract::protocol::mailbox::MessageId,
    },
    /// Returned only on the original local reader socket; never a delivery receipt.
    OutboundJournalAvailableV1 {
        commitment: [u8; 32],
    },
    Challenge {
        enrollment: Box<SignedMailboxGuestReaderEnrollment>,
        capability: Box<SignedMailboxCapability>,
        challenge: [u8; 32],
    },
    Delivery {
        lease: Box<SignedMailboxDeliveryLease>,
        content_type: ContentType,
        #[serde(with = "payload_base64")]
        payload: Vec<u8>,
    },
    /// Original destination-signed local-durable custody.
    ObjectAcceptedV1 {
        receipt: Box<mvm_contract::protocol::mailbox::SignedDestinationReceipt>,
    },
    /// The original guest has durably staged the operation locally.
    ObjectStagedV1 {
        pair: [u8; 32],
        message_id: mvm_contract::protocol::mailbox::MessageId,
    },
    ObjectDeliveryV1 {
        lease: Box<SignedMailboxDeliveryLease>,
        header: Box<mvm_contract::protocol::mailbox::MailboxEnvelopeHeader>,
        #[serde(with = "payload_base64")]
        payload: Vec<u8>,
    },
    Empty,
    Acknowledged {
        /// The exact guest-signed operation committed and anchored locally.
        /// This is correlation, not a destination-signed exportable receipt.
        ack: Box<SignedMailboxDeliveryAck>,
    },
    Refused {
        reason: Refusal,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Versioned<T> {
    version: u16,
    value: T,
}

/// Write one request, bounded before a byte is put on the stream.
pub fn write_request(stream: &mut impl Write, request: &ReaderRequest) -> Result<(), Refusal> {
    write_frame(stream, request, MAX_REQUEST_BYTES)
}

/// Read a request only after bounding its complete length.
pub fn read_request(stream: &mut impl Read) -> Result<ReaderRequest, Refusal> {
    read_frame(stream, MAX_REQUEST_BYTES)
}

/// Distinguish the reader plane from an outbox body after bounding the outer frame.
/// The legacy outbox begins with an arbitrary recipient ID, so a four-byte
/// prefix alone would misclassify valid Send operations. Unknown versions with
/// the versioned JSON envelope still fail closed in `decode_request_body`.
#[must_use]
pub fn is_reader_frame(body: &[u8]) -> bool {
    body.starts_with(b"MVMR")
        && body
            .get(READER_MAGIC.len()..)
            .is_some_and(|json| json.starts_with(b"{\"version\":"))
}

/// Decode a request when the shared mailbox listener has already read its length.
pub fn decode_request_body(body: &[u8]) -> Result<ReaderRequest, Refusal> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(Refusal::Oversized(MAX_REQUEST_BYTES));
    }
    decode_body(body)
}

/// Read one bounded, explicit application operation from the guest-local socket.
pub fn read_application_request(
    stream: &mut impl Read,
) -> Result<ApplicationReaderRequest, Refusal> {
    read_frame(stream, MAX_REQUEST_BYTES)
}

/// Send an explicit application operation to the guest-local socket.
pub fn write_application_request(
    stream: &mut impl Write,
    request: &ApplicationReaderRequest,
) -> Result<(), Refusal> {
    write_frame(stream, request, MAX_REQUEST_BYTES)
}

/// Write one destination response, including at most a bounded payload.
pub fn write_response(stream: &mut impl Write, response: &ReaderResponse) -> Result<(), Refusal> {
    write_frame(stream, response, MAX_RESPONSE_BYTES)
}

/// Read a response only after bounding its complete length.
pub fn read_response(stream: &mut impl Read) -> Result<ReaderResponse, Refusal> {
    read_frame(stream, MAX_RESPONSE_BYTES)
}

fn write_frame<T: Serialize>(
    stream: &mut impl Write,
    value: &T,
    limit: usize,
) -> Result<(), Refusal> {
    let mut json = BoundedBytes {
        bytes: Vec::new(),
        limit: limit - READER_MAGIC.len(),
    };
    serde_json::to_writer(&mut json, &Versioned { version: 1, value })
        .map_err(|_| Refusal::Oversized(limit))?;
    let len = READER_MAGIC.len() + json.bytes.len();
    stream
        .write_all(&(len as u32).to_be_bytes())
        .and_then(|()| stream.write_all(READER_MAGIC))
        .and_then(|()| stream.write_all(&json.bytes))
        .map_err(|_| Refusal::Unavailable)
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(std::io::Error::other("mailbox reader frame exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) mod payload_base64 {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error as _};

    pub(in crate::mailbox) fn serialize<S: Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(in crate::mailbox) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(D::Error::custom)
    }
}

/// During an original submission an incomplete verdict leaves acceptance unknown.
/// A completely received invalid value is still a protocol refusal.
pub fn read_submission_response(stream: &mut impl Read) -> Result<ReaderResponse, Refusal> {
    read_frame_with_io(stream, MAX_RESPONSE_BYTES, Refusal::Unavailable)
}

fn read_frame<T: DeserializeOwned>(stream: &mut impl Read, limit: usize) -> Result<T, Refusal> {
    read_frame_with_io(stream, limit, Refusal::Malformed)
}

fn read_frame_with_io<T: DeserializeOwned>(
    stream: &mut impl Read,
    limit: usize,
    io_failure: Refusal,
) -> Result<T, Refusal> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|_| io_failure.clone())?;
    let len = u32::from_be_bytes(len) as usize;
    if !(READER_MAGIC.len()..=limit).contains(&len) {
        return Err(Refusal::Oversized(limit));
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).map_err(|_| io_failure)?;
    decode_body(&body)
}

fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Refusal> {
    let json = body.strip_prefix(READER_MAGIC).ok_or(Refusal::Malformed)?;
    let frame: Versioned<T> = serde_json::from_slice(json).map_err(|_| Refusal::Malformed)?;
    if frame.version != 1 {
        return Err(Refusal::Malformed);
    }
    Ok(frame.value)
}
