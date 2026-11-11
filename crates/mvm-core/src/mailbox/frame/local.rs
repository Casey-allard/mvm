//! Checked local-service framing. Decoding is not authorization or receipt verification.
//!
//! The local mode must already be explicitly admitted; legacy frames never call
//! this decoder. Length admission is exposed separately for transports to call
//! before allocating. Socket owners retain the original I/O deadline.

use super::Refusal;
use mvm_contract::protocol::mailbox::{
    CausationId, ContentType, CorrelationId, ED25519_SIGNATURE_BYTES, MailboxMessageKind,
    MessageId, PrincipalId, ProtocolVersion, SignatureAlgorithm, local::*,
    local_service::MailboxLocalLimits,
};
use sha2::{Digest, Sha256};

const GREETING: &[u8; 8] = b"MVMBX001";
pub const LOCAL_GREETING_BYTES: usize = 52;
pub const LOCAL_CONTROL_FRAME_BYTES: usize = 4096;
pub const LOCAL_RECEIPT_BYTES: usize = 2048;
pub const LOCAL_REPLY_TOKEN_BYTES: usize = 256;

fn require(ok: bool) -> Result<(), Refusal> {
    if ok { Ok(()) } else { Err(Refusal::Malformed) }
}
fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|b| *b != 0)
}
fn role_byte(role: LocalRole) -> u8 {
    match role {
        LocalRole::Submit => 1,
        LocalRole::Deliver => 2,
        LocalRole::Control => 3,
    }
}
fn parse_role(value: u8) -> Result<LocalRole, Refusal> {
    match value {
        1 => Ok(LocalRole::Submit),
        2 => Ok(LocalRole::Deliver),
        3 => Ok(LocalRole::Control),
        _ => Err(Refusal::Malformed),
    }
}

pub fn encode_local_greeting(
    greeting: &LocalGreeting,
) -> Result<[u8; LOCAL_GREETING_BYTES], Refusal> {
    require(nonzero(&greeting.binding) && greeting.generation != 0)?;
    let mut bytes = [0; LOCAL_GREETING_BYTES];
    bytes[..8].copy_from_slice(GREETING);
    bytes[9] = 1;
    bytes[10] = role_byte(greeting.role);
    bytes[12..44].copy_from_slice(&greeting.binding);
    bytes[44..].copy_from_slice(&greeting.generation.to_be_bytes());
    Ok(bytes)
}
pub fn decode_local_greeting(bytes: &[u8; LOCAL_GREETING_BYTES]) -> Result<LocalGreeting, Refusal> {
    require(&bytes[..8] == GREETING && bytes[8..10] == [0, 1] && bytes[11] == 0)?;
    let mut cursor = Cursor(&bytes[12..]);
    let greeting = LocalGreeting {
        role: parse_role(bytes[10])?,
        binding: cursor.fixed()?,
        generation: cursor.u64()?,
    };
    require(nonzero(&greeting.binding) && greeting.generation != 0)?;
    Ok(greeting)
}
pub fn verify_local_greeting_echo(
    expected: &LocalGreeting,
    echo: &[u8; LOCAL_GREETING_BYTES],
) -> Result<(), Refusal> {
    require(decode_local_greeting(echo)? == *expected)
}

pub fn checked_local_body_length(
    prefix: &[u8; 4],
    role: LocalRole,
    limits: &MailboxLocalLimits,
) -> Result<usize, Refusal> {
    limits.validate().map_err(|_| Refusal::Malformed)?;
    let length = u32::from_be_bytes(*prefix) as usize;
    let maximum = if role == LocalRole::Control {
        (limits.max_frame_bytes as usize).min(LOCAL_CONTROL_FRAME_BYTES)
    } else {
        limits.max_frame_bytes as usize
    };
    if length > maximum {
        return Err(Refusal::Oversized(maximum));
    }
    require(length != 0)?;
    Ok(length)
}

fn opcode(frame: &LocalFrame) -> u8 {
    match frame {
        LocalFrame::Submit(_) => 1,
        LocalFrame::SubmitResult(_) => 2,
        LocalFrame::Deliver(_) => 3,
        LocalFrame::DeliveryAck(_) => 4,
        LocalFrame::ControlRequest(_) => 5,
        LocalFrame::ControlResult(_) => 6,
        LocalFrame::DestinationReceipt(_) => 7,
    }
}
fn allowed(op: u8, role: LocalRole, direction: LocalDirection) -> bool {
    use LocalDirection::{GuestToHost as G, HostToGuest as H};
    matches!(
        (op, role, direction),
        (1, LocalRole::Submit, G)
            | (2, LocalRole::Submit, H)
            | (3, LocalRole::Deliver, H)
            | (4, LocalRole::Deliver | LocalRole::Control, G)
            | (5..=7, LocalRole::Control, G | H)
    )
}
fn kind_byte(kind: MailboxMessageKind) -> u8 {
    match kind {
        MailboxMessageKind::Call => 1,
        MailboxMessageKind::Cast => 2,
        MailboxMessageKind::Reply => 3,
    }
}
fn parse_kind(value: u8) -> Result<MailboxMessageKind, Refusal> {
    match value {
        1 => Ok(MailboxMessageKind::Call),
        2 => Ok(MailboxMessageKind::Cast),
        3 => Ok(MailboxMessageKind::Reply),
        _ => Err(Refusal::Malformed),
    }
}
fn disposition_byte(value: LocalDisposition) -> u8 {
    match value {
        LocalDisposition::AcceptedEphemeral => 1,
        LocalDisposition::DuplicateEphemeral => 2,
        LocalDisposition::Full => 3,
        LocalDisposition::Backpressured => 4,
        LocalDisposition::Unauthorized => 5,
        LocalDisposition::Expired => 6,
        LocalDisposition::Unavailable => 7,
        LocalDisposition::ShuttingDown => 8,
        LocalDisposition::Conflict => 9,
        LocalDisposition::Retired => 10,
        LocalDisposition::Cancelled => 11,
        LocalDisposition::Deadline => 12,
    }
}
fn parse_disposition(value: u8) -> Result<LocalDisposition, Refusal> {
    match value {
        1 => Ok(LocalDisposition::AcceptedEphemeral),
        2 => Ok(LocalDisposition::DuplicateEphemeral),
        3 => Ok(LocalDisposition::Full),
        4 => Ok(LocalDisposition::Backpressured),
        5 => Ok(LocalDisposition::Unauthorized),
        6 => Ok(LocalDisposition::Expired),
        7 => Ok(LocalDisposition::Unavailable),
        8 => Ok(LocalDisposition::ShuttingDown),
        9 => Ok(LocalDisposition::Conflict),
        10 => Ok(LocalDisposition::Retired),
        11 => Ok(LocalDisposition::Cancelled),
        12 => Ok(LocalDisposition::Deadline),
        _ => Err(Refusal::Malformed),
    }
}
fn operation_byte(value: LocalControlOperation) -> u8 {
    match value {
        LocalControlOperation::Query => 1,
        LocalControlOperation::Cancel => 2,
        LocalControlOperation::Retire => 3,
    }
}
fn parse_operation(value: u8) -> Result<LocalControlOperation, Refusal> {
    match value {
        1 => Ok(LocalControlOperation::Query),
        2 => Ok(LocalControlOperation::Cancel),
        3 => Ok(LocalControlOperation::Retire),
        _ => Err(Refusal::Malformed),
    }
}
fn inbox_byte(value: LocalInboxDisposition) -> u8 {
    match value {
        LocalInboxDisposition::Accepted => 1,
        LocalInboxDisposition::Full => 2,
        LocalInboxDisposition::Expired => 3,
        LocalInboxDisposition::Unavailable => 4,
    }
}
fn parse_inbox(value: u8) -> Result<LocalInboxDisposition, Refusal> {
    match value {
        1 => Ok(LocalInboxDisposition::Accepted),
        2 => Ok(LocalInboxDisposition::Full),
        3 => Ok(LocalInboxDisposition::Expired),
        4 => Ok(LocalInboxDisposition::Unavailable),
        _ => Err(Refusal::Malformed),
    }
}

fn validate(frame: &LocalFrame, limits: &MailboxLocalLimits) -> Result<(), Refusal> {
    limits.validate().map_err(|_| Refusal::Malformed)?;
    match frame {
        LocalFrame::Submit(s) => {
            require(s.request_id != 0 && nonzero(&s.originating_binding))?;
            payload(&s.body, &s.reply_token, limits)?;
            match s.kind {
                MailboxMessageKind::Call | MailboxMessageKind::Cast => require(
                    !nonzero(s.correlation.as_bytes())
                        && !nonzero(s.causation.as_bytes())
                        && s.reply_token.is_empty()
                        && ((s.kind == MailboxMessageKind::Call) == (s.timeout_ms != 0)),
                )?,
                MailboxMessageKind::Reply => require(
                    nonzero(s.correlation.as_bytes())
                        && nonzero(s.causation.as_bytes())
                        && !s.reply_token.is_empty()
                        && s.timeout_ms == 0,
                )?,
            }
        }
        LocalFrame::SubmitResult(s) => {
            require(s.request_id != 0 && nonzero(&s.service_generation))?;
            accepted_identity(s.disposition, &s.message_id)?;
        }
        LocalFrame::Deliver(s) => {
            require(
                s.delivery_sequence != 0
                    && nonzero(s.message_id.as_bytes())
                    && nonzero(s.sender.as_bytes())
                    && nonzero(s.recipient.as_bytes()),
            )?;
            payload(&s.body, &s.reply_token, limits)?;
            match s.kind {
                MailboxMessageKind::Call => require(
                    nonzero(s.correlation.as_bytes())
                        && !nonzero(s.causation.as_bytes())
                        && !s.reply_token.is_empty(),
                )?,
                MailboxMessageKind::Cast => require(
                    !nonzero(s.correlation.as_bytes())
                        && !nonzero(s.causation.as_bytes())
                        && s.reply_token.is_empty(),
                )?,
                MailboxMessageKind::Reply => require(
                    nonzero(s.correlation.as_bytes())
                        && nonzero(s.causation.as_bytes())
                        && s.reply_token.is_empty(),
                )?,
            }
        }
        LocalFrame::DeliveryAck(s) => {
            require(s.delivery_sequence != 0 && nonzero(s.message_id.as_bytes()))?
        }
        LocalFrame::ControlRequest(s) => require(s.control_id != 0 && s.target_request_id != 0)?,
        LocalFrame::ControlResult(s) => {
            require(
                s.control_id != 0 && s.target_request_id != 0 && nonzero(&s.service_generation),
            )?;
            accepted_identity(s.disposition, &s.message_id)?;
        }
        LocalFrame::DestinationReceipt(s) => require(
            s.request_id != 0
                && s.signed.signature.len() == ED25519_SIGNATURE_BYTES
                && s.signed.receipt.protocol_version == ProtocolVersion::V1
                && s.signed.receipt.signature_algorithm == SignatureAlgorithm::ED25519
                && nonzero(s.signed.receipt.message_id.as_bytes())
                && nonzero(s.signed.receipt.delivery_id.as_bytes()),
        )?,
    }
    Ok(())
}
fn accepted_identity(disposition: LocalDisposition, message: &MessageId) -> Result<(), Refusal> {
    require(
        !matches!(
            disposition,
            LocalDisposition::AcceptedEphemeral | LocalDisposition::DuplicateEphemeral
        ) || nonzero(message.as_bytes()),
    )
}
fn payload(body: &[u8], token: &[u8], limits: &MailboxLocalLimits) -> Result<(), Refusal> {
    require(!body.is_empty())?;
    if body.len() > limits.payload_bytes as usize {
        return Err(Refusal::Oversized(limits.payload_bytes as usize));
    }
    if token.len() > LOCAL_REPLY_TOKEN_BYTES {
        return Err(Refusal::Oversized(LOCAL_REPLY_TOKEN_BYTES));
    }
    Ok(())
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Writer {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(Refusal::Malformed)?;
        if length > self.maximum {
            return Err(Refusal::Oversized(self.maximum));
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| Refusal::Oversized(self.maximum))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn string(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let length = u32::try_from(bytes.len()).map_err(|_| Refusal::Malformed)?;
        self.put(&length.to_be_bytes())?;
        self.put(bytes)
    }
    fn content(&mut self, value: &ContentType) -> Result<(), Refusal> {
        let length = u8::try_from(value.name().len()).map_err(|_| Refusal::Malformed)?;
        self.put(&[length])?;
        self.put(value.name().as_bytes())?;
        self.put(&value.version().to_be_bytes())
    }
}

pub fn encode_local_frame(
    frame: &LocalFrame,
    role: LocalRole,
    direction: LocalDirection,
    limits: &MailboxLocalLimits,
) -> Result<Vec<u8>, Refusal> {
    validate(frame, limits)?;
    require(allowed(opcode(frame), role, direction))?;
    let maximum = if role == LocalRole::Control {
        (limits.max_frame_bytes as usize).min(LOCAL_CONTROL_FRAME_BYTES)
    } else {
        limits.max_frame_bytes as usize
    };
    let mut w = Writer {
        bytes: Vec::new(),
        maximum,
    };
    w.put(&[opcode(frame)])?;
    match frame {
        LocalFrame::Submit(s) => {
            w.put(&s.originating_binding)?;
            w.put(&s.request_id.to_be_bytes())?;
            w.put(&[kind_byte(s.kind)])?;
            w.put(s.recipient.as_bytes())?;
            w.content(&s.content_type)?;
            w.put(&s.expires_at_unix_ms.to_be_bytes())?;
            w.put(&s.timeout_ms.to_be_bytes())?;
            w.put(s.correlation.as_bytes())?;
            w.put(s.causation.as_bytes())?;
            w.string(&s.reply_token)?;
            w.string(&s.body)?;
        }
        LocalFrame::SubmitResult(s) => {
            w.put(&s.request_id.to_be_bytes())?;
            w.put(&s.semantic_digest)?;
            w.put(&[disposition_byte(s.disposition)])?;
            w.put(s.message_id.as_bytes())?;
            w.put(s.correlation.as_bytes())?;
            w.put(&s.service_generation)?;
        }
        LocalFrame::Deliver(s) => {
            w.put(&s.delivery_sequence.to_be_bytes())?;
            w.put(s.message_id.as_bytes())?;
            w.put(s.correlation.as_bytes())?;
            w.put(s.causation.as_bytes())?;
            w.put(s.sender.as_bytes())?;
            w.put(s.recipient.as_bytes())?;
            w.put(&[kind_byte(s.kind)])?;
            w.content(&s.content_type)?;
            w.put(&s.expires_at_unix_ms.to_be_bytes())?;
            w.string(&s.reply_token)?;
            w.string(&s.body)?;
        }
        LocalFrame::DeliveryAck(s) => {
            w.put(&s.delivery_sequence.to_be_bytes())?;
            w.put(s.message_id.as_bytes())?;
            w.put(&[inbox_byte(s.disposition)])?;
        }
        LocalFrame::ControlRequest(s) => {
            w.put(&s.control_id.to_be_bytes())?;
            w.put(&[operation_byte(s.operation)])?;
            w.put(&s.target_request_id.to_be_bytes())?;
        }
        LocalFrame::ControlResult(s) => {
            w.put(&s.control_id.to_be_bytes())?;
            w.put(&s.target_request_id.to_be_bytes())?;
            w.put(&[disposition_byte(s.disposition)])?;
            w.put(s.message_id.as_bytes())?;
            w.put(s.correlation.as_bytes())?;
            w.put(&s.service_generation)?;
        }
        LocalFrame::DestinationReceipt(s) => {
            let bytes = serde_json::to_vec(&s.signed).map_err(|_| Refusal::Malformed)?;
            if bytes.len() > LOCAL_RECEIPT_BYTES {
                return Err(Refusal::Oversized(LOCAL_RECEIPT_BYTES));
            }
            w.put(&s.request_id.to_be_bytes())?;
            w.string(&bytes)?;
        }
    }
    let length = u32::try_from(w.bytes.len()).map_err(|_| Refusal::Malformed)?;
    let total = w.bytes.len().checked_add(4).ok_or(Refusal::Malformed)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total)
        .map_err(|_| Refusal::Oversized(maximum))?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&w.bytes);
    Ok(encoded)
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let (value, rest) = self.0.split_at_checked(n).ok_or(Refusal::Malformed)?;
        self.0 = rest;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Refusal> {
        self.take(N)?.try_into().map_err(|_| Refusal::Malformed)
    }
    fn byte(&mut self) -> Result<u8, Refusal> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn string(&mut self, maximum: usize) -> Result<&'a [u8], Refusal> {
        let n = self.u32()? as usize;
        if n > maximum {
            return Err(Refusal::Oversized(maximum));
        }
        self.take(n)
    }
    fn content(&mut self) -> Result<ContentType, Refusal> {
        let n = self.byte()? as usize;
        require(n != 0 && n <= 127)?;
        let name = std::str::from_utf8(self.take(n)?).map_err(|_| Refusal::Malformed)?;
        let version = u16::from_be_bytes(self.fixed()?);
        ContentType::parse(name, version).map_err(|_| Refusal::Malformed)
    }
}

pub fn decode_local_frame(
    bytes: &[u8],
    role: LocalRole,
    direction: LocalDirection,
    limits: &MailboxLocalLimits,
) -> Result<LocalFrame, Refusal> {
    let mut outer = Cursor(bytes);
    let length = checked_local_body_length(&outer.fixed()?, role, limits)?;
    require(outer.0.len() == length)?;
    let mut c = Cursor(outer.0);
    let op = c.byte()?;
    require(allowed(op, role, direction))?;
    let frame = match op {
        1 => LocalFrame::Submit(Box::new(LocalSubmit {
            originating_binding: c.fixed()?,
            request_id: c.u64()?,
            kind: parse_kind(c.byte()?)?,
            recipient: PrincipalId::from_bytes(c.fixed()?),
            content_type: c.content()?,
            expires_at_unix_ms: i64::from_be_bytes(c.fixed()?),
            timeout_ms: c.u32()?,
            correlation: CorrelationId::from_bytes(c.fixed()?),
            causation: CausationId::from_bytes(c.fixed()?),
            reply_token: c.string(LOCAL_REPLY_TOKEN_BYTES)?.to_vec(),
            body: c.string(limits.payload_bytes as usize)?.to_vec(),
        })),
        2 => LocalFrame::SubmitResult(LocalSubmitResult {
            request_id: c.u64()?,
            semantic_digest: c.fixed()?,
            disposition: parse_disposition(c.byte()?)?,
            message_id: MessageId::from_bytes(c.fixed()?),
            correlation: CorrelationId::from_bytes(c.fixed()?),
            service_generation: c.fixed()?,
        }),
        3 => LocalFrame::Deliver(Box::new(LocalDelivery {
            delivery_sequence: c.u64()?,
            message_id: MessageId::from_bytes(c.fixed()?),
            correlation: CorrelationId::from_bytes(c.fixed()?),
            causation: CausationId::from_bytes(c.fixed()?),
            sender: PrincipalId::from_bytes(c.fixed()?),
            recipient: PrincipalId::from_bytes(c.fixed()?),
            kind: parse_kind(c.byte()?)?,
            content_type: c.content()?,
            expires_at_unix_ms: i64::from_be_bytes(c.fixed()?),
            reply_token: c.string(LOCAL_REPLY_TOKEN_BYTES)?.to_vec(),
            body: c.string(limits.payload_bytes as usize)?.to_vec(),
        })),
        4 => LocalFrame::DeliveryAck(LocalDeliveryAck {
            delivery_sequence: c.u64()?,
            message_id: MessageId::from_bytes(c.fixed()?),
            disposition: parse_inbox(c.byte()?)?,
        }),
        5 => LocalFrame::ControlRequest(LocalControlRequest {
            control_id: c.u64()?,
            operation: parse_operation(c.byte()?)?,
            target_request_id: c.u64()?,
        }),
        6 => LocalFrame::ControlResult(LocalControlResult {
            control_id: c.u64()?,
            target_request_id: c.u64()?,
            disposition: parse_disposition(c.byte()?)?,
            message_id: MessageId::from_bytes(c.fixed()?),
            correlation: CorrelationId::from_bytes(c.fixed()?),
            service_generation: c.fixed()?,
        }),
        7 => {
            let request_id = c.u64()?;
            let encoded = c.string(LOCAL_RECEIPT_BYTES)?;
            let signed = serde_json::from_slice(encoded).map_err(|_| Refusal::Malformed)?;
            require(serde_json::to_vec(&signed).map_err(|_| Refusal::Malformed)? == encoded)?;
            LocalFrame::DestinationReceipt(Box::new(LocalDestinationReceipt { request_id, signed }))
        }
        _ => return Err(Refusal::Malformed),
    };
    require(c.0.is_empty())?;
    validate(&frame, limits)?;
    Ok(frame)
}

/// Digest the exact validated Submit encoding; the service must also compare bytes.
pub fn local_request_digest(
    encoded: &[u8],
    limits: &MailboxLocalLimits,
) -> Result<[u8; 32], Refusal> {
    let frame = decode_local_frame(
        encoded,
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        limits,
    )?;
    require(matches!(frame, LocalFrame::Submit(_)))?;
    let mut hash = Sha256::new();
    hash.update(b"mvm.mailbox.local.request.v1\0");
    hash.update(&encoded[4..]);
    Ok(hash.finalize().into())
}
