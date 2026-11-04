//! Portable owner-access payload DTOs carried by the canonical control envelope.
use crate::grants::owner_access::{
    AccessRefusal, ExecutionIdentity, OperationGrant, OwnerAccessBinding, PolicyRevision,
    ScalarSchema,
};
use alloc::{boxed::Box,string::String, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ScalarValue {
    Bool(bool),
    U64(u64),
    Text(String),
    Bytes(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct NamedValue {
    pub name: String,
    pub value: ScalarValue,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct TypedRecord {
    pub fields: Vec<NamedValue>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessRequest {
    pub policy: PolicyRevision,
    pub execution: ExecutionIdentity,
    pub request_id: [u8; 32],
    pub sequence: u64,
    pub operation: String,
    pub owner: String,
    pub deadline_unix_ms: u64,
    pub payload: TypedRecord,
}
impl OwnerAccessRequest {
    pub fn validate<'a>(
        &self,
        binding: &'a OwnerAccessBinding,
        now_ms: u64,
    ) -> Result<&'a OperationGrant, AccessRefusal> {
        let operation = self.validate_header(binding, now_ms)?;
        operation.validate_request(&self.payload)?;
        Ok(operation)
    }
    pub fn validate_header<'a>(
        &self,
        binding: &'a OwnerAccessBinding,
        now_ms: u64,
    ) -> Result<&'a OperationGrant, AccessRefusal> {
        binding.validate()?;
        if self.execution != binding.execution || self.request_id == [0; 32] || self.sequence == 0 {
            return Err(AccessRefusal::Identity);
        }
        if self.policy != binding.policy {
            return Err(AccessRefusal::Epoch);
        }
        let operation = binding.grant.operation(&self.operation)?;
        if !operation.owners.contains(&self.owner) {
            return Err(AccessRefusal::Owner);
        }
        let remaining = self
            .deadline_unix_ms
            .checked_sub(now_ms)
            .filter(|ms| *ms > 0)
            .ok_or(AccessRefusal::Expired)?;
        if remaining > u64::from(operation.max_deadline_ms) {
            return Err(AccessRefusal::Limit);
        }
        Ok(operation)
    }
}

pub const OWNER_ACCESS_OBJECT_MAX_PAYLOAD: u32 = 16 * 1024;
pub const OWNER_ACCESS_OBJECT_MAX_BATCH: usize = 128 * 1024;
pub const OWNER_ACCESS_OBJECT_MAPPING_VERSION: u16 = 1;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessObjectBegin {
    pub request: OwnerAccessRequest,
    pub object: [u8; 32],
    pub payload_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}
impl OwnerAccessObjectBegin {
    pub fn validate<'a>(
        &self,
        binding: &'a OwnerAccessBinding,
        now_ms: u64,
    ) -> Result<&'a OperationGrant, AccessRefusal> {
        binding
            .grant
            .object_v1
            .as_ref()
            .ok_or(AccessRefusal::Unavailable)?
            .validate()?;
        let operation = self.request.validate_header(binding, now_ms)?;
        if self.payload_bytes == 0
            || self.payload_bytes > OWNER_ACCESS_OBJECT_MAX_PAYLOAD
            || self.payload_bytes > operation.max_request_bytes
        {
            return Err(AccessRefusal::Limit);
        }
        if let Some(field) = &self.field {
            operation.validate_request(&self.request.payload)?;
            let schema = operation
                .request
                .iter()
                .find(|entry| &entry.name == field)
                .ok_or(AccessRefusal::Schema)?;
            let value = self
                .request
                .payload
                .fields
                .iter()
                .find(|entry| &entry.name == field)
                .ok_or(AccessRefusal::Schema)?;
            let limit = match (&schema.schema, &value.value) {
                (ScalarSchema::Bytes { max_bytes }, ScalarValue::Bytes(bytes))
                    if bytes.is_empty() =>
                {
                    *max_bytes
                }
                (ScalarSchema::Text { max_bytes }, ScalarValue::Text(text)) if text.is_empty() => {
                    *max_bytes
                }
                _ => return Err(AccessRefusal::Schema),
            };
            if self.payload_bytes > u32::from(limit) {
                return Err(AccessRefusal::Limit);
            }
        } else if !self.request.payload.fields.is_empty() {
            return Err(AccessRefusal::Schema);
        }
        Ok(operation)
    }
    pub fn reconstruct(
        &self,
        bytes: &[u8],
        binding: &OwnerAccessBinding,
        now_ms: u64,
    ) -> Result<OwnerAccessRequest, AccessRefusal> {
        self.validate(binding, now_ms)?;
        if bytes.len() != self.payload_bytes as usize {
            return Err(AccessRefusal::Limit);
        }
        let mut request = self.request.clone();
        request.payload = join_object_payload(&self.request.payload, self.field.as_deref(), bytes)?;
        request.validate(binding, now_ms)?;
        Ok(request)
    }
}

/// Versioned endpoint mapping only: bytes/text stay raw at the selected payload
/// position; scalar-only records retain their existing canonical JSON mapping.
pub fn split_object_payload(
    mut record: TypedRecord,
) -> Result<(TypedRecord, Option<String>, Vec<u8>), AccessRefusal> {
    if record.fields.len() > 16 {
        return Err(AccessRefusal::Limit);
    }
    let mut selected = None;
    let mut largest = 63;
    for (index, field) in record.fields.iter().enumerate() {
        if field.name.len() > 64 {
            return Err(AccessRefusal::Limit);
        }
        let length = match &field.value {
            ScalarValue::Bytes(bytes) if bytes.len() <= 4096 => bytes.len(),
            ScalarValue::Text(text) if text.len() <= 256 => text.len(),
            ScalarValue::Bytes(_) | ScalarValue::Text(_) => return Err(AccessRefusal::Limit),
            _ => 0,
        };
        if length > largest {
            largest = length;
            selected = Some(index);
        }
    }
    if let Some(index) = selected {
        let field = record.fields.get_mut(index).ok_or(AccessRefusal::Schema)?;
        let bytes = match &mut field.value {
            ScalarValue::Bytes(bytes) => core::mem::take(bytes),
            ScalarValue::Text(text) => core::mem::take(text).into_bytes(),
            _ => return Err(AccessRefusal::Schema),
        };
        let name = field.name.clone();
        Ok((record, Some(name), bytes))
    } else {
        let bytes = serde_json::to_vec(&record).map_err(|_| AccessRefusal::Schema)?;
        if bytes.len() > OWNER_ACCESS_OBJECT_MAX_PAYLOAD as usize {
            return Err(AccessRefusal::Limit);
        }
        Ok((TypedRecord::default(), None, bytes))
    }
}
pub fn join_object_payload(
    record: &TypedRecord,
    field: Option<&str>,
    bytes: &[u8],
) -> Result<TypedRecord, AccessRefusal> {
    if bytes.len() > OWNER_ACCESS_OBJECT_MAX_PAYLOAD as usize {
        return Err(AccessRefusal::Limit);
    }
    if let Some(name) = field {
        if record
            .fields
            .iter()
            .filter(|field| field.name == name)
            .count()
            != 1
        {
            return Err(AccessRefusal::Schema);
        }
        let mut record = record.clone();
        let field = record
            .fields
            .iter_mut()
            .find(|field| field.name == name)
            .ok_or(AccessRefusal::Schema)?;
        match &mut field.value {
            ScalarValue::Bytes(value) if value.is_empty() => *value = bytes.to_vec(),
            ScalarValue::Text(value) if value.is_empty() => {
                *value = String::from_utf8(bytes.to_vec()).map_err(|_| AccessRefusal::Schema)?
            }
            _ => return Err(AccessRefusal::Schema),
        }
        Ok(record)
    } else {
        if !record.fields.is_empty() {
            return Err(AccessRefusal::Schema);
        }
        serde_json::from_slice(bytes).map_err(|_| AccessRefusal::Schema)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OwnerAccessObjectDirection {
    Input,
    Reply,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessObjectFrames {
    pub request_id: [u8; 32],
    pub sequence: u64,
    pub direction: OwnerAccessObjectDirection,
    pub frames: Vec<Vec<u8>>,
}
impl OwnerAccessObjectFrames {
    pub fn validate_for(
        &self,
        begin: &OwnerAccessObjectBegin,
        direction: OwnerAccessObjectDirection,
    ) -> Result<(), AccessRefusal> {
        if self.request_id != begin.request.request_id
            || self.sequence != begin.request.sequence
            || self.direction != direction
        {
            return Err(AccessRefusal::Identity);
        }
        if self.frames.is_empty() || self.frames.len() > 8 {
            return Err(AccessRefusal::Limit);
        }
        let mut bytes = 0usize;
        for frame in &self.frames {
            if frame.is_empty() || frame.len() > 65536 {
                return Err(AccessRefusal::Limit);
            }
            bytes = bytes.checked_add(frame.len()).ok_or(AccessRefusal::Limit)?;
        }
        if bytes > OWNER_ACCESS_OBJECT_MAX_BATCH {
            return Err(AccessRefusal::Limit);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub enum OwnerAccessObjectRequest {
    Begin(Box<OwnerAccessObjectBegin>),
    Frames(OwnerAccessObjectFrames),
    Commit { request_id: [u8; 32], sequence: u64 },
    ReplyReady { request_id: [u8; 32], sequence: u64 },
    Receipt(OwnerAccessObjectFrames),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub enum OwnerAccessObjectResponse {
    Ready {
        request_id: [u8; 32],
        sequence: u64,
    },
    Frames(OwnerAccessObjectFrames),
    Reply {
        request_id: [u8; 32],
        sequence: u64,
        status: OwnerAccessStatus,
        object: [u8; 32],
        payload_bytes: u32,
        record: TypedRecord,
        field: Option<String>,
    },
    ReplyFrames(OwnerAccessObjectFrames),
    Completed {
        request_id: [u8; 32],
        sequence: u64,
        status: OwnerAccessStatus,
        object: [u8; 32],
        payload_bytes: u32,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessObjectCallFrame {
    #[serde(rename = "OwnerAccessObject")]
    pub request: OwnerAccessObjectRequest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessObjectReplyFrame {
    #[serde(rename = "OwnerAccessObject")]
    pub reply: OwnerAccessObjectResponse,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessCancel {
    pub policy: PolicyRevision,
    pub execution: ExecutionIdentity,
    pub request_id: [u8; 32],
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OwnerAccessStatus {
    Ok,
    Refused,
    Timeout,
    Cancelled,
    Error,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessReply {
    pub request_id: [u8; 32],
    pub sequence: u64,
    pub status: OwnerAccessStatus,
    pub payload: TypedRecord,
}

/// The one portable mapping for the access subset of canonical GuestRequest.
/// Crypto framing is still mvm-core Session/SealedFrame, never this DTO alone.
pub const OWNER_ACCESS_MAPPING_VERSION: u16 = 1;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessCallFrame {
    #[serde(rename = "DeliverDeclaredOperation")]
    pub request: OwnerAccessRequest,
}
impl OwnerAccessCallFrame {
    pub fn new(request: OwnerAccessRequest) -> Self {
        Self { request }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessReplyFrame {
    #[serde(rename = "OwnerAccessReply")]
    pub reply: OwnerAccessReply,
}
impl OwnerAccessReplyFrame {
    pub fn new(reply: OwnerAccessReply) -> Self {
        Self { reply }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerAccessAuditKind {
    Granted,
    Request,
    Refused,
    Completed,
    Revoked,
    Cancelled,
    Forward,
    Shutdown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessAudit {
    pub kind: OwnerAccessAuditKind,
    pub policy: PolicyRevision,
    pub execution: ExecutionIdentity,
    pub request_digest: [u8; 32],
    pub sequence: u64,
    pub operation: String,
    pub request_bytes: u64,
    pub reply_bytes: u64,
    pub reason: Option<AccessRefusal>,
}
