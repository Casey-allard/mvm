//! Signed, bounded application operations. No executable or filesystem selector.
use crate::plan::{Nonce, PlanId};
use crate::protocol::owner_access::{ScalarValue, TypedRecord};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AccessRefusal {
    #[error("invalid access declaration")]
    Declaration,
    #[error("operation not granted")]
    Operation,
    #[error("owner not granted")]
    Owner,
    #[error("access identity mismatch")]
    Identity,
    #[error("access epoch mismatch")]
    Epoch,
    #[error("access expired")]
    Expired,
    #[error("access schema mismatch")]
    Schema,
    #[error("access resource limit")]
    Limit,
    #[error("access replay")]
    Replay,
    #[error("access unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScalarSchema {
    Bool,
    U64,
    Text { max_bytes: u16 },
    Bytes { max_bytes: u16 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct FieldSchema {
    pub name: String,
    pub schema: ScalarSchema,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OperationGrant {
    pub name: String,
    pub owners: Vec<String>,
    pub request: Vec<FieldSchema>,
    pub reply: Vec<FieldSchema>,
    pub max_request_bytes: u32,
    pub max_reply_bytes: u32,
    pub max_in_flight: u16,
    pub max_calls_per_second: u16,
    pub max_deadline_ms: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessGrant {
    pub operations: Vec<OperationGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_v1: Option<OwnerAccessObjectProfile>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessObjectProfile {
    pub major: u16,
    pub codec_mask: u16,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub cache_reuse_within_execution: bool,
}
impl OwnerAccessObjectProfile {
    pub fn validate(&self) -> Result<(), AccessRefusal> {
        if self.major != 1 || self.codec_mask & 1 == 0 || self.codec_mask & !1023 != 0 {
            return Err(AccessRefusal::Declaration);
        }
        Ok(())
    }
}
/// Host-signed exact admitted instance. The complete plan ID lives here,
/// outside the plan payload whose content address it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct PolicyRevision {
    pub plan_id: PlanId,
    pub plan_version: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ExecutionIdentity {
    pub instance_id: String,
    pub plan_nonce: Nonce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_sha256: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OwnerAccessBinding {
    pub policy: PolicyRevision,
    pub execution: ExecutionIdentity,
    pub tenant: String,
    pub grant: OwnerAccessGrant,
}
impl OwnerAccessBinding {
    /// Pure derivation from an already verified/admitted plan. This is not a
    /// signature/admission replacement; the host signer enforces that boundary.
    pub fn from_plan(
        plan: &crate::plan::ExecutionPlan,
        instance: &str,
    ) -> Result<Option<Self>, AccessRefusal> {
        let Some(grant) = plan
            .grants
            .as_ref()
            .and_then(|grants| grants.owner_access.as_ref())
        else {
            return Ok(None);
        };
        let bundle = plan.bundle.as_ref().ok_or(AccessRefusal::Identity)?;
        let binding = Self {
            policy: PolicyRevision {
                plan_id: plan.plan_id.clone(),
                plan_version: plan.plan_version,
            },
            execution: ExecutionIdentity {
                instance_id: instance.into(),
                plan_nonce: plan.nonce.clone(),
                bundle_sha256: Some(bundle.bundle_sha256.clone()),
            },
            tenant: plan.tenant.0.clone(),
            grant: grant.clone(),
        };
        binding.validate()?;
        Ok(Some(binding))
    }
    pub fn validate(&self) -> Result<(), AccessRefusal> {
        if !principal(&self.execution.instance_id)
            || !principal(&self.tenant)
            || self.policy.plan_id.0.is_empty()
            || self.policy.plan_id.0.len() > 128
            || self.policy.plan_version == 0
            || self.execution.bundle_sha256.as_ref().is_none_or(|value| {
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(AccessRefusal::Identity);
        }
        self.grant.validate()
    }
}
impl OwnerAccessGrant {
    pub fn validate(&self) -> Result<(), AccessRefusal> {
        if let Some(profile) = &self.object_v1 {
            profile.validate()?;
        }
        if self.operations.is_empty() || self.operations.len() > 32 {
            return Err(AccessRefusal::Limit);
        }
        let mut seen = BTreeSet::new();
        for operation in &self.operations {
            operation.validate()?;
            if !seen.insert(&operation.name) {
                return Err(AccessRefusal::Declaration);
            }
        }
        Ok(())
    }
    pub fn operation(&self, name: &str) -> Result<&OperationGrant, AccessRefusal> {
        self.validate()?;
        self.operations
            .iter()
            .find(|operation| operation.name == name)
            .ok_or(AccessRefusal::Operation)
    }
}
impl OperationGrant {
    pub fn validate(&self) -> Result<(), AccessRefusal> {
        if !identifier(&self.name)
            || reserved(&self.name)
            || self.owners.is_empty()
            || self.owners.len() > 32
        {
            return Err(AccessRefusal::Declaration);
        }
        let mut seen = BTreeSet::new();
        for owner in &self.owners {
            if !principal(owner) || !seen.insert(owner) {
                return Err(AccessRefusal::Declaration);
            }
        }
        if self.max_request_bytes == 0
            || self.max_request_bytes > 65536
            || self.max_reply_bytes == 0
            || self.max_reply_bytes > 65536
            || self.max_in_flight == 0
            || self.max_in_flight > 64
            || self.max_calls_per_second == 0
            || self.max_calls_per_second > 1024
            || self.max_deadline_ms == 0
            || self.max_deadline_ms > 30000
        {
            return Err(AccessRefusal::Limit);
        }
        fields(&self.request)?;
        fields(&self.reply)
    }
    pub fn validate_request(&self, record: &TypedRecord) -> Result<(), AccessRefusal> {
        self.validate()?;
        record_matches(&self.request, record, self.max_request_bytes)
    }
    pub fn validate_reply(&self, record: &TypedRecord) -> Result<(), AccessRefusal> {
        self.validate()?;
        record_matches(&self.reply, record, self.max_reply_bytes)
    }
}
fn fields(fields: &[FieldSchema]) -> Result<(), AccessRefusal> {
    if fields.len() > 16 {
        return Err(AccessRefusal::Limit);
    }
    let mut names = BTreeSet::new();
    for field in fields {
        if !identifier(&field.name) || reserved(&field.name) || !names.insert(&field.name) {
            return Err(AccessRefusal::Declaration);
        }
        match field.schema {
            ScalarSchema::Text { max_bytes } if max_bytes == 0 || max_bytes > 256 => {
                return Err(AccessRefusal::Limit);
            }
            ScalarSchema::Bytes { max_bytes } if max_bytes == 0 || max_bytes > 4096 => {
                return Err(AccessRefusal::Limit);
            }
            _ => {}
        }
    }
    Ok(())
}
fn record_matches(
    schema: &[FieldSchema],
    record: &TypedRecord,
    limit: u32,
) -> Result<(), AccessRefusal> {
    if record.fields.len() != schema.len() || record.fields.len() > 16 {
        return Err(AccessRefusal::Schema);
    }
    let mut names = BTreeSet::new();
    for field in &record.fields {
        if !names.insert(&field.name) {
            return Err(AccessRefusal::Schema);
        }
        let declared = schema
            .iter()
            .find(|entry| entry.name == field.name)
            .ok_or(AccessRefusal::Schema)?;
        let valid = match (&declared.schema, &field.value) {
            (ScalarSchema::Bool, ScalarValue::Bool(_))
            | (ScalarSchema::U64, ScalarValue::U64(_)) => true,
            (ScalarSchema::Text { max_bytes }, ScalarValue::Text(value)) => {
                value.len() <= usize::from(*max_bytes)
            }
            (ScalarSchema::Bytes { max_bytes }, ScalarValue::Bytes(value)) => {
                value.len() <= usize::from(*max_bytes)
            }
            _ => false,
        };
        if !valid {
            return Err(AccessRefusal::Schema);
        }
    }
    let encoded = serde_json::to_vec(record).map_err(|_| AccessRefusal::Schema)?;
    if encoded.len() > limit as usize {
        return Err(AccessRefusal::Limit);
    }
    Ok(())
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
fn principal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:@".contains(&c))
}
fn reserved(value: &str) -> bool {
    matches!(
        value,
        "command"
            | "argv"
            | "path"
            | "env"
            | "pty"
            | "exec"
            | "shell"
            | "file"
            | "executable"
            | "cwd"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mint_binding_uses_existing_plan_facts_and_never_invents_bundle_or_clock() {
        let mut plan = crate::plan::execution_plan::minimal_plan();
        assert!(
            OwnerAccessBinding::from_plan(&plan, "actual-instance")
                .unwrap()
                .is_none()
        );
        plan.grants = Some(crate::grants::Grants {
            owner_access: Some(OwnerAccessGrant {
                object_v1: None,
                operations: vec![OperationGrant {
                    name: "status".into(),
                    owners: vec!["local-owner".into()],
                    request: vec![],
                    reply: vec![],
                    max_request_bytes: 1024,
                    max_reply_bytes: 1024,
                    max_in_flight: 1,
                    max_calls_per_second: 4,
                    max_deadline_ms: 1000,
                }],
            }),
            ..Default::default()
        });
        assert!(OwnerAccessBinding::from_plan(&plan, "actual-instance").is_err());
        plan.bundle = Some(crate::plan::bundle::PlanArtifact::new(
            "b".repeat(64),
            &[7; 64],
            crate::plan::bundle::KeyId("fixture-key".into()),
        ));
        let binding = OwnerAccessBinding::from_plan(&plan, "actual-instance")
            .unwrap()
            .unwrap();
        assert_eq!(binding.policy.plan_id, plan.plan_id);
        assert_eq!(binding.policy.plan_version, plan.plan_version);
        assert_eq!(binding.execution.instance_id, "actual-instance");
        assert_eq!(binding.execution.plan_nonce, plan.nonce);
        assert_eq!(
            binding.execution.bundle_sha256,
            Some(plan.bundle.unwrap().bundle_sha256)
        );
    }
}
