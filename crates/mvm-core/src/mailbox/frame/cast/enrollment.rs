//! Public activation projection for one original Deliver role. The signed boot
//! grant commits to the whole projection; it contains only public mailbox grants.
use super::{CastChannel, Refusal, deny};
use crate::plan::{Nonce, VerbGrant};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    MailboxGrant, PrincipalId,
    local::{LocalGreeting, LocalRole},
    local_service::MailboxLocalLimits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverEnrollmentV1 {
    pub source_plan: [u8; 32],
    pub destination_plan: [u8; 32],
    pub destination_owner: [u8; 32],
    pub pair_commitment: [u8; 32],
    pub image_sha256: [u8; 32],
    pub mount_commitment: [u8; 32],
    pub verity_root: Option<[u8; 32]>,
    pub workload: String,
    origin: MailboxGrant,
    destination: MailboxGrant,
    sender: PrincipalId,
    recipient: PrincipalId,
    binding: [u8; 32],
    generation: u64,
    limits: MailboxLocalLimits,
    valid_from: i64,
    valid_until: i64,
}

impl CastChannel {
    /// Project an already verified plan pair for the trusted launch authority.
    /// A caller holding this projection still needs the original signed boot grant.
    pub fn guest_enrollment(
        &self,
        destination_owner: [u8; 32],
        pair_commitment: [u8; 32],
        image_sha256: [u8; 32],
        mount_commitment: [u8; 32],
        verity_root: Option<[u8; 32]>,
        workload: String,
    ) -> Result<DeliverEnrollmentV1, Refusal> {
        let plan_digest = |plan: &crate::plan::PlanId| -> Result<[u8; 32], Refusal> {
            let mut result = [0; 32];
            hex::decode_to_slice(
                plan.0.strip_prefix("sha256:").ok_or_else(deny)?,
                &mut result,
            )
            .map_err(|_| deny())?;
            Ok(result)
        };
        let source_plan = plan_digest(&self.original_plans.0)?;
        let destination_plan = plan_digest(&self.original_plans.1)?;
        let value = DeliverEnrollmentV1 {
            source_plan,
            destination_plan,
            destination_owner,
            pair_commitment,
            image_sha256,
            mount_commitment,
            verity_root,
            workload,
            origin: self.source,
            destination: self.grant,
            sender: self.sender,
            recipient: self.recipient,
            binding: self.greeting.binding,
            generation: self.greeting.generation,
            limits: self.limits,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        };
        value.commitment()?;
        Ok(value)
    }
}

impl DeliverEnrollmentV1 {
    pub fn narrow_validity(&mut self, from: i64, until: i64) -> Result<(), Refusal> {
        let start = self.valid_from.max(from);
        let end = self.valid_until.min(until);
        if start >= end {
            return Err(deny());
        }
        self.valid_from = start;
        self.valid_until = end;
        Ok(())
    }
    pub fn commitment(&self) -> Result<[u8; 32], Refusal> {
        if self.workload.is_empty()
            || self.workload.len() > 128
            || self.valid_from >= self.valid_until
            || self.source_plan == self.destination_plan
            || self.generation == 0
            || [
                self.source_plan,
                self.destination_plan,
                self.destination_owner,
                self.pair_commitment,
                self.image_sha256,
                self.mount_commitment,
                self.binding,
            ]
            .contains(&[0; 32])
        {
            return Err(deny());
        }
        self.limits.validate().map_err(|_| deny())?;
        let mut hash = Sha256::new();
        hash.update(b"mvm-guest-mailbox-deliver-enrollment-v1\0");
        hash.update(serde_jcs::to_vec(self).map_err(|_| deny())?);
        Ok(hash.finalize().into())
    }

    /// Re-check the original boot-held anchor and lineage, plus the root actually
    /// activated by PID 1. Never use a key or predecessor supplied by the frame.
    pub fn open_original(
        &self,
        boot_grant: &VerbGrant,
        anchor: &VerifyingKey,
        original_session: &str,
        original_nonce: &Nonce,
        mounted_verity: Option<[u8; 32]>,
        mounted_context: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<CastChannel, Refusal> {
        boot_grant
            .verify(anchor, original_session, original_nonce, now)
            .map_err(|_| deny())?;
        if boot_grant.cast_delivery_v1 != Some(self.commitment()?)
            || original_session != self.workload
            || self.mount_commitment != mounted_context
            || self.verity_root != mounted_verity
            || now.timestamp_millis() < self.valid_from
            || now.timestamp_millis() >= self.valid_until
            || self.valid_until > boot_grant.not_after.timestamp_millis()
        {
            return Err(deny());
        }
        Ok(CastChannel {
            original_plans: (
                crate::plan::PlanId(format!("sha256:{}", hex::encode(self.source_plan))),
                crate::plan::PlanId(format!("sha256:{}", hex::encode(self.destination_plan))),
            ),
            greeting: LocalGreeting {
                role: LocalRole::Deliver,
                binding: self.binding,
                generation: self.generation,
            },
            recipient: self.recipient,
            sender: self.sender,
            limits: self.limits,
            grant: self.destination,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            source: self.origin,
        })
    }
    pub fn limits(&self) -> MailboxLocalLimits {
        self.limits
    }
}

/// Hash the fixed-order canonical activation tuple supplied by the shared guest
/// configuration module. No application data or secret is included.
pub fn mount_context<T: serde::Serialize>(configuration: &T) -> serde_json::Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"mvm-original-cast-mount-config-v1\0");
    h.update(serde_jcs::to_vec(configuration)?);
    Ok(h.finalize().into())
}
