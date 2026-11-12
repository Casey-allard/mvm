//! Boot projection for a single original Submit worker and its recipient.
use super::{Refusal, deny};
use crate::plan::{Nonce, VerbGrant};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    ContentType, PrincipalId,
    local::{LocalGreeting, LocalRole},
    local_service::MailboxLocalLimits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitEnrollmentV1 {
    pub source_plan: [u8; 32],
    pub destination_plan: [u8; 32],
    pub source_owner: [u8; 32],
    pub pair_commitment: [u8; 32],
    pub image_sha256: [u8; 32],
    pub mount_commitment: [u8; 32],
    pub verity_root: Option<[u8; 32]>,
    pub workload: String,
    pub binding: [u8; 32],
    pub generation: u64,
    pub service_generation: [u8; 32],
    pub recipient: PrincipalId,
    pub content_type: ContentType,
    pub limits: MailboxLocalLimits,
    pub max_payload: u32,
    pub valid_from: i64,
    pub valid_until: i64,
}

/// This type is created only by checking the actual original guest's boot trust.
pub struct OriginalSubmit(SubmitEnrollmentV1);
impl OriginalSubmit {
    pub fn enrollment(&self) -> &SubmitEnrollmentV1 {
        &self.0
    }
    pub fn greeting(&self) -> LocalGreeting {
        LocalGreeting {
            role: LocalRole::Submit,
            binding: self.0.binding,
            generation: self.0.generation,
        }
    }
}
impl SubmitEnrollmentV1 {
    pub fn commitment(&self) -> Result<[u8; 32], Refusal> {
        self.limits.validate().map_err(|_| deny())?;
        if self.workload.is_empty()
            || self.workload.len() > 128
            || self.source_plan == self.destination_plan
            || self.valid_from >= self.valid_until
            || self.generation == 0
            || self.max_payload == 0
            || self.max_payload > self.limits.payload_bytes
            || [
                self.source_plan,
                self.destination_plan,
                self.source_owner,
                self.pair_commitment,
                self.image_sha256,
                self.mount_commitment,
                self.binding,
                self.service_generation,
                *self.recipient.as_bytes(),
            ]
            .contains(&[0; 32])
        {
            return Err(deny());
        }
        let mut hash = Sha256::new();
        hash.update(b"mvm-guest-mailbox-submit-enrollment-v1\0");
        hash.update(serde_jcs::to_vec(self).map_err(|_| deny())?);
        Ok(hash.finalize().into())
    }
    pub fn open_original(
        &self,
        boot: &VerbGrant,
        anchor: &VerifyingKey,
        session: &str,
        nonce: &Nonce,
        mounted_verity: Option<[u8; 32]>,
        mounted_context: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<OriginalSubmit, Refusal> {
        boot.verify(anchor, session, nonce, now)
            .map_err(|_| deny())?;
        if boot.cast_submit_v1 != Some(self.commitment()?)
            || boot.cast_delivery_v1.is_some()
            || self.workload != session
            || self.verity_root != mounted_verity
            || self.mount_commitment != mounted_context
            || !((self.valid_from..self.valid_until).contains(&now.timestamp_millis()))
            || self.valid_until > boot.not_after.timestamp_millis()
        {
            return Err(deny());
        }
        Ok(OriginalSubmit(self.clone()))
    }
}
