//! Runtime reader declarations are compatibility data, never launch authority.

use super::{MAX_MAILBOX_READER_BOOT_BYTES, MailboxReaderBootBinding};
use crate::plan::ExecutionPlan;
use anyhow::{Context as _, Result, ensure};
use mvm_contract::protocol::mailbox::MailboxGrant;
use serde::{Deserialize, Serialize};

/// Historical reader limit when no authenticated compatibility profile exists.
pub const LEGACY_MAILBOX_READER_BOOT_BYTES: u64 = 2048;

/// Features understood by the guest reader named by a runtime declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxReaderFeatureV1 {
    DirectedJournalV1,
    ObjectPairV1,
    SenderOrdinalV1,
}

/// Authenticated only when contained in an authenticated runtime declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxReaderCompatibilityV1 {
    pub format: u32,
    pub max_boot_bytes: u64,
    pub features: Vec<MailboxReaderFeatureV1>,
}

impl MailboxReaderCompatibilityV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1 && self.max_boot_bytes > 0,
            "unsupported mailbox reader compatibility declaration"
        );
        for (index, feature) in self.features.iter().enumerate() {
            ensure!(
                !self.features[..index].contains(feature),
                "duplicate mailbox reader feature"
            );
        }
        ensure!(
            !self
                .features
                .contains(&MailboxReaderFeatureV1::SenderOrdinalV1)
                || self
                    .features
                    .contains(&MailboxReaderFeatureV1::DirectedJournalV1),
            "ordinal reader requires directed journal support"
        );
        Ok(())
    }

    pub fn require_grant(&self, grant: &MailboxGrant) -> Result<()> {
        self.validate()?;
        let required = [
            (
                grant.incoming_journal_policy_sha256_v1.is_some()
                    || grant.outbound_journal_v1.is_some(),
                MailboxReaderFeatureV1::DirectedJournalV1,
            ),
            (
                grant.durable_object_pair_sha256_v1.is_some(),
                MailboxReaderFeatureV1::ObjectPairV1,
            ),
            (
                grant
                    .outbound_journal_v1
                    .is_some_and(|direction| direction.sender_settlement.is_some()),
                MailboxReaderFeatureV1::SenderOrdinalV1,
            ),
        ];
        for (needed, feature) in required {
            ensure!(
                !needed || self.features.contains(&feature),
                "runtime mailbox reader does not support {feature:?}"
            );
        }
        Ok(())
    }

    pub fn require_binding(
        &self,
        plan: &ExecutionPlan,
        binding: &MailboxReaderBootBinding,
    ) -> Result<()> {
        binding.check_plan(plan)?;
        self.require_grant(
            plan.mailbox
                .as_ref()
                .context("reader boot requires a mailbox grant")?,
        )?;
        let bytes =
            serde_json::to_vec(binding).context("encode exact mailbox reader boot binding")?;
        let length = u64::try_from(bytes.len()).context("mailbox reader boot length overflow")?;
        ensure!(
            length <= self.max_boot_bytes.min(MAX_MAILBOX_READER_BOOT_BYTES),
            "runtime mailbox reader boot exceeds its encoded bound"
        );
        Ok(())
    }
}

/// Apply the historical feature set when the declaration omits a profile.
pub fn require_mailbox_reader_grant(
    profile: Option<&MailboxReaderCompatibilityV1>,
    grant: &MailboxGrant,
) -> Result<()> {
    let legacy = MailboxReaderCompatibilityV1 {
        format: 1,
        max_boot_bytes: LEGACY_MAILBOX_READER_BOOT_BYTES,
        features: Vec::new(),
    };
    profile.unwrap_or(&legacy).require_grant(grant)
}

/// Apply the historical reader contract when the declaration omits a profile.
pub fn require_mailbox_reader_compatibility(
    profile: Option<&MailboxReaderCompatibilityV1>,
    plan: &ExecutionPlan,
    binding: &MailboxReaderBootBinding,
) -> Result<()> {
    let legacy = MailboxReaderCompatibilityV1 {
        format: 1,
        max_boot_bytes: LEGACY_MAILBOX_READER_BOOT_BYTES,
        features: Vec::new(),
    };
    profile.unwrap_or(&legacy).require_binding(plan, binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> MailboxReaderCompatibilityV1 {
        MailboxReaderCompatibilityV1 {
            format: 1,
            max_boot_bytes: 8192,
            features: vec![
                MailboxReaderFeatureV1::DirectedJournalV1,
                MailboxReaderFeatureV1::ObjectPairV1,
                MailboxReaderFeatureV1::SenderOrdinalV1,
            ],
        }
    }
    fn grant() -> MailboxGrant {
        use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId};
        MailboxGrant {
            durable_object_pair_sha256_v1: None,
            incoming_journal_policy_sha256_v1: None,
            outbound_journal_v1: None,
            mailbox: MailboxId::from_bytes([4; 32]),
            authority_key: ed25519_dalek::SigningKey::from_bytes(&[5; 32])
                .verifying_key()
                .to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            report: None,
            retention: None,
        }
    }
    #[test]
    fn incoming_journal_requires_support_even_without_boot_extensions() {
        let mut grant = grant();
        assert!(require_mailbox_reader_grant(None, &grant).is_ok());
        grant.incoming_journal_policy_sha256_v1 = Some([6; 32]);
        assert!(require_mailbox_reader_grant(None, &grant).is_err());
        assert!(profile().require_grant(&grant).is_ok());
        grant.incoming_journal_policy_sha256_v1 = None;
        grant.durable_object_pair_sha256_v1 = Some([7; 32]);
        assert!(require_mailbox_reader_grant(None, &grant).is_err());
        assert!(profile().require_grant(&grant).is_ok());
    }
    #[test]
    fn ordinal_requires_an_explicit_reader_feature() {
        use mvm_contract::protocol::mailbox::{
            AuthorizationDomainId, BootId, MailboxAddress, MailboxJournalDirectionV1, PrincipalId,
            SenderSettlementProfile, TenantId,
        };
        let mut grant = grant();
        grant.outbound_journal_v1 = Some(MailboxJournalDirectionV1 {
            sender_settlement: None,
            source: PrincipalId::from_bytes([1; 32]),
            destination_plan_sha256: [2; 32],
            destination_plan_nonce: [3; 16],
            destination_boot: BootId::from_bytes([4; 32]),
            address: MailboxAddress {
                tenant: TenantId::from_bytes([5; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([6; 32]),
                mailbox: grant.mailbox,
                recipient: PrincipalId::from_bytes([7; 32]),
            },
            execution_epoch: grant.epoch,
            policy_epoch: 1,
            receipt_key: grant.authority_key,
            source_scope_grant_sha256: [8; 32],
            send_grant_sha256: [9; 32],
            receive_grant_sha256: [10; 32],
            not_before_unix_ms: 1,
            expires_at_unix_ms: 2,
            max_payload_bytes: 4096,
        });
        let mut directed = profile();
        directed
            .features
            .retain(|feature| *feature != MailboxReaderFeatureV1::SenderOrdinalV1);
        assert!(directed.require_grant(&grant).is_ok());
        grant
            .outbound_journal_v1
            .as_mut()
            .unwrap()
            .sender_settlement = Some(SenderSettlementProfile::OrdinalV1);
        assert!(directed.require_grant(&grant).is_err());
        assert!(profile().require_grant(&grant).is_ok());
        assert!(require_mailbox_reader_grant(None, &grant).is_err());
    }
    #[test]
    fn exact_binding_length_and_original_plan_are_checked() {
        use crate::plan::test_support::PlanFixture;
        let mut plan = PlanFixture::new().mailbox(grant()).build();
        plan.plan_id = crate::plan::compute_plan_id(&plan);
        let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key();
        let binding = MailboxReaderBootBinding::mint(&plan, key, key.to_bytes()).unwrap();
        let length = u64::try_from(serde_json::to_vec(&binding).unwrap().len()).unwrap();
        let mut exact = profile();
        exact.max_boot_bytes = length;
        assert!(exact.require_binding(&plan, &binding).is_ok());
        exact.max_boot_bytes = length - 1;
        assert!(exact.require_binding(&plan, &binding).is_err());
        exact.max_boot_bytes = u64::MAX;
        let mut moved = binding;
        moved.mailbox = mvm_contract::protocol::mailbox::MailboxId::from_bytes([9; 32]);
        assert!(exact.require_binding(&plan, &moved).is_err());
    }
    #[test]
    fn compatibility_roundtrip_and_closed_format() {
        let original = profile();
        let bytes = serde_json::to_vec(&original).unwrap();
        assert_eq!(
            serde_json::from_slice::<MailboxReaderCompatibilityV1>(&bytes).unwrap(),
            original
        );
        assert!(
            serde_json::from_str::<MailboxReaderCompatibilityV1>(
                r#"{"format":1,"max_boot_bytes":8192,"features":["future"]}"#
            )
            .is_err()
        );
        let mut invalid = original;
        invalid.format = 2;
        assert!(invalid.validate().is_err());
        invalid.format = 1;
        invalid.max_boot_bytes = 0;
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn duplicate_and_unbound_ordinal_are_refused() {
        let mut invalid = profile();
        invalid
            .features
            .push(MailboxReaderFeatureV1::DirectedJournalV1);
        assert!(invalid.validate().is_err());
        invalid.features = vec![MailboxReaderFeatureV1::SenderOrdinalV1];
        assert!(invalid.validate().is_err());
        invalid.features.clear();
        assert!(invalid.validate().is_ok());
    }
}
