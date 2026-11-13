use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Full facts forwarded by the existing verified-plan spawn boundary.
/// This public DTO is not itself proof of admission or a network grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedNetworkPlan {
    pub plan_id: mvm_core::plan::PlanId,
    pub plan_version: u32,
    pub plan_nonce: mvm_core::plan::Nonce,
    pub bundle_sha256: String,
    pub tenant_id: String,
    pub instance_id: String,
    pub policy_sha256: String,
}
impl AdmittedNetworkPlan {
    pub fn from_plan(
        plan: &mvm_core::plan::ExecutionPlan,
        instance: &str,
        policy: &mvm_core::policy::network_policy::NetworkPolicy,
    ) -> Result<Self> {
        let digest = mvm_core::policy::network_policy::content_sha256(policy);
        if !plan
            .asset_identities
            .iter()
            .any(|asset| asset.kind == mvm_core::plan::AssetKind::Policy && asset.digest == digest)
        {
            bail!("network policy does not match the admitted plan asset");
        }
        let bundle = plan
            .bundle
            .as_ref()
            .context("payload mapping requires the actual admitted bundle")?;
        let binding = Self {
            plan_id: plan.plan_id.clone(),
            plan_version: plan.plan_version,
            plan_nonce: plan.nonce.clone(),
            bundle_sha256: bundle.bundle_sha256.clone(),
            tenant_id: plan.tenant.0.clone(),
            instance_id: instance.into(),
            policy_sha256: digest,
        };
        binding.validate_for(policy, &plan.tenant.0, instance)?;
        Ok(binding)
    }
    pub fn validate_for(
        &self,
        policy: &mvm_core::policy::network_policy::NetworkPolicy,
        tenant: &str,
        instance: &str,
    ) -> Result<()> {
        let bounded = |value: &str| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        };
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !bounded(&self.plan_id.0)
            || self.plan_version == 0
            || !bounded(&self.tenant_id)
            || !bounded(&self.instance_id)
            || !digest(&self.bundle_sha256)
            || !digest(&self.policy_sha256)
            || self.tenant_id != tenant
            || self.instance_id != instance
            || self.policy_sha256 != mvm_core::policy::network_policy::content_sha256(policy)
        {
            bail!("admitted network plan binding mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod payload_plan_contract_tests {
    use super::*;
    use mvm_contract::policy::network_policy::{
        CooperatingPayloadPolicy, CooperatingTcpPeer, PayloadMappingProfile,
    };
    #[test]
    fn payload_plan_materialization_retains_full_actual_facts_and_policy_identity() {
        let mapping = CooperatingPayloadPolicy::new(vec![CooperatingTcpPeer {
            host: "peer.example".into(),
            port: 443,
            server_name: "peer.example".into(),
            spki_sha256: [5; 32],
            profile: PayloadMappingProfile::SpiralCoreObjectStreamV1,
        }])
        .expect("policy");
        let policy = mvm_core::policy::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::policy::network_policy::HostPort::new("peer.example", 443),
        ])
        .with_payload_mapping(Some(mapping));
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("tenant-full")
            .plan_id("full-plan-identity-not-truncated")
            .nonce([11; 16])
            .build();
        plan.bundle = Some(mvm_core::plan::bundle::PlanArtifact::new(
            "a".repeat(64),
            &[0; 64],
            mvm_core::plan::bundle::KeyId("fixture".into()),
        ));
        plan.asset_identities.push(
            mvm_core::plan::AssetIdentity::new(
                mvm_core::plan::AssetKind::Policy,
                "network",
                mvm_core::policy::network_policy::content_sha256(&policy),
            )
            .expect("identity"),
        );
        let binding = AdmittedNetworkPlan::from_plan(&plan, "vm-full-instance", &policy)
            .expect("materialize at admitted boundary");
        assert_eq!(binding.plan_id, plan.plan_id);
        assert_eq!(binding.plan_version, plan.plan_version);
        assert_eq!(binding.plan_nonce, plan.nonce);
        assert_eq!(binding.instance_id, "vm-full-instance");
        assert_eq!(
            binding.bundle_sha256,
            plan.bundle.as_ref().expect("bundle").bundle_sha256
        );
        assert_eq!(
            binding.policy_sha256,
            mvm_core::policy::network_policy::content_sha256(&policy)
        );
        let wire = serde_json::to_vec(&binding).expect("encode");
        assert_eq!(
            serde_json::from_slice::<AdmittedNetworkPlan>(&wire).expect("decode"),
            binding
        );
        assert!(
            AdmittedNetworkPlan::from_plan(
                &plan,
                "vm-full-instance",
                &mvm_core::policy::network_policy::NetworkPolicy::deny_all()
            )
            .is_err()
        );
    }
}
