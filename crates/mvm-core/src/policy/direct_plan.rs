use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Full facts forwarded by the existing verified-plan spawn boundary.
/// This public DTO is not itself proof of admission or a network grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedNetworkPlan {
    pub plan_id: crate::plan::PlanId,
    pub plan_version: u32,
    pub plan_nonce: crate::plan::Nonce,
    pub bundle_sha256: String,
    pub tenant_id: String,
    pub instance_id: String,
    pub policy_sha256: String,
}
impl AdmittedNetworkPlan {
    pub fn from_plan(
        plan: &crate::plan::ExecutionPlan,
        instance: &str,
        policy: &crate::policy::network_policy::NetworkPolicy,
    ) -> Result<Self> {
        let digest = crate::policy::network_policy::content_sha256(policy);
        let mut policies = plan.asset_identities.iter().filter(|asset|
            asset.kind == crate::plan::AssetKind::Policy && asset.name == "network_policy");
        if !policies.next().is_some_and(|asset| asset.digest == digest) || policies.next().is_some() {
            bail!("network policy does not match the unique signed network_policy asset");
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
        policy: &crate::policy::network_policy::NetworkPolicy,
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
            || self.policy_sha256 != crate::policy::network_policy::content_sha256(policy)
        {
            bail!("admitted network plan binding mismatch");
        }
        Ok(())
    }
}
