pub use mvm_core::policy::direct_plan::AdmittedNetworkPlan;

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
                "network_policy",
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
