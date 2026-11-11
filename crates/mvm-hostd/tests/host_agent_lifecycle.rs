use mvm_core::plan::test_support::PlanFixture;
use mvm_hostd::host_agent_lifecycle::{LifecycleCoverage, classify_admitted_plan};

#[test]
fn canonical_catalog_profiles_have_one_shared_coverage_classification() {
    for kind in mvm_core::vm_backend::BackendKind::ALL {
        let plan = PlanFixture::default()
            .runtime_profile(mvm_runtime::catalog::descriptor(*kind).selector)
            .build();
        let actual = classify_admitted_plan(&plan).expect("known canonical profile");
        let expected = if mvm_hostd::host_agent_sessions::host_agent_enforces_session_expiry(*kind)
        {
            LifecycleCoverage::Covered
        } else {
            LifecycleCoverage::KnownOther(*kind)
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn an_unknown_profile_never_falls_back_to_uncovered_or_firecracker() {
    let plan = PlanFixture::default()
        .runtime_profile("unknown-canonical-profile")
        .build();
    assert!(classify_admitted_plan(&plan).is_err());
}

#[test]
fn unimplemented_reliable_service_never_downshifts_to_legacy_coverage() {
    use mvm_contract::protocol::mailbox::{
        ExecutionEpoch, MailboxGrant, MailboxId, local_service::MailboxLocalServiceGrant,
    };
    for profile in ["firecracker", "mock"] {
        let plan = PlanFixture::default()
            .runtime_profile(profile)
            .mailbox(MailboxGrant {
                mailbox: MailboxId::from_bytes([7; 32]),
                authority_key: [8; 32],
                epoch: ExecutionEpoch::new(1).expect("epoch"),
                local_service: Some(MailboxLocalServiceGrant::reliable_v1()),
            })
            .build();
        let error = classify_admitted_plan(&plan).expect_err("runtime is not implemented");
        assert!(error.to_string().contains("not implemented"));
    }
}
