use mvm_contract::grants::owner_access::{OperationGrant, OwnerAccessGrant};
use mvm_core::domain::manifest::ManifestGrants;

#[test]
fn authored_access_projects_exactly_to_plan_and_host_defaults_grant_none() {
    let grant = OwnerAccessGrant {
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
    };
    let manifest: ManifestGrants =
        serde_json::from_value(serde_json::json!({"owner_access":grant})).unwrap();
    assert!(
        serde_json::to_string(&manifest)
            .unwrap()
            .contains("owner_access")
    );
    assert_eq!(
        manifest.to_grants().unwrap().owner_access,
        Some(grant.clone())
    );
    let malformed = OwnerAccessGrant {
        object_v1: None,
        operations: vec![grant.operations[0].clone(), grant.operations[0].clone()],
    };
    let manifest: ManifestGrants =
        serde_json::from_value(serde_json::json!({"owner_access":malformed})).unwrap();
    assert!(manifest.to_grants().is_err());
    let manifest: ManifestGrants = serde_json::from_str("{}").unwrap();
    assert!(manifest.to_grants().unwrap().owner_access.is_none());
}
