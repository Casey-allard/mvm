//! Canonical projection tests only; original process/transport gates are
//! separately exercised through the actual child and owned helper fixtures.
use super::*;
use std::collections::BTreeMap;

fn entry() -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: chrono::DateTime::parse_from_rfc3339("2026-11-04T12:00:00Z")
            .unwrap()
            .into(),
        tenant: TenantId("local".into()),
        plan_id: mvm_core::plan::PlanId(crate::supervisor::audit_recorder::UNBOUND_PLAN_ID.into()),
        plan_version: 0,
        bundle_id: None,
        bundle_version: None,
        image_name: "<unbound>".into(),
        image_sha256: "0".repeat(64),
        event: "host.flow.allowed".into(),
        caller_commitment: None,
        labels: BTreeMap::from([
            ("category".into(), "host".into()),
            ("vm_name".into(), "vm-1".into()),
            ("destination".into(), "fixture.invalid:443".into()),
        ]),
    }
}

#[test]
fn canonical_record_projection_preserves_every_original_field_and_outer_attribution() {
    let original = entry();
    let request = project_entry(&original, "vm-1", "local", "a-session", 7).unwrap();
    let SignerHelperRequest::AppendEntry(request) = request else {
        panic!("canonical append required")
    };
    assert_eq!(request.fields, serde_json::to_value(&original).unwrap());
    assert_eq!(request.vm_id, "vm-1");
    assert_eq!(request.workload_id, "vm-1");
    assert_eq!(request.tenant_id, "local");
    assert_eq!(request.session_id, "a-session");
    assert_eq!(request.category, "host");
    assert_eq!(request.ts, "2026-11-04T12:00:00+00:00");
    assert_eq!(request.request_id, "endpoint-7");
    assert_eq!(request.correlation_id, request.request_id);
}

#[test]
fn oversized_or_confused_canonical_entry_refuses_before_request_projection() {
    let original = entry();
    assert!(project_entry(&original, "vm-2", "local", "session", 0).is_err());
    assert!(project_entry(&original, "vm-1", "foreign", "session", 0).is_err());
    let mut wrong_category = original.clone();
    wrong_category
        .labels
        .insert("category".into(), "dns".into());
    assert!(project_entry(&wrong_category, "vm-1", "local", "session", 0).is_err());
    let mut oversized = original.clone();
    oversized
        .labels
        .insert("destination".into(), "x".repeat(ENTRY_BYTES));
    assert!(project_entry(&oversized, "vm-1", "local", "session", 0).is_err());
    let mut many_labels = original;
    for index in 0..LABELS {
        many_labels
            .labels
            .insert(format!("l{index}"), String::new());
    }
    assert!(project_entry(&many_labels, "vm-1", "local", "session", 0).is_err());
}

#[test]
fn projected_records_use_real_canonical_helper_chain_signatures_and_order() {
    use crate::audit_signer::{
        canonical::CanonicalEntry,
        chain::{OnDiskEntry, compute_entry_hash},
        helper::SignerHelper,
    };
    use base64::Engine;
    use ed25519_dalek::Verifier;
    use mvm_core::protocol::audit_signer::SignerHelperRegisterVm;
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let root = tempfile::tempdir().unwrap();
    let key_path = root.path().join("fixture.key");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap()
        .write_all(&[9; 32])
        .unwrap();
    let chain = root.path().join("audit.jsonl");
    let head = root.path().join("head");
    let mut helper = SignerHelper::new("local", Some(key_path)).with_owned_resource_limits();
    assert!(matches!(
        helper.dispatch(SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
            request_id: "register".into(),
            vm_id: "vm-1".into(),
            tenant_id: "local".into(),
            workload_id: "vm-1".into(),
            workload_chain_path: chain.to_string_lossy().into(),
            chain_head_secondary_path: head.to_string_lossy().into(),
        })),
        SignerHelperResponse::Registered { .. }
    ));
    let mut original = entry();
    let mut expected = Vec::new();
    for serial in 0..2 {
        original.event = if serial == 0 {
            "host.flow.allowed"
        } else {
            "host.flow.closed"
        }
        .into();
        expected.push(serde_json::to_value(&original).unwrap());
        assert!(matches!(
            helper.dispatch(project_entry(&original, "vm-1", "local", "session", serial).unwrap()),
            SignerHelperResponse::Ok { .. }
        ));
    }
    let text = std::fs::read_to_string(&chain).unwrap();
    assert_eq!(text.lines().count(), 2);
    let verifying = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
    let mut previous = CanonicalEntry::genesis_prev_hash();
    for (index, line) in text.lines().enumerate() {
        let record: OnDiskEntry = serde_json::from_str(line).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(record.canonical)
            .unwrap();
        let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(record.sig)
            .unwrap()
            .try_into()
            .unwrap();
        verifying
            .verify(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
            .unwrap();
        let canonical: CanonicalEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical.jcs_bytes().unwrap(), bytes);
        assert_eq!(canonical.fields, expected[index]);
        assert_eq!(canonical.tenant_id, "local");
        assert_eq!(canonical.workload_id, "vm-1");
        assert_eq!(canonical.session_id, "session");
        assert_eq!(canonical.category, "host");
        assert_eq!(canonical.correlation_id, format!("endpoint-{index}"));
        assert_eq!(canonical.prev_hash, previous);
        assert_eq!(record.entry_hash, compute_entry_hash(&previous, &bytes));
        assert_eq!(record.sig_alg, mvm_core::security::SIG_ALG_ED25519);
        previous = record.entry_hash;
    }
    assert_eq!(std::fs::read_to_string(head).unwrap(), previous);
}
