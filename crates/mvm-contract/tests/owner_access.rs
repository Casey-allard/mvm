use mvm_contract::grants::owner_access::{
    FieldSchema, OperationGrant, OwnerAccessGrant, ScalarSchema,
};
use mvm_contract::protocol::owner_access::{NamedValue, ScalarValue, TypedRecord};

#[test]
fn object_header_authorizes_before_payload_and_bounds_followup_frames() {
    use mvm_contract::{
        grants::owner_access::{
            ExecutionIdentity, OwnerAccessBinding, OwnerAccessObjectProfile, PolicyRevision,
        },
        plan::{Nonce, PlanId},
        protocol::owner_access::{
            OwnerAccessObjectBegin, OwnerAccessObjectDirection, OwnerAccessObjectFrames,
            OwnerAccessRequest,
        },
    };
    let operation = OperationGrant {
        name: "status".into(),
        owners: vec!["owner-a".into()],
        request: vec![FieldSchema {
            name: "verbose".into(),
            schema: ScalarSchema::Bool,
        }],
        reply: vec![],
        max_request_bytes: 1024,
        max_reply_bytes: 1024,
        max_in_flight: 1,
        max_calls_per_second: 4,
        max_deadline_ms: 1000,
    };
    let binding = OwnerAccessBinding {
        policy: PolicyRevision {
            plan_id: PlanId(format!("sha256:{}", "a".repeat(64))),
            plan_version: 1,
        },
        execution: ExecutionIdentity {
            instance_id: "fixture-instance".into(),
            plan_nonce: Nonce::from_bytes([3; 16]),
            bundle_sha256: Some("b".repeat(64)),
        },
        tenant: "tenant-a".into(),
        grant: OwnerAccessGrant {
            operations: vec![operation],
            object_v1: Some(OwnerAccessObjectProfile {
                major: 1,
                codec_mask: 1023,
                cache_reuse_within_execution: false,
            }),
        },
    };
    let request = OwnerAccessRequest {
        policy: binding.policy.clone(),
        execution: binding.execution.clone(),
        request_id: [5; 32],
        sequence: 1,
        operation: "status".into(),
        owner: "owner-a".into(),
        deadline_unix_ms: 1500,
        payload: TypedRecord::default(),
    };
    assert!(
        request.validate(&binding, 1000).is_err(),
        "ordinary request requires full declared schema"
    );
    let begin = OwnerAccessObjectBegin {
        request,
        object: [7; 32],
        payload_bytes: 17,
        field: None,
    };
    begin.validate(&binding, 1000).unwrap();
    assert_eq!(
        serde_json::from_slice::<OwnerAccessObjectBegin>(&serde_json::to_vec(&begin).unwrap())
            .unwrap(),
        begin
    );
    for mode in 0..5 {
        let mut invalid = begin.clone();
        match mode {
            0 => invalid.payload_bytes = 0,
            1 => invalid.payload_bytes = 16385,
            2 => invalid.request.owner = "foreign".into(),
            3 => invalid.request.deadline_unix_ms = 1000,
            _ => invalid.request.payload.fields.push(NamedValue {
                name: "verbose".into(),
                value: ScalarValue::Bool(true),
            }),
        };
        assert!(invalid.validate(&binding, 1000).is_err());
    }
    let frames = OwnerAccessObjectFrames {
        request_id: begin.request.request_id,
        sequence: 1,
        direction: OwnerAccessObjectDirection::Input,
        frames: vec![vec![1; 56]],
    };
    frames
        .validate_for(&begin, OwnerAccessObjectDirection::Input)
        .unwrap();
    let mut changed = frames.clone();
    changed.request_id = [9; 32];
    assert!(
        changed
            .validate_for(&begin, OwnerAccessObjectDirection::Input)
            .is_err()
    );
    assert!(
        frames
            .validate_for(&begin, OwnerAccessObjectDirection::Reply)
            .is_err()
    );
    let mut oversized = frames;
    oversized.frames = vec![vec![1; 65537]];
    assert!(
        oversized
            .validate_for(&begin, OwnerAccessObjectDirection::Input)
            .is_err()
    );
}

#[test]
fn object_field_mapping_roundtrips_raw_bytes_and_never_trusts_a_placeholder() {
    use mvm_contract::{
        grants::owner_access::{
            ExecutionIdentity, OwnerAccessBinding, OwnerAccessObjectProfile, PolicyRevision,
        },
        plan::{Nonce, PlanId},
        protocol::owner_access::{
            OwnerAccessObjectBegin, OwnerAccessRequest, split_object_payload,
        },
    };
    let operation = OperationGrant {
        name: "state".into(),
        owners: vec!["owner-a".into()],
        request: vec![FieldSchema {
            name: "checkpoint".into(),
            schema: ScalarSchema::Bytes { max_bytes: 4096 },
        }],
        reply: vec![],
        max_request_bytes: 16384,
        max_reply_bytes: 1024,
        max_in_flight: 1,
        max_calls_per_second: 4,
        max_deadline_ms: 1000,
    };
    let binding = OwnerAccessBinding {
        policy: PolicyRevision {
            plan_id: PlanId(format!("sha256:{}", "a".repeat(64))),
            plan_version: 1,
        },
        execution: ExecutionIdentity {
            instance_id: "fixture-instance".into(),
            plan_nonce: Nonce::from_bytes([3; 16]),
            bundle_sha256: Some("b".repeat(64)),
        },
        tenant: "tenant-a".into(),
        grant: OwnerAccessGrant {
            operations: vec![operation],
            object_v1: Some(OwnerAccessObjectProfile {
                major: 1,
                codec_mask: 1023,
                cache_reuse_within_execution: false,
            }),
        },
    };
    let bytes = (0..=255).collect::<Vec<u8>>();
    let record = TypedRecord {
        fields: vec![NamedValue {
            name: "checkpoint".into(),
            value: ScalarValue::Bytes(bytes.clone()),
        }],
    };
    let (metadata, field, body) = split_object_payload(record.clone()).unwrap();
    assert_eq!(body, bytes);
    assert_eq!(field.as_deref(), Some("checkpoint"));
    let begin = OwnerAccessObjectBegin {
        request: OwnerAccessRequest {
            policy: binding.policy.clone(),
            execution: binding.execution.clone(),
            request_id: [5; 32],
            sequence: 1,
            operation: "state".into(),
            owner: "owner-a".into(),
            deadline_unix_ms: 1500,
            payload: metadata,
        },
        object: [7; 32],
        payload_bytes: body.len() as u32,
        field,
    };
    begin.validate(&binding, 1000).unwrap();
    assert_eq!(
        begin.reconstruct(&body, &binding, 1000).unwrap().payload,
        record
    );
    assert!(begin.reconstruct(&body[..255], &binding, 1000).is_err());
    let mut invalid = begin.clone();
    invalid.field = Some("unknown".into());
    assert!(invalid.validate(&binding, 1000).is_err());
    let mut invalid = begin.clone();
    invalid.request.payload.fields[0].value = ScalarValue::Bytes(vec![1]);
    assert!(invalid.validate(&binding, 1000).is_err());
    let mut invalid = begin;
    invalid.request.payload.fields[0].value = ScalarValue::Text(String::new());
    assert!(invalid.validate(&binding, 1000).is_err());
}

#[test]
fn optional_object_profile_is_explicit_signed_and_subtractive() {
    use mvm_contract::grants::{
        Grants, owner_access::OwnerAccessObjectProfile, subset::grants_are_subset,
    };
    use mvm_contract::protocol::control::GuestCapability;
    let operation = OperationGrant {
        name: "status".into(),
        owners: vec!["owner-a".into()],
        request: vec![],
        reply: vec![],
        max_request_bytes: 1024,
        max_reply_bytes: 1024,
        max_in_flight: 1,
        max_calls_per_second: 4,
        max_deadline_ms: 1000,
    };
    let legacy = OwnerAccessGrant {
        operations: vec![operation],
        object_v1: None,
    };
    assert!(
        !serde_json::to_string(&legacy)
            .unwrap()
            .contains("object_v1")
    );
    assert_eq!(
        serde_json::from_str::<OwnerAccessGrant>(&serde_json::to_string(&legacy).unwrap()).unwrap(),
        legacy
    );
    assert_eq!(
        serde_json::to_string(&GuestCapability::OwnerAccessObjectV1).unwrap(),
        "\"owner_access_object_v1\""
    );
    let mut parent = Grants {
        owner_access: Some(legacy.clone()),
        ..Default::default()
    };
    parent.owner_access.as_mut().unwrap().object_v1 = Some(OwnerAccessObjectProfile {
        major: 1,
        codec_mask: 1023,
        cache_reuse_within_execution: true,
    });
    parent.owner_access.as_ref().unwrap().validate().unwrap();
    let mut narrow = parent.clone();
    let profile = narrow
        .owner_access
        .as_mut()
        .unwrap()
        .object_v1
        .as_mut()
        .unwrap();
    profile.codec_mask = 1;
    profile.cache_reuse_within_execution = false;
    grants_are_subset(&narrow, &parent).unwrap();
    assert!(grants_are_subset(&parent, &narrow).is_err());
    let raw = Grants {
        owner_access: Some(legacy),
        ..Default::default()
    };
    assert!(grants_are_subset(&parent, &raw).is_err());
    assert!(
        grants_are_subset(&raw, &parent).is_err(),
        "a retained operation cannot silently switch its required payload mapping"
    );
    let mut invalid = parent.owner_access.unwrap();
    invalid.object_v1.as_mut().unwrap().major = 2;
    assert!(invalid.validate().is_err());
}

#[test]
fn access_restore_containment_allows_subtraction_and_refuses_each_widening() {
    use mvm_contract::grants::{Grants, subset::grants_are_subset};
    let operation = OperationGrant {
        name: "status".into(),
        owners: vec!["owner-a".into(), "owner-b".into()],
        request: vec![],
        reply: vec![],
        max_request_bytes: 1024,
        max_reply_bytes: 1024,
        max_in_flight: 2,
        max_calls_per_second: 4,
        max_deadline_ms: 1000,
    };
    let parent = Grants {
        owner_access: Some(OwnerAccessGrant {
            object_v1: None,
            operations: vec![operation.clone()],
        }),
        ..Default::default()
    };
    let mut narrow = parent.clone();
    let op = &mut narrow.owner_access.as_mut().unwrap().operations[0];
    op.owners.pop();
    op.max_in_flight = 1;
    op.max_calls_per_second = 2;
    op.max_request_bytes = 512;
    op.max_reply_bytes = 512;
    op.max_deadline_ms = 500;
    grants_are_subset(&narrow, &parent).unwrap();
    grants_are_subset(&Grants::default(), &parent).unwrap();
    assert!(
        grants_are_subset(&parent, &Grants::default()).is_err(),
        "no inherited grant means no owner operation"
    );
    for mode in 0..8 {
        let mut wider = parent.clone();
        let op = &mut wider.owner_access.as_mut().unwrap().operations[0];
        match mode {
            0 => op.owners.push("foreign-owner".into()),
            1 => op.name = "extra-operation".into(),
            2 => op.request.push(FieldSchema {
                name: "flag".into(),
                schema: ScalarSchema::Bool,
            }),
            3 => op.max_request_bytes += 1,
            4 => op.max_reply_bytes += 1,
            5 => op.max_calls_per_second += 1,
            6 => op.max_deadline_ms += 1,
            _ => op.max_in_flight += 1,
        }
        assert!(
            grants_are_subset(&wider, &parent).is_err(),
            "widening mode {mode} accepted"
        );
    }
}

#[test]
fn optional_owner_binding_preserves_old_bytes_and_authenticates_full_identity() {
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use mvm_contract::{
        grants::owner_access::{ExecutionIdentity, OwnerAccessBinding, PolicyRevision},
        plan::{Nonce, PlanId, VerbGrant},
    };
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let nonce = Nonce::from_bytes([3; 16]);
    let key = SigningKey::from_bytes(&[19; 32]);
    let mut grant = VerbGrant {
        session_id: "fixture-instance".into(),
        plan_nonce: nonce.clone(),
        not_after: now + chrono::Duration::seconds(30),
        verbs: Vec::new(),
        drive: None,
        tool_mediation: None,
        application_terminal: None,
        owner_access: None,
        sig: Vec::new(),
    };
    let old = format!(
        "{{\"session_id\":\"fixture-instance\",\"plan_nonce\":\"{}\",\"not_after\":\"{}\",\"verbs\":[]}}",
        nonce.as_hex(),
        grant.not_after.to_rfc3339()
    );
    assert_eq!(grant.signing_bytes(), old.as_bytes());
    let operation = OperationGrant {
        name: "status".into(),
        owners: vec!["local-owner".into()],
        request: Vec::new(),
        reply: Vec::new(),
        max_request_bytes: 1024,
        max_reply_bytes: 1024,
        max_in_flight: 1,
        max_calls_per_second: 4,
        max_deadline_ms: 1000,
    };
    grant.owner_access = Some(OwnerAccessBinding {
        policy: PolicyRevision {
            plan_id: PlanId(format!("sha256:{}", "a".repeat(64))),
            plan_version: 1,
        },
        execution: ExecutionIdentity {
            instance_id: grant.session_id.clone(),
            plan_nonce: nonce.clone(),
            bundle_sha256: Some("b".repeat(64)),
        },
        tenant: "tenant-a".into(),
        grant: OwnerAccessGrant {
            object_v1: None,
            operations: vec![operation],
        },
    });
    grant.sig = key.sign(&grant.signing_bytes()).to_bytes().to_vec();
    grant
        .verify(&key.verifying_key(), "fixture-instance", &nonce, now)
        .unwrap();
    let mut object_changed = grant.clone();
    object_changed
        .owner_access
        .as_mut()
        .unwrap()
        .grant
        .object_v1 = Some(
        mvm_contract::grants::owner_access::OwnerAccessObjectProfile {
            major: 1,
            codec_mask: 1023,
            cache_reuse_within_execution: false,
        },
    );
    assert!(
        object_changed
            .verify(&key.verifying_key(), "fixture-instance", &nonce, now)
            .is_err(),
        "payload mapping is inside the existing signature"
    );
    object_changed.sig = key
        .sign(&object_changed.signing_bytes())
        .to_bytes()
        .to_vec();
    object_changed
        .verify(&key.verifying_key(), "fixture-instance", &nonce, now)
        .unwrap();
    object_changed
        .owner_access
        .as_mut()
        .unwrap()
        .grant
        .object_v1
        .as_mut()
        .unwrap()
        .cache_reuse_within_execution = true;
    assert!(
        object_changed
            .verify(&key.verifying_key(), "fixture-instance", &nonce, now)
            .is_err()
    );
    assert!(grant.permits("deliver-declared-operation"));
    let mut tampered = grant.clone();
    tampered.owner_access.as_mut().unwrap().policy.plan_version = 2;
    assert!(
        tampered
            .verify(&key.verifying_key(), "fixture-instance", &nonce, now)
            .is_err()
    );
    assert!(
        serde_json::to_string(&grant)
            .unwrap()
            .contains("owner_access")
    );
}

#[test]
fn declared_typed_record_rejects_unknown_duplicate_or_interpreter_selectors() {
    let operation = OperationGrant {
        name: "status".into(),
        owners: vec!["local-owner".into()],
        request: vec![FieldSchema {
            name: "verbose".into(),
            schema: ScalarSchema::Bool,
        }],
        reply: vec![FieldSchema {
            name: "ready".into(),
            schema: ScalarSchema::Bool,
        }],
        max_request_bytes: 1024,
        max_reply_bytes: 1024,
        max_in_flight: 1,
        max_calls_per_second: 4,
        max_deadline_ms: 1000,
    };
    let grant = OwnerAccessGrant {
        object_v1: None,
        operations: vec![operation.clone()],
    };
    grant.validate().unwrap();
    let record = TypedRecord {
        fields: vec![NamedValue {
            name: "verbose".into(),
            value: ScalarValue::Bool(true),
        }],
    };
    operation.validate_request(&record).unwrap();
    let mut duplicate = record.clone();
    duplicate.fields.push(duplicate.fields[0].clone());
    assert!(operation.validate_request(&duplicate).is_err());
    for name in ["command", "argv", "path", "env", "pty"] {
        let ungranted = TypedRecord {
            fields: vec![NamedValue {
                name: name.into(),
                value: ScalarValue::Text("untrusted input".into()),
            }],
        };
        assert!(operation.validate_request(&ungranted).is_err());
    }
    let mut too_long = operation.clone();
    too_long.request[0].schema = ScalarSchema::Text { max_bytes: 257 };
    assert!(too_long.validate().is_err());
    let mut duplicate_operation = grant.clone();
    duplicate_operation.operations.push(operation);
    assert!(duplicate_operation.validate().is_err());
    assert!(serde_json::from_str::<TypedRecord>(r#"{"fields":[],"argv":["/bin/sh"]}"#).is_err());
}
