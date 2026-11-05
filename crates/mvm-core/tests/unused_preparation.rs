//! Preparation identity only; these fixtures do not establish native exit or
//! canonical resource admission.
#![cfg(unix)]

use mvm_core::{host_lifetime::*, vm_backend::BackendKind};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

fn inputs() -> (tempfile::TempDir, HostLifetimeInputs) {
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let bytes = b"prepared";
    let state = root.path().join("state");
    fs::write(&state, bytes).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    let holder_path = root.path().join("holders.lock");
    fs::write(&holder_path, b"").unwrap();
    fs::set_permissions(&holder_path, fs::Permissions::from_mode(0o600)).unwrap();
    let inputs = HostLifetimeInputs {
        directory: fs::File::open(root.path()).unwrap(),
        holder: fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(holder_path)
            .unwrap(),
        expected: HostLeaseExpectation {
            state_name: "state".into(),
            state_bytes: bytes.len().try_into().unwrap(),
            state_sha256: Sha256::digest(bytes).into(),
            absent_names: [".state.next".into(), ".state.intent".into()],
        },
        binding: HostLaunchBinding {
            installation: [1; 32],
            profile: [2; 32],
            generation: 1,
            grant_serial: 1,
            vm_name: "unused-preparation".into(),
            backend: BackendKind::Firecracker,
            cpus: 1,
            memory_mib: 128,
        },
    };
    (root, inputs)
}

#[test]
fn original_arc_identity_is_not_equal_metadata_or_another_erased_type() {
    let (_root, inputs) = inputs();
    let expected = inputs.binding.clone();
    let original = Arc::new(String::from("same metadata"));
    let foreign = Arc::new(String::from("same metadata"));
    let prepared = PreparedHostLifetime::bind(inputs, original.clone()).unwrap();
    assert_eq!(prepared.binding(), &expected);
    assert_eq!(*original, *foreign);
    assert!(prepared.retains_parent_owner(&original));
    assert!(!prepared.retains_parent_owner(&foreign));
    assert!(!prepared.retains_parent_owner(&Arc::new(1_u64)));
    assert_eq!(Arc::strong_count(&original), 2);
    drop(prepared);
    assert_eq!(Arc::strong_count(&original), 1);
}

#[test]
fn plain_erased_metadata_cannot_supply_the_original_arc() {
    let (_root, inputs) = inputs();
    let original = Arc::new(String::from("same metadata"));
    let prepared = PreparedHostLifetime::bind(inputs, original.as_ref().clone()).unwrap();
    assert!(!prepared.retains_parent_owner(&original));
}

#[test]
fn conversion_keeps_the_same_original_owner_until_last_anchor_drop() {
    let (_root, inputs) = inputs();
    let original = Arc::new(String::from("original held owner"));
    let weak = Arc::downgrade(&original);
    let prepared = PreparedHostLifetime::bind(inputs, original.clone()).unwrap();
    assert!(prepared.retains_parent_owner(&original));
    let anchor = prepared.into_anchor();
    assert_eq!(Arc::strong_count(&original), 2);
    drop(original);
    assert!(weak.upgrade().is_some());
    drop(anchor);
    assert!(weak.upgrade().is_none());
}
