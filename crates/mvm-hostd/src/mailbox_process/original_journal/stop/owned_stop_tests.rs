//! Binding refusal controls; no native workload or helper is started.
use super::*;
use mvm_core::host_lifetime::{
    HostLaunchBinding, HostLeaseExpectation, HostLifetimeInputs, PreparedHostLifetime,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::PermissionsExt,
};

fn anchor(
    root: &std::path::Path,
    backend: BackendKind,
) -> Arc<mvm_core::host_lifetime::HostLifetimeAnchor> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("state"), b"live").unwrap();
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("holder"))
        .unwrap();
    PreparedHostLifetime::bind(
        HostLifetimeInputs {
            directory: File::open(root).unwrap(),
            holder,
            expected: HostLeaseExpectation {
                state_name: "state".into(),
                state_bytes: 4,
                state_sha256: Sha256::digest(b"live").into(),
                absent_names: ["next".into(), "intent".into()],
            },
            binding: HostLaunchBinding {
                installation: [1; 32],
                profile: [2; 32],
                generation: 1,
                grant_serial: 1,
                vm_name: "original-journal".into(),
                backend,
                cpus: 1,
                memory_mib: 128,
            },
        },
        (),
    )
    .unwrap()
    .into_anchor()
}

#[test]
fn owned_stop_refuses_a_foreign_name_before_any_stop() {
    let root = tempfile::tempdir().unwrap();
    let backend = AnyBackend::from_hypervisor("firecracker");
    let anchor = anchor(root.path(), BackendKind::Firecracker);
    let owner = InstalledStopOwner {
        backend: &backend,
        anchor: &anchor,
    };
    let refused = owner.check_name("replacement-journal").unwrap_err();
    assert!(refused.to_string().contains("stop binding differs"));
    anchor.verify_current().unwrap();
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"live");
}

#[test]
fn owned_stop_refuses_a_different_backend_before_any_stop() {
    let root = tempfile::tempdir().unwrap();
    let backend = AnyBackend::from_hypervisor("qemu");
    let anchor = anchor(root.path(), BackendKind::Firecracker);
    let owner = InstalledStopOwner {
        backend: &backend,
        anchor: &anchor,
    };
    let refused = owner.check_name("original-journal").unwrap_err();
    assert!(refused.to_string().contains("stop binding differs"));
    anchor.verify_current().unwrap();
}

#[test]
fn owned_stop_refuses_an_unsupported_matching_backend_before_any_stop() {
    let root = tempfile::tempdir().unwrap();
    let backend = AnyBackend::from_hypervisor("qemu");
    let anchor = anchor(root.path(), BackendKind::Qemu);
    let owner = InstalledStopOwner {
        backend: &backend,
        anchor: &anchor,
    };
    let refused = owner.check_name("original-journal").unwrap_err();
    assert!(refused.to_string().contains("stop backend unavailable"));
    anchor.verify_current().unwrap();
}

#[test]
fn owned_stop_selects_only_the_supported_original_binding() {
    let root = tempfile::tempdir().unwrap();
    let backend = AnyBackend::from_hypervisor("firecracker");
    let anchor = anchor(root.path(), BackendKind::Firecracker);
    let owner = InstalledStopOwner {
        backend: &backend,
        anchor: &anchor,
    };
    let selected = owner.check_name("original-journal");
    assert_eq!(selected.is_ok(), cfg!(target_os = "linux"));
    anchor.verify_current().unwrap();
}
