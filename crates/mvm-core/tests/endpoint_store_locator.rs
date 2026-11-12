#![cfg(unix)]
//! Pure projection validation: these accepting fixture guards are not disk grants.
use mvm_core::{
    host_lifetime::{
        EndpointPartitionGuard, EndpointPartitionLimits, EndpointPartitionProjection,
        EndpointStoreLocator, HostLaunchBinding, PreparedEndpointPartition,
    },
    vm_backend::BackendKind,
};
use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Guard(Arc<AtomicUsize>);
impl EndpointPartitionGuard for Guard {
    fn check_current(&self, _: &EndpointPartitionProjection) -> anyhow::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn projection() -> EndpointPartitionProjection {
    EndpointPartitionProjection {
        version: 1,
        binding: HostLaunchBinding {
            installation: [1; 32],
            profile: [2; 32],
            generation: 1,
            grant_serial: 1,
            vm_name: "locator-component".into(),
            backend: BackendKind::Firecracker,
            cpus: 1,
            memory_mib: 128,
        },
        admitted_plan_id: "fixture-not-canonical-admission".into(),
        session: [3; 32],
        partition_serial: 2,
        profile: 2,
        store: Some(EndpointStoreLocator {
            version: 1,
            path: PathBuf::from("/nonexistent-component-fixture/private-store"),
            device: 0,
            inode: 0,
            reservation_serial: 7,
            tenant: [0; 32],
            session: [3; 32],
        }),
        limits: EndpointPartitionLimits {
            host_plaintext_bytes: 1,
            host_codec_bytes: 1,
            host_carrier_bytes: 1,
            host_metadata_bytes: 1,
            host_stack_bytes: 1,
            cache_disk_bytes: 1,
            staging_disk_bytes: 1,
            workers: 1,
            max_streams: 1,
        },
    }
}

#[test]
fn store_locator_is_bounded_data_not_a_filesystem_or_tenant_authorizer() {
    let calls = Arc::new(AtomicUsize::new(0));
    let facts = projection();
    let prepared = PreparedEndpointPartition::new(facts.clone(), Arc::new(Guard(calls.clone())))
        .expect("Core validates data; only the actual original guard owns a store");
    assert_eq!(prepared.projection().store, facts.store);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // No assumption that a device/inode/tag number itself confers permission.
    // The nonexistent path above is deliberately never opened by Core.
}

#[test]
fn codec_requires_locator_but_collector_only_never_requires_object_mapping() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut facts = projection();
    facts.store = None;
    assert!(PreparedEndpointPartition::new(facts.clone(), Arc::new(Guard(calls.clone()))).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    facts.profile = 1;
    assert!(PreparedEndpointPartition::new(facts, Arc::new(Guard(calls.clone()))).is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn malformed_locator_refuses_before_guard_and_without_normalizing_original_path() {
    let base = projection();
    for index in 0..8 {
        let mut facts = base.clone();
        let store = facts.store.as_mut().unwrap();
        match index {
            0 => store.version = 0,
            1 => store.path = "relative/store".into(),
            2 => store.path = "/private/a/../store".into(),
            3 => store.path = "/private/a/./store".into(),
            4 => store.path = PathBuf::from(OsString::from_vec(b"/private/a/\0store".to_vec())),
            5 => store.path = format!("/{}", "a".repeat(4096)).into(),
            6 => store.reservation_serial = 0,
            _ => store.session = [4; 32],
        }
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            PreparedEndpointPartition::new(facts, Arc::new(Guard(calls.clone()))).is_err(),
            "locator case {index}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
