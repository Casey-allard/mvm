#![cfg(unix)]
use mvm_core::{
    host_lifetime::{
        CoreCurrentParentPermit, EndpointPartitionGuard, EndpointPartitionLimits,
        EndpointPartitionProjection, EndpointStoreLocator, HostLaunchBinding,
        PreparedEndpointPartition,
    },
    vm_backend::BackendKind,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn projection() -> EndpointPartitionProjection {
    EndpointPartitionProjection {
        version: 1,
        binding: HostLaunchBinding {
            installation: [1; 32],
            profile: [2; 32],
            generation: 1,
            grant_serial: 3,
            vm_name: "partition-unit".into(),
            backend: BackendKind::Firecracker,
            cpus: 1,
            memory_mib: 1024,
        },
        admitted_plan_id: "sha256:component-projection-not-admission".into(),
        session: [7; 32],
        partition_serial: 4,
        profile: 2,
        store: Some(EndpointStoreLocator {
            version: 1,
            path: "/nonexistent-partition-fixture/store".into(),
            device: 1,
            inode: 1,
            reservation_serial: 1,
            tenant: [0; 32],
            session: [7; 32],
        }),
        limits: EndpointPartitionLimits {
            host_plaintext_bytes: 1,
            host_codec_bytes: 2,
            host_carrier_bytes: 3,
            host_metadata_bytes: 4,
            host_stack_bytes: 5,
            cache_disk_bytes: 6,
            staging_disk_bytes: 7,
            workers: 2,
            max_streams: 3,
        },
    }
}
struct Guard {
    expected: EndpointPartitionProjection,
    open: AtomicBool,
    drops: Arc<AtomicUsize>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl EndpointPartitionGuard for Guard {
    fn check_current(&self, projection: &EndpointPartitionProjection) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.open.load(Ordering::Acquire) && projection == &self.expected,
            "stale/foreign fixture partition"
        );
        Ok(())
    }
}

#[test]
fn typed_partition_keeps_exact_guard_and_rechecks_without_becoming_a_quota_dto() {
    let wanted = projection();
    let drops = Arc::new(AtomicUsize::new(0));
    let guard = Arc::new(Guard {
        expected: wanted.clone(),
        open: AtomicBool::new(true),
        drops: drops.clone(),
    });
    let prepared = PreparedEndpointPartition::new(wanted.clone(), guard.clone()).unwrap();
    let exact: Arc<dyn EndpointPartitionGuard> = guard.clone();
    let foreign: Arc<dyn EndpointPartitionGuard> = Arc::new(Guard {
        expected: wanted.clone(),
        open: AtomicBool::new(true),
        drops: Arc::new(AtomicUsize::new(0)),
    });
    assert!(prepared.retains_guard(&exact));
    assert!(!prepared.retains_guard(&foreign));
    assert_eq!(prepared.projection(), &wanted);
    assert_eq!(wanted.limits.host_resident_bytes().unwrap(), 15);
    let mut changed = wanted;
    changed.partition_serial += 1;
    assert!(PreparedEndpointPartition::new(changed, guard.clone()).is_err());
    guard.open.store(false, Ordering::Release);
    assert!(prepared.check_current().is_err());
    assert!(
        prepared.retains_guard(&exact),
        "cleanup identity survives close"
    );
    drop(exact);
    drop(guard);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(prepared);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    // A fixture guard proves plumbing only, not an aggregate reservation.
}

#[test]
fn no_partition_default_and_checked_overflow_cannot_create_a_child_pool() {
    struct Parent;
    impl CoreCurrentParentPermit for Parent {
        fn check_current(&self, _: &HostLaunchBinding) -> anyhow::Result<()> {
            Ok(())
        }
    }
    let mut data = projection();
    assert!(Parent.prepare_endpoint_partition(&data.binding).is_err());
    data.limits.host_stack_bytes = u64::MAX;
    assert!(data.limits.host_resident_bytes().is_err());
}

#[test]
fn endpoint_handoff_is_one_opaque_owner_not_a_mixable_holder_tuple() {
    use mvm_core::{
        host_lifetime::{HostLifetimeAnchor, PreparedEndpointHandoff},
        vm_backend::VmStartConfig,
    };
    let _: fn(
        &Arc<HostLifetimeAnchor>,
        &VmStartConfig,
        BackendKind,
    ) -> anyhow::Result<PreparedEndpointHandoff> = HostLifetimeAnchor::prepare_endpoint_handoff;
}
