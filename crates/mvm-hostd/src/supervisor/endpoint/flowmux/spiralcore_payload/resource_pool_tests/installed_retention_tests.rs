//! Real registered-process authority and store custody; no booted VM or WAN.
use super::*;
use crate::installed_endpoint::InstalledEndpointResources;
use crate::supervisor::endpoint::flowmux::owned_relays::custody_tests::installed_resource_fixture;
use mvm_vmm::host::network_endpoint_spawn::InstalledEndpointChild;
use spiralcore_transfer::{resource_profile::ResourceProfile, v1::OwnedStorePolicy, wan};

const CHILD: &str = "supervisor::endpoint::flowmux::spiralcore_payload::resource_pool_tests::installed_retention_tests::installed_retention_child";

fn exchange(mode: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(installed_resource_fixture::resource_exchange_with(
            mode,
            &["--exact", CHILD, "--nocapture", "--test-threads=1"],
            |_, projection, _| {
                // The existing functional fixture funds one SmallV1 store.
                projection.limits.host_carrier_bytes = 1 << 20;
                Ok(())
            },
        ));
}

#[test]
fn original_installed_metadata_permits_store_cleanup_after_admission_close() {
    exchange("retention-close");
}

#[test]
fn original_installed_metadata_poison_retains_store_and_all_debits() {
    exchange("owned-attach-poison");
}

#[test]
fn installed_retention_child() {
    let Ok(mode) = std::env::var("MVM_INSTALLED_RESOURCES_FIXTURE") else {
        return;
    };
    assert!(matches!(
        mode.as_str(),
        "retention-close" | "owned-attach-poison"
    ));
    // SAFETY: the existing parent fixture reserves fd199 for protocol output.
    assert!(unsafe { libc::dup2(199, 1) } >= 0);
    let mut child = InstalledEndpointChild::from_stdio().unwrap();
    let resources = InstalledEndpointResources::from_child(&mut child).unwrap();
    let lease = resources.lease().clone();
    let pool = resources.payload_pool().unwrap().clone();
    assert!(pool.inner.retention.installed.is_some());
    assert_eq!(
        pool.inner.retention.operational_resident_limit,
        pool.inner.limits.resident_bytes
    );
    let parent = resources.checked_store_directory().unwrap();
    let path = resources
        .store_locator()
        .unwrap()
        .path
        .join(format!("flow-{}", hex::encode([9; 32])));
    let mut permit = pool
        .reserve_installed_profile(ResourceProfile::SmallV1)
        .unwrap();
    let context = wan::context([9; 32]);
    let limits = ResourceProfile::SmallV1.receiver_limits();
    let policy = OwnedStorePolicy::small_v1(
        &limits,
        permit.owned_store_visits().unwrap(),
        spiralcore_transfer::v1::OwnedLaneNamespaces::One(context.namespace().unwrap()),
        spiralcore_transfer::v1::OwnedWorkspaceFunding {
            heap_bytes: permit.owned_store_heap_bytes().unwrap(),
            existing_stack_bytes: 2 << 20,
        },
    )
    .unwrap();
    let store = permit
        .begin_installed_store(parent, format!("flow-{}", hex::encode([9; 32])))
        .unwrap();
    let owned = store.capture(policy).unwrap();
    let capabilities = Capabilities::small_v1();
    let mut endpoint = ObjectEndpoint::open_at_with_resource_profile(
        owned,
        limits,
        wan::BenchAuthority,
        capabilities.negotiate(&capabilities).unwrap(),
        ResourceProfile::SmallV1,
    )
    .unwrap();
    owner_mode_tests::seed_original_object(&mut endpoint);
    drop(endpoint);
    let contender = std::fs::File::open(path.join(".owner")).unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    let before = pool.snapshot().unwrap();
    assert_eq!(before.active, 1);
    let (slots, capacity, carrier) = {
        let ledger = pool.inner.ledger.lock().unwrap();
        (
            ledger.stores.as_ptr(),
            ledger.stores.capacity(),
            ledger.carrier_used,
        )
    };
    if mode == "owned-attach-poison" {
        let files = owner_mode_tests::snapshot_files(&path);
        pool.inner
            .retention
            .installed
            .as_ref()
            .unwrap()
            .poison_auxiliary_for_test();
        // The actual parent still admits: refusal is the retained metadata gate.
        lease.check_current().unwrap();
        assert!(pool.inner.check_store_cleanup().is_err());
        assert!(path.join(".owner").is_file());
        drop(permit);
        let ledger = pool.inner.ledger.lock().unwrap();
        assert_eq!(
            ledger.used,
            PayloadPoolSnapshot {
                quarantined: before.quarantined + 1,
                ..before
            }
        );
        assert_eq!(
            (
                ledger.stores.as_ptr(),
                ledger.stores.capacity(),
                ledger.carrier_used
            ),
            (slots, capacity, carrier)
        );
        assert_eq!(ledger.stores.len(), 1);
        assert!(path.join(".owner").is_file());
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        assert!(
            pool.inner
                .retention
                .installed
                .as_ref()
                .unwrap()
                .check_store_cleanup()
                .is_err()
        );
        drop(ledger);
        assert_eq!(owner_mode_tests::snapshot_files(&path), files);
        pool.close_admission().unwrap();
        assert!(!pool.drained().unwrap());
        // No Ready/Drained: original process exit is this fixture's only release.
        std::process::exit(0);
    }
    child
        .send_ready(Default::default(), Instant::now() + Duration::from_secs(2))
        .unwrap();
    let mut event = libc::pollfd {
        fd: child.control_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: bounded event wait on the original inherited control descriptor.
    assert!(unsafe { libc::poll(&mut event, 1, 3000) } > 0);
    assert!(lease.check_current().is_err());
    lease.check_store_cleanup().unwrap();
    pool.inner.check_store_cleanup().unwrap();
    assert_eq!(pool.snapshot().unwrap(), before);
    pool.close_admission().unwrap();
    assert!(!pool.drained().unwrap());
    drop(permit);
    assert!(!path.exists());
    assert!(contender.try_lock().is_ok());
    assert_eq!(pool.snapshot().unwrap(), PayloadPoolSnapshot::default());
    pool.close_admission().unwrap();
    assert!(pool.drained().unwrap());
    let ledger = pool.inner.ledger.lock().unwrap();
    assert_eq!(
        (
            ledger.stores.as_ptr(),
            ledger.stores.capacity(),
            ledger.carrier_used
        ),
        (slots, capacity, 0)
    );
    assert!(pool.inner.retention.installed.is_some());
    drop(ledger);
    child
        .send_drained(Instant::now() + Duration::from_secs(2))
        .unwrap();
    std::process::exit(0);
}
