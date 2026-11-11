//! Sticky coordination metadata only; no native readiness/Child receipt.
use super::*;
use mvm_core::tenant_lifecycle::{LifecycleCoordinator, LifecycleGeneration};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

#[tokio::test]
async fn original_drain_request_keeps_first_deadline_and_wakes_original_observer() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let generation = LifecycleGeneration::new([131; 32], 1).unwrap();
    let _metadata = LifecycleCoordinator::prepare_after_exclusion(
        directory.path(),
        "local",
        generation.clone(),
        256,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    let daemon = HostAgentDaemon::new(
        "local",
        ed25519_dalek::SigningKey::from_bytes(&[132; 32]).verifying_key(),
        65_536,
    )
    .with_lifecycle_coordination(directory.path(), generation.clone())
    .unwrap();
    let controller = daemon.drain_controller().unwrap();
    let mut observer = controller.subscribe();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), observer.next())
            .await
            .is_err(),
        "subscription alone is not an accepted drain request"
    );
    let first = Instant::now() + Duration::from_secs(10);
    let request = controller.request(first).unwrap();
    let observed = tokio::time::timeout(Duration::from_secs(1), observer.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.generation(), &generation);
    assert_eq!(observed.generation(), &generation);
    assert_eq!(request.deadline(), first);
    assert_eq!(observed.deadline(), first);
    let same_original = daemon.drain_controller().unwrap();
    assert_eq!(
        same_original
            .request(first + Duration::from_secs(5))
            .unwrap()
            .deadline(),
        first,
        "re-entry cannot renew the original monotonic grace"
    );
    let mut late = same_original.subscribe();
    assert_eq!(
        late.next().await.unwrap().deadline(),
        first,
        "late subscriber rechecks sticky original state instead of losing wake"
    );
}

#[test]
fn original_inline_control_turn_is_shared_without_creating_another_budget() {
    let daemon = HostAgentDaemon::new(
        "local",
        ed25519_dalek::SigningKey::from_bytes(&[133; 32]).verifying_key(),
        65_536,
    );
    let first = daemon.inline_control_turn();
    let second = daemon.inline_control_turn();
    assert!(Arc::ptr_eq(&first, &second));
    let held = first.try_lock().unwrap();
    assert!(
        second.try_lock().is_err(),
        "shutdown and original inline reply must use the SAME turn"
    );
    drop(held);
    assert!(second.try_lock().is_ok());
}
