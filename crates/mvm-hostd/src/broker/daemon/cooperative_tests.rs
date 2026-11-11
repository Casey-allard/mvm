//! Direct original-daemon ownership witnesses. Include only for the dedicated
//! integration step after inner server/cell API REDs have been observed.
use super::*;
use crate::broker::control_prepare::ServiceFixture;
use crate::broker::server::tests::{HeldDispatch, held_call, held_registry};
use std::time::Duration;
use tokio::net::UnixStream;

struct HeldDaemon {
    _directory: tempfile::TempDir,
    daemon: Option<HostAgentDaemon>,
    custody: DaemonCustodyOwner,
    handler: Arc<HeldDispatch>,
    slots: Arc<tokio::sync::Semaphore>,
    _client: UnixStream,
}

async fn held_daemon() -> HeldDaemon {
    let directory = tempfile::tempdir().unwrap();
    let mut daemon = HostAgentDaemon::new(
        "local",
        ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key(),
        65_536,
    );
    let custody = daemon.custody_owner();
    let slots = daemon.connection_slots.clone();
    let handler = Arc::new(HeldDispatch::new());
    let path = directory.path().join("owned-service.sock");
    let start = custody
        .cell
        .install_fixture(
            "owned-vm",
            ServiceFixture {
                listen_socket: path.clone(),
                registry: held_registry(handler.clone()),
                workload_id: "owned-workload".into(),
                tenant_id: "local".into(),
                max_frame_bytes: 65_536,
                connection_slots: slots.clone(),
            },
        )
        .unwrap();
    let mut registration = super::tests::register(directory.path(), "owned-vm", "local", None);
    registration.broker_listen_socket = path.to_string_lossy().into_owned();
    daemon.registrations.insert("owned-vm".into(), registration);
    // Prove the public daemon lookup routes to THIS original retained map,
    // rather than testing a detached cell or a second fabricated map.
    assert!(daemon.is_registered("owned-vm").unwrap());
    start.release().unwrap();
    let mut client = UnixStream::connect(path).await.unwrap();
    write_frame(&mut client, &held_call()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), handler.entered_at_least(1))
        .await
        .unwrap();
    HeldDaemon {
        _directory: directory,
        daemon: Some(daemon),
        custody,
        handler,
        slots,
        _client: client,
    }
}

#[tokio::test]
async fn dropping_actual_daemon_retains_original_map_and_entered_service() {
    let mut fixture = held_daemon().await;
    drop(fixture.daemon.take().unwrap());
    let query = fixture.custody.cell.try_contains_vm("owned-vm");
    let pending =
        tokio::time::timeout(Duration::from_millis(20), fixture.custody.drain_services()).await;
    let completed = fixture.handler.completed_count();
    let held = fixture.slots.available_permits();
    fixture.handler.release_dispatches(1);
    tokio::time::timeout(Duration::from_secs(1), fixture.custody.drain_services())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !matches!(query, Ok(false)),
        "retained original owner is never absent"
    );
    assert!(
        pending.is_err(),
        "daemon Drop cannot manufacture a service receipt"
    );
    assert_eq!(completed, 0);
    assert_eq!(held, 255);
    assert_eq!(fixture.handler.completed_count(), 1);
    assert_eq!(fixture.slots.available_permits(), 256);
}

#[tokio::test]
async fn dropping_actual_daemon_while_map_is_loaned_keeps_same_originals() {
    let mut fixture = held_daemon().await;
    let mut loan = fixture.custody.cell.map_loan().unwrap();
    drop(fixture.daemon.take().unwrap());
    let retained = loan.value_mut().vms.contains_key("owned-vm");
    let query = fixture.custody.cell.try_contains_vm("owned-vm");
    let closed = fixture.slots.is_closed();
    drop(loan);
    fixture.handler.release_dispatches(1);
    tokio::time::timeout(Duration::from_secs(1), fixture.custody.drain_services())
        .await
        .unwrap()
        .unwrap();
    assert!(
        retained,
        "Drop never transfers or overwrites a loaned original map"
    );
    assert!(
        query.is_err(),
        "loaned original inventory is Unknown, never absent"
    );
    assert!(
        closed,
        "original daemon Drop fences shared ingress without locking the map"
    );
    assert_eq!(fixture.handler.completed_count(), 1);
}

#[tokio::test]
async fn cancelled_signed_replacement_retains_original_service_and_mutation_credit() {
    let mut fixture = held_daemon().await;
    use mvm_vmm::host::installed_owner::{InstallationKey, InstallationOwner};
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        fixture._directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let key = InstallationKey {
        installation: [61; 32],
        profile: [62; 32],
    };
    let mut installation =
        InstallationOwner::initialize(&fixture._directory.path().join("original-resources"), key)
            .unwrap();
    let epoch = installation.begin().unwrap();
    let original = fixture
        .daemon
        .take()
        .unwrap()
        .with_resource_binding(Arc::new(installation.active_binding(epoch).unwrap()));
    let lane = original.mutation_lane();
    let original_registration = original.registrations.get("owned-vm").unwrap().clone();
    let shared = Arc::new(Mutex::new(original));
    let signed = broker_control::sign(
        ControlRequest::Register(Box::new(original_registration)),
        &[5; 32],
    )
    .unwrap();
    let caller_daemon = shared.clone();
    let caller =
        tokio::spawn(
            async move { HostAgentDaemon::apply_signed_shared(caller_daemon, signed).await },
        );
    // Observe the actual old owner moved into its original mutation field;
    // the held canonical handler provides the causal retirement barrier.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let absent_live_key = fixture
                .custody
                .cell
                .map_loan()
                .map(|mut map| !map.value_mut().vms.contains_key("owned-vm"))
                .unwrap_or(false);
            if absent_live_key && !matches!(fixture.custody.cell.has_inflight_mutation(), Ok(false))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let query = shared.lock().await.is_registered("owned-vm");
    let accepted = shared.lock().await.has_accepted_work();
    let permit_count = lane.available_permits();
    let completed = fixture.handler.completed_count();
    let resource_retained = installation.finish(epoch).is_err();
    // Fixture recovery explicitly joins the SAME retained old service; it is
    // not a production recovery API or a successful replacement receipt.
    fixture.handler.release_dispatches(1);
    let mut mutation = fixture.custody.cell.mutation_loan().unwrap();
    let original = mutation.value_mut();
    tokio::time::timeout(
        Duration::from_secs(1),
        original.retiring.as_mut().unwrap().finish(),
    )
    .await
    .unwrap()
    .unwrap();
    original.retiring = None;
    fixture.custody.cell.complete_mutation(mutation).unwrap();
    shared.lock().await.registrations.remove("owned-vm");
    fixture.custody.drain_services().await.unwrap();
    installation.finish(epoch).unwrap();
    assert!(
        resource_retained,
        "cancelled caller cannot release the original resource lease"
    );
    assert!(
        query.is_err(),
        "absent live-map key cannot hide a retained original service"
    );
    assert!(
        accepted.unwrap(),
        "cancelled caller cannot settle accepted work"
    );
    assert_eq!(
        permit_count, 0,
        "original mutation credit cannot be refunded"
    );
    assert_eq!(
        completed, 0,
        "caller cancellation cannot manufacture a service join"
    );
    assert_eq!(fixture.handler.completed_count(), 1);
    assert_eq!(lane.available_permits(), 1);
    assert!(!shared.lock().await.has_accepted_work().unwrap());
}
