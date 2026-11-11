//! Original accepted-turn bookkeeping; no VM/Child receipt is fabricated.
use super::*;
use crate::broker::control_prepare::MutationCell;

#[test]
fn accepted_settlement_failure_keeps_the_same_original_token() {
    let owner = Arc::new(AcceptedWorkOwner {
        state: std::sync::Mutex::new(AcceptedWorkState {
            next: 1,
            closed: false,
            rows: HashMap::from([(1, None)]),
        }),
        unresolved: std::sync::atomic::AtomicBool::new(false),
        changed: tokio::sync::watch::channel(()).0,
    });
    let mut original = AcceptedDaemonWork {
        owner: owner.clone(),
        id: 1,
        settled: false,
    };
    let poison = owner.clone();
    assert!(
        std::thread::spawn(move || {
            let _held = poison.state.lock().unwrap();
            panic!("controlled accepted-ledger poison");
        })
        .join()
        .is_err()
    );
    assert!(original.settle().is_err());
    assert!(
        !original.is_settled(),
        "fallible settlement must retain this exact token"
    );
    let retained = match owner.state.lock() {
        Err(poisoned) => poisoned.into_inner(),
        Ok(_) => panic!("controlled poison precondition was lost"),
    };
    assert!(
        retained.rows.contains_key(&1),
        "failure cannot release original resource credit"
    );
    drop(retained);
    // No unpoison/retry/new token/collection claim. This is bookkeeping only.
    drop(original);
}

#[tokio::test]
async fn mutation_reserves_its_original_cell_before_creating_accepted_work() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let owner = Arc::new(AcceptedWorkOwner {
        state: std::sync::Mutex::new(AcceptedWorkState {
            next: 0,
            closed: false,
            rows: HashMap::new(),
        }),
        unresolved: std::sync::atomic::AtomicBool::new(false),
        changed: tokio::sync::watch::channel(()).0,
    });
    let callbacks = AtomicUsize::new(0);
    let reserve = || -> Result<AcceptedDaemonWork> {
        callbacks.fetch_add(1, Ordering::SeqCst);
        let mut state = owner.state.try_lock().unwrap();
        state.next = state.next.checked_add(1).unwrap();
        let id = state.next;
        state.rows.insert(id, None);
        Ok(AcceptedDaemonWork {
            owner: owner.clone(),
            id,
            settled: false,
        })
    };
    let slots = Arc::new(tokio::sync::Semaphore::new(256));
    let cell = MutationCell::new(slots);
    let lane = Arc::new(tokio::sync::Semaphore::new(2));
    let mut first = Some(lane.clone().acquire_owned().await.unwrap());
    let loan = cell.reserve_mutation(&mut first, reserve).unwrap();
    assert!(first.is_none());
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    let mut second = Some(lane.clone().acquire_owned().await.unwrap());
    assert!(cell.reserve_mutation(&mut second, reserve).is_err());
    assert!(
        second.is_some(),
        "loaned cell retains caller's unaccepted permit"
    );
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    drop(loan);
    assert!(cell.reserve_mutation(&mut second, reserve).is_err());
    assert!(
        second.is_some(),
        "retained cell must not consume another permit"
    );
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    assert_eq!(owner.state.try_lock().unwrap().rows.len(), 1);
    assert!(!owner.unresolved.load(Ordering::SeqCst));
    cell.complete_mutation(cell.mutation_loan().unwrap())
        .unwrap();
    assert!(owner.state.try_lock().unwrap().rows.is_empty());
    drop(second);
    assert_eq!(lane.available_permits(), 2);
}

#[tokio::test]
async fn mutation_keeps_its_original_resource_lease_until_explicit_settlement() {
    use mvm_vmm::host::installed_owner::{HolderLease, InstallationKey, InstallationOwner};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().join("owner");
    let key = InstallationKey {
        installation: [51; 32],
        profile: [52; 32],
    };
    let mut installation = InstallationOwner::initialize(&root, key).unwrap();
    let epoch = installation.begin().unwrap();
    let owner = Arc::new(AcceptedWorkOwner {
        state: std::sync::Mutex::new(AcceptedWorkState {
            next: 1,
            closed: false,
            rows: HashMap::from([(1, None)]),
        }),
        unresolved: std::sync::atomic::AtomicBool::new(false),
        changed: tokio::sync::watch::channel(()).0,
    });
    let accepted = AcceptedDaemonWork {
        owner: owner.clone(),
        id: 1,
        settled: false,
    };
    let cell = MutationCell::new(Arc::new(tokio::sync::Semaphore::new(256)));
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let mut loan = cell
        .begin_mutation(lane.clone().acquire_owned().await.unwrap(), accepted)
        .unwrap();
    loan.value_mut()
        .attach_resource(HolderLease::acquire(&root, key, epoch.generation()).unwrap())
        .unwrap();
    drop(loan);
    assert!(
        installation.finish(epoch).is_err(),
        "original accepted resource must remain held"
    );
    assert_eq!(lane.available_permits(), 0);
    assert!(
        owner
            .state
            .try_lock()
            .unwrap()
            .rows
            .get(&1)
            .unwrap()
            .is_some()
    );
    cell.complete_mutation(cell.mutation_loan().unwrap())
        .unwrap();
    installation.finish(epoch).unwrap();
    assert_eq!(lane.available_permits(), 1);
}

#[tokio::test]
async fn service_drain_refuses_a_retained_or_loaned_original_mutation() {
    use crate::broker::control_prepare::{ServiceFixture, VmMapPhase};
    use crate::broker::server::tests::{HeldDispatch, held_call, held_registry};
    use std::time::Duration;
    use tokio::net::UnixStream;
    let directory = tempfile::tempdir().unwrap();
    let slots = Arc::new(tokio::sync::Semaphore::new(256));
    let cell = MutationCell::new(slots.clone());
    let held = Arc::new(HeldDispatch::new());
    let path = directory.path().join("retained.sock");
    cell.install_fixture(
        "original",
        ServiceFixture {
            listen_socket: path.clone(),
            registry: held_registry(held.clone()),
            workload_id: "original-workload".into(),
            tenant_id: "original-tenant".into(),
            max_frame_bytes: 65_536,
            connection_slots: slots.clone(),
        },
    )
    .unwrap()
    .release()
    .unwrap();
    let mut client = UnixStream::connect(path).await.unwrap();
    write_frame(&mut client, &held_call()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), held.entered_at_least(1))
        .await
        .unwrap();
    let owner = Arc::new(AcceptedWorkOwner {
        state: std::sync::Mutex::new(AcceptedWorkState {
            next: 1,
            closed: false,
            rows: HashMap::from([(1, None)]),
        }),
        unresolved: std::sync::atomic::AtomicBool::new(false),
        changed: tokio::sync::watch::channel(()).0,
    });
    let accepted = AcceptedDaemonWork {
        owner: owner.clone(),
        id: 1,
        settled: false,
    };
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let mut original = cell
        .begin_mutation(lane.clone().acquire_owned().await.unwrap(), accepted)
        .unwrap();
    {
        let live = cell
            .map_loan()
            .unwrap()
            .value_mut()
            .vms
            .remove("original")
            .unwrap();
        original.value_mut().retiring = Some(live.retire());
    }
    drop(original);
    let retained_result = cell.drain_services().await;
    let premature_drained = cell.map_loan().unwrap().value_mut().phase == VmMapPhase::Drained;
    let mut original = cell.mutation_loan().unwrap();
    let loaned_result = cell.drain_services().await;
    let completed_before_cleanup = held.completed_count();
    let held_credit = lane.available_permits();
    // Always finish this SAME original before reporting the intended RED.
    held.release_dispatches(1);
    tokio::time::timeout(
        Duration::from_secs(1),
        original.value_mut().retiring.as_mut().unwrap().finish(),
    )
    .await
    .unwrap()
    .unwrap();
    original.value_mut().retiring = None;
    cell.complete_mutation(original).unwrap();
    cell.drain_services().await.unwrap();
    assert!(
        retained_result.is_err(),
        "an empty live map cannot hide its retained original mutation"
    );
    assert!(
        loaned_result.is_err(),
        "a borrowed original mutation is Unknown, never drained"
    );
    assert!(
        !premature_drained,
        "no Drained phase before actual original service collection"
    );
    assert_eq!(completed_before_cleanup, 0);
    assert_eq!(held_credit, 0);
    assert_eq!(held.completed_count(), 1);
    assert_eq!(lane.available_permits(), 1);
    assert!(owner.state.try_lock().unwrap().rows.is_empty());
}
