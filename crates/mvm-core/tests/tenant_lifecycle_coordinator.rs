#![cfg(unix)]

use std::path::Path;
use std::time::{Duration, Instant};

use mvm_core::private_fs::create_owned_private_dir;
use mvm_core::tenant_lifecycle::{
    LifecycleCoordinator, LifecycleGeneration, LifecyclePhase, TenantLifecycleGate,
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

fn bootstrap(home: &Path, generation: &LifecycleGeneration) -> LifecycleCoordinator {
    create_owned_private_dir(home).expect("private home");
    // Storage fixtures satisfy only local coordination preconditions. Production
    // callers must retain actual resource exclusion, readiness and original owners.
    LifecycleCoordinator::prepare_after_exclusion(
        home,
        "tenant-a",
        generation.clone(),
        256,
        deadline(),
    )
    .expect("prepare fenced generation")
}

fn activate(coordinator: &LifecycleCoordinator, generation: &LifecycleGeneration) {
    coordinator
        .activate_after_reconciliation(generation, deadline())
        .expect("activate reconciled generation");
}

#[test]
fn activation_callbacks_keep_original_file_turn_and_publish_only_durable_active() {
    use mvm_core::util::atomic_io::FileLock;
    use std::cell::Cell;
    let home = tempfile::tempdir().unwrap();
    let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
    let coordinator = bootstrap(home.path(), &generation);
    let lock_path =
        mvm_core::config::host_agent_dir_at(home.path(), "tenant-a").join("lifecycle.lock");
    let prechecked = Cell::new(false);
    let published = Cell::new(false);
    coordinator
        .activate_after_reconciliation_with(
            &generation,
            deadline(),
            |snapshot| {
                assert_eq!(snapshot.phase(), LifecyclePhase::Preparing);
                // Test-only kernel probe: both callbacks must observe the SAME retained
                // file turn. Production callbacks perform only nonblocking memory checks.
                assert!(FileLock::try_acquire(&lock_path)?.is_none());
                prechecked.set(true);
                Ok(())
            },
            |snapshot| {
                assert!(prechecked.get());
                assert_eq!(snapshot.phase(), LifecyclePhase::Active);
                assert!(FileLock::try_acquire(&lock_path)?.is_none());
                published.set(true);
                Ok(())
            },
        )
        .unwrap();
    assert!(published.get());
    assert_eq!(
        coordinator.snapshot(deadline()).unwrap().phase(),
        LifecyclePhase::Active
    );
}

#[test]
fn activation_precheck_refusal_preserves_preparing_bytes_and_never_publishes() {
    let home = tempfile::tempdir().unwrap();
    let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
    let coordinator = bootstrap(home.path(), &generation);
    let state = mvm_core::config::host_agent_dir_at(home.path(), "tenant-a").join("lifecycle.json");
    let original = std::fs::read(&state).unwrap();
    let result = coordinator.activate_after_reconciliation_with(
        &generation,
        deadline(),
        |_| anyhow::bail!("original owner check refused"),
        |_| panic!("publication after refused precheck"),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&state).unwrap(), original);
}

#[test]
fn activation_callbacks_refuse_stale_generation_and_expired_admission_before_any_callback() {
    let home = tempfile::tempdir().unwrap();
    let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
    let coordinator = bootstrap(home.path(), &generation);
    let stale = LifecycleGeneration::new([8; 32], 2).unwrap();
    let path = mvm_core::config::host_agent_dir_at(home.path(), "tenant-a").join("lifecycle.json");
    let original = std::fs::read(&path).unwrap();
    for (expected, expires) in [(&stale, deadline()), (&generation, Instant::now())] {
        assert!(
            coordinator
                .activate_after_reconciliation_with(
                    expected,
                    expires,
                    |_| panic!("precheck ran for stale or expired activation"),
                    |_| panic!("publication ran for stale or expired activation")
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[test]
fn failed_or_panicking_partial_publication_fences_same_generation_without_claiming_rollback() {
    use std::cell::Cell;
    for panic in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
        let coordinator = bootstrap(home.path(), &generation);
        let released = Cell::new(false);
        let result = coordinator.activate_after_reconciliation_with(
            &generation,
            deadline(),
            |_| Ok(()),
            |_| {
                released.set(true); // One fixture latch has already been released.
                if panic {
                    panic!("controlled partial publication panic");
                }
                anyhow::bail!("controlled partial publication refusal")
            },
        );
        assert!(released.get());
        assert!(result.is_err());
        let observed = coordinator.snapshot(deadline()).unwrap();
        assert_eq!(observed.generation(), &generation);
        assert_eq!(observed.phase(), LifecyclePhase::Draining);
        assert!(observed.unresolved());
        assert!(
            TenantLifecycleGate::new(home.path(), "tenant-a")
                .unwrap()
                .reserve_launch("vm-after-partial", "plan-a", deadline())
                .is_err()
        );
    }
}

#[test]
fn open_existing_refuses_absence_and_missing_state_without_initializing_anything() {
    let parent = tempfile::tempdir().expect("parent");
    let missing = parent.path().join("absent-home");
    assert!(LifecycleCoordinator::open_existing(&missing, "tenant-a", deadline()).is_err());
    assert!(!missing.exists());

    let home = parent.path().join("private-home");
    let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
    let coordinator = bootstrap(&home, &generation);
    drop(coordinator);
    let directory = mvm_core::config::host_agent_dir_at(&home, "tenant-a");
    let state = directory.join("lifecycle.json");
    // Locate the canonical state filename explicitly: no synthesized replacement
    // is permitted when its original lock already exists.
    assert!(state.is_file());
    let original_lock = std::fs::read(directory.join("lifecycle.lock")).unwrap();
    std::fs::remove_file(&state).unwrap();
    assert!(LifecycleCoordinator::open_existing(&home, "tenant-a", deadline()).is_err());
    assert!(!state.exists());
    assert_eq!(
        std::fs::read(directory.join("lifecycle.lock")).unwrap(),
        original_lock
    );
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(&state, b"{").unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(LifecycleCoordinator::open_existing(&home, "tenant-a", deadline()).is_err());
    assert_eq!(std::fs::read(&state).unwrap(), b"{");
}

#[test]
fn open_existing_preserves_active_original_generation_revision_and_pending_until_explicit_drain() {
    let home = tempfile::tempdir().unwrap();
    let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
    let coordinator = bootstrap(home.path(), &generation);
    activate(&coordinator, &generation);
    let gate = TenantLifecycleGate::new(home.path(), "tenant-a").unwrap();
    let reservation = gate.reserve_launch("vm-a", "plan-a", deadline()).unwrap();
    let before = coordinator.snapshot(deadline()).unwrap();
    let directory = mvm_core::config::host_agent_dir_at(home.path(), "tenant-a");
    let state = directory.join("lifecycle.json");
    let original = std::fs::read(&state).unwrap();
    drop(coordinator);
    let recovery =
        LifecycleCoordinator::open_existing(home.path(), "tenant-a", deadline()).unwrap();
    let reopened = recovery.snapshot(deadline()).unwrap();
    assert_eq!(std::fs::read(&state).unwrap(), original);
    assert_eq!(reopened.generation(), &generation);
    assert_eq!(reopened.revision(), before.revision());
    assert_eq!(reopened.phase(), LifecyclePhase::Active);
    assert_eq!(reopened.unresolved(), before.unresolved());
    assert_eq!(reopened.pending().len(), 1);
    assert_eq!(reopened.pending()[0].id(), reservation.id());
    assert_eq!(reopened.pending()[0].vm(), "vm-a");
    assert_eq!(reopened.pending()[0].plan_id(), "plan-a");
    recovery
        .begin_drain(&generation, reopened.revision(), deadline(), |_| Ok(()))
        .unwrap();
    assert!(gate.reserve_launch("vm-b", "plan-b", deadline()).is_err());
    assert_eq!(recovery.snapshot(deadline()).unwrap().pending().len(), 1);
}

#[test]
fn bootstrap_is_fenced_until_checked_drain_and_reconciliation() {
    let home = tempfile::tempdir().expect("home");
    let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
    let coordinator = bootstrap(home.path(), &generation);
    assert_eq!(
        coordinator.snapshot(deadline()).expect("state").phase(),
        LifecyclePhase::Preparing
    );
    let gate = TenantLifecycleGate::new(home.path(), "tenant-a").expect("same gate");
    assert!(gate.reserve_launch("vm-a", "plan-a", deadline()).is_err());
    coordinator
        .begin_drain(
            &generation,
            coordinator
                .snapshot(deadline())
                .expect("Preparing revision")
                .revision(),
            deadline(),
            |_| Ok(()),
        )
        .expect("startup error fences its prepared generation");
    coordinator
        .mark_unresolved(&generation, deadline())
        .expect("persist original expiry or join uncertainty");
    let reconciled = coordinator
        .snapshot(deadline())
        .expect("original startup state");
    assert!(reconciled.unresolved());
    assert_eq!(reconciled.phase(), LifecyclePhase::Draining);
    coordinator
        .retire_after_resource_reconciliation(
            &generation,
            reconciled.revision(),
            deadline(),
            |_| Ok(()),
        )
        .expect("checked resource reconciliation is distinct from child collection");
    let next_generation = LifecycleGeneration::new([8; 32], 2).expect("new resource epoch");
    coordinator
        .prepare_generation_after_reconciliation(&next_generation, deadline())
        .expect("prepare reconciled epoch before spawning any child");
    assert_eq!(
        coordinator
            .snapshot(deadline())
            .expect("next Preparing state")
            .phase(),
        LifecyclePhase::Preparing
    );
    coordinator
        .activate_after_reconciliation(&next_generation, deadline())
        .expect("activate reconciled original generation");
    gate.with_active(&next_generation, deadline(), || Ok(()))
        .expect("active turn");
    let _reservation = gate
        .reserve_launch("vm-a", "plan-a", deadline())
        .expect("admitted launch row");
    assert_eq!(
        coordinator
            .snapshot(deadline())
            .expect("pending state")
            .pending()
            .len(),
        1
    );
}

#[test]
fn pending_launch_cannot_vanish_when_drain_wins_or_cleanup_is_uncertain() {
    let home = tempfile::tempdir().expect("home");
    let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
    let coordinator = bootstrap(home.path(), &generation);
    activate(&coordinator, &generation);
    let gate = TenantLifecycleGate::new(home.path(), "tenant-a").expect("same gate");
    let mut reservation = gate
        .reserve_launch("vm-a", "plan-a", deadline())
        .expect("original launch");
    coordinator
        .begin_drain(
            &generation,
            coordinator
                .snapshot(deadline())
                .expect("current revision")
                .revision(),
            deadline(),
            |_| Ok(()),
        )
        .expect("explicit stop fence");
    let record = mvm_core::session::SessionRecord::new_running(
        "vm-a",
        "workload-a",
        mvm_core::session::SessionMode::Prod,
    );
    assert!(reservation.publish_running(&record, deadline()).is_err());
    assert!(
        coordinator
            .finish_drain_after_collection(&generation, deadline(), |_| Ok(()))
            .is_err()
    );
    assert!(
        coordinator
            .settle_after_original_cleanup(
                &generation,
                reservation.id(),
                deadline(),
                || anyhow::bail!("original cleanup unresolved")
            )
            .is_err()
    );
    assert_eq!(
        coordinator
            .snapshot(deadline())
            .expect("uncertain row retained")
            .pending()
            .len(),
        1
    );
    coordinator
        .settle_after_original_cleanup(&generation, reservation.id(), deadline(), || Ok(()))
        .expect("actual original cleanup result");
    coordinator
        .finish_drain_after_collection(&generation, deadline(), |_| Ok(()))
        .expect("drained after settlement");
    assert_eq!(
        coordinator
            .snapshot(deadline())
            .expect("drained state")
            .phase(),
        LifecyclePhase::Drained
    );
}

#[test]
fn preparing_a_replacement_never_resets_old_generation_or_pending_rows() {
    let home = tempfile::tempdir().expect("home");
    let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
    let coordinator = bootstrap(home.path(), &generation);
    activate(&coordinator, &generation);
    let gate = TenantLifecycleGate::new(home.path(), "tenant-a").expect("same gate");
    let _reservation = gate
        .reserve_launch("vm-a", "plan-a", deadline())
        .expect("original launch");
    let replacement_generation =
        LifecycleGeneration::new([8; 32], 2).expect("replacement generation");
    let replacement = LifecycleCoordinator::prepare_after_exclusion(
        home.path(),
        "tenant-a",
        replacement_generation.clone(),
        256,
        deadline(),
    )
    .expect("fence original state");
    let retained = replacement.snapshot(deadline()).expect("retained state");
    assert_eq!(retained.generation(), &generation);
    assert_eq!(retained.phase(), LifecyclePhase::Draining);
    assert_eq!(retained.pending().len(), 1);
    assert!(
        replacement
            .activate_after_reconciliation(&replacement_generation, deadline())
            .is_err()
    );
    assert!(
        gate.with_active(&generation, deadline(), || Ok(()))
            .is_err()
    );
}
