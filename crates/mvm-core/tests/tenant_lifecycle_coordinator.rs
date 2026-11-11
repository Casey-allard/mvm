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
