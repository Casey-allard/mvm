//! Actual signed control and retained original custody. The held registry is
//! an explicit cfg(test) dispatch barrier, not native admission qualification.
use super::*;
use crate::broker::control_prepare::ServiceFixture;
use crate::broker::server::tests::{HeldDispatch, held_call, held_registry};
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};
use mvm_core::tenant_lifecycle::{
    LifecycleCoordinator, LifecycleGeneration, LifecyclePhase, TenantLifecycleGate,
};
use mvm_vmm::host::host_agent_installation::{create_new_home_and_provision, descriptor};
use mvm_vmm::host::installed_owner::InstallationOwner;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[tokio::test]
async fn signed_deregister_reconciles_original_then_commits_its_own_removal() {
    signed_deregister_with_journal(FixtureJournal::Original).await;
}

#[tokio::test]
async fn signed_deregister_preserves_conflicting_journal_and_charge() {
    signed_deregister_with_journal(FixtureJournal::RepeatedVm).await;
}

enum FixtureJournal {
    Original,
    RepeatedVm,
}

async fn signed_deregister_with_journal(inventory: FixtureJournal) {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("mvm-home");
    let provisioned = create_new_home_and_provision(&home, "local").unwrap();
    provisioned.verify().unwrap();
    let labels = descriptor(&home, "local").unwrap();
    let mut installation = InstallationOwner::open(&labels.root, labels.key).unwrap();
    let epoch = installation.begin().unwrap();
    let generation = LifecycleGeneration::new([91; 32], epoch.generation()).unwrap();
    let coordinator = LifecycleCoordinator::prepare_after_exclusion(
        &home,
        "local",
        generation.clone(),
        256,
        deadline(),
    )
    .unwrap();
    // Lifecycle phase construction is a metadata fixture, not signer/VM Ready.
    coordinator
        .activate_after_reconciliation(&generation, deadline())
        .unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
    let mut daemon = HostAgentDaemon::new("local", signing.verifying_key(), 65_536)
        .with_resource_binding(Arc::new(installation.active_binding(epoch).unwrap()))
        .with_lifecycle_coordination(&home, generation.clone())
        .unwrap();
    TenantLifecycleGate::new(&home, "local")
        .unwrap()
        .with_active(&generation, deadline(), || {
            daemon.open_local_admission(&generation)
        })
        .unwrap();
    let shared = Arc::new(Mutex::new(daemon));
    let custody = shared.lock().await.custody_owner();
    let lane = shared.lock().await.mutation_lane();
    let slots = shared.lock().await.connection_slots.clone();
    let mut original_records = Vec::new();
    for id in ["recover-a", "recover-b"] {
        let mut record = super::tests::register(&home, id, "local", None);
        record.services_bindings = vec![ServiceId::parse("host.time.v1").unwrap()];
        let signed = broker_control::sign(
            ControlRequest::Register(Box::new(record.clone())),
            &signing.to_bytes(),
        )
        .unwrap();
        HostAgentDaemon::apply_signed_shared(shared.clone(), signed)
            .await
            .unwrap();
        let mut client = UnixStream::connect(&record.broker_listen_socket)
            .await
            .unwrap();
        write_frame(
            &mut client,
            &ServiceCall {
                service: ServiceId::parse("host.time.v1").unwrap(),
                verb: "now".into(),
                correlation_id: CorrelationId::new(id),
                payload: serde_json::json!({}),
                capability: None,
            },
        )
        .await
        .unwrap();
        let reply: ServiceResponse =
            tokio::time::timeout(Duration::from_secs(1), read_frame(&mut client, 65_536))
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(reply, ServiceResponse::Ok { .. }));
        original_records.push(record);
    }
    let journal_path =
        mvm_core::config::host_agent_dir_at(&home, "local").join("registrations.json");
    {
        // Checkpoint the complete actually served NONEMPTY original set using
        // the canonical writer, never a fixture [] seed or freshness claim.
        let mut daemon = shared.lock().await;
        let journal = RegistrationJournal::new(&journal_path);
        journal.store(daemon.registrations.values()).unwrap();
        daemon.registration_journal = Some(journal);
    }
    assert_eq!(
        RegistrationJournal::new(&journal_path).load().unwrap(),
        original_records
    );
    // Join the initial original owner before installing the existing controlled
    // barrier at that SAME path/map. No production registry or policy override.
    {
        let mut map = custody.cell.map_loan().unwrap();
        let owners = &mut map.value_mut().vms;
        owners
            .get_mut("recover-a")
            .unwrap()
            .finish_retirement()
            .await
            .unwrap();
        owners.remove("recover-a");
    }
    let held = Arc::new(HeldDispatch::new());
    custody
        .cell
        .install_fixture(
            "recover-a",
            ServiceFixture {
                listen_socket: PathBuf::from(&original_records[0].broker_listen_socket),
                registry: held_registry(held.clone()),
                workload_id: "recovery-controlled-original".into(),
                tenant_id: "local".into(),
                max_frame_bytes: 65_536,
                connection_slots: slots.clone(),
            },
        )
        .unwrap()
        .release()
        .unwrap();
    let mut held_client = UnixStream::connect(&original_records[0].broker_listen_socket)
        .await
        .unwrap();
    write_frame(&mut held_client, &held_call()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), held.entered_at_least(1))
        .await
        .unwrap();
    let mut retirement_stop = custody
        .cell
        .map_loan()
        .unwrap()
        .value_mut()
        .vms
        .get("recover-a")
        .unwrap()
        .stop_observer();
    let replacement = broker_control::sign(
        ControlRequest::Register(Box::new(original_records[0].clone())),
        &signing.to_bytes(),
    )
    .unwrap();
    let caller_daemon = shared.clone();
    let caller = tokio::spawn(async move {
        HostAgentDaemon::apply_signed_shared(caller_daemon, replacement).await
    });
    let stopped = tokio::time::timeout(Duration::from_secs(1), retirement_stop.changed()).await;
    caller.abort();
    let caller_result = caller.await;
    let cancelled = matches!(&caller_result, Err(error) if error.is_cancelled());
    let retired = custody
        .cell
        .map_loan()
        .map(|mut map| !map.value_mut().vms.contains_key("recover-a"))
        .unwrap_or(false);
    let retained = !matches!(custody.cell.has_inflight_mutation(), Ok(false));
    if !matches!(stopped, Ok(Ok(()))) || !cancelled || !retired || !retained {
        held.release_dispatches(1);
        cleanup_owned_fixture(
            &shared,
            &custody,
            &coordinator,
            &generation,
            &mut installation,
            epoch,
        )
        .await;
        panic!(
            "retirement setup failed after original cleanup: stop={stopped:?}, cancelled={cancelled}, retired={retired}, retained={retained}, caller={caller_result:?}"
        );
    }
    let (original_row, original_sequence) = {
        let daemon = shared.lock().await;
        let state = daemon.work.state.try_lock().unwrap();
        assert_eq!(state.rows.len(), 1);
        let (&row, lease) = state.rows.iter().next().unwrap();
        assert!(lease.is_some());
        (row, state.next)
    };
    assert_eq!(lane.available_permits(), 0);
    assert_eq!(held.completed_count(), 0);
    assert!(installation.finish(epoch).is_err());
    assert!(shared.lock().await.is_registered("recover-a").is_err());
    // Simulate a storage inconsistency after the operation captured its real,
    // complete checkpoint. The encoded records are valid in isolation.
    let journal_at_retry = match inventory {
        FixtureJournal::Original => original_records.clone(),
        FixtureJournal::RepeatedVm => {
            let records = vec![original_records[0].clone(), original_records[0].clone()];
            RegistrationJournal::new(&journal_path)
                .store(records.iter())
                .unwrap();
            records
        }
    };
    let file_at_retry = std::fs::read(&journal_path).unwrap();
    let current = broker_control::sign(
        ControlRequest::Deregister(broker_control::DeregisterVm {
            vm_id: "recover-a".into(),
        }),
        &signing.to_bytes(),
    )
    .unwrap();
    let current_daemon = shared.clone();
    let mut current_caller =
        tokio::spawn(
            async move { HostAgentDaemon::apply_signed_shared(current_daemon, current).await },
        );
    let early = tokio::time::timeout(Duration::from_millis(20), &mut current_caller).await;
    let returned_before_original_join = early.is_ok();
    let charged_during_wait = lane.available_permits() == 0;
    let original_still_retained = {
        let daemon = shared.lock().await;
        let state = daemon.work.state.try_lock().unwrap();
        state.rows.contains_key(&original_row) && state.next == original_sequence
    };
    let journal_before_release = RegistrationJournal::new(&journal_path).load().unwrap();
    // Always release and collect the SAME fixture before asserting intended RED.
    held.release_dispatches(1);
    let current_result = match early {
        Ok(result) => result.unwrap(),
        Err(_) => tokio::time::timeout(Duration::from_secs(2), current_caller)
            .await
            .unwrap()
            .unwrap(),
    };
    let current_error = current_result.as_ref().err().map(ToString::to_string);
    let committed_records = RegistrationJournal::new(&journal_path).load().unwrap();
    let file_after_attempt = std::fs::read(&journal_path).unwrap();
    let charged_after_attempt = lane.available_permits() == 0;
    let phase_before_fixture_cleanup = coordinator.snapshot(deadline()).unwrap().phase();
    let (original_settled, new_current_turn_completed, original_charge_intact) = {
        let daemon = shared.lock().await;
        let state = daemon.work.state.try_lock().unwrap();
        (
            !state.rows.contains_key(&original_row),
            state.rows.is_empty() && state.next == original_sequence + 1,
            state.rows.len() == 1
                && state.rows.get(&original_row).is_some_and(Option::is_some)
                && state.next == original_sequence,
        )
    };
    let mut journal_restoration_failed = false;
    if matches!(inventory, FixtureJournal::RepeatedVm) {
        // Preserve the failed row/lease exactly as observed. Join any original
        // fixture handles before dropping this private daemon with its ledger.
        if custody.cell.has_inflight_mutation().unwrap() {
            let mut loan = custody.cell.mutation_loan().unwrap();
            let original = loan.value_mut();
            journal_restoration_failed =
                original.io_status(MutationIoStage::JournalRestoration) == MutationIoStatus::Failed;
            if let Some(retiring) = original.retiring.as_mut() {
                retiring.finish().await.unwrap();
            }
            if let Some(prepared) = original.prepared.as_mut()
                && !prepared.service_transferred()
            {
                prepared.cancel_services().await.unwrap();
            }
        }
        let mut map = custody.cell.map_loan().unwrap();
        for live in map.value_mut().vms.values_mut() {
            live.finish_retirement().await.unwrap();
        }
    } else {
        cleanup_owned_fixture(
            &shared,
            &custody,
            &coordinator,
            &generation,
            &mut installation,
            epoch,
        )
        .await;
    }
    eprintln!(
        "RECONCILED_STOPPED_WITNESS returned_before_join={returned_before_original_join} charged={charged_during_wait} original_row_retained={original_still_retained} original_settled={original_settled} new_current_turn_completed={new_current_turn_completed} current_error={current_error:?}"
    );
    assert_eq!(journal_before_release, journal_at_retry);
    if let FixtureJournal::RepeatedVm = inventory {
        assert!(
            current_result.is_err(),
            "inconsistent journal admitted: {current_result:?}"
        );
        assert!(
            journal_restoration_failed,
            "expected the retained JournalRestoration stage to fail"
        );
        assert_eq!(
            file_after_attempt, file_at_retry,
            "do not rewrite an unknown original"
        );
        assert_eq!(committed_records, journal_at_retry);
        assert!(charged_after_attempt && original_charge_intact);
        assert!(!original_settled && !new_current_turn_completed);
        assert_eq!(phase_before_fixture_cleanup, LifecyclePhase::Draining);
        return;
    }
    assert!(
        current_result.is_ok(),
        "current signed Deregister must reconcile the original and execute its OWN coherent removal: {current_error:?}"
    );
    assert!(
        !returned_before_original_join,
        "no current success/refusal may substitute for retained original cleanup"
    );
    assert!(charged_during_wait && original_still_retained);
    assert_eq!(journal_before_release, original_records);
    assert_eq!(
        committed_records,
        vec![original_records[1].clone()],
        "new current Deregister must commit its OWN removal after full original restoration"
    );
    assert!(original_settled && new_current_turn_completed);
    assert_eq!(
        phase_before_fixture_cleanup,
        LifecyclePhase::Draining,
        "recovery must remain stopped, never reactivate"
    );
    assert_eq!(held.completed_count(), 1);
    assert_eq!(lane.available_permits(), 1);
}

async fn cleanup_owned_fixture(
    shared: &Arc<Mutex<HostAgentDaemon>>,
    custody: &DaemonCustodyOwner,
    coordinator: &LifecycleCoordinator,
    generation: &LifecycleGeneration,
    installation: &mut InstallationOwner,
    epoch: mvm_vmm::host::installed_owner::Epoch,
) {
    // Fixture safety only. This never satisfies assertions about the actual
    // current request's original-row settlement or journal commit.
    if custody.cell.has_inflight_mutation().unwrap() {
        let mut mutation = custody.cell.mutation_loan().unwrap();
        if let Some(retiring) = mutation.value_mut().retiring.as_mut() {
            retiring.finish().await.unwrap();
        }
        mutation.value_mut().retiring = None;
        if let Some(prepared) = mutation.value_mut().prepared.as_mut() {
            prepared.cancel_services().await.unwrap();
        }
        mutation.value_mut().prepared = None;
        custody.cell.complete_mutation(mutation).unwrap();
    }
    let snapshot = coordinator.snapshot(deadline()).unwrap();
    if snapshot.phase() != LifecyclePhase::Draining {
        coordinator
            .begin_drain(generation, snapshot.revision(), deadline(), |_| Ok(()))
            .unwrap();
    }
    shared.lock().await.close_local_admission().unwrap();
    custody.drain_services().await.unwrap();
    shared
        .lock()
        .await
        .accepted_work_drain()
        .unwrap()
        .drain()
        .await
        .unwrap();
    installation.finish(epoch).unwrap();
    coordinator
        .finish_drain_after_collection(generation, deadline(), |_| Ok(()))
        .unwrap();
}

#[test]
fn stopped_inventory_compares_each_complete_registration_exactly_once() {
    let dir = Path::new("/fixture");
    let a = super::tests::register(dir, "a", "local", None);
    let b = super::tests::register(dir, "b", "local", None);
    let expected = vec![a.clone(), b.clone()];
    assert!(same_recordset(&[b.clone(), a.clone()], &expected));
    let mut changed = b.clone();
    changed.workload_id = Some("another-workload".into());
    assert!(!same_recordset(&[a.clone(), changed], &expected));
    let duplicate = vec![a.clone(), a];
    assert!(!same_recordset(&duplicate, &expected));
    assert!(!same_recordset(&expected, &duplicate));
    assert!(!same_recordset(&duplicate, &duplicate));
}
