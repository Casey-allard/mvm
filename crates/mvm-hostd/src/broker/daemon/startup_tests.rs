//! Actual retained sockets and canonical nonempty journal replay. Core phase
//! construction is a metadata fixture, not signer/VM/readiness qualification.
use super::*;
use ed25519_dalek::SigningKey;
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
fn time_call() -> ServiceCall {
    ServiceCall {
        service: ServiceId::parse("host.time.v1").unwrap(),
        verb: "now".into(),
        correlation_id: CorrelationId::new("queued-original-time"),
        payload: serde_json::json!({}),
        capability: None,
    }
}

#[tokio::test]
async fn trusted_preparing_replay_keeps_two_original_services_parked_until_active() {
    let parent = tempfile::tempdir().unwrap();
    let home = parent.path().join("mvm-home");
    let provisioned = create_new_home_and_provision(&home, "local").unwrap();
    provisioned.verify().unwrap();
    let labels = descriptor(&home, "local").unwrap();
    let mut owner = InstallationOwner::open(&labels.root, labels.key).unwrap();
    let epoch_one = owner.begin().unwrap();
    let generation_one = LifecycleGeneration::new([31; 32], epoch_one.generation()).unwrap();
    let coordinator = LifecycleCoordinator::prepare_after_exclusion(
        &home,
        "local",
        generation_one.clone(),
        256,
        deadline(),
    )
    .unwrap();
    // Storage phase setup only. The actual old services below have real sockets,
    // signed controls and responses; this fixture starts no signer child or VM.
    coordinator
        .activate_after_reconciliation(&generation_one, deadline())
        .unwrap();
    let journal_path =
        mvm_core::config::host_agent_dir_at(&home, "local").join("registrations.json");
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut old = HostAgentDaemon::new("local", key.verifying_key(), 65_536)
        .with_resource_binding(Arc::new(owner.active_binding(epoch_one).unwrap()))
        .with_lifecycle_coordination(&home, generation_one.clone())
        .unwrap();
    TenantLifecycleGate::new(&home, "local")
        .unwrap()
        .with_active(&generation_one, deadline(), || {
            old.open_local_admission(&generation_one)
        })
        .unwrap();
    let old = Arc::new(Mutex::new(old));
    let old_custody = old.lock().await.custody_owner();
    let mut records = Vec::new();
    for vm_id in ["replay-a", "replay-b"] {
        let mut record = super::tests::register(&home, vm_id, "local", None);
        record.services_bindings = vec![ServiceId::parse("host.time.v1").unwrap()];
        let signed = broker_control::sign(
            ControlRequest::Register(Box::new(record.clone())),
            &key.to_bytes(),
        )
        .unwrap();
        HostAgentDaemon::apply_signed_shared(old.clone(), signed)
            .await
            .unwrap();
        let mut stream = UnixStream::connect(&record.broker_listen_socket)
            .await
            .unwrap();
        write_frame(&mut stream, &time_call()).await.unwrap();
        let response: ServiceResponse =
            tokio::time::timeout(Duration::from_secs(1), read_frame(&mut stream, 65_536))
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(response, ServiceResponse::Ok { .. }));
        records.push(record);
    }
    // Checkpoint the exact actually served records through the canonical
    // domain writer; this is NONEMPTY history, not an empty-journal seed or
    // product freshness authority. Prior controls used Unconfigured storage.
    {
        let mut prior = old.lock().await;
        let journal = RegistrationJournal::new(&journal_path);
        journal.store(prior.registrations.values()).unwrap();
        prior.registration_journal = Some(journal);
    }
    let original = RegistrationJournal::new(&journal_path).load().unwrap();
    assert_eq!(
        original, records,
        "journal comes from actual original signed registrations, not fixture [] seeding"
    );
    let before = coordinator.snapshot(deadline()).unwrap();
    coordinator
        .begin_drain(&generation_one, before.revision(), deadline(), |_| Ok(()))
        .unwrap();
    old.lock().await.close_local_admission().unwrap();
    old_custody.drain_services().await.unwrap();
    old.lock()
        .await
        .accepted_work_drain()
        .unwrap()
        .drain()
        .await
        .unwrap();
    owner.finish(epoch_one).unwrap();
    coordinator
        .finish_drain_after_collection(&generation_one, deadline(), |_| Ok(()))
        .unwrap();
    drop(old);
    drop(old_custody);
    {
        // Retain the actual independent holders EX while validating the known
        // original recordset. No Copy Recovery or PID absence is used as proof.
        let exclusion = owner.reconcile_with_exclusion().unwrap();
        exclusion.revalidate().unwrap();
        assert_eq!(
            RegistrationJournal::new(&journal_path).load().unwrap(),
            original
        );
    }
    let epoch_two = owner.begin().unwrap();
    let generation_two = LifecycleGeneration::new([32; 32], epoch_two.generation()).unwrap();
    coordinator
        .prepare_generation_after_reconciliation(&generation_two, deadline())
        .unwrap();
    let replay = HostAgentDaemon::new("local", key.verifying_key(), 65_536)
        .with_registration_journal(&journal_path)
        .with_resource_binding(Arc::new(owner.active_binding(epoch_two).unwrap()))
        .with_lifecycle_coordination(&home, generation_two.clone())
        .unwrap();
    let replay = Arc::new(Mutex::new(replay));
    let custody = replay.lock().await.custody_owner();
    let ordinary = broker_control::sign(
        ControlRequest::Register(Box::new(records[0].clone())),
        &key.to_bytes(),
    )
    .unwrap();
    assert!(
        HostAgentDaemon::apply_signed_shared(replay.clone(), ordinary)
            .await
            .is_err(),
        "normal signed Register cannot bypass Preparing via cleanup semantics"
    );
    let staged = tokio::time::timeout(
        Duration::from_secs(2),
        HostAgentDaemon::prepare_journaled_services_shared(replay.clone(), &generation_two),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        staged, 2,
        "record-one preparation must settle before record two takes the same lane"
    );
    assert_eq!(
        RegistrationJournal::new(&journal_path).load().unwrap(),
        original,
        "preparation must not overwrite the full original journal with a partial prefix"
    );
    assert_eq!(replay.lock().await.mutation_lane().available_permits(), 1);
    assert!(
        !replay.lock().await.has_accepted_work().unwrap(),
        "prepared is represented custody, not Ready"
    );
    let mut clients = Vec::new();
    for record in &records {
        let mut client = UnixStream::connect(&record.broker_listen_socket)
            .await
            .unwrap();
        write_frame(&mut client, &time_call()).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                read_frame::<ServiceResponse>(&mut client, 65_536)
            )
            .await
            .is_err(),
            "a bound original socket cannot dispatch while Preparing"
        );
        clients.push(client);
    }
    assert_eq!(
        coordinator.snapshot(deadline()).unwrap().phase(),
        LifecyclePhase::Preparing
    );
    let check = replay.clone();
    let publish = replay.clone();
    coordinator
        .activate_after_reconciliation_with(
            &generation_two,
            deadline(),
            |_| {
                let original = check
                    .try_lock()
                    .map_err(|_| anyhow::anyhow!("original map unavailable"))?;
                anyhow::ensure!(
                    original.check_prepared_services(&generation_two)? == 2,
                    "the full original recordset must match its exact parked owners"
                );
                Ok(())
            },
            |_| {
                let mut original = publish
                    .try_lock()
                    .map_err(|_| anyhow::anyhow!("original map unavailable"))?;
                anyhow::ensure!(
                    original.release_prepared_services(&generation_two)? == 2,
                    "release only those same original parked latches"
                );
                original.open_local_admission(&generation_two)
            },
        )
        .unwrap();
    for client in &mut clients {
        let response: ServiceResponse =
            tokio::time::timeout(Duration::from_secs(1), read_frame(client, 65_536))
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(response, ServiceResponse::Ok { .. }));
    }
    drop(clients);
    let before = coordinator.snapshot(deadline()).unwrap();
    coordinator
        .begin_drain(&generation_two, before.revision(), deadline(), |_| Ok(()))
        .unwrap();
    replay.lock().await.close_local_admission().unwrap();
    custody.drain_services().await.unwrap();
    replay
        .lock()
        .await
        .accepted_work_drain()
        .unwrap()
        .drain()
        .await
        .unwrap();
    owner.finish(epoch_two).unwrap();
    coordinator
        .finish_drain_after_collection(&generation_two, deadline(), |_| Ok(()))
        .unwrap();
}
