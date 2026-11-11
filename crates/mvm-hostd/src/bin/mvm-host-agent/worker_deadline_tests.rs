//! The actual installed coordinator must never start a new grace period when
//! it re-enters cleanup for the same resource generation.
use super::*;
use mvm_core::tenant_lifecycle::LifecyclePhase;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::host_keypair;
use mvm_vmm::host::host_agent_installation::create_new_home_and_provision;
use std::os::unix::fs::PermissionsExt;

fn with_provisioned_worker(test: impl FnOnce(&mut WorkerCoordinator) -> Result<()>) -> Result<()> {
    let mut env = TestEnv::new();
    let base = tempfile::tempdir()?;
    std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700))?;
    let home = base.path().join("mvm-home");
    let tenant = "local";
    let original = create_new_home_and_provision(&home, tenant)?;
    original.verify()?;
    env.set("MVM_HOME", &home);
    let signer = host_keypair::load_or_init_at(&home.join("keys"))?;
    let config = HostAgentConfig {
        tenant_id: tenant.into(),
        control_socket: mvm_core::config::host_agent_control_socket(tenant),
        registration_journal_path: Some(
            mvm_core::config::host_agent_dir(tenant).join("registrations.json"),
        ),
        host_signer_public_key_path: signer.public_path,
        signer_helper_uds_path: mvm_core::config::host_agent_signer_helper_socket(tenant),
        software_chain_key_path: signer.secret_path,
        max_frame_bytes: 65_536,
    };

    test(&mut WorkerCoordinator::open(config)?)
}

#[test]
fn repeated_worker_drain_reuses_first_grace_deadline() -> Result<()> {
    with_provisioned_worker(|worker| {
        let first = worker
            .begin_drain(false)?
            .context("initial error drain refused")?;
        let second = worker
            .begin_drain(false)?
            .context("repeated error drain refused")?;
        let phase = worker
            .lifecycle
            .snapshot(Instant::now() + LIFECYCLE_IO_BUDGET)?
            .phase();
        // No signer or guest was started. Collect the actual fixture's service
        // map and resource owner before checking the deadline contract.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(worker.collect_originals())?;
        assert_eq!(phase, LifecyclePhase::Draining);
        assert_eq!(
            second, first,
            "the original cleanup grace must not be renewed"
        );
        Ok(())
    })
}

#[test]
fn refused_idle_does_not_consume_the_next_shutdown_grace() -> Result<()> {
    with_provisioned_worker(|worker| {
        let metadata_deadline = || Instant::now() + LIFECYCLE_IO_BUDGET;
        worker
            .lifecycle
            .activate_after_reconciliation(&worker.generation, metadata_deadline())?;
        let gate = mvm_core::tenant_lifecycle::TenantLifecycleGate::new(
            &worker.resources.home,
            &worker.cfg.tenant_id,
        )?;
        let mut pending = gate.reserve_launch("grace-test", "grace-plan", metadata_deadline())?;
        let declined = worker.begin_drain(true)?;
        let active = worker.lifecycle.snapshot(metadata_deadline())?;
        // This fixture reserved the launch and never started its backend.
        pending.settle_after_original_cleanup(metadata_deadline(), || Ok(()))?;
        let earliest = Instant::now() + COOPERATIVE_DRAIN_GRACE;
        let accepted = worker.begin_drain(false)?.context("error drain refused")?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(worker.collect_originals())?;
        assert!(declined.is_none());
        assert_eq!(active.phase(), LifecyclePhase::Active);
        assert_eq!(active.pending().len(), 1);
        assert!(
            accepted >= earliest,
            "an idle refusal consumed part of the shutdown grace"
        );
        Ok(())
    })
}

#[test]
fn original_control_task_joins_before_signer_stop() -> Result<()> {
    with_provisioned_worker(|worker| {
        tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let listener = tokio::net::UnixListener::bind(worker.resources.home.join("control-order.sock"))?;
        let (control_stop, stopped) = tokio::sync::watch::channel(false);
        let (at_join_tx, at_join_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let daemon = worker.daemon.clone();
        // The original handle owns the ACTUAL canonical loop. The test barrier
        // widens its completion edge; it does not fabricate a successful loop.
        let task = tokio::spawn(async move {
            HostAgentDaemon::run_shared_on_listener_until(daemon, listener, stopped).await?;
            let _ = at_join_tx.send(());
            release_rx.await.context("test join barrier lost")?;
            Ok(())
        });
        worker.control = Some(ControlLoopHandle { stop: control_stop, task: Some(task), completed: false, failed: false, terminal_error: None });
        let (signer_stop, mut signer_stopped) = tokio::sync::watch::channel(false);
        let stop_observer = signer_stopped.clone();
        worker.signer = Some(SignerSupervisionHandle {
            stop: signer_stop,
            task: Some(tokio::spawn(async move {
                wait_for_stop(&mut signer_stopped).await;
                SignerDrainReceipt
            })),
            receipt: None, unresolved: false,
            active_stop: Arc::new(std::sync::Mutex::new(None)),
        });
        worker.begin_drain(false)?.context("drain fence refused")?;
        // Poll the real collector and the independent barrier together. This
        // future is borrowed, never moved into a cancellation-dropping task.
        let mut collect = Box::pin(worker.collect_originals());
        let barrier = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut collect => Ok(Some(result)),
                result = at_join_rx => result.context("original loop did not reach join barrier").map(|()| None),
            }
        }).await;
        let signer_stopped_early = *stop_observer.borrow();
        // Release original task before any intended assertion or error return.
        let _ = release_tx.send(());
        let barrier_ok = matches!(&barrier, Ok(Ok(None)));
        let early_finish = matches!(&barrier, Ok(Ok(Some(_))));
        let collection = match barrier {
            Ok(Ok(Some(result))) => result,
            _ => tokio::time::timeout(Duration::from_secs(2), &mut collect).await.context("original collection timed out")?,
        };
        drop(collect);
        collection?;
        anyhow::ensure!(!early_finish, "collector finished before the original control task joined");
        anyhow::ensure!(barrier_ok, "control join barrier lost or timed out");

        anyhow::ensure!(!signer_stopped_early, "signer stopped before original control task joined");
        anyhow::ensure!(*stop_observer.borrow(), "original signer task was not stopped after control join");
        anyhow::ensure!(worker.control.as_ref().is_some_and(|control| control.completed), "original control task not collected");
        anyhow::ensure!(worker.signer.as_ref().is_some_and(|signer| signer.receipt.is_some()), "synthetic signer task not joined");
        Ok(())
    })
    })
}

#[test]
fn forced_worker_drain_fences_while_the_control_loop_owns_the_daemon() -> Result<()> {
    with_provisioned_worker(|worker| {
        let daemon = worker.daemon.clone();
        let original = daemon.try_lock().context("fixture daemon should be idle")?;
        let fenced = worker.begin_drain(false);
        drop(original);
        // Finish the fixture using the original owner even on the old implementation.
        worker
            .begin_drain(false)?
            .context("cleanup fence refused")?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(worker.collect_originals())?;
        anyhow::ensure!(fenced?.is_some(), "forced drain remained unfenced");
        Ok(())
    })
}

#[test]
fn queued_idle_cannot_claim_a_drain_started_by_another_owner() -> Result<()> {
    with_provisioned_worker(|worker| {
        let deadline = || Instant::now() + LIFECYCLE_IO_BUDGET;
        worker
            .lifecycle
            .activate_after_reconciliation(&worker.generation, deadline())?;
        let active = worker.lifecycle.snapshot(deadline())?;
        worker
            .lifecycle
            .begin_drain(
                &worker.generation,
                active.revision(),
                deadline(),
                |_| Ok(()),
            )?;
        let first = worker
            .drain_controller
            .request(Instant::now() + COOPERATIVE_DRAIN_GRACE)?;
        // Simulate both select arms becoming ready. A queued idle observation
        // is no longer authority to report an idle exit after this other fence.
        let idle = worker.begin_drain(true);
        let current = worker.lifecycle.snapshot(deadline())?;
        let recovered = worker
            .begin_drain(false)?
            .context("original recovery fence refused")?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(worker.collect_originals())?;
        anyhow::ensure!(
            idle.is_err(),
            "queued idle claimed another owner's shutdown"
        );
        assert_eq!(current.phase(), LifecyclePhase::Draining);
        assert_eq!(recovered, first.deadline());
        Ok(())
    })
}
