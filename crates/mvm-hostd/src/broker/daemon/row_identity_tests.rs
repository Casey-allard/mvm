//! Deterministic stale PRODUCTION callers, with fixture-local test gaps only.
//! Lifecycle setup is metadata; no VM, signer or Child receipt is asserted.
use super::*;
use mvm_core::tenant_lifecycle::{
    LifecycleCoordinator, LifecycleGeneration, LifecyclePhase, TenantLifecycleGate,
};
use mvm_vmm::host::host_agent_installation::{create_new_home_and_provision, descriptor};
use mvm_vmm::host::installed_owner::{Epoch, HolderLease, InstallationOwner};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GapPoint {
    RecoveryAfterFence,
    MutationAfterReservation,
}

pub(super) struct RowGap {
    point: GapPoint,
    entered: AtomicBool,
    changed: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}
impl RowGap {
    fn new(point: GapPoint) -> Self {
        Self {
            point,
            entered: AtomicBool::new(false),
            changed: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        }
    }
    pub(super) async fn pause(&self, point: GapPoint) {
        if self.point != point {
            return;
        }
        self.entered.store(true, Ordering::Release);
        self.changed.notify_one();
        self.release.acquire().await.unwrap().forget();
    }
    async fn entered(&self) {
        loop {
            let event = self.changed.notified();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            event.await;
        }
    }
    fn resume(&self) {
        self.release.add_permits(1);
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

struct Fixture {
    _directory: tempfile::TempDir,
    home: PathBuf,
    shared: Arc<Mutex<HostAgentDaemon>>,
    cell: Arc<MutationCell>,
    lane: Arc<tokio::sync::Semaphore>,
    gap: Arc<RowGap>,
    signing: ed25519_dalek::SigningKey,
    generation: LifecycleGeneration,
    coordinator: LifecycleCoordinator,
    installation: InstallationOwner,
    epoch: Epoch,
}
impl Fixture {
    async fn new(point: GapPoint) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("mvm-home");
        let provisioned = create_new_home_and_provision(&home, "local").unwrap();
        provisioned.verify().unwrap();
        let labels = descriptor(&home, "local").unwrap();
        let mut installation = InstallationOwner::open(&labels.root, labels.key).unwrap();
        let epoch = installation.begin().unwrap();
        let generation = LifecycleGeneration::new([121; 32], epoch.generation()).unwrap();
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            &home,
            "local",
            generation.clone(),
            256,
            deadline(),
        )
        .unwrap();
        coordinator
            .activate_after_reconciliation(&generation, deadline())
            .unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[122; 32]);
        let gap = Arc::new(RowGap::new(point));
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
        daemon.row_gap = Some(gap.clone());
        let cell = daemon.custody.clone();
        let lane = daemon.mutation_lane();
        Self {
            _directory: directory,
            home,
            shared: Arc::new(Mutex::new(daemon)),
            cell,
            lane,
            gap,
            signing,
            generation,
            coordinator,
            installation,
            epoch,
        }
    }
    fn removal(&self) -> SignedControl {
        broker_control::sign(
            ControlRequest::Deregister(broker_control::DeregisterVm {
                vm_id: "row-vm".into(),
            }),
            &self.signing.to_bytes(),
        )
        .unwrap()
    }
    async fn sole_row(&self) -> u64 {
        let daemon = self.shared.lock().await;
        let state = daemon.work.state.try_lock().unwrap();
        assert_eq!(state.rows.len(), 1);
        *state.rows.keys().next().unwrap()
    }
    async fn reserve_current_row(&self, full_snapshot: bool) -> u64 {
        let signed = self.removal();
        let (mut operation, admission, binding) = {
            let daemon = self.shared.lock().await;
            let request = broker_control::verify(&signed, &daemon.verifying_key)
                .unwrap()
                .clone();
            (
                Some(
                    daemon
                        .original_operation_descriptor(request, Some(signed), None)
                        .unwrap(),
                ),
                daemon.lifecycle_admission.clone().unwrap(),
                daemon.resources.clone().unwrap(),
            )
        };
        let mut permit = Some(self.lane.clone().try_acquire_owned().unwrap());
        let reserve = || {
            let daemon = self.shared.try_lock().unwrap();
            let mut loan = self.cell.reserve_mutation(&mut permit, || {
                daemon.reserve_cleanup_work(&self.generation)
            })?;
            loan.value_mut()
                .capture_operation(operation.take().unwrap())
        };
        match self.coordinator.snapshot(deadline()).unwrap().phase() {
            LifecyclePhase::Active => admission
                .gate
                .with_active(&self.generation, deadline(), reserve)
                .unwrap(),
            LifecyclePhase::Draining => admission
                .gate
                .with_draining(&self.generation, deadline(), reserve)
                .unwrap(),
            _ => panic!("fixture phase cannot reserve canonical cleanup"),
        }
        if full_snapshot {
            let mut loan = self.cell.mutation_loan().unwrap();
            loan.value_mut()
                .capture_journal(JournalSnapshots {
                    original: vec![],
                    candidate: vec![],
                })
                .unwrap();
            loan.value_mut()
                .attach_resource(
                    HolderLease::acquire(&binding.root, binding.key, binding.generation).unwrap(),
                )
                .unwrap();
        }
        self.sole_row().await
    }
    async fn row_is_retained(&self, id: u64) -> bool {
        let daemon = self.shared.lock().await;
        let state = daemon.work.state.try_lock().unwrap();
        state.rows.contains_key(&id)
    }
    async fn cleanup(&mut self) {
        self.cell.request_stop();
        let mut mutation = if self.cell.has_inflight_mutation().unwrap() {
            Some(self.cell.mutation_loan().unwrap())
        } else {
            None
        };
        if let Some(loan) = mutation.as_mut() {
            if let Some(retiring) = loan.value_mut().retiring.as_mut() {
                retiring.finish().await.unwrap();
            }
            loan.value_mut().retiring = None;
            if let Some(prepared) = loan.value_mut().prepared.as_mut()
                && !prepared.service_transferred()
            {
                prepared.cancel_services().await.unwrap();
            }
        }
        {
            let mut map = self.cell.map_loan().unwrap();
            for live in map.value_mut().vms.values() {
                live.request_stop();
            }
            for live in map.value_mut().vms.values_mut() {
                live.finish_retirement().await.unwrap();
            }
            map.value_mut().vms.clear();
            map.value_mut().phase = VmMapPhase::Drained;
        }
        if let Some(mut loan) = mutation {
            loan.value_mut().prepared = None;
            self.cell.complete_mutation(loan).unwrap();
        }
        let snapshot = self.coordinator.snapshot(deadline()).unwrap();
        if snapshot.phase() != LifecyclePhase::Draining {
            self.coordinator
                .begin_drain(
                    &self.generation,
                    snapshot.revision(),
                    deadline(),
                    |_| Ok(()),
                )
                .unwrap();
        }
        self.installation.finish(self.epoch).unwrap();
        self.coordinator
            .finish_drain_after_collection(&self.generation, deadline(), |_| Ok(()))
            .unwrap();
    }
}

#[tokio::test]
async fn stale_recovery_caller_cannot_settle_a_replacement_row_in_the_same_cell() {
    let mut fixture = Fixture::new(GapPoint::RecoveryAfterFence).await;
    let original = fixture.reserve_current_row(true).await;
    let shared = fixture.shared.clone();
    let signed = fixture.removal();
    let caller = tokio::spawn(async move {
        let request = signed.request.clone();
        reconcile_original_mutation(&mut DaemonAccess::Shared(shared), Some((&request, &signed)))
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), fixture.gap.entered())
        .await
        .unwrap();
    // A real competitor collects the known no-effect original turn, then
    // reserves a DIFFERENT canonical same-VM cleanup in this SAME ledger/cell.
    fixture
        .cell
        .complete_mutation(fixture.cell.mutation_loan().unwrap())
        .unwrap();
    let replacement = fixture.reserve_current_row(true).await;
    assert!(replacement > original);
    fixture.gap.resume();
    let result = tokio::time::timeout(Duration::from_secs(2), caller)
        .await
        .unwrap()
        .unwrap();
    let retained = fixture.row_is_retained(replacement).await;
    let credit = fixture.lane.available_permits();
    let lease_retained = retained && fixture.installation.finish(fixture.epoch).is_err();
    fixture.cleanup().await;
    eprintln!(
        "RECOVERY_ROW_ABA original={original} replacement={replacement} stale_error={:?} replacement_retained={retained} permits_before_fixture_cleanup={credit} lease_retained={lease_retained}",
        result.as_ref().err().map(ToString::to_string)
    );
    assert!(
        result.is_err(),
        "stale recovery must reject the changed original row, never retarget to the newest same-VM row"
    );
    assert!(
        retained && lease_retained,
        "replacement row and its actual lease remain owned"
    );
    assert_eq!(credit, 0, "stale recovery cannot refund replacement credit");
}

#[tokio::test]
async fn stale_normal_publication_cannot_mutate_a_replacement_row_in_the_same_cell() {
    let mut fixture = Fixture::new(GapPoint::MutationAfterReservation).await;
    let record = super::tests::register(&fixture.home, "row-vm", "local", None);
    let endpoint = PathBuf::from(&record.broker_listen_socket);
    let signed = broker_control::sign(
        ControlRequest::Register(Box::new(record)),
        &fixture.signing.to_bytes(),
    )
    .unwrap();
    let shared = fixture.shared.clone();
    let caller =
        tokio::spawn(async move { HostAgentDaemon::apply_signed_shared(shared, signed).await });
    tokio::time::timeout(Duration::from_secs(1), fixture.gap.entered())
        .await
        .unwrap();
    let original = fixture.sole_row().await;
    fixture
        .cell
        .complete_mutation(fixture.cell.mutation_loan().unwrap())
        .unwrap();
    // This is the real legal post-reservation state: original descriptor is
    // captured, but no effect snapshot/lease/prepare operation has begun.
    let replacement = fixture.reserve_current_row(false).await;
    assert!(replacement > original);
    fixture.gap.resume();
    let result = tokio::time::timeout(Duration::from_secs(2), caller)
        .await
        .unwrap()
        .unwrap();
    let retained = fixture.row_is_retained(replacement).await;
    let credit = fixture.lane.available_permits();
    let exposed = match std::fs::symlink_metadata(&endpoint) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("owned endpoint observation failed: {error}"),
    };
    fixture.cleanup().await;
    eprintln!(
        "NORMAL_ROW_ABA original={original} replacement={replacement} stale_error={:?} replacement_retained={retained} permits_before_fixture_cleanup={credit} endpoint_exposed={exposed}",
        result.as_ref().err().map(ToString::to_string)
    );
    assert!(
        result.is_err(),
        "stale normal caller must reject the changed original row before effects"
    );
    assert!(
        retained,
        "normal caller cannot settle the replacement cleanup row"
    );
    assert_eq!(credit, 0);
    assert!(
        !exposed,
        "stale original request cannot publish a listener using the replacement row"
    );
}
