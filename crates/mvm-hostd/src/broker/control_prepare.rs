//! Retained preparation and retirement of canonical broker registrations.
//!
//! The original daemon owns one bounded cell with two fixed custody fields:
//! an inflight mutation and the original VM map retained from construction.
//! Neither this coordination cell nor its tests establish admission, readiness
//! or original-child collection.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, ensure};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, MutexGuard, OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio::task::JoinSet;

use super::audit_client::AuditClient;
use super::daemon::{
    AcceptedDaemonWork, MutationOperationDescriptor, RegistrationSnapshot,
    open_admitted_assurance_session, validate_registration,
};
use super::handlers::host_audit_v1::HostAuditV1Handler;
use super::handlers::{BoundHandlers, build_bound_handlers};
use super::registry::Registry;
use super::server::{ServiceConnectionOwner, serve_on_listener_owned};
use super::service_proxy::ControllerServiceProxy;

#[cfg(test)]
#[path = "control_prepare/publication_tests.rs"]
mod publication_tests;

/// Internal memory custody only. A live loan leaves the original object inside
/// this same field, so canceling its future releases only the borrowed guard.
struct CustodyField<T> {
    value: Mutex<Option<T>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyError {
    Busy,
    Empty,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "original custody field is retained or loaned",
            Self::Empty => "original custody field is empty",
        })
    }
}

impl std::error::Error for CustodyError {}

impl<T> CustodyField<T> {
    fn new() -> Self {
        Self {
            value: Mutex::new(None),
        }
    }

    fn retaining(original: T) -> Self {
        Self {
            value: Mutex::new(Some(original)),
        }
    }

    fn loan(&self) -> Result<CustodyLoan<'_, T>, CustodyError> {
        let value = self.value.try_lock().map_err(|_| CustodyError::Busy)?;
        if value.is_none() {
            return Err(CustodyError::Empty);
        }
        Ok(CustodyLoan {
            origin: self,
            value,
        })
    }

    fn is_vacant(&self) -> Result<bool, CustodyError> {
        let value = self.value.try_lock().map_err(|_| CustodyError::Busy)?;
        Ok(value.is_none())
    }
}

/// Original daemon and coordinator share this one cell before any service is
/// created. Neither field is a permission source. A borrowed Tokio guard keeps
/// its original value physically in the field across I/O and cancellation.
/// Release each preparation loan before entering the final FileGate turn;
/// that turn takes daemon.try_lock then cell.try-loan, never the reverse.
pub(crate) struct MutationCell {
    inflight_mutation: CustodyField<InflightMutation>,
    retiring_original_vm_map: CustodyField<OriginalVmMap>,
    connection_slots: Arc<Semaphore>,
    stopping: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmMapPhase {
    Live,
    Retiring,
    Drained,
}

pub(crate) struct OriginalVmMap {
    pub(crate) phase: VmMapPhase,
    pub(crate) vms: HashMap<String, LiveVmHandle>,
}

/// The same original permit and accepted-work token survive unknown outcomes.
/// Cleanup/preparation resources are captured here before their first effect.
pub(crate) struct InflightMutation {
    accepted: AcceptedDaemonWork,
    _permit: OwnedSemaphorePermit,
    pub(crate) prepared: Option<PreparedRegistration>,
    pub(crate) retiring: Option<RetiringRegistration>,
    io: [RetainedIo; 5],
    journal: Option<JournalSnapshots>,
    operation: Option<MutationOperationDescriptor>,
}

/// Observation of one original effect, never permission to replay it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MutationIoStatus {
    NotStarted,
    Pending,
    Succeeded,
    Failed,
}

/// Separate effect identities prevent an old deregistration result from being
/// mistaken for rollback of a subsequently registered helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MutationIoStage {
    HelperRetirement,
    HelperRegistration,
    JournalPublication,
    RollbackHelperRegistration,
    JournalRestoration,
}

impl MutationIoStage {
    fn index(self) -> usize {
        match self {
            Self::HelperRetirement => 0,
            Self::HelperRegistration => 1,
            Self::JournalPublication => 2,
            Self::RollbackHelperRegistration => 3,
            Self::JournalRestoration => 4,
        }
    }
}

pub(crate) struct JournalSnapshots {
    pub(crate) original: Vec<mvm_core::protocol::broker_control::RegisterVm>,
    pub(crate) candidate: Vec<mvm_core::protocol::broker_control::RegisterVm>,
}

/// One original blocking operation, captured in its cell before spawn. It can
/// start once; cancellation of finish does not drop its JoinSet or replay it.
struct RetainedIo {
    tasks: JoinSet<Result<()>>,
    started: bool,
    completed: bool,
    failure: Option<anyhow::Error>,
}

impl RetainedIo {
    fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            started: false,
            completed: false,
            failure: None,
        }
    }

    fn start(&mut self, operation: impl FnOnce() -> Result<()> + Send + 'static) -> Result<()> {
        ensure!(!self.started, "original I/O stage was already attempted");
        // Mark before insertion. Spawn uncertainty cannot be reported as no I/O.
        self.started = true;
        self.tasks.spawn_blocking(operation);
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        ensure!(self.started, "original I/O stage was not started");
        if !self.completed {
            match self.tasks.join_next().await {
                Some(Ok(Ok(()))) => self.completed = true,
                Some(Ok(Err(error))) => {
                    self.completed = true;
                    self.failure = Some(error);
                }
                Some(Err(error)) => {
                    self.completed = true;
                    self.failure = Some(error.into());
                }
                None => anyhow::bail!("original I/O completion unavailable"),
            }
        }
        ensure!(
            self.failure.is_none(),
            "original I/O failed; retained outcome requires reconciliation"
        );
        Ok(())
    }

    fn pending(&self) -> bool {
        self.started && !self.completed
    }
    fn succeeded(&self) -> bool {
        self.completed && self.failure.is_none()
    }

    fn status(&self) -> MutationIoStatus {
        if !self.started {
            MutationIoStatus::NotStarted
        } else if !self.completed {
            MutationIoStatus::Pending
        } else if self.failure.is_some() {
            MutationIoStatus::Failed
        } else {
            MutationIoStatus::Succeeded
        }
    }
}

impl InflightMutation {
    /// Original monotonic row within the retained cell's ledger, not authority.
    pub(crate) fn original_row_id(&self) -> u64 {
        self.accepted.original_row_id()
    }

    /// Preserve the original canonical caller's immutable recipe before effects.
    /// The descriptor is data, not current activation or cleanup authority.
    pub(crate) fn capture_operation(
        &mut self,
        operation: MutationOperationDescriptor,
    ) -> Result<()> {
        ensure!(
            self.operation.is_none()
                && self.journal.is_none()
                && self.prepared.is_none()
                && self.retiring.is_none()
                && self.io.iter().all(|io| !io.started),
            "capture the original operation once before service or I/O effects"
        );
        // Configured bindings must have their checked observation bound
        // outside outer locks. Presence alone is not freshness or authority.
        operation.journal_presence()?;
        self.operation = Some(operation);
        Ok(())
    }

    pub(crate) fn operation(&self) -> Result<&MutationOperationDescriptor> {
        self.operation
            .as_ref()
            .context("original operation recipe missing")
    }

    pub(crate) fn io_status(&self, stage: MutationIoStage) -> MutationIoStatus {
        self.io[stage.index()].status()
    }

    /// Attach the original installation lease before any service or I/O effect.
    /// The canonical caller decides whether its admitted role requires a lease;
    /// this cell neither creates that authority nor moves the accepted token out.
    pub(crate) fn attach_resource(
        &mut self,
        lease: mvm_vmm::host::installed_owner::HolderLease,
    ) -> Result<()> {
        ensure!(
            self.prepared.is_none()
                && self.retiring.is_none()
                && self.io.iter().all(|io| !io.started),
            "attach original resource before service or I/O effects"
        );
        self.accepted.attach_resource(lease)
    }

    /// The canonical caller captures both full snapshots before its first I/O;
    /// neither can be replaced by a later view of partially changed state.
    pub(crate) fn capture_journal(&mut self, snapshots: JournalSnapshots) -> Result<()> {
        ensure!(
            self.operation.is_some(),
            "capture the original operation before journal snapshots"
        );
        ensure!(
            self.journal.is_none() && self.io.iter().all(|io| !io.started),
            "original journal snapshots were already captured or I/O began"
        );
        self.journal = Some(snapshots);
        Ok(())
    }

    pub(crate) fn journal_snapshots(&self) -> Result<&JournalSnapshots> {
        self.journal
            .as_ref()
            .context("original journal snapshots missing")
    }

    /// Operations supplied here are the existing canonical helper/journal
    /// calls with owned original arguments. This creates no alternate protocol.
    pub(crate) fn start_io(
        &mut self,
        stage: MutationIoStage,
        operation: impl FnOnce() -> Result<()> + Send + 'static,
    ) -> Result<()> {
        ensure!(
            self.journal.is_some(),
            "capture original journal snapshots before I/O"
        );
        ensure!(
            self.io.iter().all(|io| !io.pending()),
            "finish the original I/O before starting another effect"
        );
        self.io[stage.index()].start(operation)
    }

    pub(crate) async fn finish_io(&mut self, stage: MutationIoStage) -> Result<()> {
        self.io[stage.index()].finish().await
    }

    fn io_reconciled(&self) -> bool {
        if self.io.iter().any(RetainedIo::pending) {
            return false;
        }
        if self.io.iter().all(|io| io.failure.is_none()) {
            return true;
        }
        // The original errors remain recorded. Only actual successful rollback
        // and original-snapshot restoration resolve their uncertain effects.
        self.io[MutationIoStage::RollbackHelperRegistration.index()].succeeded()
            && self.io[MutationIoStage::JournalRestoration.index()].succeeded()
    }
}

pub(crate) type MapLoan<'a> = CustodyLoan<'a, OriginalVmMap>;
pub(crate) type MutationLoan<'a> = CustodyLoan<'a, InflightMutation>;

impl MutationCell {
    pub(crate) fn new(connection_slots: Arc<Semaphore>) -> Self {
        Self {
            inflight_mutation: CustodyField::new(),
            retiring_original_vm_map: CustodyField::retaining(OriginalVmMap {
                phase: VmMapPhase::Live,
                vms: HashMap::new(),
            }),
            connection_slots,
            stopping: AtomicBool::new(false),
        }
    }

    /// Tenant ingress fence without acquiring the map, even while it is loaned.
    /// Closing the shared budget wakes queued waiters; it is not a constant-time
    /// claim and does not cancel an already entered dispatch.
    pub(crate) fn request_stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.connection_slots.close();
    }

    pub(crate) fn stop_requested(&self) -> bool {
        self.stopping.load(Ordering::Acquire) || self.connection_slots.is_closed()
    }

    pub(crate) fn map_loan(&self) -> Result<MapLoan<'_>> {
        self.retiring_original_vm_map
            .loan()
            .context("original service map unavailable; status is unresolved")
    }

    pub(crate) fn try_contains_vm(&self, vm_id: &str) -> Result<bool> {
        // An absent live-map key does not prove absence while an original
        // mutation may retain its prepared or retiring service. Query both
        // fields in one short nonblocking observation; never await here.
        let inflight =
            self.inflight_mutation.value.try_lock().map_err(|_| {
                anyhow::anyhow!("original mutation is loaned; VM status is unresolved")
            })?;
        let mut map = self.map_loan()?;
        let original = map.value_mut();
        if original.vms.contains_key(vm_id) {
            return Ok(true);
        }
        ensure!(
            inflight.is_none() && original.phase != VmMapPhase::Retiring,
            "original preparation or retirement remains; VM status is unresolved"
        );
        Ok(false)
    }

    pub(crate) fn has_inflight_mutation(&self) -> Result<bool> {
        Ok(!self.inflight_mutation.is_vacant()?)
    }

    /// Reserve this original field before the canonical short bookkeeping
    /// callback creates accepted work. Busy refusal leaves the caller's permit
    /// untouched and creates no accepted token needing another custody slot.
    pub(crate) fn reserve_mutation(
        &self,
        permit: &mut Option<OwnedSemaphorePermit>,
        reserve_accepted: impl FnOnce() -> Result<AcceptedDaemonWork>,
    ) -> Result<MutationLoan<'_>> {
        let mut value = self
            .inflight_mutation
            .value
            .try_lock()
            .map_err(|_| CustodyError::Busy)?;
        ensure!(value.is_none(), CustodyError::Busy);
        ensure!(permit.is_some(), "original mutation permit missing");
        let accepted = reserve_accepted()?;
        *value = Some(InflightMutation {
            accepted,
            _permit: permit.take().expect("checked original mutation permit"),
            prepared: None,
            retiring: None,
            io: std::array::from_fn(|_| RetainedIo::new()),
            journal: None,
            operation: None,
        });
        Ok(CustodyLoan {
            origin: &self.inflight_mutation,
            value,
        })
    }

    pub(crate) fn mutation_loan(&self) -> Result<MutationLoan<'_>> {
        self.inflight_mutation
            .loan()
            .context("original mutation unavailable; status is unresolved")
    }

    /// Called outside daemon/FileGate locks only after all mutation resources
    /// were represented in the original map or actually retired.
    pub(crate) fn complete_mutation(&self, mut loan: MutationLoan<'_>) -> Result<()> {
        ensure!(
            std::ptr::eq(loan.origin, &self.inflight_mutation),
            "mutation belongs to another original cell"
        );
        let original = loan.value_mut();
        ensure!(
            original.prepared.is_none() && original.retiring.is_none(),
            "original mutation still retains service custody"
        );
        ensure!(
            original.io_reconciled(),
            "original mutation I/O remains unfinished or unresolved"
        );
        original.accepted.settle()?;
        ensure!(
            original.accepted.is_settled(),
            "accepted work remains unresolved"
        );
        drop(loan.complete()?);
        Ok(())
    }

    /// Capture before bind/spawn. Canonical helper RPCs and ordered journal I/O
    /// remain the caller's retained mutation work outside both outer locks.
    pub(crate) fn prepare_registration(
        &self,
        loan: &mut MutationLoan<'_>,
        snapshot: RegistrationSnapshot,
    ) -> Result<()> {
        ensure!(
            std::ptr::eq(loan.origin, &self.inflight_mutation),
            "mutation belongs to another original cell"
        );
        ensure!(
            !self.stop_requested(),
            "original service admission is stopped"
        );
        ensure!(
            Arc::ptr_eq(&snapshot.connection_slots, &self.connection_slots),
            "registration uses another tenant connection budget"
        );
        validate_registration(&snapshot.tenant, &snapshot.registration)?;
        let original = loan.value_mut();
        ensure!(
            original.operation.is_some() && original.journal.is_some(),
            "capture the original operation and journal before service preparation"
        );
        ensure!(
            original.prepared.is_none(),
            "original preparation already retained"
        );
        original.prepared = Some(PreparedRegistration::captured(snapshot));
        original
            .prepared
            .as_mut()
            .expect("captured original preparation")
            .prepare()
    }

    /// Borrow the same retained map, not a draining iterator or removed values.
    /// A canceled await leaves every original and its completion cache in place.
    pub(crate) async fn drain_services(&self) -> Result<()> {
        self.request_stop();
        // The live map can be empty while the original mutation still owns a
        // prepared or retiring service. Keep this known-vacant loan through
        // actual joins so another reservation cannot enter that gap.
        let inflight = self
            .inflight_mutation
            .value
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original mutation is loaned; drain is unresolved"))?;
        ensure!(
            inflight.is_none(),
            "original mutation remains retained; drain is unresolved"
        );
        let mut loan = self.map_loan()?;
        let map = loan.value_mut();
        if map.phase == VmMapPhase::Drained {
            return Ok(());
        }
        map.phase = VmMapPhase::Retiring;
        for handle in map.vms.values() {
            handle.request_stop();
        }
        for handle in map.vms.values_mut() {
            handle.finish_retirement().await?;
        }
        map.vms.clear();
        map.phase = VmMapPhase::Drained;
        Ok(())
    }
}

/// Registry construction is canonical and side-effect free with respect to
/// process-global assurance publication. Legacy and staged registration must
/// use this same builder; authentication remains the caller's signed control.
pub(crate) fn build_registration_registry(
    snapshot: &RegistrationSnapshot,
) -> Result<(Arc<Registry>, BoundHandlers)> {
    let r = &snapshot.registration;
    validate_registration(&snapshot.tenant, r)?;
    let proxy_services: HashSet<_> = r
        .service_proxies
        .iter()
        .map(|proxy| proxy.service.clone())
        .collect();
    let mut registry = Registry::new();
    registry
        .admit_capabilities(r.capability_bindings.clone())
        .context("load host-signed capability bindings")?;
    let local_services: Vec<_> = r
        .services_bindings
        .iter()
        .filter(|service| !proxy_services.contains(*service))
        .cloned()
        .collect();
    let bound = build_bound_handlers(&mut registry, &local_services);
    open_admitted_assurance_session(&bound, r);
    for binding in &r.service_proxies {
        let proxy = Arc::new(ControllerServiceProxy::new(binding.clone())?);
        let handler: Arc<dyn mvm_core::protocol::handler::ServiceHandler> = proxy.clone();
        registry.register(Arc::clone(&handler));
        registry.require_capability(binding.service.clone());
        for descriptor in proxy.descriptors() {
            registry
                .register_capability(Arc::clone(&handler), descriptor.clone())
                .context("register controller-backed typed capability")?;
        }
    }
    let host_audit = mvm_core::protocol::broker::ServiceId::parse("host.audit.v1")
        .expect("host.audit.v1 is a valid ServiceId");
    if r.services_bindings.contains(&host_audit) && !proxy_services.contains(&host_audit) {
        let client = if let Some(helper) = &snapshot.helper {
            Some(AuditClient::new_signer_helper(
                helper.clone(),
                r.vm_id.clone(),
            ))
        } else {
            r.audit_signer_uds_path
                .as_ref()
                .map(|signer| AuditClient::new(signer.clone()))
        };
        if let Some(client) = client {
            let handler = Arc::new(HostAuditV1Handler::new(client));
            registry.register(handler.clone());
            for descriptor in HostAuditV1Handler::capability_descriptors() {
                registry
                    .register_capability(handler.clone(), descriptor)
                    .context("register host.audit typed capability")?;
            }
        }
    }
    Ok((Arc::new(registry), bound))
}

pub(crate) struct PreparedRegistration {
    snapshot: RegistrationSnapshot,
    live: Option<LiveVmHandle>,
    start: Option<StartLatch>,
}

impl PreparedRegistration {
    fn captured(snapshot: RegistrationSnapshot) -> Self {
        let live = LiveVmHandle::unstarted(
            PathBuf::from(&snapshot.registration.broker_listen_socket),
            Arc::clone(&snapshot.connection_slots),
        );
        Self {
            snapshot,
            live: Some(live),
            start: None,
        }
    }

    fn prepare(&mut self) -> Result<()> {
        let (registry, bound) = build_registration_registry(&self.snapshot)?;
        let live = self
            .live
            .as_mut()
            .context("original prepared service missing")?;
        // Parent creation retains the canonical registration's existing path
        // semantics; no stale path is unlinked speculatively before binding.
        if let Some(parent) = live.listen_socket.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.start = Some(
            live.bind_and_suspend(
                registry,
                self.snapshot
                    .registration
                    .workload_id
                    .clone()
                    .unwrap_or_else(|| self.snapshot.registration.vm_id.clone()),
                self.snapshot.tenant.clone(),
                self.snapshot.max_frame_bytes,
                bound,
            )?,
        );
        Ok(())
    }

    pub(crate) fn registration(&self) -> &mvm_core::protocol::broker_control::RegisterVm {
        &self.snapshot.registration
    }

    /// Validate both fields before taking either. Called only in the final
    /// short commit turn; the caller immediately inserts Live in the original
    /// map before releasing StartLatch, with no await or fallible I/O between.
    pub(crate) fn take_suspended_parts(&mut self) -> Result<(LiveVmHandle, StartLatch)> {
        ensure!(
            self.live.is_some() && self.start.is_some(),
            "original service is not fully prepared"
        );
        Ok((
            self.live.take().expect("checked original service"),
            self.start.take().expect("checked original start latch"),
        ))
    }

    /// Service-only cancellation. Helper/journal reconciliation and mutation
    /// settlement remain separate original operations, never inferred here.
    pub(crate) async fn cancel_services(&mut self) -> Result<RegistrationDrainReceipt> {
        drop(self.start.take());
        self.live
            .as_mut()
            .context("service transferred to original live map")?
            .finish_retirement()
            .await
    }

    pub(crate) fn service_transferred(&self) -> bool {
        self.live.is_none() && self.start.is_none()
    }
}

#[cfg(test)]
pub(crate) struct ServiceFixture {
    pub(crate) listen_socket: PathBuf,
    pub(crate) registry: Arc<Registry>,
    pub(crate) workload_id: String,
    pub(crate) tenant_id: String,
    pub(crate) max_frame_bytes: usize,
    pub(crate) connection_slots: Arc<Semaphore>,
}

#[cfg(test)]
impl MutationCell {
    /// No production registry override. Tests retain the actual service in the
    /// same original map before using the same private bind/spawn constructor.
    pub(crate) fn install_fixture(
        &self,
        vm_id: &str,
        fixture: ServiceFixture,
    ) -> Result<StartLatch> {
        ensure!(
            !self.stop_requested(),
            "original service admission is stopped"
        );
        ensure!(
            Arc::ptr_eq(&fixture.connection_slots, &self.connection_slots),
            "fixture uses another tenant connection budget"
        );
        let mut loan = self.map_loan()?;
        let map = loan.value_mut();
        ensure!(
            map.phase == VmMapPhase::Live && !map.vms.contains_key(vm_id),
            "original VM is retained or retiring"
        );
        map.vms.insert(
            vm_id.to_owned(),
            LiveVmHandle::unstarted(fixture.listen_socket, fixture.connection_slots),
        );
        map.vms
            .get_mut(vm_id)
            .expect("captured original fixture")
            .bind_and_suspend(
                fixture.registry,
                fixture.workload_id,
                fixture.tenant_id,
                fixture.max_frame_bytes,
                BoundHandlers::default(),
            )
    }
}

/// Path cleanup follows original object identity and actual task joins; a
/// pathname's absence never supplies service or child collection authority.
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn read(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_socket(),
            "broker path is not a socket"
        );
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn matches(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

/// This private receipt follows actual original listener/connection joins.
/// It is neither admission authority nor OS-child collection evidence.
#[derive(Clone, Copy)]
pub(crate) struct RegistrationDrainReceipt {
    _joined: (),
}

pub(crate) struct LiveVmHandle {
    listen_socket: PathBuf,
    socket_identity: Option<SocketIdentity>,
    listener: Option<UnixListener>,
    listener_tasks: JoinSet<Result<()>>,
    listener_spawned: bool,
    listener_joined: bool,
    listener_failure: Option<anyhow::Error>,
    connection_owner: ServiceConnectionOwner,
    start_stop: watch::Sender<bool>,
    start_stopped: Option<watch::Receiver<bool>>,
    parked_start: Option<StartLatch>,
    socket_removed: bool,
    completed: Option<RegistrationDrainReceipt>,
}

impl LiveVmHandle {
    fn unstarted(listen_socket: PathBuf, connection_slots: Arc<Semaphore>) -> Self {
        let (start_stop, start_stopped) = watch::channel(false);
        Self {
            listen_socket,
            socket_identity: None,
            listener: None,
            listener_tasks: JoinSet::new(),
            listener_spawned: false,
            listener_joined: false,
            listener_failure: None,
            connection_owner: ServiceConnectionOwner::new(connection_slots),
            start_stop,
            start_stopped: Some(start_stopped),
            parked_start: None,
            socket_removed: false,
            completed: None,
        }
    }

    /// The containing original field/map already owns self before this call.
    fn bind_and_suspend(
        &mut self,
        registry: Arc<Registry>,
        workload_id: String,
        tenant_id: String,
        max_frame_bytes: usize,
        bound: BoundHandlers,
    ) -> Result<StartLatch> {
        ensure!(
            !self.listener_spawned && self.listener.is_none(),
            "service already prepared"
        );
        self.listener = Some(UnixListener::bind(&self.listen_socket)?);
        self.socket_identity = Some(SocketIdentity::read(&self.listen_socket)?);
        let admission = self.connection_owner.take_listener_admission()?;
        let mut stopped = self
            .start_stopped
            .take()
            .context("original start observer missing")?;
        let listener = self.listener.take().context("original listener missing")?;
        let (start, ready) = oneshot::channel();
        // Mark before spawn; a panic cannot turn an uncertain spawn into known
        // zero tasks. JoinSet retains its original task from insertion onward.
        self.listener_spawned = true;
        self.listener_tasks.spawn(async move {
            if *stopped.borrow() {
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = stopped.changed() => Ok(()),
                released = ready => {
                    if released.is_err() || *stopped.borrow() {
                        Ok(())
                    } else {
                        serve_on_listener_owned(listener, registry, workload_id, tenant_id,
                            max_frame_bytes, admission).await
                    }
                }
            }
        });
        Ok(StartLatch {
            start: Some(start),
            bound,
        })
    }

    pub(crate) fn request_stop(&self) {
        self.start_stop.send_replace(true);
        self.connection_owner.request_stop();
    }

    /// Observe the same original stop event in controlled custody tests.
    /// This neither requests stop nor proves service/Child collection.
    #[cfg(test)]
    pub(crate) fn stop_observer(&self) -> watch::Receiver<bool> {
        self.start_stop.subscribe()
    }

    /// The canonical startup caller keeps this original pair together in its
    /// retained map while Preparing. Parking never opens service admission.
    pub(crate) fn park_start(&mut self, start: StartLatch) -> Result<()> {
        ensure!(
            self.parked_start.is_none()
                && self.listener_spawned
                && !self.listener_joined
                && !*self.start_stop.borrow(),
            "original service cannot park another start latch"
        );
        self.parked_start = Some(start);
        Ok(())
    }

    /// Called only after the original generation is durably Active under its
    /// retained gate. This local release does not establish that authority.
    pub(crate) fn release_parked_start(&mut self) -> Result<()> {
        ensure!(
            !*self.start_stop.borrow(),
            "original service admission is stopped"
        );
        self.parked_start
            .take()
            .context("original parked start latch unavailable")?
            .release()
    }

    /// Cached original-owner shape for the final short preparation check.
    /// This performs no pathname I/O and is not readiness or authority proof;
    /// releasing the original latch can still refuse a failed listener.
    pub(crate) fn is_parked_at(&self, path: &Path) -> bool {
        self.listen_socket == path
            && self.parked_start.is_some()
            && self.socket_identity.is_some()
            && self.listener_spawned
            && !self.listener_joined
            && !*self.start_stop.borrow()
            && !self.socket_removed
            && self.completed.is_none()
    }

    /// Cached association to this original owner, retained after actual joins.
    /// This performs no pathname lookup and proves neither current filesystem
    /// ownership nor historical crash provenance, authority or collection.
    pub(crate) fn matches_original_endpoint(&self, path: &Path) -> bool {
        self.listen_socket == path && self.socket_identity.is_some()
    }

    pub(crate) fn retire(self) -> RetiringRegistration {
        self.request_stop();
        RetiringRegistration { live: self }
    }

    pub(crate) async fn finish_retirement(&mut self) -> Result<RegistrationDrainReceipt> {
        if let Some(receipt) = self.completed {
            return Ok(receipt);
        }
        self.request_stop();
        drop(self.parked_start.take());
        if !self.listener_joined {
            if self.listener_spawned {
                match self.listener_tasks.join_next().await {
                    Some(Ok(Ok(()))) => self.listener_joined = true,
                    Some(Ok(Err(error))) => {
                        self.listener_joined = true;
                        self.listener_failure = Some(error);
                    }
                    Some(Err(error)) => {
                        self.listener_joined = true;
                        self.listener_failure = Some(error.into());
                    }
                    None => anyhow::bail!("original listener completion unavailable"),
                }
            } else {
                // Known not spawned: the exact bound descriptor is still here.
                drop(self.listener.take());
                self.listener_joined = true;
            }
        }
        self.connection_owner.drain().await?;
        ensure!(
            self.listener_failure.is_none(),
            "original listener failed; retirement unresolved"
        );
        if !self.socket_removed {
            match SocketIdentity::read(&self.listen_socket) {
                Ok(current) => {
                    let original = self
                        .socket_identity
                        .as_ref()
                        .context("original socket identity unavailable")?;
                    ensure!(
                        original.matches(&current),
                        "broker socket path was replaced"
                    );
                    std::fs::remove_file(&self.listen_socket)?;
                }
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
                Err(error) => return Err(error),
            }
            self.socket_removed = true;
        }
        let receipt = RegistrationDrainReceipt { _joined: () };
        self.completed = Some(receipt);
        Ok(receipt)
    }
}

pub(crate) struct RetiringRegistration {
    live: LiveVmHandle,
}

impl RetiringRegistration {
    pub(crate) fn matches_original_endpoint(&self, path: &Path) -> bool {
        self.live.matches_original_endpoint(path)
    }

    pub(crate) async fn finish(&mut self) -> Result<RegistrationDrainReceipt> {
        self.live.finish_retirement().await
    }
}

pub(crate) struct StartLatch {
    start: Option<oneshot::Sender<()>>,
    bound: BoundHandlers,
}

impl StartLatch {
    /// The caller first inserts the original service under its final canonical
    /// generation/authority check. This only releases that suspended service.
    pub(crate) fn release(mut self) -> Result<()> {
        let publication = self.bound.reserve_publication()?;
        let Some(start) = self.start.take() else {
            drop(publication);
            anyhow::bail!("original service start latch missing");
        };
        if start.send(()).is_err() {
            drop(publication);
            anyhow::bail!("original suspended listener unavailable");
        }
        publication.commit();
        Ok(())
    }
}

/// This is a borrow of the retained field, never a second owner of its value.
/// Drop and unwind leave the Option untouched. Only explicit completion takes
/// the original; service-specific callers must establish their actual outcome.
pub(crate) struct CustodyLoan<'a, T> {
    origin: &'a CustodyField<T>,
    value: MutexGuard<'a, Option<T>>,
}

impl<T> CustodyLoan<'_, T> {
    pub(crate) fn value_mut(&mut self) -> &mut T {
        self.value
            .as_mut()
            .expect("loan retains its original value")
    }

    fn complete(mut self) -> Result<T, CustodyError> {
        self.value.take().ok_or(CustodyError::Empty)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::CustodyField;

    #[derive(Debug)]
    struct Original {
        id: usize,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for Original {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn original(id: usize, drops: &Arc<AtomicUsize>) -> Original {
        Original {
            id,
            drops: Arc::clone(drops),
        }
    }

    #[test]
    fn original_operation_capture_survives_unwind_and_refuses_replacement() {
        use mvm_core::protocol::broker_control::{self, ControlRequest, DeregisterVm};
        use mvm_core::tenant_lifecycle::{
            LifecycleCoordinator, LifecycleGeneration, TenantLifecycleGate,
        };
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        // Storage/ledger fixture only: activation here supplies no service,
        // native admission or original-child collection evidence.
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let generation = LifecycleGeneration::new([81; 32], 1).unwrap();
        let deadline = || Instant::now() + Duration::from_secs(1);
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            directory.path(),
            "local",
            generation.clone(),
            256,
            deadline(),
        )
        .unwrap();
        coordinator
            .activate_after_reconciliation(&generation, deadline())
            .unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[82; 32]);
        let mut daemon =
            crate::broker::daemon::HostAgentDaemon::new("local", signing.verifying_key(), 65_536)
                .with_lifecycle_coordination(directory.path(), generation.clone())
                .unwrap();
        let gate = TenantLifecycleGate::new(directory.path(), "local").unwrap();
        gate.with_active(&generation, deadline(), || {
            daemon.open_local_admission(&generation)
        })
        .unwrap();
        let lane = daemon.mutation_lane();
        let mut permit = Some(lane.clone().try_acquire_owned().unwrap());
        let descriptor = |vm: &str| {
            let request = ControlRequest::Deregister(DeregisterVm { vm_id: vm.into() });
            let signed = broker_control::sign(request.clone(), &signing.to_bytes()).unwrap();
            daemon
                .original_operation_descriptor(request, Some(signed), None)
                .unwrap()
        };
        let first = descriptor("vm-original");
        let replacement = descriptor("vm-replacement");
        let cell = super::MutationCell::new(Arc::new(tokio::sync::Semaphore::new(256)));
        let mut loan = cell
            .reserve_mutation(&mut permit, || daemon.reserve_accepted_work(&generation))
            .unwrap();
        loan.value_mut().capture_operation(first).unwrap();
        let no_effect = loan
            .value_mut()
            .io_status(super::MutationIoStage::HelperRetirement)
            == super::MutationIoStatus::NotStarted;
        drop(loan);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut loan = cell.mutation_loan().unwrap();
            assert_eq!(loan.value_mut().operation().unwrap().vm_id(), "vm-original");
            panic!("controlled original-operation waiter unwind");
        }));
        let mut loan = cell.mutation_loan().unwrap();
        let rejected = loan.value_mut().capture_operation(replacement).is_err();
        let original = loan.value_mut().operation().unwrap();
        let same_vm = original.vm_id() == "vm-original";
        let same_tenant = original.tenant() == "local";
        let same_generation = original.generation() == Some(&generation);
        let charged = lane.available_permits();
        // Explicitly settle the SAME no-effect original before assertions.
        cell.complete_mutation(loan).unwrap();
        assert!(unwound.is_err());
        assert!(
            rejected,
            "a second operation cannot replace the original recipe"
        );
        assert!(same_vm && same_tenant && same_generation);
        assert!(no_effect, "descriptor capture starts no helper effect");
        assert_eq!(
            charged, 0,
            "unwinding cannot refund original mutation credit"
        );
        assert_eq!(lane.available_permits(), 1);
        assert!(!daemon.has_accepted_work().unwrap());
    }

    // Occupied/loaned mutation rejection is tested through actual atomic
    // reservation in daemon::token_tests, including callback/row/permit custody.
    // These generic tests exercise the production retaining constructor/loan.
    #[test]
    fn canceled_loan_restores_the_same_original_field_without_dropping_it() {
        let drops = Arc::new(AtomicUsize::new(0));
        let field = CustodyField::retaining(original(7, &drops));
        {
            let mut loan = field.loan().expect("borrow original custody");
            assert_eq!(loan.value_mut().id, 7);
            assert!(field.is_vacant().is_err(), "loaned is unknown, not empty");
        }
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!field.is_vacant().expect("retained original"));
        let mut retry = field.loan().expect("explicit same-owner cleanup retry");
        assert_eq!(retry.value_mut().id, 7);
        let released = retry.complete().expect("complete original memory custody");
        assert!(field.is_vacant().expect("completed field"));
        drop(released);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unwinding_restores_original_custody_before_an_explicit_retry() {
        let drops = Arc::new(AtomicUsize::new(0));
        let field = CustodyField::retaining(original(7, &drops));
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut loan = field.loan().expect("original loan");
            assert_eq!(loan.value_mut().id, 7);
            panic!("controlled preparation unwind");
        }));
        assert!(failed.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!field.is_vacant().expect("original restored after unwind"));
        let mut retry = field.loan().expect("retry the same retained object");
        assert_eq!(retry.value_mut().id, 7);
        drop(retry.complete().expect("original completion"));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cached_endpoint_association_survives_original_retirement_without_path_lookup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.sock");
        let other = directory.path().join("other.sock");
        let slots = Arc::new(tokio::sync::Semaphore::new(256));
        let unstarted = super::LiveVmHandle::unstarted(path.clone(), Arc::clone(&slots));
        let unbound_matches = unstarted.matches_original_endpoint(&path);
        drop(unstarted);

        let cell = super::MutationCell::new(Arc::clone(&slots));
        let start = cell
            .install_fixture(
                "vm-original",
                super::ServiceFixture {
                    listen_socket: path.clone(),
                    registry: Arc::new(crate::broker::registry::Registry::new()),
                    workload_id: "original-workload".into(),
                    tenant_id: "original-tenant".into(),
                    max_frame_bytes: 65_536,
                    connection_slots: Arc::clone(&slots),
                },
            )
            .unwrap();
        let mut map = cell.map_loan().unwrap();
        let live = map.value_mut().vms.get("vm-original").unwrap();
        let live_matches = live.matches_original_endpoint(&path);
        let live_rejects_other = !live.matches_original_endpoint(&other);
        // The fixture retains this SAME original owner through actual joins.
        // Production moves it into the existing retained mutation field.
        let mut retiring = map.value_mut().vms.remove("vm-original").unwrap().retire();
        drop(map);
        let retiring_matches = retiring.matches_original_endpoint(&path);
        let retiring_rejects_other = !retiring.matches_original_endpoint(&other);
        tokio::time::timeout(std::time::Duration::from_secs(1), retiring.finish())
            .await
            .unwrap()
            .unwrap();
        drop(start);
        // The pathname is gone, but the original wrapper still carries its
        // cached association. This is NOT current filesystem ownership,
        // historical crash provenance, authority or a new collection receipt.
        let joined_matches = retiring.matches_original_endpoint(&path);
        assert!(!path.exists());
        assert!(!unbound_matches);
        assert!(live_matches && live_rejects_other);
        assert!(retiring_matches && retiring_rejects_other && joined_matches);
        assert_eq!(slots.available_permits(), 256);
    }

    #[tokio::test]
    async fn parked_start_defers_typed_dispatch_and_original_assurance_publication() {
        use tokio::io::AsyncWriteExt;
        const CHILD: &str = "MVM_TEST_PARKED_BROKER_START";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "broker::control_prepare::tests::parked_start_defers_typed_dispatch_and_original_assurance_publication",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "isolated original publication fixture");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("parked.sock");
        let slots = Arc::new(tokio::sync::Semaphore::new(256));
        let cell = super::MutationCell::new(Arc::clone(&slots));
        let handler = Arc::new(crate::broker::server::tests::HeldDispatch::new());
        let registry = crate::broker::server::tests::held_registry(Arc::clone(&handler));
        let mut registry = Arc::try_unwrap(registry).ok().unwrap();
        let service = mvm_core::protocol::broker::ServiceId::parse(
            crate::broker::handlers::host_assurance_v1::HOST_ASSURANCE_SERVICE,
        )
        .unwrap();
        let bound = super::build_bound_handlers(&mut registry, &[service]);
        let original_assurance = Arc::clone(bound.assurance.as_ref().unwrap());
        let mut map = cell.map_loan().unwrap();
        map.value_mut().vms.insert(
            "vm-original".into(),
            super::LiveVmHandle::unstarted(path.clone(), Arc::clone(&slots)),
        );
        let live = map.value_mut().vms.get_mut("vm-original").unwrap();
        let start = live
            .bind_and_suspend(
                Arc::new(registry),
                "workload".into(),
                "tenant".into(),
                65_536,
                bound,
            )
            .unwrap();
        live.park_start(start).unwrap();
        drop(map);
        let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let body = serde_json::to_vec(&crate::broker::server::tests::held_call()).unwrap();
        client
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&body).await.unwrap();
        let early = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            handler.entered_at_least(1),
        )
        .await;
        let early_plane = crate::assurance_session::host_assurance_plane();
        // A dropped preparation loan must leave the same parked latch in Live.
        let mut map = cell.map_loan().unwrap();
        map.value_mut()
            .vms
            .get_mut("vm-original")
            .unwrap()
            .release_parked_start()
            .unwrap();
        drop(map);
        let entered = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handler.entered_at_least(1),
        )
        .await;
        let published = crate::assurance_session::host_assurance_plane();
        cell.request_stop();
        let canceled =
            tokio::time::timeout(std::time::Duration::from_millis(20), cell.drain_services()).await;
        let held = slots.available_permits();
        handler.release_dispatches(1);
        tokio::time::timeout(std::time::Duration::from_secs(1), cell.drain_services())
            .await
            .unwrap()
            .unwrap();
        assert!(early.is_err(), "parked listener must not dispatch");
        assert!(early_plane.is_none(), "parked assurance must not publish");
        entered.unwrap();
        assert!(Arc::ptr_eq(&original_assurance, &published.unwrap()));
        assert!(canceled.is_err(), "actual admitted handler remains owned");
        assert_eq!(
            held, 255,
            "canceled drain retains original connection credit"
        );
        assert_eq!(handler.completed_count(), 1);
        assert_eq!(slots.available_permits(), 256);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn stopping_a_parked_start_joins_without_releasing_the_original_latch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("parked-stop.sock");
        let slots = Arc::new(tokio::sync::Semaphore::new(256));
        let cell = super::MutationCell::new(Arc::clone(&slots));
        let start = cell
            .install_fixture(
                "vm-original",
                super::ServiceFixture {
                    listen_socket: path.clone(),
                    registry: Arc::new(crate::broker::registry::Registry::new()),
                    workload_id: "workload".into(),
                    tenant_id: "tenant".into(),
                    max_frame_bytes: 65_536,
                    connection_slots: Arc::clone(&slots),
                },
            )
            .unwrap();
        let mut map = cell.map_loan().unwrap();
        map.value_mut()
            .vms
            .get_mut("vm-original")
            .unwrap()
            .park_start(start)
            .unwrap();
        drop(map);
        cell.request_stop();
        tokio::time::timeout(std::time::Duration::from_secs(1), cell.drain_services())
            .await
            .unwrap()
            .unwrap();
        assert!(!path.exists());
        assert_eq!(slots.available_permits(), 256);
    }

    #[tokio::test]
    async fn stopping_an_unreleased_registration_joins_its_original_listener() {
        let directory = tempfile::tempdir().expect("owned socket fixture");
        let path = directory.path().join("suspended.sock");
        let slots = Arc::new(tokio::sync::Semaphore::new(256));
        let cell = super::MutationCell::new(Arc::clone(&slots));
        let latch = cell
            .install_fixture(
                "vm-original",
                super::ServiceFixture {
                    listen_socket: path.clone(),
                    registry: Arc::new(crate::broker::registry::Registry::new()),
                    workload_id: "original-workload".into(),
                    tenant_id: "original-tenant".into(),
                    max_frame_bytes: 65_536,
                    connection_slots: Arc::clone(&slots),
                },
            )
            .expect("capture the original suspended service in its map");
        assert!(path.exists(), "fixture must own an actual bound listener");
        cell.request_stop();
        let stopped =
            tokio::time::timeout(std::time::Duration::from_secs(1), cell.drain_services()).await;
        // A broken cancel-start wake must not strand the fixture. Dropping
        // the original sender allows its original listener to finish; collect
        // that exact owner before reporting a failed first drain.
        drop(latch);
        tokio::time::timeout(std::time::Duration::from_secs(1), cell.drain_services())
            .await
            .expect("fixture cleanup deadline")
            .expect("original fixture service cleanup");
        stopped
            .expect("stop must wake the original listener before latch release")
            .expect("original service drain");
        assert!(!path.exists(), "remove only the joined original socket");
        assert!(!cell.try_contains_vm("vm-original").expect("completed map"));
    }

    #[tokio::test]
    async fn a_stopped_cell_refuses_new_registration_before_binding() {
        let directory = tempfile::tempdir().expect("owned socket fixture");
        let path = directory.path().join("refused.sock");
        let slots = Arc::new(tokio::sync::Semaphore::new(256));
        let cell = super::MutationCell::new(Arc::clone(&slots));
        cell.request_stop();
        let refused = cell.install_fixture(
            "vm-refused",
            super::ServiceFixture {
                listen_socket: path.clone(),
                registry: Arc::new(crate::broker::registry::Registry::new()),
                workload_id: "original-workload".into(),
                tenant_id: "original-tenant".into(),
                max_frame_bytes: 65_536,
                connection_slots: Arc::clone(&slots),
            },
        );
        assert!(refused.is_err(), "stop fences new listener creation");
        assert!(!path.exists(), "refusal must precede actual socket bind");
        cell.drain_services()
            .await
            .expect("known empty original map");
    }

    #[tokio::test]
    async fn a_registration_cannot_substitute_another_tenants_ingress_budget() {
        let directory = tempfile::tempdir().expect("owned socket fixture");
        let path = directory.path().join("foreign-budget.sock");
        let original_slots = Arc::new(tokio::sync::Semaphore::new(256));
        let other_slots = Arc::new(tokio::sync::Semaphore::new(256));
        let cell = super::MutationCell::new(Arc::clone(&original_slots));
        let refused = cell.install_fixture(
            "vm-foreign-budget",
            super::ServiceFixture {
                listen_socket: path.clone(),
                registry: Arc::new(crate::broker::registry::Registry::new()),
                workload_id: "original-workload".into(),
                tenant_id: "original-tenant".into(),
                max_frame_bytes: 65_536,
                connection_slots: other_slots,
            },
        );
        assert!(
            refused.is_err(),
            "a foreign budget would mint extra capacity"
        );
        assert!(!path.exists(), "budget refusal must precede socket bind");
        assert_eq!(original_slots.available_permits(), 256);
        cell.request_stop();
        cell.drain_services()
            .await
            .expect("known empty original map");
    }

    #[tokio::test]
    async fn canceled_io_wait_retains_and_finishes_the_same_blocking_operation() {
        let mut io = super::RetainedIo::new();
        assert_eq!(io.status(), super::MutationIoStatus::NotStarted);
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let original_gate = Arc::clone(&gate);
        let launches = Arc::new(AtomicUsize::new(0));
        let original_launches = Arc::clone(&launches);
        let (entered, started) = tokio::sync::oneshot::channel();
        io.start(move || {
            original_launches.fetch_add(1, Ordering::SeqCst);
            let _ = entered.send(());
            let (released, changed) = &*original_gate;
            let held = released.lock().expect("fixture release lock");
            let (_held, result) = changed
                .wait_timeout_while(held, std::time::Duration::from_secs(5), |released| {
                    !*released
                })
                .expect("fixture blocking operation");
            anyhow::ensure!(!result.timed_out(), "fixture release deadline");
            Ok(())
        })
        .expect("capture and start original operation");
        assert_eq!(io.status(), super::MutationIoStatus::Pending);
        let began = tokio::time::timeout(std::time::Duration::from_secs(1), started).await;
        let canceled =
            tokio::time::timeout(std::time::Duration::from_millis(20), io.finish()).await;
        // Always release and join the actual original operation before checking
        // the timeout, including a failing counterfactual fixture run.
        *gate.0.lock().expect("fixture release lock") = true;
        gate.1.notify_all();
        tokio::time::timeout(std::time::Duration::from_secs(5), io.finish())
            .await
            .expect("original I/O cleanup deadline")
            .expect("original I/O completion");
        began
            .expect("original operation began")
            .expect("original start signal");
        assert!(
            canceled.is_err(),
            "a canceled waiter must not finish the held operation"
        );
        assert!(io.succeeded());
        assert_eq!(io.status(), super::MutationIoStatus::Succeeded);
        io.finish().await.expect("cached original completion");
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rollback_io_executes_a_distinct_effect_after_new_registration() {
        use super::MutationIoStage as Stage;
        let directory = tempfile::tempdir().expect("owned I/O fixture");
        let journal = directory.path().join("journal");
        let helper = directory.path().join("helper");
        let mut stages: [super::RetainedIo; 5] = std::array::from_fn(|_| super::RetainedIo::new());
        for (stage, path, body) in [
            (Stage::HelperRetirement, helper.clone(), "old-deregister"),
            (Stage::HelperRegistration, helper.clone(), "new-register"),
            (Stage::JournalPublication, journal.clone(), "candidate"),
            (
                Stage::RollbackHelperRegistration,
                helper.clone(),
                "new-deregister",
            ),
            (Stage::JournalRestoration, journal.clone(), "original"),
        ] {
            let effect_path = path.clone();
            stages[stage.index()]
                .start(move || {
                    std::fs::write(effect_path, body)?;
                    Ok(())
                })
                .expect("each distinct original stage starts once");
            stages[stage.index()]
                .finish()
                .await
                .expect("actual stage I/O joined");
            assert_eq!(std::fs::read_to_string(path).expect("actual effect"), body);
        }
        assert!(stages.iter().all(super::RetainedIo::succeeded));
        assert_eq!(
            std::fs::read_to_string(helper).expect("rollback effect"),
            "new-deregister"
        );
        assert_eq!(
            std::fs::read_to_string(journal).expect("restored effect"),
            "original"
        );
    }

    #[tokio::test]
    async fn failed_io_retains_original_error_and_cannot_replay_its_stage() {
        let mut io = super::RetainedIo::new();
        io.start(|| anyhow::bail!("original controlled I/O refusal"))
            .expect("original attempt");
        assert!(io.finish().await.is_err());
        assert!(!io.pending());
        assert!(!io.succeeded());
        assert_eq!(io.status(), super::MutationIoStatus::Failed);
        let original = io.failure.as_ref().expect("retained original error") as *const _;
        assert!(io.finish().await.is_err());
        assert!(std::ptr::eq(
            original,
            io.failure.as_ref().expect("same original error")
        ));
        let replay = io.start(|| Ok(()));
        if replay.is_ok() {
            // Collect an unexpected replay before reporting the failed guard.
            while io.tasks.join_next().await.is_some() {}
        }
        assert!(
            replay.is_err(),
            "the same stage must not manufacture a second effect"
        );
    }
}
