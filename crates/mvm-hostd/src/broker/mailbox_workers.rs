//! Bounded ownership of original mailbox worker children. An explicitly
//! provisioned installation binds the canonical helper, resource epoch and
//! local workload. Signed controls carry no private key material.
//! Collected status is local process evidence, not a mailbox delivery receipt.
//! Drop hands original custody to one charged host-budget actor; that handoff
//! is asynchronous. A collected child receipt requires original custody and
//! a checked exit status.
mod owned_factory;
use mvm_core::protocol::mailbox_worker_control::*;
use mvm_vmm::host::process_exit::{
    ProcessExitObserver, ProcessExitWait, collect_after_exit_event, require_owned_child_custody,
    wait_process_exit_events,
};
pub use owned_factory::{InstalledMailboxWorkerFactory, OwnedMailboxWorkerFactory};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const CONTROL_WORKSPACE_BYTES: usize = MAX_WORKER_CONTROL_BYTES * 5;
const TERMINAL_RETENTION: std::time::Duration = std::time::Duration::from_secs(60);
const ACTOR_STACK_BYTES: usize = 128 * 1024;
const ACTOR_CELL_BYTES: usize = 1024;

fn refused(message: &str) -> io::Error {
    io::Error::other(message)
}
fn lock<T>(mutex: &Mutex<T>) -> io::Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| refused("mailbox owner state poisoned"))
}

/// Limits belong to the original shared host budget, never a per-VM mint.
#[derive(Clone, Copy, Debug)]
pub struct WorkerLimits {
    pub host_workers: usize,
    pub tenant_workers: usize,
    pub host_bytes: usize,
    pub tenant_bytes: usize,
    pub bytes_per_worker: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkerUsage {
    pub workers: usize,
    pub bytes: usize,
}
#[derive(Default)]
struct Ledger {
    host: WorkerUsage,
    tenants: HashMap<String, WorkerUsage>,
    registrations: HashMap<(String, String), usize>,
    host_controls: usize,
    tenant_controls: HashMap<String, usize>,
}
/// One shared ledger/clock must be injected into every tenant owner. This
/// in-process provider does not establish cross-process/global host accounting.
pub struct MailboxWorkerBudget {
    limits: WorkerLimits,
    ledger: Arc<Mutex<Ledger>>,
    origin: Instant,
    unix_origin_ms: u64,
    clock_high_water: Mutex<u64>,
    cleanup: Arc<CleanupState>,
    sender: Mutex<Option<mpsc::SyncSender<CleanupCell>>>,
    wake: Mutex<Option<UnixStream>>,
    actor: Mutex<Option<std::thread::JoinHandle<()>>>,
}
#[derive(Default)]
struct CleanupCell {
    slot: Option<Arc<Mutex<Slot>>>,
}
struct CleanupState {
    ledger: Arc<Mutex<Ledger>>,
    pool: Mutex<Vec<CleanupCell>>,
    emergency: Mutex<Vec<CleanupCell>>,
    failed: Arc<AtomicBool>,
    running: AtomicBool,
    limits: WorkerLimits,
    actor_charge: usize,
}
impl MailboxWorkerBudget {
    pub fn new(limits: WorkerLimits) -> io::Result<Arc<Self>> {
        let actor_charge = limits
            .host_workers
            .checked_mul(ACTOR_CELL_BYTES)
            .and_then(|bytes| bytes.checked_add(ACTOR_STACK_BYTES + 4096))
            .ok_or_else(|| refused("actor reservation overflow"))?;
        if limits.host_workers == 0
            || limits.tenant_workers == 0
            || limits.tenant_workers > limits.host_workers
            || limits.host_workers > 1024
            || limits.bytes_per_worker < MAX_WORKER_CONTROL_BYTES
            || limits.host_bytes > 1024 * 1024 * 1024
            || limits.tenant_bytes > limits.host_bytes
            || limits
                .bytes_per_worker
                .checked_add(CONTROL_WORKSPACE_BYTES)
                .is_none_or(|v| v > limits.tenant_bytes || v > limits.host_bytes)
            || actor_charge
                .checked_add(limits.bytes_per_worker)
                .and_then(|v| v.checked_add(CONTROL_WORKSPACE_BYTES))
                .is_none_or(|v| v > limits.host_bytes)
        {
            return Err(refused("invalid shared mailbox worker limits"));
        }
        let unix_origin_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refused("host clock precedes Unix epoch"))?
            .as_millis()
            .try_into()
            .map_err(|_| refused("host clock overflow"))?;
        let ledger = Arc::new(Mutex::new(Ledger {
            host: WorkerUsage {
                workers: 0,
                bytes: actor_charge,
            },
            ..Ledger::default()
        }));
        let cleanup = Arc::new(CleanupState {
            ledger: ledger.clone(),
            pool: Mutex::new(
                (0..limits.host_workers)
                    .map(|_| CleanupCell::default())
                    .collect(),
            ),
            emergency: Mutex::new(Vec::with_capacity(limits.host_workers)),
            failed: Arc::new(AtomicBool::new(false)),
            running: AtomicBool::new(true),
            limits,
            actor_charge,
        });
        let (wake_reader, wake_writer) = UnixStream::pair()?;
        wake_reader.set_nonblocking(true)?;
        wake_writer.set_nonblocking(true)?;
        let (sender, receiver) = mpsc::sync_channel(limits.host_workers);
        let actor_state = cleanup.clone();
        let actor = std::thread::Builder::new()
            .name("mailbox-owned-cleanup".into())
            .stack_size(ACTOR_STACK_BYTES)
            .spawn(move || {
                // Receiver/pending cells outlive unwinding of a single iteration.
                // An actor failure retains original children and charged state.
                let mut pending = Vec::with_capacity(limits.host_workers);
                let mut wake_reader = wake_reader;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    cleanup_loop(&actor_state, &receiver, &mut pending, &mut wake_reader)
                }));
                if !matches!(result, Ok(Ok(()))) {
                    actor_state.failed.store(true, Ordering::Release);
                    loop {
                        std::thread::park();
                    }
                }
                actor_state.running.store(false, Ordering::Release);
            })?;
        Ok(Arc::new(Self {
            limits,
            ledger,
            origin: Instant::now(),
            unix_origin_ms,
            clock_high_water: Mutex::new(unix_origin_ms),
            cleanup,
            sender: Mutex::new(Some(sender)),
            wake: Mutex::new(Some(wake_writer)),
            actor: Mutex::new(Some(actor)),
        }))
    }
    pub fn usage(&self) -> io::Result<WorkerUsage> {
        Ok(lock(&self.ledger)?.host)
    }
    /// Trusted shared monotonic clock anchored to actual canonical Unix time.
    pub fn now_unix_ms(&self) -> io::Result<u64> {
        let elapsed: u64 = self
            .origin
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| refused("mailbox clock overflow"))?;
        let monotonic = self
            .unix_origin_ms
            .checked_add(elapsed)
            .ok_or_else(|| refused("mailbox clock overflow"))?;
        let wall: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refused("host clock precedes Unix epoch"))?
            .as_millis()
            .try_into()
            .map_err(|_| refused("host clock overflow"))?;
        let mut high = lock(&self.clock_high_water)?;
        *high = (*high).max(monotonic).max(wall);
        Ok(*high)
    }
    fn charge(&self, tenant: &str, vm: Option<&str>) -> io::Result<Option<CleanupCell>> {
        if self.cleanup.failed.load(Ordering::Acquire) {
            return Err(refused("cleanup owner unavailable"));
        }
        let worker = vm.is_some();
        let mut ledger = lock(&self.ledger)?;
        if let Some(vm) = vm
            && ledger
                .registrations
                .contains_key(&(tenant.to_owned(), vm.to_owned()))
        {
            return Err(refused("original budget already owns this tenant/VM"));
        }
        let old = ledger.tenants.get(tenant).copied().unwrap_or_default();
        let bytes = if worker {
            self.limits.bytes_per_worker
        } else {
            CONTROL_WORKSPACE_BYTES
        };
        let host_headroom = if worker {
            CONTROL_WORKSPACE_BYTES.saturating_sub(ledger.host_controls)
        } else {
            0
        };
        let tenant_headroom = if worker {
            CONTROL_WORKSPACE_BYTES
                .saturating_sub(ledger.tenant_controls.get(tenant).copied().unwrap_or(0))
        } else {
            0
        };
        let host_bytes = ledger
            .host
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| refused("budget overflow"))?;
        let tenant_bytes = old
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| refused("budget overflow"))?;
        if host_bytes
            .checked_add(host_headroom)
            .is_none_or(|v| v > self.limits.host_bytes)
            || tenant_bytes
                .checked_add(tenant_headroom)
                .is_none_or(|v| v > self.limits.tenant_bytes)
            || (worker
                && (ledger.host.workers >= self.limits.host_workers
                    || old.workers >= self.limits.tenant_workers))
        {
            return Err(refused("shared mailbox worker budget exhausted"));
        }
        let cell = if worker {
            Some(
                lock(&self.cleanup.pool)?
                    .pop()
                    .ok_or_else(|| refused("original cleanup cells exhausted"))?,
            )
        } else {
            None
        };
        ledger.host.bytes = host_bytes;
        ledger.host.workers += usize::from(worker);
        if let Some(vm) = vm {
            ledger
                .registrations
                .insert((tenant.to_owned(), vm.to_owned()), bytes);
        } else {
            ledger.host_controls += CONTROL_WORKSPACE_BYTES;
            *ledger.tenant_controls.entry(tenant.to_owned()).or_default() +=
                CONTROL_WORKSPACE_BYTES;
        }
        ledger.tenants.insert(
            tenant.to_owned(),
            WorkerUsage {
                workers: old.workers + usize::from(worker),
                bytes: tenant_bytes,
            },
        );
        Ok(cell)
    }
    fn release_control(&self, tenant: &str) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.host.bytes -= CONTROL_WORKSPACE_BYTES;
            ledger.host_controls -= CONTROL_WORKSPACE_BYTES;
            if let Some(bytes) = ledger.tenant_controls.get_mut(tenant) {
                *bytes -= CONTROL_WORKSPACE_BYTES;
            }
            if ledger.tenant_controls.get(tenant) == Some(&0) {
                ledger.tenant_controls.remove(tenant);
            }
            if let Some(usage) = ledger.tenants.get_mut(tenant) {
                usage.bytes -= CONTROL_WORKSPACE_BYTES;
            }
            if ledger
                .tenants
                .get(tenant)
                .is_some_and(|usage| usage.bytes == 0 && usage.workers == 0)
            {
                ledger.tenants.remove(tenant);
            }
        }
    }
    fn collected(&self, tenant: &str) -> io::Result<()> {
        release_worker_credit(&self.ledger, tenant)
    }
    fn retire(&self, tenant: &str, vm: &str) -> io::Result<()> {
        retire_worker_state(&self.ledger, tenant, vm)
    }
    fn return_cell(&self, mut cell: CleanupCell) {
        cell.slot = None;
        let mut pool = self
            .cleanup
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pool.len() < self.limits.host_workers {
            pool.push(cell);
        }
    }
    fn handoff(&self, cell: CleanupCell) {
        // Each original reservation owns one unique cell. At most N cells
        // exist; a channel of capacity N cannot be full with another in hand.
        // Still retain the returned cell on every transport failure.
        let sender = self
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let returned = match sender.as_ref() {
            Some(sender) => match sender.try_send(cell) {
                Ok(()) => None,
                Err(mpsc::TrySendError::Full(cell) | mpsc::TrySendError::Disconnected(cell)) => {
                    Some(cell)
                }
            },
            None => Some(cell),
        };
        drop(sender);
        if let Some(cell) = returned {
            self.cleanup.failed.store(true, Ordering::Release);
            let mut emergency = self
                .cleanup
                .emergency
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Unique preallocated tokens bound emergency + queue + active
            // cells together by N; this push never requires growth.
            emergency.push(cell);
        }
        let mut wake_endpoint = self
            .wake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(wake) = wake_endpoint.as_mut() {
            // WouldBlock means a prior notification is already readable. The
            // cell is retained before notification, including every error.
            if notify_handoff(|| wake.write(&[1])).is_err() {
                self.cleanup.failed.store(true, Ordering::Release);
                // Closing the sole producer endpoint wakes the actor with EOF.
                // Its next loop drains every retained cell before any wait.
                wake_endpoint.take();
            }
        }
    }
}
fn notify_handoff(mut write: impl FnMut() -> io::Result<usize>) -> io::Result<()> {
    for _ in 0..16 {
        match write() {
            Ok(1) => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "missing wake marker",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            // Only canonical notification bytes use this private socketpair;
            // a full nonblocking send buffer guarantees an earlier wake byte.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "wake interruption budget exhausted",
    ))
}
impl Drop for MailboxWorkerBudget {
    fn drop(&mut self) {
        // The actor owns no provider or Sender. Disconnect wakes a final scan;
        // dropping this JoinHandle is NOT a collected receipt. The actor keeps
        // its original children/ledger alive until collection (or quarantine).
        self.sender
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.wake
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.actor
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}
fn release_worker_credit(ledger: &Mutex<Ledger>, tenant: &str) -> io::Result<()> {
    let mut ledger = lock(ledger)?;
    if ledger.host.workers == 0
        || ledger
            .tenants
            .get(tenant)
            .is_none_or(|usage| usage.workers == 0)
    {
        return Err(refused("missing original worker credit"));
    }
    ledger.host.workers -= 1;
    ledger
        .tenants
        .get_mut(tenant)
        .expect("validated above")
        .workers -= 1;
    Ok(())
}
fn retire_worker_state(ledger: &Mutex<Ledger>, tenant: &str, vm: &str) -> io::Result<()> {
    let mut ledger = lock(ledger)?;
    let key = (tenant.to_owned(), vm.to_owned());
    let bytes = *ledger
        .registrations
        .get(&key)
        .ok_or_else(|| refused("missing original reservation"))?;
    refund_bytes(&mut ledger, tenant, bytes)?;
    ledger.registrations.remove(&key);
    Ok(())
}
fn refund_bytes(ledger: &mut Ledger, tenant: &str, bytes: usize) -> io::Result<()> {
    if ledger.host.bytes < bytes || ledger.tenants.get(tenant).is_none_or(|u| u.bytes < bytes) {
        return Err(refused("missing original byte credit"));
    }
    ledger.host.bytes -= bytes;
    let usage = ledger
        .tenants
        .get_mut(tenant)
        .ok_or_else(|| refused("missing tenant reservation"))?;
    usage.bytes -= bytes;
    if usage.workers == 0 && usage.bytes == 0 {
        ledger.tenants.remove(tenant);
    }
    Ok(())
}
fn collect_child(worker: &mut Worker) -> io::Result<Option<ExitStatus>> {
    if worker.status.is_some() {
        return Ok(worker.status);
    }
    if worker.custody_uncertain {
        return Err(refused("original child custody uncertain"));
    }
    if let Err(error) = require_owned_child_custody() {
        worker.custody_uncertain = true;
        return Err(error);
    }
    match worker.child.try_wait() {
        Ok(status) => {
            if status.is_some() {
                drop(worker.parent_lease.take());
            }
            worker.status = status;
            Ok(status)
        }
        Err(error) => {
            worker.custody_uncertain = true;
            Err(error)
        }
    }
}
fn cleanup_loop(
    state: &CleanupState,
    receiver: &mpsc::Receiver<CleanupCell>,
    pending: &mut Vec<CleanupCell>,
    wake: &mut UnixStream,
) -> io::Result<()> {
    let mut disconnected = false;
    let mut wake_closed = false;
    loop {
        loop {
            match receiver.try_recv() {
                Ok(cell) => pending.push(cell),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        {
            let mut emergency = state
                .emergency
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.extend(emergency.drain(..));
        }
        let mut observers = Vec::with_capacity(state.limits.host_workers);
        let mut watched = Vec::with_capacity(state.limits.host_workers);
        let mut observed_exits = Vec::with_capacity(state.limits.host_workers);
        let mut index = 0;
        while index < pending.len() {
            let slot = pending[index]
                .slot
                .as_ref()
                .ok_or_else(|| refused("empty cleanup cell"))?
                .clone();
            let mut guard = lock(&slot)?;
            let mut done = false;
            if let Some(worker) = guard.worker.as_mut() {
                match collect_child(worker) {
                    Ok(Some(status)) => {
                        guard.state = collected(status);
                        done = true;
                    }
                    Ok(None) => {
                        if worker.exit_observed {
                            observed_exits.push(slot.clone());
                            index += 1;
                            continue;
                        }
                        if worker.observer.is_none()
                            && let Ok(pid) = worker.child.id().try_into()
                            && let Ok(observer) = ProcessExitObserver::arm(pid)
                        {
                            worker.observer = Some(Arc::new(observer));
                        }
                        if let Some(observer) = &worker.observer {
                            observers.push(observer.clone());
                            watched.push(slot.clone());
                        }
                    }
                    Err(_) => {
                        guard.state = MailboxWorkerState::Unresolved;
                    }
                }
            }
            let tenant = guard.request.tenant.clone();
            let vm = guard.request.vm_id.clone();
            drop(guard);
            if done {
                let mut cell = pending.swap_remove(index);
                release_worker_credit(&state.ledger, &tenant)?;
                retire_worker_state(&state.ledger, &tenant, &vm)?;
                cell.slot = None;
                let mut pool = lock(&state.pool)?;
                if pool.len() < state.limits.host_workers {
                    pool.push(cell);
                }
            } else {
                index += 1;
            }
        }
        if disconnected && pending.is_empty() {
            let mut ledger = lock(&state.ledger)?;
            if ledger.host.workers != 0 {
                return Err(refused("unresolved worker reservation on final disconnect"));
            }
            ledger.host.bytes -= state.actor_charge;
            return Ok(());
        }
        if !observed_exits.is_empty() {
            for slot in observed_exits {
                let _ = collect_after_exit_event(
                    Instant::now() + std::time::Duration::from_secs(5),
                    || {
                        let mut guard = lock(&slot)?;
                        let worker = guard
                            .worker
                            .as_mut()
                            .ok_or_else(|| refused("original child missing"))?;
                        collect_child(worker)
                    },
                );
            }
            continue;
        }
        if observers.is_empty() && wake_closed {
            // No supported event handle does not prove exit. Retain every
            // original Child and charge; no timer/PID fallback or false drain.
            state.failed.store(true, Ordering::Release);
            loop {
                std::thread::park();
            }
        }
        let borrowed: Vec<_> = observers.iter().map(Arc::as_ref).collect();
        let events =
            wait_process_exit_events(&borrowed, (!wake_closed).then(|| wake.as_fd()), None)
                .map_err(|_| refused("cleanup event multiplexer failed; custody retained"))?;
        if events.wake_ready {
            let mut buffer = [0; 128];
            loop {
                match wake.read(&mut buffer) {
                    Ok(0) => {
                        wake_closed = true;
                        break;
                    }
                    Ok(_) => (),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        wake_closed = true;
                        state.failed.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        }
        for index in events.exited {
            let slot = &watched[index];
            if let Some(worker) = lock(slot)?.worker.as_mut() {
                worker.exit_observed = true;
            }
            // Original Child stays in its restoration-safe cell. Only the
            // nonblocking try_wait syscall holds its private mutex; event waits
            // and canonical post-event collection backoff hold no mutex.
            let _ = collect_after_exit_event(
                Instant::now() + std::time::Duration::from_secs(5),
                || {
                    let mut guard = lock(slot)?;
                    let worker = guard
                        .worker
                        .as_mut()
                        .ok_or_else(|| refused("original child missing"))?;
                    collect_child(worker)
                },
            );
        }
    }
}
/// Bounds the full connection/frame workspace, including time before decoding.
pub struct WorkerControlPermit {
    budget: Arc<MailboxWorkerBudget>,
    tenant: String,
}
impl Drop for WorkerControlPermit {
    fn drop(&mut self) {
        self.budget.release_control(&self.tenant);
    }
}

/// Factory is trusted host-owner code, not a command/path from signed control.
/// Once a child exists the factory must return it even if later preparation
/// fails; ownership must never disappear into an ordinary post-spawn error.
pub trait MailboxWorkerFactory: Send + Sync {
    /// A dynamically provisioned worker requires the launcher's signed
    /// ProvisionAdmittedV1 before an Acquire can recover its reservation.
    fn requires_signed_provision(&self) -> bool { false }
    fn admit(&self, _request: &MailboxWorkerRequest) -> io::Result<()> {
        Ok(())
    }
    fn spawn(
        &self,
        request: &MailboxWorkerRequest,
        owner: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker>;

    /// Classify a failure only when the trusted factory can prove no helper
    /// exists. A legacy error or unwind retains the original reservation.
    fn spawn_classified(&self, request: &MailboxWorkerRequest, owner: &MailboxWorkerOwner)
        -> Result<SpawnedMailboxWorker, MailboxSpawnFailure> {
        self.spawn(request, owner).map_err(MailboxSpawnFailure::Uncertain)
    }
}
pub enum MailboxSpawnFailure {
    NoChild(io::Error),
    Uncertain(io::Error),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SpawnState {
    NotAttempted,
    RejectedBeforeSpawn,
    RequiresCollection,
}

/// Original child plus exclusive private readiness/lifetime connection. The
/// production helper mode remains separately gated; test fixtures may implement
/// the same bounded owner-JSON readiness line without a real guest.
pub struct SpawnedMailboxWorker {
    pub child: Child,
    pub control: UnixStream,
    pub parent_lease: Option<mvm_vmm::host::installed_owner::HolderLease>,
}
struct Worker {
    parent_lease: Option<mvm_vmm::host::installed_owner::HolderLease>,
    child: Child,
    control: UnixStream,
    observer: Option<Arc<ProcessExitObserver>>,
    ready: Vec<u8>,
    custody_uncertain: bool,
    exit_observed: bool,
    status: Option<ExitStatus>,
}
struct Slot {
    request: MailboxWorkerRequest,
    owner: MailboxWorkerOwner,
    state: MailboxWorkerState,
    busy: bool,
    delegated: bool,
    stop_requested: bool,
    worker: Option<Worker>,
    terminal_at: Option<Instant>,
    cell: Option<CleanupCell>,
    spawn_state: SpawnState,
    reservation_released: bool,
    // Last field: release the original metadata charge after the Child and FDs drop.
    terminal_metadata: Option<TerminalMetadata>,
}
struct TerminalMetadata {
    cleanup: Arc<CleanupState>,
    tenant: String,
    vm: String,
}
impl Drop for TerminalMetadata {
    fn drop(&mut self) {
        if retire_worker_state(&self.cleanup.ledger, &self.tenant, &self.vm).is_err() {
            self.cleanup.failed.store(true, Ordering::Release);
        }
    }
}
fn service_lock_error<T>(error: std::sync::TryLockError<T>) -> io::Error {
    match error {
        std::sync::TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
        std::sync::TryLockError::Poisoned(_) => refused("mailbox service inventory poisoned"),
    }
}
impl Slot {
    fn allows_service_activation(&self) -> bool {
        !self.reservation_released && !self.stop_requested
            && matches!(self.state, MailboxWorkerState::Reserved | MailboxWorkerState::Starting | MailboxWorkerState::Serving)
    }
}
struct WorkerLoan {
    slot: Arc<Mutex<Slot>>,
    worker: Option<Worker>,
    committed: bool,
}
impl Drop for WorkerLoan {
    fn drop(&mut self) {
        if !self.committed {
            let mut slot = self
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.worker.is_some() {
                slot.delegated = true;
            }
            slot.worker = self.worker.take();
            slot.state = MailboxWorkerState::Unresolved;
            slot.busy = false;
        }
    }
}
struct ProviderState {
    deadline: Option<Instant>,
    active: usize,
    publications: usize,
    running: bool,
    failed: bool,
    retired: Option<MailboxWorkersRetirement>,
}
struct ProviderFence {
    state: Mutex<ProviderState>,
    changed: Condvar,
}
struct ExitProof {
    exits: Box<[(MailboxWorkerOwner, MailboxWorkerExit)]>,
    ledger: Arc<Mutex<Ledger>>,
    failed: Arc<AtomicBool>,
    tenant: String,
    bytes: usize,
}
impl Drop for ExitProof {
    fn drop(&mut self) {
        // Release the exit array before returning its charge.
        drop(std::mem::take(&mut self.exits));
        let result = lock(&self.ledger)
            .and_then(|mut ledger| refund_bytes(&mut ledger, &self.tenant, self.bytes));
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
    }
}
/// In-process proof from the original provider. Empty receipts own no heap storage.
#[derive(Clone)]
pub struct MailboxWorkersRetirement {
    boot: [u8; 32],
    deadline: Instant,
    proof: Option<Arc<ExitProof>>,
    never_spawned: usize,
}
impl MailboxWorkersRetirement {
    pub fn retained_bytes(&self) -> usize {
        self.proof.as_ref().map_or(0, |p| p.bytes)
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn never_spawned_released(&self) -> usize {
        self.never_spawned
    }
    pub fn original_exit(&self, owner: &MailboxWorkerOwner) -> Option<&MailboxWorkerExit> {
        self.proof
            .as_ref()?
            .exits
            .iter()
            .find(|(original, _)| original == owner)
            .map(|(_, exit)| exit)
    }
}
/// Nonblocking reservation of a pre-fence activation; holds no mutex across I/O.
pub struct MailboxActivationPermit {
    fence: Arc<ProviderFence>,
    counted: bool,
}
impl Drop for MailboxActivationPermit {
    fn drop(&mut self) {
        let mut state = self
            .fence
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.counted {
            if state.active == 0 {
                state.failed = true;
            } else {
                state.active -= 1;
            }
        }
        self.fence.changed.notify_all();
    }
}
/// Outstanding original bounded SCM send; admitted sends may finish after fence.
/// Quiescence requires its drop and no new publication is admitted after fence.
pub struct MailboxConfigPublication {
    fence: Arc<ProviderFence>,
}
impl Drop for MailboxConfigPublication {
    fn drop(&mut self) {
        let mut state = self
            .fence
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.publications == 0 {
            state.failed = true;
        } else {
            state.publications -= 1;
        }
        self.fence.changed.notify_all();
    }
}
struct RetirementJob(Arc<ProviderFence>);
impl Drop for RetirementJob {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.running = false;
        self.0.changed.notify_all();
    }
}

/// Long-lived tenant owner injected into the actual daemon. All state is bounded
/// by the shared ledger. Default daemon construction never enables this path.
pub struct MailboxWorkers {
    tenant: String,
    budget: Arc<MailboxWorkerBudget>,
    factory: Arc<dyn MailboxWorkerFactory>,
    finalizer: Mutex<()>,
    boot: [u8; 32],
    slots: Mutex<HashMap<String, Arc<Mutex<Slot>>>>,
    generation: Mutex<u64>,
    fence: Arc<ProviderFence>,
}
impl MailboxWorkers {
    pub fn new(
        tenant: &str,
        budget: Arc<MailboxWorkerBudget>,
        factory: Arc<dyn MailboxWorkerFactory>,
    ) -> io::Result<Self> {
        if tenant.is_empty() || tenant.len() > 128 {
            return Err(refused("invalid worker tenant"));
        }
        Ok(Self {
            tenant: tenant.into(),
            budget,
            factory,
            finalizer: Mutex::new(()),
            boot: rand::random(),
            slots: Mutex::new(HashMap::new()),
            generation: Mutex::new(0),
            fence: Arc::new(ProviderFence {
                state: Mutex::new(ProviderState {
                    deadline: None,
                    active: 0,
                    publications: 0,
                    running: false,
                    failed: false,
                    retired: None,
                }),
                changed: Condvar::new(),
            }),
        })
    }
    /// Short memory-only admission to be retained through original handle/reply.
    pub fn try_activation(&self) -> io::Result<MailboxActivationPermit> {
        let mut state = self
            .fence
            .state
            .try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        if state.deadline.is_some() || state.failed {
            return Err(refused("mailbox provider admission stopped"));
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| refused("activation count exhausted"))?;
        Ok(MailboxActivationPermit {
            fence: self.fence.clone(),
            counted: true,
        })
    }
    /// Conservative snapshot only, not a retirement receipt or absence proof.
    pub fn try_idle(&self) -> io::Result<bool> {
        let state = self
            .fence
            .state
            .try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let slots = self
            .slots
            .try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        Ok(!state.failed
            && state.deadline.is_none()
            && state.active == 0
            && state.publications == 0
            && slots.is_empty())
    }
    fn operation_permit(
        &self,
        request: &MailboxWorkerRequest,
    ) -> io::Result<MailboxActivationPermit> {
        let mut state = lock(&self.fence.state)?;
        if state.failed {
            return Err(refused("provider fence uncertain"));
        }
        let activation = matches!(
            request.operation,
            MailboxWorkerOperation::Acquire | MailboxWorkerOperation::ProvisionAdmittedV1 { .. } | MailboxWorkerOperation::DelegateConfig { .. }
        );
        if activation && state.deadline.is_some() {
            return Err(refused("mailbox provider admission stopped"));
        }
        let counted = state.deadline.is_none();
        if counted {
            state.active = state
                .active
                .checked_add(1)
                .ok_or_else(|| refused("operation count exhausted"))?;
        }
        Ok(MailboxActivationPermit {
            fence: self.fence.clone(),
            counted,
        })
    }
    pub fn begin_retirement(&self, deadline: Instant) -> io::Result<()> {
        let mut state = lock(&self.fence.state)?;
        if state.failed {
            return Err(refused("provider fence uncertain"));
        }
        if state.deadline.is_none() {
            state.deadline = Some(deadline);
        }
        self.fence.changed.notify_all();
        Ok(())
    }
    /// Reserve BEFORE SCM send; caller holds this through its bounded send.
    /// Exact owner/expiry checks are facts, never independent grant authority.
    pub fn begin_config_publication(
        &self,
        request: &MailboxWorkerRequest,
    ) -> io::Result<MailboxConfigPublication> {
        let mut state = self
            .fence
            .state
            .try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        if state.failed || state.deadline.is_some() {
            return Err(refused("provider publication stopped"));
        }
        let MailboxWorkerOperation::DelegateConfig { owner } = &request.operation else {
            return Err(refused("publication requires original DelegateConfig"));
        };
        let slots = self
            .slots
            .try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let slot = slots
            .get(&request.vm_id)
            .ok_or_else(|| refused("original publication slot absent"))?;
        let slot = slot
            .try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let now = self.now_unix_ms()?;
        if request.tenant != self.tenant
            || &slot.owner != owner
            || slot.owner.context_commitment
                != context_commitment(request).map_err(|_| refused("publication context"))?
            || !slot.delegated
            || slot.stop_requested
            || slot.busy
            || !matches!(slot.state, MailboxWorkerState::Starting)
            || now >= request.admission_expires_at_unix_ms
            || now >= request.deadline_unix_ms
        {
            return Err(refused(
                "original publication context unavailable or expired",
            ));
        }
        state.publications = state
            .publications
            .checked_add(1)
            .ok_or_else(|| refused("publication count exhausted"))?;
        Ok(MailboxConfigPublication {
            fence: self.fence.clone(),
        })
    }
    pub fn validate_retirement(&self, receipt: &MailboxWorkersRetirement) -> io::Result<()> {
        let state = lock(&self.fence.state)?;
        if state.failed
            || !state.retired.as_ref().is_some_and(|original| {
                original.boot == receipt.boot
                    && match (&original.proof, &receipt.proof) {
                        (None, None) => true,
                        (Some(first), Some(other)) => Arc::ptr_eq(first, other),
                        _ => false,
                    }
            })
        {
            return Err(refused("retirement is not from this original provider"));
        }
        Ok(())
    }
    /// Run in a retained blocking job. Expired grace never renews: original
    /// outstanding turns/exit events may finish beyond it with custody retained.
    pub fn retire_originals(&self) -> io::Result<MailboxWorkersRetirement> {
        let mut state = lock(&self.fence.state)?;
        let deadline = state
            .deadline
            .ok_or_else(|| refused("provider must fence before retirement"))?;
        if state.failed {
            return Err(refused("provider fence uncertain"));
        }
        if let Some(proof) = &state.retired {
            return Ok(proof.clone());
        }
        if state.running {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        state.running = true;
        drop(state);
        let _job = RetirementJob(self.fence.clone());
        let mut state = lock(&self.fence.state)?;
        while state.active != 0 || state.publications != 0 {
            state = self
                .fence
                .changed
                .wait(state)
                .map_err(|_| refused("provider wait poisoned"))?;
            if state.failed {
                return Err(refused("provider fence uncertain"));
            }
        }
        drop(state);
        let slots: Vec<_> = lock(&self.slots)?.values().cloned().collect();
        // Fence every original lifetime channel BEFORE waiting for any child.
        // A busy post-fence Stop already requests that same shutdown itself.
        for slot in &slots {
            let mut guard = lock(slot)?;
            guard.stop_requested = true;
            if let Some(worker) = guard.worker.as_mut() {
                drop(worker.child.stdin.take());
                let _ = worker.control.shutdown(std::net::Shutdown::Both);
            }
        }
        let mut exits = Vec::new();
        exits
            .try_reserve_exact(slots.len())
            .map_err(|_| refused("retirement receipt allocation"))?;
        let mut never_spawned = 0;
        for slot in slots {
            // A pre-existing Stop/Query may already hold the actual loan. Its
            // operation guard notifies this SAME event; fresh cleanup traffic
            // is not added to the pre-fence outstanding count.
            let mut guard = loop {
                let state = lock(&self.fence.state)?;
                let guard = lock(&slot)?;
                if !guard.busy {
                    drop(state);
                    break guard;
                }
                drop(guard);
                drop(
                    self.fence
                        .changed
                        .wait(state)
                        .map_err(|_| refused("slot loan wait poisoned"))?,
                );
            };
            guard.stop_requested = true;
            let owner = guard.owner.clone();
            if guard.spawn_state != SpawnState::RequiresCollection && guard.worker.is_none() {
                if !guard.reservation_released {
                    self.budget.collected(&self.tenant)?;
                    guard.reservation_released = true;
                }
                if let Some(cell) = guard.cell.take() {
                    self.budget.return_cell(cell);
                }
                // Retirement is a local released reservation, NOT Collected.
                guard.state = MailboxWorkerState::Unresolved;
                self.retain_metadata_until_drop(&mut guard);
                never_spawned += 1;
                continue;
            }
            guard.busy = true;
            let original_worker = guard.worker.take();
            drop(guard);
            let mut loan = WorkerLoan {
                slot: slot.clone(),
                worker: original_worker,
                committed: false,
            };
            let worker = loan
                .worker
                .as_mut()
                .ok_or_else(|| refused("spawned original worker missing"))?;
            drop(worker.child.stdin.take());
            let _ = worker.control.shutdown(std::net::Shutdown::Both);
            let status = if let Some(status) = collect_child(worker)? {
                status
            } else {
                if !worker.exit_observed {
                    let observer = worker
                        .observer
                        .as_ref()
                        .ok_or_else(|| refused("original worker observer missing"))?;
                    let event = wait_process_exit_events(&[observer], None, None)
                        .map_err(|_| refused("original exit wait failed"))?;
                    if event.exited.is_empty() {
                        return Err(refused("original exit not observed"));
                    }
                    worker.exit_observed = true;
                }
                require_owned_child_custody().inspect_err(|_| worker.custody_uncertain = true)?;
                let status = worker
                    .child
                    .wait()
                    .inspect_err(|_| worker.custody_uncertain = true)?;
                drop(worker.parent_lease.take());
                worker.status = Some(status);
                status
            };
            let terminal = collected(status);
            let MailboxWorkerState::Collected { exit } = &terminal else {
                unreachable!()
            };
            exits.push((owner, exit.clone()));
            let mut guard = lock(&slot)?;
            if !matches!(guard.state, MailboxWorkerState::Collected { .. }) {
                self.budget.collected(&self.tenant)?;
            }
            if let Some(cell) = guard.cell.take() {
                self.budget.return_cell(cell);
            }
            guard.worker = loan.worker.take();
            guard.state = terminal;
            guard.busy = false;
            guard.terminal_at = Some(Instant::now());
            loan.committed = true;
            self.retain_metadata_until_drop(&mut guard);
        }
        let mut state = lock(&self.fence.state)?;
        if state.failed || state.active != 0 || state.publications != 0 {
            return Err(refused("provider did not quiesce"));
        }
        let receipt = MailboxWorkersRetirement {
            boot: self.boot,
            deadline,
            never_spawned,
            proof: self.reserve_exit_proof(exits)?,
        };
        state.retired = Some(receipt.clone());
        Ok(receipt)
    }
    fn retain_metadata_until_drop(&self, slot: &mut Slot) {
        slot.terminal_metadata
            .get_or_insert_with(|| TerminalMetadata {
                cleanup: self.budget.cleanup.clone(),
                tenant: self.tenant.clone(),
                vm: slot.request.vm_id.clone(),
            });
    }
    fn reserve_exit_proof(
        &self,
        exits: Vec<(MailboxWorkerOwner, MailboxWorkerExit)>,
    ) -> io::Result<Option<Arc<ExitProof>>> {
        if exits.is_empty() {
            return Ok(None);
        }
        let exits = exits.into_boxed_slice();
        let slots = lock(&self.slots)?;
        let keys: Vec<_> = slots
            .keys()
            .map(|vm| (self.tenant.clone(), vm.clone()))
            .collect();
        // Move a portion of existing registrations into the receipt. This succeeds
        // even at the quota limit and never mints an independent byte allowance.
        let size = std::mem::size_of_val(&*exits)
            + std::mem::size_of::<ExitProof>()
            + 2 * std::mem::size_of::<usize>()
            + self.tenant.len();
        if keys.is_empty() {
            return Err(refused("original exit registration missing"));
        }
        let share = size.div_ceil(keys.len());
        let bytes = share * keys.len();
        let mut ledger = lock(&self.budget.ledger)?;
        if keys
            .iter()
            .any(|key| ledger.registrations.get(key).is_none_or(|b| *b < share))
        {
            return Err(refused("original proof registration credit missing"));
        }
        for key in keys {
            *ledger
                .registrations
                .get_mut(&key)
                .expect("verified original registration") -= share;
        }
        Ok(Some(Arc::new(ExitProof {
            exits,
            ledger: self.budget.ledger.clone(),
            failed: self.budget.cleanup.failed.clone(),
            tenant: self.tenant.clone(),
            bytes,
        })))
    }
    /// Called after admitted control tasks join. The receipt retains the exit
    /// values and their quota until its last owner drops it.
    pub fn finalize_retirement(&self, receipt: &MailboxWorkersRetirement) -> io::Result<()> {
        let _finalizer = lock(&self.finalizer)?;
        self.validate_retirement(receipt)?;
        let mut slots = lock(&self.slots)?;
        for slot in slots.values() {
            if Arc::strong_count(slot) != 1 || lock(slot)?.terminal_metadata.is_none() {
                return Err(refused("original slot still borrowed or uncollected"));
            }
        }
        let heavy = std::mem::take(&mut *slots);
        drop(slots);
        drop(heavy);
        if self.budget.cleanup.failed.load(Ordering::Acquire) {
            return Err(refused("original metadata retirement uncertain"));
        }
        Ok(())
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn now_unix_ms(&self) -> io::Result<u64> {
        self.budget.now_unix_ms()
    }
    pub(crate) fn reserve_control(&self) -> io::Result<WorkerControlPermit> {
        self.budget.charge(&self.tenant, None)?;
        Ok(WorkerControlPermit {
            budget: self.budget.clone(),
            tenant: self.tenant.clone(),
        })
    }
    pub(crate) fn registration_count(&self) -> io::Result<usize> {
        self.expire_terminals()?;
        Ok(lock(&self.slots)?.len())
    }
    pub(crate) fn contains(&self, vm: &str) -> io::Result<bool> {
        self.expire_terminals()?;
        Ok(lock(&self.slots)?.contains_key(vm))
    }
    /// Conservative collision observation for an already-held lifecycle turn.
    /// No expiry, clock, Child collection or accounting mutation occurs here.
    pub(crate) fn try_contains(&self, vm: &str) -> io::Result<bool> {
        let slots = self.slots.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                io::Error::new(io::ErrorKind::WouldBlock, "worker inventory is busy")
            }
            std::sync::TryLockError::Poisoned(_) => refused("worker inventory is poisoned"),
        })?;
        Ok(slots.contains_key(vm))
    }
    /// Bounded observation while reconciling sibling service registration.
    pub(crate) fn try_service_owner(&self, vm: &str) -> io::Result<Option<(MailboxWorkerOwner, bool)>> {
        self.try_service_slot(vm, |slot| slot.map(|slot| (slot.owner.clone(), slot.allows_service_activation())))
    }

    fn try_service_slot<T>(&self, vm: &str, inspect: impl FnOnce(Option<&Slot>) -> T) -> io::Result<T> {
        let slots = self.slots.try_lock().map_err(service_lock_error)?;
        let Some(slot) = slots.get(vm) else { return Ok(inspect(None)) };
        let slot = slot.try_lock().map_err(service_lock_error)?;
        if slot.busy { return Err(io::Error::from(io::ErrorKind::WouldBlock)); }
        Ok(inspect(Some(&slot)))
    }

    /// Linearize the local broker map insertion and suspended-start release
    /// against both terminal transitions and the provider's activation fence.
    /// The callback must perform only the pre-reserved synchronous publication.
    pub(crate) fn try_publish_service<T>(
        &self, vm: &str, original: &MailboxWorkerOwner,
        publish: impl FnOnce() -> anyhow::Result<T>
    ) -> anyhow::Result<T> {
        let fence = self.fence.state.try_lock().map_err(service_lock_error)?;
        anyhow::ensure!(!fence.failed && fence.deadline.is_none(), "mailbox activation is fenced");
        self.try_service_slot(vm, |slot| {
            anyhow::ensure!(slot.is_some_and(|slot| &slot.owner == original && slot.allows_service_activation()),
                "mailbox has closed or changed before broker publication");
            publish()
        })?
    }

    fn expire_terminals(&self) -> io::Result<()> {
        let fence = lock(&self.fence.state)?;
        if fence.deadline.is_some() {
            return Ok(());
        }
        // Keep SAME short fence-to-slots turn: retirement cannot capture an
        // entry whose expiry has passed its check but has not removed it yet.
        let _fence = fence;
        let mut slots = lock(&self.slots)?;
        let expired: Vec<String> = slots
            .iter()
            .filter_map(|(vm, slot)| {
                if Arc::strong_count(slot) != 1 {
                    return None;
                }
                let state = slot.lock().ok()?;
                (!state.busy
                    && (state.reservation_released
                        || matches!(state.state, MailboxWorkerState::Collected { .. }))
                    && state
                        .terminal_at
                        .is_some_and(|at| at.elapsed() >= TERMINAL_RETENTION))
                .then(|| vm.clone())
            })
            .collect();
        for vm in expired {
            if let Some(slot) = slots.get(&vm) {
                let cell = lock(slot)?.cell.take();
                if let Some(cell) = cell {
                    self.budget.return_cell(cell);
                }
            }
            self.budget.retire(&self.tenant, &vm)?;
            slots.remove(&vm);
        }
        Ok(())
    }
    pub(crate) fn handoff_uncertain(&self, request: &MailboxWorkerRequest) -> io::Result<()> {
        let MailboxWorkerOperation::DelegateConfig { owner } = &request.operation else {
            return Ok(());
        };
        let slots = lock(&self.slots)?;
        let slot = slots
            .get(&request.vm_id)
            .ok_or_else(|| refused("unknown worker handoff"))?;
        let mut slot = lock(slot)?;
        if owner != &slot.owner || slot.reservation_released || !slot.delegated {
            return Err(refused("uncertain handoff does not match original delegated worker"));
        }
        if !matches!(slot.state, MailboxWorkerState::Collected { .. }) {
            slot.state = MailboxWorkerState::Unresolved;
        }
        Ok(())
    }
    /// The daemon must verify the host signature with its original key before
    /// this call. Exact owner context is rechecked here; this is not a substitute
    /// for the original admission owner injecting this service at all.
    pub(crate) fn handle(
        &self,
        request: &MailboxWorkerRequest,
    ) -> io::Result<(MailboxWorkerResult, Option<OwnedFd>)> {
        let provision = matches!(request.operation, MailboxWorkerOperation::ProvisionAdmittedV1 { .. });
        if provision && !self.factory.requires_signed_provision() {
            return Err(refused("installed mailbox provisioning disabled"));
        }
        self.factory.admit(request)?;
        let _operation = self.operation_permit(request)?;
        if request.tenant != self.tenant {
            return Err(refused("foreign worker tenant"));
        }
        let now = self.now_unix_ms()?;
        let remaining = request
            .deadline_unix_ms
            .checked_sub(now)
            .filter(|v| *v > 0 && *v <= MAX_WORKER_OPERATION_MS)
            .ok_or_else(|| refused("worker deadline"))?;
        let deadline = Instant::now() + std::time::Duration::from_millis(remaining);
        let context = context_commitment(request).map_err(|_| refused("worker context"))?;
        // Lookup has no budget or slot mutations, including terminal expiry.
        // It never falls through to the original legacy Acquire path.
        if matches!(request.operation, MailboxWorkerOperation::LookupExistingV1) {
            let slots = lock(&self.slots)?;
            let slot = lock(slots.get(&request.vm_id).ok_or_else(|| refused("original reservation absent"))?)?;
            if slot.request.request_nonce != request.request_nonce || slot.owner.context_commitment != context
                || slot.owner.daemon_boot_nonce != self.boot || slot.busy {
                return Err(refused("original reservation unavailable"));
            }
            let state = if slot.reservation_released {
                MailboxWorkerState::ReleasedBeforeSpawn
            } else if slot.stop_requested && !matches!(slot.state, MailboxWorkerState::Collected { .. }) {
                MailboxWorkerState::Unresolved
            } else {
                slot.state.clone()
            };
            return Ok((MailboxWorkerResult { request_nonce: request.request_nonce, owner: slot.owner.clone(), state, delegates_config: false }, None));
        }
        self.expire_terminals()?;
        let slot = {
            // SAME fence turn linearizes new reservation against retirement.
            let admission = if matches!(request.operation, MailboxWorkerOperation::Acquire | MailboxWorkerOperation::ProvisionAdmittedV1 { .. }) {
                let guard = lock(&self.fence.state)?;
                if guard.deadline.is_some() || guard.failed {
                    return Err(refused("provider acquisition stopped"));
                }
                Some(guard)
            } else {
                None
            };
            let _admission = admission;
            let mut slots = lock(&self.slots)?;
            if matches!(request.operation, MailboxWorkerOperation::Acquire | MailboxWorkerOperation::ProvisionAdmittedV1 { .. }) {
                if let Some(slot) = slots.get(&request.vm_id) {
                    let slot_guard = lock(slot)?;
                    if slot_guard.reservation_released {
                        return Err(refused("original reservation already released"));
                    }
                    if slot_guard.request.request_nonce != request.request_nonce
                        || slot_guard.owner.context_commitment != context
                    {
                        return Err(refused("conflicting worker acquisition"));
                    }
                    // Recover the ORIGINAL reservation receipt, as required by
                    // v1 result validation. This never resets current state;
                    // Query is the live-state operation for the recovered lease.
                    return Ok((
                        MailboxWorkerResult {
                            request_nonce: request.request_nonce,
                            owner: slot_guard.owner.clone(),
                            state: MailboxWorkerState::Reserved,
                            delegates_config: false,
                        },
                        None,
                    ));
                }
                if !provision && self.factory.requires_signed_provision() {
                    return Err(refused("no installed reservation for this acquisition"));
                }
                let mut generation = lock(&self.generation)?;
                let next = generation
                    .checked_add(1)
                    .ok_or_else(|| refused("worker generation exhausted"))?;
                let cell = self
                    .budget
                    .charge(&self.tenant, Some(&request.vm_id))?
                    .ok_or_else(|| refused("missing original cleanup reservation"))?;
                *generation = next;
                let owner = MailboxWorkerOwner {
                    daemon_boot_nonce: self.boot,
                    lease: rand::random(),
                    generation: next,
                    context_commitment: context,
                };
                let slot = Arc::new(Mutex::new(Slot {
                    request: request.clone(),
                    owner: owner.clone(),
                    state: MailboxWorkerState::Reserved,
                    busy: false,
                    delegated: false,
                    stop_requested: false,
                    worker: None,
                    terminal_at: None,
                    cell: Some(cell),
                    spawn_state: SpawnState::NotAttempted,
                    reservation_released: false,
                    terminal_metadata: None,
                }));
                slots.insert(request.vm_id.clone(), slot);
                return Ok((
                    MailboxWorkerResult {
                        request_nonce: request.request_nonce,
                        owner,
                        state: MailboxWorkerState::Reserved,
                        delegates_config: false,
                    },
                    None,
                ));
            }
            slots
                .get(&request.vm_id)
                .cloned()
                .ok_or_else(|| refused("unknown worker acquisition"))?
        };
        let (original_worker, state, mut delegated, owner) = {
            let _admission = if matches!(
                request.operation,
                MailboxWorkerOperation::DelegateConfig { .. }
            ) {
                let guard = lock(&self.fence.state)?;
                if guard.deadline.is_some() || guard.failed {
                    return Err(refused("provider delegation stopped"));
                }
                Some(guard)
            } else {
                None
            };
            let mut slot = lock(&slot)?;
            let supplied = match &request.operation {
                MailboxWorkerOperation::DelegateConfig { owner }
                | MailboxWorkerOperation::Query { owner }
                | MailboxWorkerOperation::Stop { owner }
                | MailboxWorkerOperation::ReleaseUnstartedV1 { owner } => owner,
                MailboxWorkerOperation::Acquire | MailboxWorkerOperation::LookupExistingV1 | MailboxWorkerOperation::ProvisionAdmittedV1 { .. } => unreachable!(),
            };
            if supplied != &slot.owner
                || slot.owner.context_commitment != context
                || slot.owner.daemon_boot_nonce != self.boot
            {
                return Err(refused("stale or mismatched worker owner"));
            }
            if matches!(request.operation, MailboxWorkerOperation::Query { .. })
                && slot.stop_requested
            {
                let state = if matches!(slot.state, MailboxWorkerState::Collected { .. }) {
                    slot.state.clone()
                } else {
                    MailboxWorkerState::Unresolved
                };
                return Ok((
                    MailboxWorkerResult {
                        request_nonce: request.request_nonce,
                        owner: slot.owner.clone(),
                        state,
                        delegates_config: false,
                    },
                    None,
                ));
            }
            if slot.busy {
                return Err(refused("worker operation in progress"));
            }
            if matches!(
                request.operation,
                MailboxWorkerOperation::ReleaseUnstartedV1 { .. }
            ) {
                // Under the original slot lock a competing Delegate is either
                // still busy, already attempted, or will see stop_requested.
                if slot.spawn_state == SpawnState::RequiresCollection || slot.worker.is_some() || slot.delegated {
                    return Err(refused("original worker spawn was attempted"));
                }
                if !slot.reservation_released {
                    self.budget.collected(&self.tenant)?;
                    slot.reservation_released = true;
                    slot.stop_requested = true;
                    slot.terminal_at = Some(Instant::now());
                    if let Some(cell) = slot.cell.take() {
                        self.budget.return_cell(cell);
                    }
                }
                return Ok((
                    MailboxWorkerResult {
                        request_nonce: request.request_nonce,
                        owner: slot.owner.clone(),
                        state: MailboxWorkerState::ReleasedBeforeSpawn,
                        delegates_config: false,
                    },
                    None,
                ));
            }
            if (slot.stop_requested || (!slot.delegated && slot.spawn_state != SpawnState::NotAttempted))
                && matches!(
                    request.operation,
                    MailboxWorkerOperation::DelegateConfig { .. }
                )
            {
                return Err(refused("worker admission has already been stopped"));
            }
            if matches!(request.operation, MailboxWorkerOperation::Stop { .. }) {
                slot.stop_requested = true;
            }
            slot.busy = true;
            (
                slot.worker.take(),
                slot.state.clone(),
                slot.delegated,
                slot.owner.clone(),
            )
        };
        let mut loan = WorkerLoan {
            slot: slot.clone(),
            worker: original_worker,
            committed: false,
        };
        let worker = &mut loan.worker;
        // No daemon/slot/budget mutex is held during factory, pipe, or exit I/O.
        let mut state = state;
        let mut fd = None;
        let operation = (|| -> io::Result<()> {
            if matches!(state, MailboxWorkerState::Collected { .. }) {
                return Ok(());
            }
            if matches!(
                request.operation,
                MailboxWorkerOperation::DelegateConfig { .. }
            ) && !delegated
            {
                let now = self.now_unix_ms()?;
                if now >= request.admission_expires_at_unix_ms || Instant::now() >= deadline {
                    return Err(refused("worker authority expired before spawn"));
                }
                require_owned_child_custody()?;
                // Set before calling external factory code: panic, a rejected
                // handoff without proof, or loss of custody must fail closed.
                lock(&slot)?.spawn_state = SpawnState::RequiresCollection;
                let spawned = match self.factory.spawn_classified(request, &owner) {
                    Ok(child) => child,
                    Err(MailboxSpawnFailure::NoChild(error)) => {
                        lock(&slot)?.spawn_state = SpawnState::RejectedBeforeSpawn;
                        return Err(error);
                    }
                    Err(MailboxSpawnFailure::Uncertain(error)) => return Err(error),
                };
                *worker = Some(Worker {
                    parent_lease: spawned.parent_lease,
                    child: spawned.child,
                    control: spawned.control,
                    observer: None,
                    ready: Vec::new(),
                    custody_uncertain: false,
                    exit_observed: false,
                    status: None,
                });
                delegated = true; // Mark before any post-spawn failure; never spawn twice.
                state = MailboxWorkerState::Unresolved;
                let child = worker
                    .as_mut()
                    .expect("worker stored before fallible setup");
                child.control.set_nonblocking(true)?;
                let pid = child
                    .child
                    .id()
                    .try_into()
                    .map_err(|_| refused("worker PID range"))?;
                child.observer = Some(Arc::new(
                    ProcessExitObserver::arm(pid)
                        .map_err(|_| refused("worker observer unavailable"))?,
                ));
                // Factory/OS spawn ran outside the gate. Retain the original
                // Child first, then refresh authority immediately before any
                // pipe writer can escape to the launcher.
                if lock(&self.fence.state)?.deadline.is_some()
                    || self.now_unix_ms()? >= request.admission_expires_at_unix_ms
                    || Instant::now() >= deadline
                {
                    drop(child.child.stdin.take());
                    return Err(refused("worker authority expired during spawn"));
                }
                let writer = child
                    .child
                    .stdin
                    .take()
                    .ok_or_else(|| refused("worker config stdin missing"))?;
                fd = Some(writer.into());
                state = MailboxWorkerState::Starting;
            }
            if let Some(child) = worker.as_mut() {
                if let Some(status) = collect_child(child)? {
                    state = collected(status);
                } else if matches!(request.operation, MailboxWorkerOperation::Stop { .. }) {
                    state = MailboxWorkerState::Stopping;
                    child.control.shutdown(std::net::Shutdown::Both)?;
                    let observer = child
                        .observer
                        .as_ref()
                        .ok_or_else(|| refused("worker observer absent"))?;
                    if !child.exit_observed
                        && observer
                            .wait_event(deadline)
                            .map_err(|_| refused("worker exit observer failed"))?
                            == ProcessExitWait::TimedOut
                    {
                        state = MailboxWorkerState::Unresolved;
                        return Err(refused("worker stop timed out; original custody retained"));
                    }
                    child.exit_observed = true;
                    let status = collect_after_exit_event(deadline, || collect_child(child))?
                        .ok_or_else(|| refused("worker exit was not collected"))?;
                    state = collected(status);
                } else if matches!(state, MailboxWorkerState::Starting)
                    && fd.is_none()
                    && child.parent_lease.is_some()
                {
                    if crate::mailbox_process::owned_wire::poll_ready(
                        &mut child.control,
                        &mut child.ready,
                        &owner,
                    )? {
                        state = MailboxWorkerState::Serving;
                    }
                } else if matches!(state, MailboxWorkerState::Starting) && fd.is_none() {
                    let mut byte = [0; 1];
                    while child.ready.len() <= 4096 {
                        match child.control.read(&mut byte) {
                            Ok(0) => return Err(refused("worker exited before readiness")),
                            Ok(_) if byte[0] == b'\n' => {
                                let ready: MailboxWorkerOwner =
                                    serde_json::from_slice(&child.ready)?;
                                if ready != owner {
                                    return Err(refused("worker readiness context mismatch"));
                                }
                                state = MailboxWorkerState::Serving;
                                break;
                            }
                            Ok(_) => child.ready.push(byte[0]),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error),
                        }
                    }
                    if child.ready.len() > 4096 {
                        return Err(refused("worker readiness bound"));
                    }
                }
            } else if matches!(request.operation, MailboxWorkerOperation::Stop { .. }) {
                // No child ever started: releasing a reserved admission is not
                // a collected process result. Keep its bounded reservation.
                state = MailboxWorkerState::Unresolved;
            }
            Ok(())
        })();
        if matches!(state, MailboxWorkerState::Collected { .. }) {
            // The original child already exited: never delegate a dead writer
            // or emit a result that violates the typed transport contract.
            fd = None;
        }
        if operation.is_err() {
            // Outside the slot gate, fence the private lifetime channel. Do not
            // abandon original custody or release any uncertain live credit.
            if let Some(child) = worker.as_mut() {
                drop(child.child.stdin.take());
                let _ = child.control.shutdown(std::net::Shutdown::Both);
            }
            state = MailboxWorkerState::Unresolved;
            fd = None;
        }
        let mut slot = lock(&slot)?;
        let newly_collected = matches!(state, MailboxWorkerState::Collected { .. })
            && !matches!(slot.state, MailboxWorkerState::Collected { .. });
        slot.worker = worker.take();
        slot.state = state.clone();
        slot.delegated = delegated;
        slot.busy = false;
        loan.committed = true;
        if newly_collected {
            if let Some(cell) = slot.cell.take() {
                self.budget.return_cell(cell);
            }
            self.budget.collected(&self.tenant)?;
            slot.terminal_at = Some(Instant::now());
        }
        operation?;
        Ok((
            MailboxWorkerResult {
                request_nonce: request.request_nonce,
                owner,
                state,
                delegates_config: fd.is_some(),
            },
            fd,
        ))
    }
}
impl Drop for MailboxWorkers {
    fn drop(&mut self) {
        let slots = self
            .slots
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, slot) in slots.drain() {
            let mut guard = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let collected = matches!(guard.state, MailboxWorkerState::Collected { .. });
            let never_spawned = guard.worker.is_none() && guard.spawn_state != SpawnState::RequiresCollection && !guard.busy;
            if collected || never_spawned {
                let metadata_owned = guard.terminal_metadata.is_some();
                let cell = guard.cell.take();
                let tenant = guard.request.tenant.clone();
                let vm = guard.request.vm_id.clone();
                let released = guard.reservation_released;
                drop(guard);
                let credit = if never_spawned && !released {
                    self.budget.collected(&tenant)
                } else {
                    Ok(())
                };
                if credit
                    .and_then(|()| {
                        if metadata_owned {
                            Ok(())
                        } else {
                            self.budget.retire(&tenant, &vm)
                        }
                    })
                    .is_err()
                {
                    self.budget.cleanup.failed.store(true, Ordering::Release);
                }
                if let Some(cell) = cell {
                    self.budget.return_cell(cell);
                }
                continue;
            }
            // The actor gets original ownership, never a PID reconstruction.
            // EOF/stdin closure only requests shutdown; it is not collection.
            if let Some(worker) = guard.worker.as_mut() {
                drop(worker.child.stdin.take());
                let _ = worker.control.shutdown(std::net::Shutdown::Both);
            }
            guard.state = MailboxWorkerState::Unresolved;
            let mut cell = guard.cell.take().unwrap_or_else(|| {
                // Preserve the Child even after an internal custody invariant
                // failure. No new admission is possible; at most N existing
                // live reservations can reach this charged quarantine.
                self.budget.cleanup.failed.store(true, Ordering::Release);
                CleanupCell::default()
            });
            drop(guard);
            cell.slot = Some(slot);
            self.budget.handoff(cell);
        }
    }
}
fn collected(status: ExitStatus) -> MailboxWorkerState {
    let exit = match status.code() {
        Some(code) => MailboxWorkerExit::Code { code },
        None => MailboxWorkerExit::Signal {
            signal: status.signal().unwrap_or(0),
        },
    };
    MailboxWorkerState::Collected { exit }
}

/// Canonical typed errors use the same new-mode marker but no delegated FD.
/// The current receiving foundation rejects them without exposing an owner.
pub(crate) fn write_error(stream: &mut UnixStream, message: &str) -> io::Result<()> {
    let body = serde_json::to_vec(&mvm_core::protocol::broker_control::ControlResponse::Err {
        message: message.to_owned(),
    })?;
    stream.write_all(&[0x4d])?;
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::daemon::HostAgentDaemon;
    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
    use mvm_core::protocol::broker_control::{self, ControlRequest};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::{Condvar, mpsc};

    fn limits() -> WorkerLimits {
        WorkerLimits {
            host_workers: 2,
            tenant_workers: 1,
            host_bytes: 1_048_576,
            tenant_bytes: 524_288,
            bytes_per_worker: 65_536,
        }
    }
    #[test]
    fn paired_publication_holds_original_slot_until_listener_activation() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let provider = MailboxWorkers::new("tenant", budget.clone(), Arc::new(NeverSpawn)).unwrap();
        let mut req = request(&budget, "tenant");
        let owner = provider.handle(&req).unwrap().0.owner;
        let slot = provider.slots.lock().unwrap()[&req.vm_id].clone();
        let mut competing = req.clone();
        competing.operation = MailboxWorkerOperation::ReleaseUnstartedV1{owner:owner.clone()};
        let (started, starting) = mpsc::sync_channel(0);
        let (published, after_publish) = mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            let provider = &provider;
            let release = scope.spawn(move || {
                // Wait until the actual publish closure owns its slot, then
                // attempt signed-operation handling on the ordinary owner.
                starting.recv().unwrap();
                published.send(()).unwrap();
                provider.handle(&competing).unwrap().0.state
            });
            provider.try_publish_service(&req.vm_id, &owner, || {
                started.send(()).unwrap();
                after_publish.recv_timeout(std::time::Duration::from_secs(2))?;
                assert!(matches!(slot.try_lock(), Err(std::sync::TryLockError::WouldBlock)));
                assert!(matches!(provider.fence.state.try_lock(), Err(std::sync::TryLockError::WouldBlock)));
                Ok(())
            }).unwrap();
            assert_eq!(release.join().unwrap(), MailboxWorkerState::ReleasedBeforeSpawn);
        });
        assert!(provider.try_publish_service(&req.vm_id, &owner, || -> anyhow::Result<()> { panic!("released slot published a listener") }).is_err());
        req.operation = MailboxWorkerOperation::LookupExistingV1;
        assert_eq!(provider.handle(&req).unwrap().0.state,MailboxWorkerState::ReleasedBeforeSpawn);
    }

    #[test]
    fn provider_fence_waits_original_activation_beyond_grace_without_renewing_it() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let provider =
            Arc::new(MailboxWorkers::new("tenant", budget, Arc::new(NeverSpawn)).unwrap());
        assert!(provider.try_idle().unwrap());
        let activation = provider.try_activation().unwrap();
        assert!(!provider.try_idle().unwrap());
        let first = Instant::now(); // Already-expired grace is not a new wait grant.
        provider.begin_retirement(first).unwrap();
        assert!(provider.try_activation().is_err());
        assert!(!provider.try_idle().unwrap());
        // A same-thread try proves the short gate is not held across the turn.
        assert!(provider.fence.state.try_lock().is_ok());
        drop(activation);
        let receipt = provider.retire_originals().unwrap();
        assert_eq!(receipt.deadline(), first);
        provider.validate_retirement(&receipt).unwrap();
        assert_eq!(receipt.never_spawned_released(), 0);
    }

    #[test]
    fn original_provider_retirement_releases_only_never_spawned_and_binds_its_receipt() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let baseline = budget.usage().unwrap();
        let provider = MailboxWorkers::new("tenant", budget.clone(), Arc::new(NeverSpawn)).unwrap();
        let original_request = request(&budget, "tenant");
        let acquired = provider.handle(&original_request).unwrap().0;
        assert_eq!(budget.usage().unwrap().workers, 1);
        let first = Instant::now() + std::time::Duration::from_secs(1);
        provider.begin_retirement(first).unwrap();
        provider
            .begin_retirement(first + std::time::Duration::from_secs(5))
            .unwrap();
        assert!(
            provider.handle(&original_request).is_err(),
            "Acquire cannot restart a frozen provider"
        );
        let receipt = provider.retire_originals().unwrap();
        provider.validate_retirement(&receipt).unwrap();
        assert_eq!(receipt.deadline(), first);
        assert_eq!(receipt.never_spawned_released(), 1);
        assert!(
            receipt.original_exit(&acquired.owner).is_none(),
            "never-spawned is not Child collection"
        );
        provider.finalize_retirement(&receipt).unwrap();
        assert_eq!(budget.usage().unwrap().workers, 0);
        assert_eq!(
            budget.usage().unwrap().bytes,
            baseline.bytes,
            "all original per-VM metadata registrations released"
        );
        let other =
            MailboxWorkers::new("other-tenant", budget.clone(), Arc::new(NeverSpawn)).unwrap();
        other.handle(&request(&budget, "other-tenant")).unwrap();
        drop(other);
        let foreign = MailboxWorkers::new("tenant", budget, Arc::new(NeverSpawn)).unwrap();
        assert!(
            foreign.validate_retirement(&receipt).is_err(),
            "same tenant is not same original provider"
        );
    }

    #[test]
    fn nonblocking_collision_read_refuses_contention_poison_and_retains_terminal_slots() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let owner =
            Arc::new(MailboxWorkers::new("tenant", budget.clone(), Arc::new(NeverSpawn)).unwrap());
        assert!(!owner.try_contains("vm-one").unwrap());
        owner.handle(&request(&budget, "tenant")).unwrap();
        assert!(owner.try_contains("vm-one").unwrap());
        // Accounting-only terminal fixture: no Child was spawned or collected.
        {
            let slots = lock(&owner.slots).unwrap();
            let mut slot = lock(slots.get("vm-one").unwrap()).unwrap();
            slot.state = MailboxWorkerState::Collected {
                exit: MailboxWorkerExit::Code { code: 0 },
            };
            slot.terminal_at =
                Some(Instant::now() - TERMINAL_RETENTION - std::time::Duration::from_secs(1));
        }
        budget.collected("tenant").unwrap();
        let usage = budget.usage().unwrap();
        assert!(
            owner.try_contains("vm-one").unwrap(),
            "collision reads cannot expire retained slots"
        );
        assert_eq!(budget.usage().unwrap(), usage);

        let held = lock(&owner.slots).unwrap();
        let (send, recv) = mpsc::channel();
        let other = owner.clone();
        let thread = std::thread::spawn(move || send.send(other.try_contains("vm-one")).unwrap());
        let observed = recv.recv_timeout(std::time::Duration::from_secs(1));
        drop(held);
        thread.join().unwrap();
        assert!(
            observed
                .expect("collision read blocked on another mutex guard")
                .is_err()
        );

        let other = owner.clone();
        assert!(
            std::thread::spawn(move || {
                let _held = other.slots.lock().unwrap();
                panic!("controlled worker-map poison");
            })
            .join()
            .is_err()
        );
        assert!(
            owner.try_contains("vm-one").is_err(),
            "poison cannot become absence"
        );
    }
    #[test]
    fn handoff_wakeup_retries_interrupted_write_worker_review_red() {
        let (mut read, mut write) = UnixStream::pair().unwrap();
        read.set_nonblocking(true).unwrap();
        let mut attempts = 0;
        notify_handoff(|| {
            attempts += 1;
            if attempts == 1 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                write.write(&[1])
            }
        })
        .unwrap();
        assert_eq!(
            read.read(&mut [0]).unwrap(),
            1,
            "interrupted notification must be retried before parking the actor"
        );
        assert_eq!(attempts, 2);
    }
    #[test]
    fn handoff_wakeup_reports_hard_failure_worker_review_red() {
        assert!(
            notify_handoff(|| Err(io::ErrorKind::BrokenPipe.into())).is_err(),
            "hard wake failure must reach the producer's fail-closed handler"
        );
    }
    #[test]
    fn ordinary_collection_refuses_ignored_sigchld_worker_review_red() {
        let output=Command::new(std::env::current_exe().unwrap())
            .args(["--exact","broker::mailbox_workers::tests::isolated_ignored_sigchld_collect_entry_worker_review_red","--nocapture","--test-threads=1"])
            .env("MVM_OWNER_IGNORED_SIGCHLD_ENTRY","1").output().unwrap();
        assert!(
            output.status.success(),
            "isolated custody guard failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn poisoned_owner_with_watched_session_keeps_actual_idle_watcher_live_worker_review_red() {
        let output=Command::new(std::env::current_exe().unwrap())
            .args(["--exact","broker::mailbox_workers::tests::isolated_poisoned_idle_watcher_entry_worker_review_red","--nocapture","--test-threads=1"])
            .env("MVM_OWNER_POISONED_IDLE_ENTRY","1").output().unwrap();
        assert!(
            output.status.success(),
            "isolated actual idle watcher failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn isolated_poisoned_idle_watcher_entry_worker_review_red() {
        if std::env::var_os("MVM_OWNER_POISONED_IDLE_ENTRY").is_none() {
            return;
        }
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let owner = Arc::new(MailboxWorkers::new("tenant", budget, Arc::new(NeverSpawn)).unwrap());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = owner.slots.lock().unwrap();
                panic!("controlled owner-map poison");
            }))
            .is_err()
        );
        let daemon = HostAgentDaemon::new(
            "tenant",
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            65_536,
        )
        .with_mailbox_workers(owner)
        .unwrap();
        assert_eq!(
            daemon.registration_count(),
            usize::MAX,
            "unknown owner count must remain the non-idle sentinel"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let watcher = tokio::spawn(crate::host_agent_idle::run_idle_watcher(
                Arc::new(tokio::sync::Mutex::new(daemon)),
                Arc::new(std::sync::atomic::AtomicUsize::new(1)),
                Some(std::time::Duration::ZERO),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                !watcher.is_finished(),
                "unknown registrations plus a watched session must not panic or become idle"
            );
            watcher.abort();
            assert!(watcher.await.unwrap_err().is_cancelled());
        });
    }
    #[test]
    fn isolated_ignored_sigchld_collect_entry_worker_review_red() {
        if std::env::var_os("MVM_OWNER_IGNORED_SIGCHLD_ENTRY").is_none() {
            return;
        }
        require_owned_child_custody().unwrap();
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let owner = MailboxWorkers::new("tenant", budget.clone(), Arc::new(PipeChild)).unwrap();
        let mut r = request(&budget, "tenant");
        let acquired = owner.handle(&r).unwrap().0;
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: acquired.owner.clone(),
        };
        r.request_nonce = [2; 32];
        let (_, writer) = owner.handle(&r).unwrap();
        let slot = lock(&owner.slots).unwrap().get("vm-one").cloned().unwrap();
        let pid = lock(&slot).unwrap().worker.as_ref().unwrap().child.id();
        let observer = ProcessExitObserver::arm(pid.try_into().unwrap()).unwrap();
        // SAFETY: this branch runs only in the separately exec'd test process.
        // The real Child already exists, has an armed observer, and is kept
        // alive by its owned stdin writer. No parent/host disposition changes.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_IGN;
            assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()),
                0
            );
        }
        assert!(
            require_owned_child_custody().is_err(),
            "isolated IGN must be active"
        );
        r.operation = MailboxWorkerOperation::Query {
            owner: acquired.owner,
        };
        r.request_nonce = [3; 32];
        let refused = owner.handle(&r).is_err();
        let uncertain = lock(&slot)
            .unwrap()
            .worker
            .as_ref()
            .unwrap()
            .custody_uncertain;
        assert_eq!(
            observer
                .wait_event(Instant::now() + std::time::Duration::from_millis(1))
                .unwrap(),
            ProcessExitWait::TimedOut,
            "fixture child exited unexpectedly during IGN; no identity restoration is permitted"
        );
        assert_eq!(
            budget.usage().unwrap().workers,
            1,
            "custody refusal cannot refund the original reservation"
        );
        drop(writer); // Fixture release only: IGN remains installed until exec child exits.
        assert_eq!(
            observer
                .wait_event(Instant::now() + std::time::Duration::from_secs(2))
                .unwrap(),
            ProcessExitWait::Exited
        );
        eprintln!(
            "FIXTURE_ONLY: exit observed under SIGCHLD=IGN; no collected receipt or refund claimed"
        );
        assert!(
            refused,
            "ordinary collection accepted invalid current custody disposition"
        );
        assert!(uncertain);
    }
    fn request(budget: &MailboxWorkerBudget, tenant: &str) -> MailboxWorkerRequest {
        let now = budget.now_unix_ms().unwrap();
        MailboxWorkerRequest {
            domain: MAILBOX_WORKER_DOMAIN.into(),
            version: 1,
            request_nonce: [1; 32],
            tenant: tenant.into(),
            vm_id: "vm-one".into(),
            workload_id: "workload-one".into(),
            plan_commitment: [2; 32],
            mailbox_grant: MailboxGrant {
                mailbox: MailboxId::from_bytes([3; 32]),
                authority_key: [4; 32],
                epoch: ExecutionEpoch::new(1).unwrap(),
                local_service: None,
            },
            admission_expires_at_unix_ms: now + 60_000,
            deadline_unix_ms: now + 4_000,
            backend: MailboxWorkerBackend::Firecracker,
            operation: MailboxWorkerOperation::Acquire,
        }
    }
    #[test]
    fn paired_installed_budget_preserves_two_particular_admissions_and_one_shared_workspace() {
        use crate::mailbox_process::installed_profile::{InstalledMailboxProfile, MailboxPair};
        use std::os::unix::fs::PermissionsExt;
        use mvm_vmm::host::installed_owner::{InstallationBinding, InstallationKey};
        let home = tempfile::tempdir().unwrap();
        let binary = home.path().join("mvm-mailbox");
        std::fs::write(&binary, b"no children started in this test").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binding = Arc::new(InstallationBinding {
            root: home.path().join("unused"), generation: 2,
            key: InstallationKey { installation: [1; 32], profile: [2; 32] },
        });
        // Run the pre-existing installed mode against the same canonical
        // reservations before choosing the explicitly paired capacity.
        {
            let budget = MailboxWorkerBudget::new(InstalledMailboxProfile::Single.worker_limits()).unwrap();
            let factory = InstalledMailboxWorkerFactory::new(&binary, binding.clone(), home.path()).unwrap();
            let workers = MailboxWorkers::new("local", budget.clone(), Arc::new(factory)).unwrap();
            let key = SigningKey::from_bytes(&[7; 32]);
            let reserve = |vm: &str, nonce| {
                let mut r = request(&budget, "local");
                r.vm_id = vm.into();
                r.workload_id = vm.into();
                r.request_nonce = [nonce; 32];
                r.operation = MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch: 2 };
                let envelope = broker_control::sign(ControlRequest::MailboxWorkerV1(Box::new(r.clone())), &key.to_bytes()).unwrap();
                verify_request(&envelope, &key.verifying_key(), budget.now_unix_ms()?)
                .map_err(|_| refused("canonical worker binding refused"))?;
                workers.handle(&r)
            };
            reserve("alpha", 4).unwrap();
            let before = budget.usage().unwrap();
            assert!(reserve("beta", 5).is_err());
            assert_eq!(budget.usage().unwrap(), before);
            assert_eq!(before.workers, 1);
        }
        let pair = MailboxPair::new(["alpha", "beta"]).unwrap();
        let profile = InstalledMailboxProfile::Pair(pair);
        let limits = profile.worker_limits();
        let budget = MailboxWorkerBudget::new(limits).unwrap();
        let factory = InstalledMailboxWorkerFactory::with_profile(&binary, binding, home.path(), profile).unwrap();
        let workers = MailboxWorkers::new("local", budget.clone(), Arc::new(factory)).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let call = |request: &MailboxWorkerRequest| {
            let envelope = broker_control::sign(ControlRequest::MailboxWorkerV1(Box::new(request.clone())), &key.to_bytes()).unwrap();
            verify_request(&envelope, &key.verifying_key(), budget.now_unix_ms()?)
                .map_err(|_| refused("canonical worker binding refused"))?;
            workers.handle(request)
        };
        let request_for = |vm: &str, nonce: u8| {
            let mut r = request(&budget, "local");
            r.vm_id = vm.to_owned();
            r.workload_id = vm.to_owned();
            r.request_nonce = [nonce; 32];
            r.operation = MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch: 2 };
            r
        };
        let baseline = budget.usage().unwrap();
        let deny_foreign = || {
            let usage = budget.usage().unwrap();
            let mut third = request_for("foreign", 9);
            assert!(call(&third).is_err());
            third.operation = MailboxWorkerOperation::Acquire;
            assert!(call(&third).is_err());
            assert_eq!(budget.usage().unwrap(), usage);
        };
        deny_foreign();
        let mut a = request_for("alpha", 4);
        let mut b = request_for("beta", 5);
        let (oa, ob) = std::thread::scope(|scope| {
            let a = scope.spawn(|| call(&a).unwrap().0.owner);
            let b = scope.spawn(|| call(&b).unwrap().0.owner);
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_ne!(oa, ob);
        assert_eq!(budget.usage().unwrap().bytes, baseline.bytes + 2 * limits.bytes_per_worker);
        assert_eq!(budget.usage().unwrap().workers, 2);
        let workspace = workers.reserve_control().unwrap();
        assert!(budget.usage().unwrap().bytes <= limits.host_bytes);
        assert!(workers.reserve_control().is_err());
        drop(workspace);
        assert!(call(&request_for("alpha", 8)).is_err());
        b.operation = MailboxWorkerOperation::DelegateConfig { owner: oa.clone() };
        assert!(workers.handoff_uncertain(&b).is_err());
        b.operation = MailboxWorkerOperation::ReleaseUnstartedV1 { owner: oa.clone() };
        assert!(call(&b).is_err());
        a.operation = MailboxWorkerOperation::ReleaseUnstartedV1 { owner: oa.clone() };
        assert_eq!(call(&a).unwrap().0.state, MailboxWorkerState::ReleasedBeforeSpawn);
        assert_eq!(budget.usage().unwrap().workers, 1);
        deny_foreign();
        b.operation = MailboxWorkerOperation::Query { owner: ob.clone() };
        assert_eq!(call(&b).unwrap().0.state, MailboxWorkerState::Reserved);
        assert!(call(&request_for("alpha", 6)).is_err());
        b.operation = MailboxWorkerOperation::ReleaseUnstartedV1 { owner: ob };
        assert_eq!(call(&b).unwrap().0.state, MailboxWorkerState::ReleasedBeforeSpawn);
        lock(&lock(&workers.slots).unwrap()["alpha"]).unwrap().terminal_at =
            Some(Instant::now() - TERMINAL_RETENTION);
        let replacement = call(&request_for("alpha", 6)).unwrap().0.owner;
        assert_ne!(replacement, oa);
        a.operation = MailboxWorkerOperation::DelegateConfig { owner: oa };
        assert!(workers.handoff_uncertain(&a).is_err());
        a = request_for("alpha", 6);
        a.operation = MailboxWorkerOperation::Query { owner: replacement };
        assert_eq!(call(&a).unwrap().0.state, MailboxWorkerState::Reserved);
        assert!(call(&request_for("beta", 7)).is_err());
        assert_eq!(call(&b).unwrap().0.state, MailboxWorkerState::ReleasedBeforeSpawn);
    }

    #[test]
    fn missing_vm_state_before_spawn_allows_signed_release_and_joined_retirement() {
        use std::os::unix::fs::PermissionsExt;
        use mvm_vmm::host::installed_owner::{InstallationBinding, InstallationKey};
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("mvm-mailbox");
        std::fs::write(&image, b"unused: this fixture fails before exec").unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binding = Arc::new(InstallationBinding {
            root: dir.path().join("unused"),
            key: InstallationKey { installation: [1; 32], profile: [2; 32] }, generation: 1,
        });
        let factory = InstalledMailboxWorkerFactory::new(&image, binding, dir.path()).unwrap();
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let workers = MailboxWorkers::new("local", budget.clone(), Arc::new(factory)).unwrap();
        let mut r = request(&budget, "local");
        r.workload_id = r.vm_id.clone();
        let signed = |r: &MailboxWorkerRequest| {
            let key = SigningKey::from_bytes(&[7; 32]);
            let envelope = broker_control::sign(ControlRequest::MailboxWorkerV1(Box::new(r.clone())), &key.to_bytes()).unwrap();
            verify_request(&envelope, &key.verifying_key(), budget.now_unix_ms().unwrap()).unwrap();
            workers.handle(r)
        };
        r.operation = MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch: 1 };
        let original = signed(&r).unwrap().0.owner;
        r.operation = MailboxWorkerOperation::DelegateConfig { owner: original.clone() };
        assert_eq!(signed(&r).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(signed(&r).unwrap_err().to_string().contains("admission has already been stopped"));
        r.operation = MailboxWorkerOperation::Stop { owner: original.clone() };
        assert_eq!(signed(&r).unwrap().0.state, MailboxWorkerState::Unresolved);
        r.operation = MailboxWorkerOperation::ReleaseUnstartedV1 { owner: original.clone() };
        assert_eq!(signed(&r).expect("original factory never created a child").0.state, MailboxWorkerState::ReleasedBeforeSpawn);
        assert_eq!(budget.usage().unwrap().workers, 0);
        r.operation = MailboxWorkerOperation::DelegateConfig { owner: original.clone() };
        assert!(signed(&r).is_err());
        r.vm_id = "another-vm".into();
        r.workload_id = r.vm_id.clone();
        r.operation = MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch: 1 };
        let next = signed(&r).unwrap().0.owner;
        assert_ne!(next, original);
        assert_eq!(budget.usage().unwrap().workers, 1);
        workers.begin_retirement(Instant::now()).unwrap();
        let receipt = workers.retire_originals().unwrap();
        assert_eq!(receipt.never_spawned_released(), 2);
        assert!(receipt.original_exit(&original).is_none());
        workers.finalize_retirement(&receipt).unwrap();
        assert_eq!(budget.usage().unwrap().workers, 0);
    }
    #[test]
    fn uncertain_or_panicked_spawn_cannot_redelegate_or_release() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        use std::sync::atomic::AtomicUsize;
        struct FailedFactory { panic: bool, attempts: Arc<AtomicUsize> }
        impl MailboxWorkerFactory for FailedFactory {
            fn spawn(&self, _: &MailboxWorkerRequest, _: &MailboxWorkerOwner) -> io::Result<SpawnedMailboxWorker> {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                if self.panic { panic!("factory lost its original handoff"); }
                Err(io::Error::other("unclassified legacy spawn failure"))
            }
        }
        for panic in [false, true] {
            let budget = MailboxWorkerBudget::new(limits()).unwrap();
            let attempts = Arc::new(AtomicUsize::new(0));
            let workers = MailboxWorkers::new("tenant", budget.clone(), Arc::new(FailedFactory { panic, attempts: attempts.clone() })).unwrap();
            let mut r = request(&budget, "tenant");
            let owner = workers.handle(&r).unwrap().0.owner;
            r.operation = MailboxWorkerOperation::DelegateConfig { owner: owner.clone() };
            let first = catch_unwind(AssertUnwindSafe(|| workers.handle(&r)));
            assert!(if panic { first.is_err() } else { first.unwrap().is_err() });
            assert!(workers.handle(&r).is_err());
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            r.operation = MailboxWorkerOperation::ReleaseUnstartedV1 { owner };
            assert!(workers.handle(&r).is_err());
            assert_eq!(budget.usage().unwrap().workers, 1);
            workers.begin_retirement(Instant::now()).unwrap();
            assert!(workers.retire_originals().is_err());
        }
    }
    struct NeverSpawn;
    impl MailboxWorkerFactory for NeverSpawn {
        fn spawn(
            &self,
            _: &MailboxWorkerRequest,
            _: &MailboxWorkerOwner,
        ) -> io::Result<SpawnedMailboxWorker> {
            Err(refused("test must not spawn"))
        }
    }
    struct PipeChild;
    impl MailboxWorkerFactory for PipeChild {
        fn spawn(
            &self,
            _: &MailboxWorkerRequest,
            _: &MailboxWorkerOwner,
        ) -> io::Result<SpawnedMailboxWorker> {
            let (control, child_control) = UnixStream::pair()?;
            let child = Command::new("/bin/cat")
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::from(OwnedFd::from(child_control)))
                .stderr(Stdio::null())
                .spawn()?;
            Ok(SpawnedMailboxWorker {
                child,
                control,
                parent_lease: None,
            })
        }
    }
    #[test]
    fn finalized_provider_drops_heavy_slots_while_original_status_proof_survives() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let provider = MailboxWorkers::new("tenant", budget.clone(), Arc::new(PipeChild)).unwrap();
        let mut request = request(&budget, "tenant");
        let owner = provider.handle(&request).unwrap().0.owner;
        request.operation = MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        };
        request.request_nonce = [2; 32];
        let (_, writer) = provider.handle(&request).unwrap();
        drop(writer);
        let original = Arc::downgrade(&lock(&provider.slots).unwrap()["vm-one"]);
        provider.begin_retirement(Instant::now()).unwrap();
        let receipt = provider.retire_originals().unwrap();
        provider.validate_retirement(&receipt).unwrap();
        assert_eq!(
            receipt.original_exit(&owner),
            Some(&MailboxWorkerExit::Code { code: 0 })
        );
        let before = budget.usage().unwrap();
        let held = original.upgrade().unwrap();
        assert!(provider.finalize_retirement(&receipt).is_err());
        assert_eq!(budget.usage().unwrap(), before);
        drop(held);
        provider.finalize_retirement(&receipt).unwrap();
        provider.finalize_retirement(&receipt).unwrap();
        assert!(
            original.upgrade().is_none(),
            "reaped original heavy slot remains alive"
        );
        assert_eq!(
            budget.usage().unwrap().bytes,
            before.bytes - limits().bytes_per_worker + receipt.retained_bytes()
        );
        assert!(receipt.retained_bytes() > 0);
        drop(provider);
        assert_eq!(
            receipt.original_exit(&owner),
            Some(&MailboxWorkerExit::Code { code: 0 })
        );
        let lease = receipt.retained_bytes();
        let ledger = budget.ledger.clone();
        let cleanup = Arc::downgrade(&budget.cleanup);
        let actor = lock(&budget.actor).unwrap().take().unwrap();
        drop(budget);
        actor.join().unwrap();
        assert!(
            cleanup.upgrade().is_none(),
            "receipt retained original cleanup storage"
        );
        assert_eq!(lock(&ledger).unwrap().host.bytes, lease);
        assert_eq!(
            receipt.original_exit(&owner),
            Some(&MailboxWorkerExit::Code { code: 0 })
        );
        drop(receipt);
        assert_eq!(lock(&ledger).unwrap().host.bytes, 0);
        eprintln!("original_exit=0 retained_proof_bytes={lease} final_ledger_bytes=0");
    }

    #[test]
    fn returned_handoff_cell_keeps_original_child_and_credit_on_queue_failure() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let owner = MailboxWorkers::new("tenant", budget.clone(), Arc::new(PipeChild)).unwrap();
        let mut r = request(&budget, "tenant");
        let acquired = owner.handle(&r).unwrap().0;
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: acquired.owner,
        };
        r.request_nonce = [2; 32];
        let (_, writer) = owner.handle(&r).unwrap();
        let slot = lock(&owner.slots).unwrap().get("vm-one").cloned().unwrap();
        let pid = lock(&slot).unwrap().worker.as_ref().unwrap().child.id();
        let original = Arc::downgrade(&slot);
        drop(slot);
        let (dead_sender, dead_receiver) = mpsc::sync_channel(1);
        drop(dead_receiver);
        *lock(&budget.sender).unwrap() = Some(dead_sender);
        drop(owner);
        // Holding the caller's writer deliberately keeps this actual cat child
        // alive. A returned channel item must still own the original handle.
        let retained = original
            .upgrade()
            .expect("handoff failure dropped original child owner");
        assert_eq!(
            lock(&retained).unwrap().worker.as_ref().unwrap().child.id(),
            pid
        );
        assert_eq!(budget.usage().unwrap().workers, 1);
        assert!(budget.cleanup.failed.load(Ordering::Acquire));
        assert!(budget.charge("another-tenant", None).is_err());
        drop(writer); // Only releases fixture input; no external process wait.
    }
    #[test]
    fn idle_terminal_expiry_removes_zero_charge_tenants_worker_review_red() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let baseline = budget.usage().unwrap();
        for index in 0..100 {
            let tenant = format!("tenant-{index}");
            let owner = MailboxWorkers::new(&tenant, budget.clone(), Arc::new(NeverSpawn)).unwrap();
            let r = request(&budget, &tenant);
            owner.handle(&r).unwrap();
            // Pure accounting fixture: no Child/exit proof is manufactured on
            // the control wire. Advance only the private terminal timestamp.
            let slot = lock(&owner.slots).unwrap().get("vm-one").cloned().unwrap();
            {
                let mut slot = lock(&slot).unwrap();
                slot.state = MailboxWorkerState::Collected {
                    exit: MailboxWorkerExit::Code { code: 0 },
                };
                slot.terminal_at =
                    Some(Instant::now() - TERMINAL_RETENTION - std::time::Duration::from_millis(1));
            }
            budget.collected(&tenant).unwrap();
            drop(slot);
            assert_eq!(owner.registration_count().unwrap(), 0);
            assert_eq!(budget.usage().unwrap(), baseline);
            assert!(
                lock(&budget.ledger).unwrap().tenants.is_empty(),
                "idle expiry outside a control permit must not retain tenant strings"
            );
        }
    }

    struct PausedSpawn {
        entered: mpsc::SyncSender<()>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }
    impl MailboxWorkerFactory for PausedSpawn {
        fn spawn(
            &self,
            _: &MailboxWorkerRequest,
            _: &MailboxWorkerOwner,
        ) -> io::Result<SpawnedMailboxWorker> {
            let (control, child_control) = UnixStream::pair()?;
            let child = Command::new("/bin/cat")
                .env_clear()
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::from(OwnedFd::from(child_control)))
                .stderr(Stdio::null())
                .spawn()?;
            self.entered.send(()).unwrap();
            let (gate, changed) = &*self.gate;
            let mut release = gate.lock().unwrap();
            while !*release {
                release = changed.wait(release).unwrap();
            }
            Ok(SpawnedMailboxWorker {
                child,
                control,
                parent_lease: None,
            })
        }
    }
    fn call(
        path: &std::path::Path,
        r: &MailboxWorkerRequest,
    ) -> io::Result<(MailboxWorkerResult, Option<OwnedFd>)> {
        let mut stream = UnixStream::connect(path)?;
        let signed = broker_control::sign(
            ControlRequest::MailboxWorkerV1(Box::new(r.clone())),
            &[7; 32],
        )
        .unwrap();
        let bytes = serde_json::to_vec(&signed)?;
        stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
        stream.write_all(&bytes)?;
        mvm_vmm::host::mailbox_worker_transport::recv_response(
            &mut stream,
            r,
            Instant::now() + std::time::Duration::from_secs(5),
        )
    }
    #[tokio::test]
    async fn spawn_completion_rechecks_admission_before_writer_worker_review_red() {
        let budget = MailboxWorkerBudget::new(limits()).unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let factory = Arc::new(PausedSpawn {
            entered: entered_tx,
            gate: gate.clone(),
        });
        let owner = Arc::new(MailboxWorkers::new("tenant", budget.clone(), factory).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let daemon = HostAgentDaemon::new(
            "tenant",
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            65_536,
        )
        .with_mailbox_workers(owner)
        .unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { daemon.run(&server_path).await });
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let mut r = request(&budget, "tenant");
        r.admission_expires_at_unix_ms = budget.now_unix_ms().unwrap() + 1_000;
        let p = path.clone();
        let q = r.clone();
        let acquired = tokio::task::spawn_blocking(move || call(&p, &q).unwrap().0)
            .await
            .unwrap();
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: acquired.owner.clone(),
        };
        r.request_nonce = [2; 32];
        let p = path.clone();
        let q = r.clone();
        let delegated = tokio::task::spawn_blocking(move || call(&p, &q));
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
        })
        .await
        .unwrap();
        // Trusted, private clock seam, advanced only after real Child exists.
        *lock(&budget.clock_high_water).unwrap() = r.admission_expires_at_unix_ms + 1;
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        let result = delegated.await.unwrap();
        let stale_writer_was_exposed = result.is_ok();
        if let Ok((_, fd)) = result {
            drop(fd);
        }
        r.operation = MailboxWorkerOperation::Stop {
            owner: acquired.owner,
        };
        r.request_nonce = [3; 32];
        r.deadline_unix_ms = budget.now_unix_ms().unwrap() + 4_000;
        let cleanup = tokio::task::spawn_blocking(move || call(&path, &r))
            .await
            .unwrap();
        assert!(
            matches!(
                cleanup.unwrap().0.state,
                MailboxWorkerState::Collected { .. }
            ),
            "original child must remain available for collection"
        );
        server.abort();
        assert!(
            !stale_writer_was_exposed,
            "factory finished after admission expiry; no writer may be published"
        );
    }
}
