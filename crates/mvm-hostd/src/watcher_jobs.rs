//! One finite cleanup job per watcher, retaining the original Child and lease.
//! Stop fences new reservations; timeout/cancellation never refunds a live job.
//! Call blocking drain outside daemon/file locks and outside an async executor.
//! The trusted caller must exclude competing reapers/disposition changes for the
//! entire child lifetime. This component does not grant command/VM authority.
use mvm_vmm::host::installed_owner::{HolderLease, spawn_with_resource_lease};
use mvm_vmm::host::process_exit::{
    ProcessExitObserver, collect_after_exit_event, require_owned_child_custody,
    wait_process_exit_events,
};
use std::fmt;
use std::io;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const WAITER_STACK_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Active,
    Joining,
    Unresolved,
}
struct Inner {
    stopped: bool,
    phase: Phase,
    collected: u64,
    spawn_failures: u64,
    waiter: Option<JoinHandle<()>>,
    retry_requested: bool,
    retryable: bool,
}
struct State {
    inner: Mutex<Inner>,
    changed: Condvar,
}
struct Control {
    state: Arc<State>,
}
impl Drop for Control {
    fn drop(&mut self) {
        let mut inner = self
            .state
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.stopped = true;
        self.state.changed.notify_all();
    }
}
/// Clones share exactly one reserved job slot. The actor holds State, not
/// Control, so dropping the last external owner stops future reservations.
#[derive(Clone)]
pub struct WatcherJobOwner {
    control: Arc<Control>,
}
/// Constructed only after stop fencing and actual original-child collection.
#[derive(Debug)]
pub struct WatcherDrainReceipt {
    collected: u64,
    spawn_failures: u64,
}
impl WatcherDrainReceipt {
    pub fn collected_jobs(&self) -> u64 {
        self.collected
    }
    /// Known failures before a Child existed, distinct from collected jobs.
    pub fn spawn_failures(&self) -> u64 {
        self.spawn_failures
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatcherDrainError {
    TimedOut,
    Unresolved,
    Poisoned,
}
impl fmt::Display for WatcherDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "watcher cleanup drain: {self:?}")
    }
}
impl std::error::Error for WatcherDrainError {}
impl Default for WatcherJobOwner {
    fn default() -> Self {
        Self::new()
    }
}
impl WatcherJobOwner {
    pub fn new() -> Self {
        Self {
            control: Arc::new(Control {
                state: Arc::new(State {
                    inner: Mutex::new(Inner {
                        stopped: false,
                        phase: Phase::Idle,
                        collected: 0,
                        spawn_failures: 0,
                        waiter: None,
                        retry_requested: false,
                        retryable: false,
                    }),
                    changed: Condvar::new(),
                }),
            }),
        }
    }
    /// Conservative nonblocking activity observation for the daemon's final
    /// admission gate. Err is unknown, never idle. False does not join a waiter
    /// or create a collection receipt; callers still fence all new admissions.
    pub fn has_inflight_job(&self) -> Result<bool, WatcherDrainError> {
        let inner = self
            .control
            .state
            .inner
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => WatcherDrainError::Unresolved,
                std::sync::TryLockError::Poisoned(_) => WatcherDrainError::Poisoned,
            })?;
        Ok(inner.phase != Phase::Idle)
    }
    /// Reserves before creating a waiter or Child. Ok means accepted, not
    /// spawned/collected. Trusted fixed-command construction remains external.
    /// Jobs accepted before stop remain accounted as inflight even if OS spawn
    /// follows the stop request. The typed installer retains the actual CLI SH.
    pub fn try_spawn(&self, command: Command, lease: HolderLease) -> io::Result<()> {
        require_owned_child_custody()?;
        let state = &self.control.state;
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| io::Error::other("watcher job state poisoned"))?;
        if inner.stopped || inner.phase != Phase::Idle {
            return Err(io::Error::other("watcher job stopped, busy or unresolved"));
        }
        inner.phase = Phase::Active;
        inner.retry_requested = false;
        inner.retryable = false;
        let previous = inner.waiter.take();
        drop(inner);
        if previous.is_some_and(|waiter| waiter.join().is_err()) {
            quarantine(state, false);
            return Err(io::Error::other("watcher waiter failed"));
        }
        let actor_state = state.clone();
        // Publish the JoinHandle before the actor may publish terminal state.
        // No child wait, join or command spawn holds this private mutex.
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| io::Error::other("watcher job state poisoned"))?;
        match std::thread::Builder::new()
            .name("host-agent-watcher-job".into())
            .stack_size(WAITER_STACK_BYTES)
            .spawn(move || run_job(actor_state, command, lease))
        {
            Ok(waiter) => {
                inner.waiter = Some(waiter);
                Ok(())
            }
            Err(error) => {
                inner.phase = Phase::Idle;
                inner.spawn_failures = inner.spawn_failures.saturating_add(1);
                state.changed.notify_all();
                Err(error)
            }
        }
    }
    pub fn request_stop(&self) {
        let state = &self.control.state;
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.stopped = true;
        state.changed.notify_all();
    }
    /// Request one cleanup retry of the SAME retained original Child/lease.
    /// This never replays Command, remints an epoch, reopens admission or reports
    /// collection. The actor sleeps between explicit requests; repeated requests
    /// while one is active are refused rather than queued.
    pub fn retry_cleanup(&self) -> io::Result<()> {
        require_owned_child_custody()?;
        let state = &self.control.state;
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| io::Error::other("watcher job state poisoned"))?;
        if inner.phase != Phase::Unresolved || !inner.retryable {
            return Err(io::Error::other(
                "no retained watcher child available for retry",
            ));
        }
        let actor = inner
            .waiter
            .as_ref()
            .ok_or_else(|| io::Error::other("original watcher actor missing"))?
            .thread()
            .clone();
        inner.retry_requested = true;
        inner.phase = Phase::Active;
        drop(inner);
        actor.unpark();
        Ok(())
    }
    /// Some uses the caller's original deadline; None waits the same retained
    /// completion after grace expiry. Neither timeout nor cancellation kills or
    /// drops the original child. This method itself fences new reservations.
    pub fn drain(
        &self,
        deadline: Option<Instant>,
    ) -> Result<WatcherDrainReceipt, WatcherDrainError> {
        self.request_stop();
        let state = &self.control.state;
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| WatcherDrainError::Poisoned)?;
        loop {
            match inner.phase {
                Phase::Unresolved => return Err(WatcherDrainError::Unresolved),
                Phase::Idle => {
                    if let Some(waiter) = inner.waiter.take() {
                        inner.phase = Phase::Joining;
                        drop(inner);
                        let joined = waiter.join();
                        inner = state
                            .inner
                            .lock()
                            .map_err(|_| WatcherDrainError::Poisoned)?;
                        if joined.is_err() {
                            inner.phase = Phase::Unresolved;
                        } else {
                            inner.phase = Phase::Idle;
                        }
                        state.changed.notify_all();
                        continue;
                    }
                    return Ok(WatcherDrainReceipt {
                        collected: inner.collected,
                        spawn_failures: inner.spawn_failures,
                    });
                }
                Phase::Active | Phase::Joining => {
                    inner = match deadline {
                        Some(deadline) => {
                            let remaining = deadline
                                .checked_duration_since(Instant::now())
                                .filter(|remaining| !remaining.is_zero())
                                .ok_or(WatcherDrainError::TimedOut)?;
                            state
                                .changed
                                .wait_timeout(inner, remaining)
                                .map_err(|_| WatcherDrainError::Poisoned)?
                                .0
                        }
                        None => state
                            .changed
                            .wait(inner)
                            .map_err(|_| WatcherDrainError::Poisoned)?,
                    };
                }
            }
        }
    }
}
fn quarantine(state: &State, retryable: bool) {
    let mut inner = state
        .inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    inner.stopped = true;
    inner.phase = Phase::Unresolved;
    inner.retry_requested = false;
    inner.retryable = retryable;
    state.changed.notify_all();
}
struct OriginalJob {
    child: Child,
    _parent_lease: HolderLease,
    observer: Option<ProcessExitObserver>,
    exit_observed: bool,
}
fn collect_original(job: &mut OriginalJob) -> io::Result<ExitStatus> {
    require_owned_child_custody()?;
    if let Some(status) = job.child.try_wait()? {
        return Ok(status);
    }
    if !job.exit_observed {
        if job.observer.is_none() {
            let pid = job
                .child
                .id()
                .try_into()
                .map_err(|_| io::Error::other("watcher child PID range"))?;
            job.observer = Some(
                ProcessExitObserver::arm(pid)
                    .map_err(|_| io::Error::other("watcher child observer unavailable"))?,
            );
        }
        let observer = job
            .observer
            .as_ref()
            .ok_or_else(|| io::Error::other("original watcher observer missing"))?;
        loop {
            let events = wait_process_exit_events(&[observer], None, None)
                .map_err(|_| io::Error::other("watcher child observer failed"))?;
            if !events.exited.is_empty() {
                break;
            }
        }
        // Persist before the fallible custody/collection check: Darwin's event
        // may have been consumed, including when this attempt becomes unresolved.
        job.exit_observed = true;
    }
    // One bounded post-event collection window. Timeout retains custody for an
    // explicit retry; no automatic renewal or unbounded timer-poll ladder.
    collect_after_exit_event(Instant::now() + Duration::from_secs(5), || {
        require_owned_child_custody()?;
        job.child.try_wait()
    })?
    .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "watcher exit not collected"))
}
fn run_job(state: Arc<State>, command: Command, lease: HolderLease) {
    let mut job = None;
    let mut outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
            require_owned_child_custody()?;
            // All fallible installer preparation precedes spawn; both original
            // owners are returned without a fallible post-spawn gap.
            let (child, parent_lease) = spawn_with_resource_lease(command, lease)?;
            job = Some(OriginalJob {
                child,
                _parent_lease: parent_lease,
                observer: None,
                exit_observed: false,
            });
            collect_original(job.as_mut().expect("original job retained"))?;
            Ok(())
        }));
    loop {
        match outcome {
            Ok(Ok(())) => {
                drop(job.take());
                let mut inner = state
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                inner.collected = inner.collected.saturating_add(1);
                inner.phase = Phase::Idle;
                inner.retryable = false;
                state.changed.notify_all();
                return;
            }
            Ok(Err(_)) if job.is_none() => {
                let mut inner = state
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                inner.spawn_failures = inner.spawn_failures.saturating_add(1);
                inner.phase = Phase::Idle;
                inner.retryable = false;
                state.changed.notify_all();
                return;
            }
            Ok(Err(_)) => quarantine(&state, job.is_some()),
            Err(payload) => {
                // A panic is not a transient I/O refusal. Retain its payload
                // too: dropping an arbitrary panic payload could itself unwind
                // and abandon the original job. No retry or replacement here.
                quarantine(&state, false);
                let _retained_panic = payload;
                loop {
                    std::thread::park();
                }
            }
        }
        // Original job and epoch stay on this actor's stack. Spurious unparks
        // do nothing: only a bounded explicit request enables the SAME cleanup.
        loop {
            std::thread::park();
            let mut inner = state
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if inner.retry_requested && job.is_some() {
                inner.retry_requested = false;
                break;
            }
        }
        if let Some(job) = job.as_mut()
            && !job.exit_observed
        {
            // An unobserved faulty event handle may be rearmed, never a Child
            // or lease replacement. A consumed exit observation stays sticky.
            job.observer = None;
        }
        outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
            collect_original(
                job.as_mut()
                    .ok_or_else(|| io::Error::other("original watcher job missing"))?,
            )?;
            Ok(())
        }));
    }
}
