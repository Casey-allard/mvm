//! Original thread custody for the installed endpoint's TCP relays.

#[cfg(test)]
#[path = "owned_relays_tests.rs"]
mod custody_tests;

use super::socket::FlowSocket;
use crate::installed_endpoint::{InstalledEndpointComponentPermit, InstalledEndpointResources};
use mvm_vmm::host::network_endpoint_spawn::InstalledGuestWake;
use std::{
    io,
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub const OWNED_TCP_RELAY_STACK_BYTES: u64 = 2 << 20;
const MAX_RELAYS: usize = 32;
const CLOSURE_LIMIT: usize = 16 << 10;
const SLOT_METADATA_BYTES: u64 = 64 << 10;
const GROUP_METADATA_BYTES: u64 = 16 << 10;

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// One original installed resource subdivision, shared across all sessions.
pub struct OwnedTcpRelays {
    inner: Arc<Inner>,
}
impl std::fmt::Debug for OwnedTcpRelays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedTcpRelays").finish_non_exhaustive()
    }
}
struct Inner {
    resource: InstalledEndpointComponentPermit,
    ledger: Mutex<Ledger>,
    changed: Condvar,
    fenced: AtomicBool,
    retained: AtomicBool,
}
struct Ledger {
    closed: bool,
    failed: bool,
    next: u64,
    slots: Vec<Slot>,
    quarantine: Vec<Worker>,
    reader_quarantine: Vec<Arc<RelayWake>>,
}
struct Slot {
    serial: u64,
    phase: Phase,
    setup: Option<Arc<SetupWake>>,
    prepared: Option<Arc<RelayWake>>,
}
enum Phase {
    Empty,
    Reserved,
    Launching,
    Active(Worker),
    Joining,
    Reader { wake: Arc<RelayWake>, busy: bool },
}
struct Worker {
    handle: JoinHandle<()>,
    wake: Arc<RelayWake>,
    completed: Arc<AtomicBool>,
}
struct Completion {
    inner: Arc<Inner>,
    signalled: Arc<AtomicBool>,
}
impl Drop for Completion {
    fn drop(&mut self) {
        // The predicate and notification use the same ledger as the waiter,
        // including unwind/startup refusal, so completion cannot be missed.
        let _ledger = match self.inner.ledger.lock() {
            Ok(ledger) => ledger,
            Err(poisoned) => {
                self.inner.retain();
                poisoned.into_inner()
            }
        };
        self.signalled.store(true, Ordering::Release);
        self.inner.changed.notify_all();
    }
}
pub(super) struct RelayWake {
    pub upstream: Mutex<FlowSocket>,
    pub guest: Arc<InstalledGuestWake>,
    pub retired: Arc<AtomicBool>,
}
struct SetupWake {
    upstream: TcpStream,
    guest: Arc<InstalledGuestWake>,
    upstream_stopped: Mutex<bool>,
}
impl SetupWake {
    fn shutdown(&self) -> io::Result<()> {
        let upstream = (|| {
            // Serialize observation with the actual nonblocking shutdown, not
            // with the relay ledger or its potentially concurrent transitions.
            let mut stopped = self
                .upstream_stopped
                .lock()
                .map_err(|_| refused("owned setup wake poisoned"))?;
            if !*stopped {
                self.upstream.shutdown(Shutdown::Both)?;
                *stopped = true;
            }
            Ok(())
        })();
        let guest = self.guest.shutdown();
        upstream.and(guest)
    }
}
enum Wake {
    Setup(Arc<SetupWake>),
    Relay(Arc<RelayWake>),
}
impl Wake {
    fn shutdown(&self) -> io::Result<()> {
        match self {
            Self::Setup(wake) => wake.shutdown(),
            Self::Relay(wake) => wake.shutdown(),
        }
    }
}
impl RelayWake {
    fn cancel_reader(&self) -> io::Result<()> {
        match self.upstream.try_lock() {
            Ok(socket) => socket.shutdown(Shutdown::Both),
            // The same original path is already owned by cleanup; positive
            // reader completion is still required before the slot can retire.
            Err(std::sync::TryLockError::WouldBlock) => Ok(()),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err(io::Error::other("owned relay wake poisoned"))
            }
        }
    }
    fn shutdown(&self) -> io::Result<()> {
        self.retired.store(true, Ordering::Release);
        // Always attempt both original paths, including if the first fails.
        let upstream = self.cancel_reader();
        let guest = self.guest.shutdown();
        upstream.and(guest)
    }
    fn complete_reader_until(&self, until: Instant) -> io::Result<()> {
        match self.upstream.try_lock() {
            Ok(socket) => socket.close_reader_until(until),
            Err(std::sync::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "original reader cleanup busy",
            )),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err(io::Error::other("owned relay wake poisoned"))
            }
        }
    }
}

struct ReaderClaim {
    inner: Arc<Inner>,
    finished: bool,
}
impl Drop for ReaderClaim {
    fn drop(&mut self) {
        if !self.finished {
            self.inner.retain();
            if let Ok(mut ledger) = self.inner.ledger.lock() {
                ledger.closed = true;
                ledger.failed = true;
            }
            self.inner.changed.notify_all();
        }
    }
}

impl OwnedTcpRelays {
    pub(super) fn check_installed_audit(
        &self,
        audit: &mvm_vmm::host::network_endpoint_spawn::InstalledEndpointAudit,
    ) -> io::Result<()> {
        self.inner.resource.check_current()?;
        if !self.inner.resource.has_original_audit(audit) {
            return Err(refused("owned relay original audit authority differs"));
        }
        audit
            .check_current()
            .map_err(|_| refused("original audit authority closed"))?;
        if self.inner.fenced.load(Ordering::Acquire) {
            return Err(refused("owned relay admission closed"));
        }
        Ok(())
    }
    pub(super) fn check_reader_partition(
        &self,
        reader: &InstalledEndpointComponentPermit,
    ) -> io::Result<()> {
        reader.check_current()?;
        self.inner.resource.check_current()?;
        if !self.inner.resource.same_partition(reader) {
            return Err(refused("owned relay original partition differs"));
        }
        if self.inner.fenced.load(Ordering::Acquire) {
            return Err(refused("owned relay admission closed"));
        }
        Ok(())
    }
    pub fn from_installed_resources(
        original: &InstalledEndpointResources,
    ) -> io::Result<Arc<Self>> {
        if original.network_config().is_none() {
            return Err(refused(
                "owned TCP relays require original network resources",
            ));
        }
        let count = usize::from(original.lease().projection().limits.max_streams);
        if !(1..=MAX_RELAYS).contains(&count)
            || std::mem::size_of::<Slot>() + std::mem::size_of::<RelayWake>() > 4096
        {
            return Err(refused("owned TCP relay shape unsupported"));
        }
        let count_u64 = u64::try_from(count).map_err(|_| refused("relay count overflow"))?;
        let stack_terms =
            mvm_core::host_lifetime::native_thread_stack_terms(OWNED_TCP_RELAY_STACK_BYTES)
                .map_err(io::Error::other)?;
        let stacks = count_u64
            .checked_mul(stack_terms.known_rust_bytes)
            .ok_or_else(|| refused("relay stack sum overflow"))?;
        let metadata = count_u64
            .checked_mul(SLOT_METADATA_BYTES)
            .and_then(|bytes| bytes.checked_add(GROUP_METADATA_BYTES))
            .ok_or_else(|| refused("relay metadata sum overflow"))?;
        let resource = original.claim_relay_group(stacks, metadata)?;
        resource.check_current()?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| io::Error::other("relay slot allocation refused"))?;
        slots.extend((0..count).map(|_| Slot {
            serial: 0,
            phase: Phase::Empty,
            setup: None,
            prepared: None,
        }));
        let mut quarantine = Vec::new();
        quarantine
            .try_reserve_exact(count)
            .map_err(|_| io::Error::other("relay custody allocation refused"))?;
        let mut reader_quarantine = Vec::new();
        reader_quarantine
            .try_reserve_exact(count)
            .map_err(|_| io::Error::other("reader custody allocation refused"))?;
        Ok(Arc::new(Self {
            inner: Arc::new(Inner {
                resource,
                ledger: Mutex::new(Ledger {
                    closed: false,
                    failed: false,
                    next: 1,
                    slots,
                    quarantine,
                    reader_quarantine,
                }),
                changed: Condvar::new(),
                fenced: AtomicBool::new(false),
                retained: AtomicBool::new(false),
            }),
        }))
    }

    pub(super) fn reserve_until(&self, until: Instant) -> io::Result<RelayReservation> {
        self.inner.resource.check_current()?;
        self.collect_finished(until)?;
        self.inner.resource.check_current()?;
        if Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned relay admission deadline",
            ));
        }
        let mut ledger = self.inner.lock()?;
        if ledger.closed || ledger.failed || self.inner.fenced.load(Ordering::Acquire) {
            return Err(refused("owned relay admission closed"));
        }
        let index = ledger
            .slots
            .iter()
            .position(|slot| {
                matches!(slot.phase, Phase::Empty)
                    && slot.setup.is_none()
                    && slot.prepared.is_none()
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "owned relay capacity full")
            })?;
        let serial = ledger.next;
        ledger.next = serial.checked_add(1).ok_or_else(|| {
            self.inner.fenced.store(true, Ordering::Release);
            refused("owned relay serial exhausted")
        })?;
        ledger.slots[index] = Slot {
            serial,
            phase: Phase::Reserved,
            setup: None,
            prepared: None,
        };
        Ok(RelayReservation {
            inner: self.inner.clone(),
            index,
            serial,
        })
    }

    fn collect_finished(&self, until: Instant) -> io::Result<()> {
        loop {
            let next = {
                let mut ledger = self.inner.lock()?;
                if ledger.failed {
                    return Err(refused("owned relay cleanup uncertain"));
                }
                ledger.slots.iter_mut().enumerate().find_map(|(index, slot)| {
                    if matches!(&slot.phase, Phase::Active(worker) if worker.handle.is_finished()) {
                        let Phase::Active(worker) = std::mem::replace(&mut slot.phase, Phase::Joining)
                        else {
                            return None;
                        };
                        Some((index, slot.serial, worker))
                    } else {
                        None
                    }
                })
            };
            let Some((index, serial, worker)) = next else {
                return self.collect_readers(until);
            };
            let result = worker.handle.join();
            let wake = worker.wake;
            let mut ledger = match self.inner.lock() {
                Ok(ledger) => ledger,
                Err(error) => {
                    std::mem::forget(wake);
                    self.inner.retain();
                    return Err(error);
                }
            };
            if ledger.slots[index].serial != serial
                || !matches!(ledger.slots[index].phase, Phase::Joining)
            {
                ledger.failed = true;
                ledger.closed = true;
                // A corrupted identity cannot authorize dropping the original
                // last mapped wake. This one orphan remains quarantined.
                std::mem::forget(wake);
                self.inner.retain();
                return Err(refused("owned relay join identity differs"));
            }
            ledger.slots[index].phase = Phase::Reader { wake, busy: false };
            if result.is_err() {
                ledger.failed = true;
                ledger.closed = true;
                self.inner.retain();
                return Err(io::Error::other("owned relay panicked"));
            }
            self.inner.changed.notify_all();
        }
    }

    fn collect_readers(&self, until: Instant) -> io::Result<()> {
        loop {
            let next = {
                let mut ledger = self.inner.lock()?;
                if ledger.failed {
                    return Err(refused("owned reader cleanup uncertain"));
                }
                let closed = ledger.closed;
                ledger
                    .slots
                    .iter_mut()
                    .enumerate()
                    .find_map(|(index, slot)| {
                        if let Phase::Reader { wake, busy } = &mut slot.phase
                            && !*busy
                            && (closed || wake.retired.load(Ordering::Acquire))
                        {
                            *busy = true;
                            return Some((index, slot.serial, wake.clone()));
                        }
                        None
                    })
            };
            let Some((index, serial, wake)) = next else {
                return Ok(());
            };
            // The ledger keeps its own original wake throughout this call.
            // Unwind or timeout cannot drop the last reader/codec owner.
            let mut claim = ReaderClaim {
                inner: self.inner.clone(),
                finished: false,
            };
            let result = wake.complete_reader_until(until);
            let mut ledger = self.inner.lock()?;
            let slot = &mut ledger.slots[index];
            if slot.serial != serial || !matches!(slot.phase, Phase::Reader { busy: true, .. }) {
                std::mem::forget(wake);
                return Err(refused("owned reader identity differs"));
            }
            if let Err(error) = result {
                if let Phase::Reader { busy, .. } = &mut slot.phase {
                    *busy = false;
                }
                if !matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) {
                    ledger.failed = true;
                    ledger.closed = true;
                }
                self.inner.retain();
                self.inner.changed.notify_all();
                claim.finished = true;
                return Err(error);
            }
            let original = std::mem::replace(&mut slot.phase, Phase::Empty);
            self.inner.changed.notify_all();
            claim.finished = true;
            drop(ledger);
            // Explicit positive reader completion precedes the final mapped
            // drop/store cleanup; all such work stays outside the ledger.
            drop(original);
            drop(wake);
            if Instant::now() >= until {
                self.inner.retain();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned reader cleanup deadline",
                ));
            }
        }
    }

    pub(crate) fn close_and_wake(&self) -> io::Result<()> {
        let wakes = {
            let mut ledger = self.inner.lock()?;
            ledger.closed = true;
            self.inner.fenced.store(true, Ordering::Release);
            self.inner.changed.notify_all();
            let mut wakes = Vec::new();
            wakes
                .try_reserve_exact(
                    ledger.slots.len() + ledger.quarantine.len() + ledger.reader_quarantine.len(),
                )
                .map_err(|_| io::Error::other("relay wake allocation refused"))?;
            for slot in &ledger.slots {
                if let Some(wake) = &slot.prepared {
                    wakes.push(Wake::Relay(wake.clone()));
                } else if let Some(wake) = &slot.setup {
                    wakes.push(Wake::Setup(wake.clone()));
                } else if let Phase::Active(worker) = &slot.phase {
                    if !worker.handle.is_finished() {
                        wakes.push(Wake::Relay(worker.wake.clone()));
                    }
                } else if let Phase::Reader { wake, .. } = &slot.phase {
                    wakes.push(Wake::Relay(wake.clone()));
                }
            }
            wakes.extend(
                ledger
                    .quarantine
                    .iter()
                    .map(|worker| Wake::Relay(worker.wake.clone())),
            );
            wakes.extend(
                ledger
                    .reader_quarantine
                    .iter()
                    .map(|wake| Wake::Relay(wake.clone())),
            );
            wakes
        };
        let mut failed = None;
        for wake in wakes {
            if let Err(error) = wake.shutdown() {
                failed = Some(error);
            }
        }
        if let Some(error) = failed {
            let mut ledger = self.inner.lock()?;
            ledger.failed = true;
            self.inner.retain();
            return Err(error);
        }
        Ok(())
    }

    pub fn close_and_join(&self, deadline: Instant) -> io::Result<()> {
        self.close_and_wake()?;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                self.inner.retain();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned relay join deadline",
                ));
            }
            self.collect_finished(deadline)?;
            let ledger = self.inner.lock()?;
            if ledger.failed {
                return Err(refused("owned relay cleanup uncertain"));
            }
            if ledger
                .slots
                .iter()
                .all(|slot| matches!(slot.phase, Phase::Empty))
            {
                if Instant::now() >= deadline {
                    self.inner.retain();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "owned relay join deadline",
                    ));
                }
                return Ok(());
            }
            // The owned completion event precedes std's final native thread
            // epilogue. Only that short compatibility phase samples the
            // original JoinHandle; active work waits on its actual event.
            let native_epilogue = ledger.slots.iter().any(|slot| {
                matches!(&slot.phase, Phase::Active(worker) if worker.completed.load(Ordering::Acquire))
            });
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                self.inner.retain();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned relay join deadline",
                ));
            }
            let wait = if native_epilogue {
                left.min(Duration::from_millis(1))
            } else {
                left
            };
            drop(self.inner.changed.wait_timeout(ledger, wait).map_err(|_| {
                self.inner.retain();
                refused("owned relay completion ledger poisoned")
            })?);
        }
    }
}
impl Drop for OwnedTcpRelays {
    fn drop(&mut self) {
        if self.close_and_wake().is_err()
            || !self.inner.lock().is_ok_and(|ledger| {
                !ledger.failed
                    && ledger
                        .slots
                        .iter()
                        .all(|slot| matches!(slot.phase, Phase::Empty))
                    && ledger.quarantine.is_empty()
                    && ledger.reader_quarantine.is_empty()
            })
        {
            self.inner.retain();
        }
    }
}
impl Inner {
    fn lock(self: &Arc<Self>) -> io::Result<std::sync::MutexGuard<'_, Ledger>> {
        self.ledger.lock().map_err(|_| {
            self.retain();
            refused("owned relay ledger poisoned")
        })
    }
    fn retain(self: &Arc<Self>) {
        self.fenced.store(true, Ordering::Release);
        if !self.retained.swap(true, Ordering::AcqRel) {
            std::mem::forget(self.clone());
        }
    }
}

pub(super) struct RelayReservation {
    inner: Arc<Inner>,
    index: usize,
    serial: u64,
}

#[derive(Clone)]
pub(super) struct RelayWitness {
    inner: Arc<Inner>,
    index: usize,
    serial: u64,
    guest: Arc<InstalledGuestWake>,
}
impl std::fmt::Debug for RelayWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayWitness").finish_non_exhaustive()
    }
}
impl RelayWitness {
    pub(super) fn retain_prepared(
        &self,
        stream: super::spiralcore_payload::EnrolledPayloadStream,
    ) -> io::Result<()> {
        #[cfg(test)]
        custody_tests::before_attach(self);
        let wake = Arc::new(RelayWake {
            upstream: Mutex::new(FlowSocket::mapped(Box::new(stream))),
            guest: self.guest.clone(),
            retired: Arc::new(AtomicBool::new(false)),
        });
        // Core already exists. Even a concurrent close or poisoned ledger must
        // accept cleanup custody before returning any error to its creator.
        let mut ledger = match self.inner.ledger.lock() {
            Ok(ledger) => ledger,
            Err(poisoned) => {
                self.inner.retain();
                let mut ledger = poisoned.into_inner();
                ledger.failed = true;
                ledger.closed = true;
                ledger
            }
        };
        let valid = ledger.slots.get(self.index).is_some_and(|slot| {
            slot.serial == self.serial
                && matches!(slot.phase, Phase::Reserved)
                && slot.prepared.is_none()
        });
        if valid {
            ledger.slots[self.index].prepared = Some(wake);
            self.inner.changed.notify_all();
            if ledger.closed || ledger.failed || self.inner.fenced.load(Ordering::Acquire) {
                return Err(refused("prepared reader retained after admission closed"));
            }
            return Ok(());
        }
        ledger.closed = true;
        ledger.failed = true;
        self.inner.retain();
        if ledger.reader_quarantine.len() < ledger.slots.len() {
            ledger.reader_quarantine.push(wake);
        } else {
            // The first custody inconsistency fences all further allocation.
            std::mem::forget(wake);
        }
        self.inner.changed.notify_all();
        Err(refused(
            "prepared reader identity differs; custody retained",
        ))
    }
    pub(super) fn check(&self, reader: &InstalledEndpointComponentPermit) -> io::Result<()> {
        reader.check_current()?;
        self.inner.resource.check_current()?;
        if !self.inner.resource.same_partition(reader) {
            return Err(refused("relay witness original partition differs"));
        }
        let ledger = self.inner.lock()?;
        if ledger.closed
            || ledger.failed
            || self.inner.fenced.load(Ordering::Acquire)
            || !ledger.slots.get(self.index).is_some_and(|slot| {
                slot.serial == self.serial
                    && match &slot.phase {
                        Phase::Reserved | Phase::Launching | Phase::Active(_) => true,
                        Phase::Reader { wake, busy } => {
                            !*busy && !wake.retired.load(Ordering::Acquire)
                        }
                        _ => false,
                    }
            })
        {
            return Err(refused("relay witness is not current"));
        }
        Ok(())
    }
}
impl RelayReservation {
    pub(super) fn bind_setup(
        &self,
        upstream: &TcpStream,
        guest: Arc<InstalledGuestWake>,
    ) -> io::Result<()> {
        self.inner.resource.check_current()?;
        let wake = Arc::new(SetupWake {
            upstream: upstream.try_clone()?,
            guest,
            upstream_stopped: Mutex::new(false),
        });
        let mut ledger = self.inner.lock()?;
        if ledger.closed || ledger.failed || self.inner.fenced.load(Ordering::Acquire) {
            return Err(refused("owned setup admission closed"));
        }
        let slot = ledger
            .slots
            .get_mut(self.index)
            .ok_or_else(|| refused("owned setup slot missing"))?;
        if slot.serial != self.serial
            || !matches!(slot.phase, Phase::Reserved)
            || slot.setup.is_some()
            || slot.prepared.is_some()
        {
            return Err(refused("owned setup reservation differs"));
        }
        slot.setup = Some(wake);
        self.inner.changed.notify_all();
        Ok(())
    }
    pub(super) fn setup_was_stopped(&self) -> io::Result<bool> {
        let wake = {
            let ledger = self.inner.lock()?;
            ledger
                .slots
                .get(self.index)
                .filter(|slot| slot.serial == self.serial)
                .and_then(|slot| slot.setup.clone())
        };
        wake.map_or(Ok(false), |wake| {
            wake.upstream_stopped
                .lock()
                .map(|stopped| *stopped)
                .map_err(|_| refused("owned setup wake poisoned"))
        })
    }
    pub(super) fn witness(&self) -> io::Result<RelayWitness> {
        let ledger = self.inner.lock()?;
        let slot = ledger
            .slots
            .get(self.index)
            .ok_or_else(|| refused("relay witness slot missing"))?;
        if slot.serial != self.serial || !matches!(slot.phase, Phase::Reserved) {
            return Err(refused("relay witness reservation differs"));
        }
        let guest = slot
            .setup
            .as_ref()
            .ok_or_else(|| refused("relay witness setup wake missing"))?
            .guest
            .clone();
        Ok(RelayWitness {
            inner: self.inner.clone(),
            index: self.index,
            serial: self.serial,
            guest,
        })
    }
    pub(super) fn spawn(
        self,
        wake: RelayWake,
        run: impl FnOnce() + Send + 'static,
    ) -> io::Result<()> {
        let stack = usize::try_from(OWNED_TCP_RELAY_STACK_BYTES)
            .map_err(|_| refused("relay stack shape"))?;
        self.inner.resource.check_current()?;
        if std::mem::size_of_val(&run) > CLOSURE_LIMIT {
            return Err(refused("owned relay closure too large"));
        }
        {
            let mut ledger = self.inner.lock()?;
            if ledger.closed || self.inner.fenced.load(Ordering::Acquire) {
                return Err(refused("owned relay admission closed"));
            }
            let slot = &mut ledger.slots[self.index];
            if slot.serial != self.serial || !matches!(slot.phase, Phase::Reserved) {
                return Err(refused("owned relay reservation differs"));
            }
            slot.phase = Phase::Launching;
        }
        let wake = Arc::new(wake);
        let completed = Arc::new(AtomicBool::new(false));
        let completion = Completion {
            inner: self.inner.clone(),
            signalled: completed.clone(),
        };
        let (start, started) = mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name(format!("flowmux-owned-relay-{}", self.serial))
            .stack_size(stack)
            .spawn(move || {
                let _completion = completion;
                if started.recv() == Ok(true) {
                    run();
                } else {
                    // Release captured original I/O before signalling body
                    // completion, including admission closing during launch.
                    drop(run);
                }
                drop(started);
            });
        match spawned {
            Err(error) => {
                let mut ledger = match self.inner.ledger.lock() {
                    Ok(ledger) => ledger,
                    Err(poisoned) => {
                        self.inner.retain();
                        let mut ledger = poisoned.into_inner();
                        ledger.failed = true;
                        ledger.closed = true;
                        ledger
                    }
                };
                let slot = &mut ledger.slots[self.index];
                let mut replaced = None;
                let mut setup = None;
                wake.retired.store(true, Ordering::Release);
                if slot.serial == self.serial && matches!(slot.phase, Phase::Launching) {
                    replaced = slot.prepared.take();
                    setup = slot.setup.take();
                    slot.phase = Phase::Reader {
                        wake: wake.clone(),
                        busy: false,
                    };
                } else {
                    ledger.failed = true;
                    self.inner.retain();
                    if ledger.reader_quarantine.len() < ledger.slots.len() {
                        ledger.reader_quarantine.push(wake.clone());
                    } else {
                        std::mem::forget(wake.clone());
                    }
                }
                ledger.closed = true;
                self.inner.fenced.store(true, Ordering::Release);
                self.inner.changed.notify_all();
                drop(ledger);
                let _ = wake.shutdown();
                drop(replaced);
                drop(setup);
                Err(error)
            }
            Ok(handle) => {
                let current = self.inner.resource.check_current();
                // Successful spawn must transfer its original handle before
                // any fallible return, including a poisoned/accounting ledger.
                let mut ledger = match self.inner.ledger.lock() {
                    Ok(ledger) => ledger,
                    Err(poisoned) => {
                        self.inner.retain();
                        let mut ledger = poisoned.into_inner();
                        ledger.failed = true;
                        ledger.closed = true;
                        ledger
                    }
                };
                let admitted =
                    current.is_ok() && !ledger.closed && !self.inner.fenced.load(Ordering::Acquire);
                let slot = &mut ledger.slots[self.index];
                if slot.serial != self.serial || !matches!(slot.phase, Phase::Launching) {
                    // There can be at most one successful in-flight launch
                    // per fixed slot; this separate array was reserved first.
                    ledger.quarantine.push(Worker {
                        handle,
                        wake,
                        completed,
                    });
                    ledger.failed = true;
                    self.inner.retain();
                    return Err(refused("owned relay launch identity differs"));
                }
                slot.phase = Phase::Active(Worker {
                    handle,
                    wake,
                    completed,
                });
                let prepared = slot.prepared.take();
                let setup = slot.setup.take();
                if !admitted {
                    ledger.closed = true;
                    self.inner.fenced.store(true, Ordering::Release);
                }
                self.inner.changed.notify_all();
                drop(ledger);
                drop(prepared);
                drop(setup);
                start.send(admitted).map_err(|_| {
                    self.inner.retain();
                    refused("owned relay startup failed")
                })?;
                if admitted {
                    Ok(())
                } else {
                    Err(refused("owned relay admission closed during launch"))
                }
            }
        }
    }
}
impl Drop for RelayReservation {
    fn drop(&mut self) {
        let mut setup = None;
        let mut cancel = None;
        let mut cancel_here = false;
        if let Ok(mut ledger) = self.inner.lock() {
            cancel_here = !ledger.closed && !self.inner.fenced.load(Ordering::Acquire);
            let slot = &mut ledger.slots[self.index];
            if slot.serial == self.serial && matches!(slot.phase, Phase::Reserved) {
                setup = slot.setup.take();
                if let Some(wake) = &slot.prepared {
                    wake.retired.store(true, Ordering::Release);
                    cancel = Some(wake.clone());
                } else {
                    slot.phase = Phase::Empty;
                }
                self.inner.changed.notify_all();
            } else if slot.serial == self.serial && matches!(slot.phase, Phase::Launching) {
                ledger.closed = true;
                ledger.failed = true;
                self.inner.retain();
                self.inner.changed.notify_all();
            }
        }
        drop(setup);
        if let Some(wake) = cancel {
            // Keep the original owner reserved while cancellation runs. A
            // closing group owns its cancellation under the caller deadline.
            if cancel_here && wake.cancel_reader().is_err() {
                self.inner.retain();
                if let Ok(mut ledger) = self.inner.ledger.lock() {
                    ledger.closed = true;
                    ledger.failed = true;
                }
            }
            if let Ok(mut ledger) = self.inner.lock() {
                let slot = &mut ledger.slots[self.index];
                if slot.serial == self.serial && matches!(slot.phase, Phase::Reserved) {
                    if let Some(original) = slot.prepared.take() {
                        slot.phase = Phase::Reader {
                            wake: original,
                            busy: false,
                        };
                    }
                    self.inner.changed.notify_all();
                } else {
                    ledger.failed = true;
                    ledger.closed = true;
                    self.inner.retain();
                }
            }
        }
    }
}
