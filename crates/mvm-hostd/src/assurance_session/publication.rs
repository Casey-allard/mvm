//! One private writer turn for the canonical first-install-wins plane.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};

use crate::broker::handlers::host_assurance_v1::HostAssuranceV1Handler;

pub(super) struct PlanePublicationSlot {
    value: OnceLock<Arc<HostAssuranceV1Handler>>,
    writer: Mutex<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanePublicationError {
    Busy,
    Poisoned,
}

impl fmt::Display for PlanePublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "original assurance publication writer is busy",
            Self::Poisoned => "original assurance publication writer is poisoned",
        })
    }
}

impl std::error::Error for PlanePublicationError {}

/// Borrows the original candidate; it owns no service, resource or permission.
/// Dropping before commit only releases the writer, without installing anything.
pub(crate) struct PlanePublicationReservation<'a> {
    slot: &'a PlanePublicationSlot,
    candidate: &'a Arc<HostAssuranceV1Handler>,
    _writer: MutexGuard<'a, ()>,
}

impl PlanePublicationSlot {
    pub(super) const fn new() -> Self {
        Self {
            value: OnceLock::new(),
            writer: Mutex::new(()),
        }
    }

    pub(super) fn get(&self) -> Option<&Arc<HostAssuranceV1Handler>> {
        self.value.get()
    }

    /// Legacy callers may wait outside admission. All writes, including this
    /// path, use the same private writer turn. Never recover poisoned custody.
    pub(super) fn install(&self, candidate: Arc<HostAssuranceV1Handler>) -> bool {
        let Ok(writer) = self.writer.lock() else {
            return false;
        };
        let installed = self.value.set(candidate);
        // A rejected owned candidate may be its last Arc. Drop it only after
        // releasing the writer, independently of the canonical first winner.
        drop(writer);
        installed.is_ok()
    }

    pub(super) fn try_reserve<'a>(
        &'a self,
        candidate: &'a Arc<HostAssuranceV1Handler>,
    ) -> Result<PlanePublicationReservation<'a>, PlanePublicationError> {
        let writer = self.writer.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => PlanePublicationError::Busy,
            TryLockError::Poisoned(_) => PlanePublicationError::Poisoned,
        })?;
        Ok(PlanePublicationReservation {
            slot: self,
            candidate,
            _writer: writer,
        })
    }
}

impl PlanePublicationReservation<'_> {
    /// Every private setter holds this writer, so no concurrent initializer can
    /// make OnceLock::set wait. Arc cloning does not allocate. The borrowed
    /// original also prevents a rejected clone from dropping the last handler.
    pub(crate) fn commit(self) -> bool {
        self.slot.value.set(Arc::clone(self.candidate)).is_ok()
    }
}

#[cfg(test)]
pub(crate) fn hold_original_global_writer_for_test()
-> Result<MutexGuard<'static, ()>, PlanePublicationError> {
    super::HOST_ASSURANCE_PLANE
        .writer
        .lock()
        .map_err(|_| PlanePublicationError::Poisoned)
}

#[cfg(test)]
mod tests {
    use super::{PlanePublicationError, PlanePublicationSlot};
    use crate::broker::handlers::host_assurance_v1::HostAssuranceV1Handler;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[test]
    fn busy_reservation_returns_before_the_original_writer_unlocks() {
        let slot = Arc::new(PlanePublicationSlot::new());
        let candidate = Arc::new(HostAssuranceV1Handler::new());
        let original_writer = slot.writer.lock().unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker_slot = Arc::clone(&slot);
        let worker = std::thread::spawn(move || {
            let result = worker_slot.try_reserve(&candidate).map(drop);
            sender.send(result).unwrap();
        });
        // A hang guard, not a performance budget. Always release and collect
        // the original worker before asserting a counterexample.
        let observed = receiver.recv_timeout(Duration::from_secs(5));
        drop(original_writer);
        worker.join().unwrap();
        assert!(matches!(observed, Ok(Err(PlanePublicationError::Busy))));
        assert!(slot.get().is_none(), "refusal must not publish a plane");
    }

    #[test]
    fn reservation_drop_and_first_wins_preserve_the_original_plane() {
        let slot = PlanePublicationSlot::new();
        let original = Arc::new(HostAssuranceV1Handler::new());
        let other = Arc::new(HostAssuranceV1Handler::new());
        let reservation = slot.try_reserve(&original).unwrap();
        assert!(slot.get().is_none(), "reservation is not publication");
        drop(reservation);
        assert!(slot.get().is_none(), "dropping cannot install the plane");
        assert!(slot.try_reserve(&original).unwrap().commit());
        assert!(Arc::ptr_eq(slot.get().unwrap(), &original));
        assert!(!slot.install(Arc::clone(&other)));
        assert!(!slot.try_reserve(&other).unwrap().commit());
        assert!(Arc::ptr_eq(slot.get().unwrap(), &original));
    }

    #[test]
    fn poisoned_original_writer_refuses_without_repair_or_publication() {
        let slot = Arc::new(PlanePublicationSlot::new());
        let worker_slot = Arc::clone(&slot);
        let worker = std::thread::spawn(move || {
            let _original = worker_slot.writer.lock().unwrap();
            panic!("controlled original publication writer poison");
        });
        assert!(worker.join().is_err());
        let candidate = Arc::new(HostAssuranceV1Handler::new());
        assert!(matches!(
            slot.try_reserve(&candidate),
            Err(PlanePublicationError::Poisoned)
        ));
        assert!(!slot.install(candidate));
        assert!(slot.get().is_none());
    }
}
