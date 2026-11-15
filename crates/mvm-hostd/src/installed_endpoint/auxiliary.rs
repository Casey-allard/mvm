use mvm_vmm::host::network_endpoint_spawn::{
    INSTALLED_CONTROL_BUFFER_BYTES, InstalledEndpointAudit, InstalledEndpointLease,
};
use std::{
    io,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Copy)]
pub(super) enum Component {
    Relay,
    CodecReaders,
    Collector,
    Controller,
    Audit,
}
impl Component {
    fn bit(self) -> u8 {
        match self {
            Self::Relay => 1,
            Self::CodecReaders => 2,
            Self::Collector => 4,
            Self::Controller => 8,
            Self::Audit => 16,
        }
    }
}

struct Remaining {
    stack: u64,
    metadata: u64,
    claims: u8,
}

pub(super) struct AuxiliaryLedger {
    remaining: Mutex<Remaining>,
    fenced: AtomicBool,
    terminal_failure: AtomicBool,
}
impl AuxiliaryLedger {
    pub(super) fn new_with_bootstrap(
        stack: u64,
        metadata: u64,
        bootstrap: u64,
    ) -> io::Result<Self> {
        if bootstrap < mvm_vmm::host::network_endpoint_spawn::INSTALLED_BOOTSTRAP_MIN_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bootstrap model floor missing",
            ));
        }
        let mut ledger = Self::new(stack, metadata)?;
        let extra = bootstrap
            .checked_sub(INSTALLED_CONTROL_BUFFER_BYTES)
            .ok_or_else(|| io::Error::other("bootstrap credit underflow"))?;
        let remaining = ledger
            .remaining
            .get_mut()
            .map_err(|_| io::Error::other("new auxiliary ledger poisoned"))?;
        remaining.metadata = remaining.metadata.checked_sub(extra).ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "bootstrap credit exhausted")
        })?;
        Ok(ledger)
    }
    pub(super) fn new(stack: u64, metadata: u64) -> io::Result<Self> {
        let metadata = metadata
            .checked_sub(INSTALLED_CONTROL_BUFFER_BYTES)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "control buffer credit missing")
            })?;
        Ok(Self {
            remaining: Mutex::new(Remaining {
                stack,
                metadata,
                claims: 0,
            }),
            fenced: AtomicBool::new(false),
            terminal_failure: AtomicBool::new(false),
        })
    }
    fn open(&self) -> io::Result<()> {
        if self.remaining.is_poisoned() {
            self.fenced.store(true, Ordering::Release);
        }
        if self.fenced.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "endpoint auxiliary credits fenced",
            ));
        }
        Ok(())
    }
    fn lock(&self) -> io::Result<MutexGuard<'_, Remaining>> {
        self.remaining.lock().map_err(|_| {
            self.fenced.store(true, Ordering::Release);
            io::Error::other("endpoint auxiliary ledger poisoned")
        })
    }
    pub(super) fn reserve(
        &self,
        component: Component,
        stack: u64,
        metadata: u64,
        current: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        {
            let mut remaining = self.lock()?;
            self.open()?;
            if remaining.claims & component.bit() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "endpoint component already claimed",
                ));
            }
            remaining.claims |= component.bit();
        }
        if let Err(error) = current() {
            self.fenced.store(true, Ordering::Release);
            return Err(error);
        }
        let mut remaining = self.lock()?;
        self.open()?;
        let stack = remaining.stack.checked_sub(stack).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "endpoint component stack credit exhausted",
            )
        })?;
        let metadata = remaining.metadata.checked_sub(metadata).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "endpoint component metadata credit exhausted",
            )
        })?;
        remaining.stack = stack;
        remaining.metadata = metadata;
        Ok(())
    }
}

/// Retention of one actual subdivision; dropping it does not replenish credits.
pub(crate) struct InstalledEndpointComponentPermit {
    lease: InstalledEndpointLease,
    auxiliary: Arc<AuxiliaryLedger>,
}
impl InstalledEndpointComponentPermit {
    pub(super) fn new(lease: InstalledEndpointLease, auxiliary: Arc<AuxiliaryLedger>) -> Self {
        Self { lease, auxiliary }
    }
    pub(crate) fn same_partition(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.auxiliary, &other.auxiliary)
    }
    pub(crate) fn has_original_audit(&self, audit: &InstalledEndpointAudit) -> bool {
        audit.same_endpoint(&self.lease)
    }
    pub(crate) fn fence(&self) {
        self.record_terminal_failure();
        self.auxiliary.fenced.store(true, Ordering::Release);
        self.lease.fence();
    }
    pub(crate) fn record_terminal_failure(&self) {
        self.auxiliary
            .terminal_failure
            .store(true, Ordering::Release);
    }
    pub(crate) fn has_terminal_failure(&self) -> bool {
        self.auxiliary.terminal_failure.load(Ordering::Acquire)
    }
    pub(crate) fn check_current(&self) -> io::Result<()> {
        self.auxiliary.open()?;
        if let Err(error) = self.lease.check_current() {
            self.auxiliary.fenced.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                error.to_string(),
            ));
        }
        self.auxiliary.open()
    }
}

#[cfg(test)]
mod poison_tests {
    use super::*;

    #[test]
    fn retained_permit_gate_observes_poison_before_another_component_claim() {
        let ledger =
            Arc::new(AuxiliaryLedger::new(10, INSTALLED_CONTROL_BUFFER_BYTES + 100).unwrap());
        ledger.reserve(Component::Relay, 1, 1, || Ok(())).unwrap();
        let other = ledger.clone();
        let result = std::thread::spawn(move || {
            let _held = other.remaining.lock().unwrap();
            panic!("controlled auxiliary accounting poison");
        })
        .join();
        assert!(result.is_err());
        assert!(
            ledger.open().is_err(),
            "the retained permit current gate must observe poison without a new claim"
        );
    }
}
