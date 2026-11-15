//! Private local stop disposition, never admission/retirement authority.
use super::InstalledEndpointComponentPermit;
use mvm_vmm::host::network_endpoint_spawn::InstalledEndpointAudit;
use std::{
    io,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub(crate) struct InstalledSessionControl {
    permit: Arc<InstalledEndpointComponentPermit>,
    stopping: AtomicBool,
    stop_publication: Mutex<()>,
    stopped: Condvar,
}
impl InstalledSessionControl {
    pub(super) fn new(permit: Arc<InstalledEndpointComponentPermit>) -> Arc<Self> {
        Arc::new(Self {
            permit,
            stopping: AtomicBool::new(false),
            stop_publication: Mutex::new(()),
            stopped: Condvar::new(),
        })
    }
    /// Sole controller calls BEFORE shutting the retained original transport.
    /// This closes work only; it cannot clear a failure or prove completion.
    pub(super) fn request_stop(&self) {
        let _publication = self.stop_publication.lock().unwrap_or_else(|poisoned| {
            self.fail();
            poisoned.into_inner()
        });
        self.stopping.store(true, Ordering::Release);
        self.stopped.notify_all();
    }
    /// After a clean peer EOF, retain the original Session owner without new
    /// I/O until the sole controller stops it. Its Drop fence must not turn a
    /// completed guest into an unrelated endpoint failure before parent EOF.
    pub(super) fn wait_for_stop(&self) -> io::Result<()> {
        let mut held = self.stop_publication.lock().map_err(|_| {
            self.fail();
            io::Error::other("installed session stop publication poisoned")
        })?;
        while !self.stopping() {
            held = self.stopped.wait(held).map_err(|_| {
                self.fail();
                io::Error::other("installed session stop publication poisoned")
            })?;
        }
        Ok(())
    }
    pub(crate) fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }
    pub(crate) fn stop_error(&self) -> Option<io::Error> {
        self.stopping()
            .then(|| io::Error::new(io::ErrorKind::Interrupted, OriginalSessionStop))
    }
    pub(crate) fn is_stop_error(&self, error: &io::Error) -> bool {
        self.stopping()
            && error
                .get_ref()
                .is_some_and(|error| error.is::<OriginalSessionStop>())
    }
    pub(crate) fn matches(&self, audit: &InstalledEndpointAudit) -> bool {
        self.permit.has_original_audit(audit)
    }
    pub(crate) fn fail(&self) {
        self.permit.record_terminal_failure();
    }
    pub(super) fn check_failure(&self) -> io::Result<()> {
        if self.permit.has_terminal_failure() {
            Err(io::Error::other("installed session terminal failure"))
        } else {
            Ok(())
        }
    }
}

// A typed local disposition preserves the existing public FlowMuxError enum.
// Its constructor remains private, and it proves no drain/exit/refund state.
#[derive(Debug)]
struct OriginalSessionStop;
impl std::fmt::Display for OriginalSessionStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original installed session stop requested")
    }
}
impl std::error::Error for OriginalSessionStop {}
