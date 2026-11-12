//! Optional original VMM lifetime on the launcher's private configuration pipe.
use std::cell::RefCell;
use std::io::{Error, ErrorKind, Result};
use std::time::Instant;

use mvm_vmm::host::{
    network_endpoint_spawn::EndpointPid,
    process_exit::{ProcessExitError, ProcessExitObserver, ProcessExitWait},
};

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalVmm {
    pid: libc::pid_t,
    started: u64,
}

impl OriginalVmm {
    pub(super) fn from_held(original: EndpointPid) -> Result<Self> {
        Ok(Self {
            pid: original.pid,
            started: original
                .started
                .ok_or_else(|| Error::other("no VMM birth identity"))?,
        })
    }

    pub(super) fn observe(self) -> Result<Lifetime> {
        let original = EndpointPid {
            pid: self.pid,
            started: Some(self.started),
        };
        let check = || {
            if original.pid > 1 && original.is_live_and_ours() {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "original VMM generation changed",
                ))
            }
        };
        check()?;
        let observer = ProcessExitObserver::arm(original.pid).map_err(Error::other)?;
        check()?;
        Ok(Lifetime {
            observer,
            terminal: RefCell::new(None),
        })
    }
}

pub(super) struct Lifetime {
    observer: ProcessExitObserver,
    // kqueue consumes an exit note. Retain the first terminal outcome so the
    // guest-read predicate and the outer service loop observe the same exit.
    terminal: RefCell<Option<std::result::Result<(), ProcessExitError>>>,
}

impl Lifetime {
    pub(super) fn alive_until(&self, until: Instant) -> bool {
        if self.terminal.borrow().is_some() {
            return false;
        }
        match self.observer.wait_event(until) {
            Ok(ProcessExitWait::TimedOut) => true,
            Ok(ProcessExitWait::Exited) => {
                *self.terminal.borrow_mut() = Some(Ok(()));
                false
            }
            Err(ProcessExitError::Io(err)) if err.kind() == ErrorKind::Interrupted => true,
            Err(error) => {
                *self.terminal.borrow_mut() = Some(Err(error));
                false
            }
        }
    }

    pub(super) fn finish(self) -> Result<()> {
        self.terminal
            .into_inner()
            .unwrap_or(Ok(()))
            .map_err(Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_original_generation_refuses_before_service() {
        let original = EndpointPid::of_child(std::process::id());
        let mut handoff = OriginalVmm::from_held(original).unwrap();
        handoff.started ^= 1;
        assert!(matches!(handoff.observe(), Err(e) if e.kind() == ErrorKind::PermissionDenied));
    }
}
