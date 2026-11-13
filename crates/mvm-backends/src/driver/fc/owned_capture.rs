//! One guest exit-report listener retained by the original Firecracker launch.
use anyhow::{Result, ensure};
use mvm_core::vm_backend::VmExitStatus;
use mvm_vmm::host::fc_lifetime::worker_terms::owned_exit_capture_stack_terms;
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{
            fs::OpenOptionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::Instant,
};

/// Independent readers of the original worker's single terminal observation.
#[derive(Clone, Debug, Default)]
pub(super) struct CaptureReport {
    shared: Arc<ReportState>,
}

#[derive(Debug, Default)]
struct ReportState {
    // None until this worker returns. A completed worker can have no guest code.
    outcome: Mutex<Option<Option<i32>>>,
    changed: Condvar,
}

impl CaptureReport {
    pub(super) fn wait(&self, until: Instant) -> Result<VmExitStatus> {
        let poisoned = |_| anyhow::anyhow!("original exit capture report poisoned");
        let mut outcome = self.shared.outcome.lock().map_err(poisoned)?;
        loop {
            if let Some(code) = *outcome {
                return Ok(VmExitStatus {
                    code,
                    success: code == Some(0),
                });
            }
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                return Ok(VmExitStatus::UNKNOWN);
            };
            (outcome, _) = self
                .shared
                .changed
                .wait_timeout(outcome, remaining)
                .map_err(|_| anyhow::anyhow!("original exit capture wait poisoned"))?;
        }
    }
}

impl mvm_vmm::driver::OriginalWorkloadReport for CaptureReport {
    fn wait_until(&self, until: Instant) -> Result<VmExitStatus> {
        self.wait(until)
    }
}

/// Publish even on unwind, waking everyone with an unknown workload result.
struct Completion {
    report: CaptureReport,
    code: Option<i32>,
}

impl Drop for Completion {
    fn drop(&mut self) {
        let shared = &self.report.shared;
        let mut outcome = shared
            .outcome
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *outcome = Some(self.code);
        shared.changed.notify_all();
    }
}

#[derive(Debug)]
pub(super) struct CaptureWorker {
    report: CaptureReport,
    cancel: UnixStream,
    done: mpsc::Receiver<()>,
    thread: Option<JoinHandle<()>>,
    panicked: bool,
}

impl CaptureWorker {
    pub(super) fn report(&self) -> CaptureReport {
        self.report.clone()
    }

    pub(super) fn spawn(socket: &Path, state_dir: &Path) -> Result<Self> {
        // Anchor the canonical writer to the original directory even if its
        // pathname is renamed while the guest is live.
        let state = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(state_dir)?;
        Self::start(socket, move |stream| {
            let path = PathBuf::from(format!("/proc/self/fd/{}", state.as_raw_fd()));
            mvm_core::exit_capture::capture_stream(stream, &path)
        })
    }

    fn start(
        socket: &Path,
        capture: impl FnOnce(CancelStream<'_>) -> io::Result<i32> + Send + 'static,
    ) -> Result<Self> {
        let stack = usize::try_from(owned_exit_capture_stack_terms()?.requested_builder_bytes)?;
        let (cancel, stop) = UnixStream::pair()?;
        let (finished, done) = mpsc::channel();
        // The runtime directory owner cleans up its namespace. Never replace
        // or unlink a name the caller may not own.
        let listener = UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        let report = CaptureReport::default();
        let outcome = report.clone();
        let thread = thread::Builder::new()
            .name("fc-exit-capture".into())
            .stack_size(stack)
            .spawn(move || {
                let mut completion = Completion {
                    report: outcome,
                    code: None,
                };
                let accepted = wait_io(&listener, &stop, libc::POLLIN, || listener.accept());
                let result = accepted.and_then(|(stream, _)| {
                    stream.set_nonblocking(true)?;
                    capture(CancelStream {
                        stream,
                        stop: &stop,
                    })
                });
                completion.code = result.as_ref().ok().copied();
                if let Err(error) = result
                    && error.raw_os_error() != Some(libc::ECANCELED)
                {
                    tracing::warn!(%error, "original Firecracker workload exit capture failed");
                }
                // All capture work is finished. Only joining proves the thread
                // returned normally; dropping this sender also wakes on panic.
                drop(completion);
                drop(finished);
            })?;
        Ok(Self {
            report,
            cancel,
            done,
            thread: Some(thread),
            panicked: false,
        })
    }

    pub(super) fn stop(&mut self, until: Instant) -> Result<()> {
        ensure!(!self.panicked, "original exit capture worker panicked");
        if self.thread.is_none() {
            return Ok(());
        }
        self.cancel.shutdown(Shutdown::Write)?;
        match self
            .done
            .recv_timeout(until.saturating_duration_since(Instant::now()))
        {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(io::Error::from(io::ErrorKind::TimedOut).into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
            Ok(()) => unreachable!("the worker only closes its completion channel"),
        }
        if let Some(thread) = self.thread.take() {
            self.panicked = thread.join().is_err();
        }
        ensure!(!self.panicked, "original exit capture worker panicked");
        Ok(())
    }
}

impl Drop for CaptureWorker {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = self.cancel.shutdown(Shutdown::Write);
            let _ = thread.join();
        }
    }
}

struct CancelStream<'a> {
    stream: UnixStream,
    stop: &'a UnixStream,
}

impl Read for CancelStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        wait_io(&self.stream, self.stop, libc::POLLIN, || {
            (&self.stream).read(bytes)
        })
    }
}

impl Write for CancelStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        wait_io(&self.stream, self.stop, libc::POLLOUT, || {
            (&self.stream).write(bytes)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Poll both owned descriptors before a nonblocking accept/read/write. A
/// cancellation must not become Interrupted: Read::read_exact retries that.
fn wait_io<T>(
    socket: &impl AsFd,
    stop: &UnixStream,
    event: libc::c_short,
    mut operation: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut sockets = [
        libc::pollfd {
            fd: stop.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: socket.as_fd().as_raw_fd(),
            events: event,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: both borrowed descriptors stay live, and poll writes only
        // into the two initialized entries of this array.
        let rc = unsafe { libc::poll(sockets.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if sockets[0].revents != 0 {
            return Err(io::Error::from_raw_os_error(libc::ECANCELED));
        }
        match operation() {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests;
