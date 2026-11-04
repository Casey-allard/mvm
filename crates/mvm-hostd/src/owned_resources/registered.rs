//! Observable retirement for the owned process's registered Unix sockets.
//!
//! This is a local admission fence, not service or installation authority.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

/// Shared by every owned registration in one process. Fatal is monotonic.
pub struct RegistrationAdmission {
    fatal: AtomicBool,
    registration: Mutex<()>,
    closed: Notify,
    #[cfg(test)]
    fail_retirement: AtomicBool,
}

impl Default for RegistrationAdmission {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistrationAdmission {
    pub fn new() -> Self {
        Self {
            fatal: AtomicBool::new(false),
            registration: Mutex::new(()),
            closed: Notify::new(),
            #[cfg(test)]
            fail_retirement: AtomicBool::new(false),
        }
    }

    pub fn check(&self) -> io::Result<()> {
        if self.fatal.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "owned registration admission fenced",
            ))
        } else {
            Ok(())
        }
    }

    pub fn fence(&self) {
        if !self.fatal.swap(true, Ordering::AcqRel) {
            self.closed.notify_waiters();
        }
    }

    pub async fn closed(&self) {
        loop {
            let notified = self.closed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.check().is_err() {
                return;
            }
            notified.await;
        }
    }

    fn registration_guard(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.check()?;
        let guard = self.registration.lock().map_err(|_| {
            self.fence();
            io::Error::other("owned registration lock poisoned")
        })?;
        self.check()?;
        Ok(guard)
    }

    /// The closure must contain only direct Tokio bind/from_std. Guarding must
    /// precede chmod, namespace capture and every other fallible setup step.
    pub fn listener(
        self: &Arc<Self>,
        bind: impl FnOnce() -> io::Result<UnixListener>,
    ) -> io::Result<RegisteredListener> {
        let registration = self.registration_guard()?;
        let listener = RegisteredListener {
            inner: Some(bind()?),
            admission: self.clone(),
        };
        drop(registration);
        self.check()?;
        Ok(listener)
    }

    fn retired<T>(&self, result: io::Result<T>) -> io::Result<()> {
        // Close the returned standard socket; no raw descriptor escapes.
        let result = result.map(drop);
        #[cfg(test)]
        let result = if self.fail_retirement.swap(false, Ordering::AcqRel) && result.is_ok() {
            Err(io::Error::other("injected owned retirement failure"))
        } else {
            result
        };
        if result.is_err() {
            self.fence();
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn fail_next_retirement(&self) {
        self.fail_retirement.store(true, Ordering::Release);
    }
}

/// A listener cannot escape its process's observable retirement path.
pub struct RegisteredListener {
    inner: Option<UnixListener>,
    admission: Arc<RegistrationAdmission>,
}

impl RegisteredListener {
    pub async fn accept(&self) -> io::Result<RegisteredStream> {
        std::future::poll_fn(|cx| {
            // The lock covers one nonblocking poll only, never an await.
            let registration = match self.admission.registration_guard() {
                Ok(guard) => guard,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let result = self
                .inner
                .as_ref()
                .expect("live owned listener")
                .poll_accept(cx)
                .map_ok(|(stream, _)| RegisteredStream {
                    inner: Some(stream),
                    admission: self.admission.clone(),
                });
            drop(registration);
            if let Err(error) = self.admission.check() {
                // A ready stream is guarded before this post-operation check,
                // including the bounded poll already in flight at fencing.
                drop(result);
                return Poll::Ready(Err(error));
            }
            result
        })
        .await
    }

    pub fn retire(mut self) -> io::Result<()> {
        self.retire_inner()
    }

    fn retire_inner(&mut self) -> io::Result<()> {
        match self.inner.take() {
            Some(listener) => self.admission.retired(listener.into_std()),
            None => Ok(()),
        }
    }
}

impl Drop for RegisteredListener {
    fn drop(&mut self) {
        // retired() latches the error even when a destructor cannot return it.
        let _ = self.retire_inner();
    }
}

/// The canonical AsyncRead/AsyncWrite bytes pass through without a new frame.
pub struct RegisteredStream {
    inner: Option<UnixStream>,
    admission: Arc<RegistrationAdmission>,
}

impl RegisteredStream {
    pub fn retire(mut self) -> io::Result<()> {
        self.retire_inner()
    }

    fn retire_inner(&mut self) -> io::Result<()> {
        match self.inner.take() {
            Some(stream) => self.admission.retired(stream.into_std()),
            None => Ok(()),
        }
    }
}

impl Drop for RegisteredStream {
    fn drop(&mut self) {
        let _ = self.retire_inner();
    }
}

impl AsyncRead for RegisteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.admission.check()?;
        Pin::new(self.inner.as_mut().expect("live owned stream")).poll_read(cx, buf)
    }
}

impl AsyncWrite for RegisteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.admission.check()?;
        Pin::new(self.inner.as_mut().expect("live owned stream")).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.admission.check()?;
        Pin::new(self.inner.as_mut().expect("live owned stream")).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.admission.check()?;
        Pin::new(self.inner.as_mut().expect("live owned stream")).poll_shutdown(cx)
    }
}
