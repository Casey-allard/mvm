//! One retained control session bound to the original VMM process and lease.
use super::owned::OwnedFcState;
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_agentd::vsock::{
    AuthenticatedSession, EntrypointEvent, GUEST_AGENT_PORT, GuestRequest, GuestResponse,
    check_response, complete_connect_handshake, connect_unix_before,
    send_entrypoint_on_authenticated_session,
};
use mvm_core::host_lifetime::HostLifetimeAnchor;
use mvm_vmm::driver::{OriginalEntrypointChannel, OriginalEntrypointIdentity};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Authenticated,
    Activated,
    Terminal,
    Flushed,
    Uncertain,
}

struct Channel {
    original: Arc<Mutex<OwnedFcState>>,
    anchor: Arc<HostLifetimeAnchor>,
    stream: Option<UnixStream>,
    session: AuthenticatedSession,
    first_guest: VerifyingKey,
    path: PathBuf,
    host: [u8; 32],
    phase: Phase,
}

fn current(
    original: &OwnedFcState,
    anchor: &HostLifetimeAnchor,
    stream: Option<&UnixStream>,
    until: Instant,
) -> Result<()> {
    before(until)?;
    original.check_kernel_anchor(anchor)?;
    if let Some(stream) = stream {
        original.process()?.authenticate_config(stream)?;
    }
    original.check_current()?;
    anchor.verify_current()?;
    before(until)
}

pub(super) fn open(
    original: Arc<Mutex<OwnedFcState>>,
    anchor: Arc<HostLifetimeAnchor>,
    identity: OriginalEntrypointIdentity,
    path: &Path,
    until: Instant,
) -> Result<Box<dyn OriginalEntrypointChannel>> {
    {
        let mut held = original
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original custody busy or poisoned"))?;
        ensure!(
            !held.entrypoint_opened,
            "original entrypoint open already attempted"
        );
        held.entrypoint_opened = true;
        current(&held, &anchor, None, until)?;
    }
    let (stream, session, peer) = connect(&original, &anchor, &identity.host, path, until)?;
    Ok(Box::new(Channel {
        original,
        anchor,
        stream: Some(stream),
        session,
        first_guest: peer,
        path: path.to_owned(),
        host: identity.host,
        phase: Phase::Authenticated,
    }))
}

fn connect(
    original: &Mutex<OwnedFcState>,
    anchor: &HostLifetimeAnchor,
    host: &[u8; 32],
    path: &Path,
    until: Instant,
) -> Result<(UnixStream, AuthenticatedSession, VerifyingKey)> {
    {
        let held = original
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original custody busy or poisoned"))?;
        current(&held, anchor, None, until).context("original control pre-dial custody")?;
    }
    let keys = mvm_core::config::mvm_keys_dir_at(mvm_core::config::mvm_home_strict()?);
    let (signer, public) = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys.join("host-signer.ed25519"),
        &keys.join("host-signer.pub"),
    )?;
    ensure!(
        &public.to_bytes() == host,
        "original registered host identity changed"
    );
    before(until)?;
    let mut stream = connect_unix_before(path, until).context("original control Unix dial")?;
    check(original, anchor, &stream, until).context("original control dial peer authentication")?;
    complete_connect_handshake(
        &mut DeadlineIo {
            stream: &mut stream,
            until,
        },
        GUEST_AGENT_PORT,
    )
    .context("original control CONNECT handshake")?;
    check(original, anchor, &stream, until).context("original control post-CONNECT custody")?;
    let session_id = mvm_core::domain::session::SessionId::new();
    let (session, peer) = AuthenticatedSession::host_retaining_peer(
        &mut DeadlineIo {
            stream: &mut stream,
            until,
        },
        session_id.as_str(),
        signer,
    )
    .context("original control protected guest handshake")?;
    check(original, anchor, &stream, until).context("original control post-handshake custody")?;
    Ok((stream, session, peer))
}

fn check(
    original: &Mutex<OwnedFcState>,
    anchor: &HostLifetimeAnchor,
    stream: &UnixStream,
    until: Instant,
) -> Result<()> {
    let held = original
        .try_lock()
        .map_err(|_| anyhow::anyhow!("original custody busy or poisoned"))?;
    current(&held, anchor, Some(stream), until)
}

impl Channel {
    fn take(&mut self, expected: Phase, until: Instant) -> Result<UnixStream> {
        let phase = std::mem::replace(&mut self.phase, Phase::Uncertain);
        // The local descriptor closes on every error or unwind; never restore
        // a connection whose protected operation may have been consumed.
        let stream = self
            .stream
            .take()
            .context("original control session consumed")?;
        ensure!(phase == expected, "original control operation out of order");
        check(&self.original, &self.anchor, &stream, until)?;
        Ok(stream)
    }

    fn finish(&mut self, stream: UnixStream, phase: Phase, until: Instant) -> Result<()> {
        check(&self.original, &self.anchor, &stream, until)?;
        self.stream = Some(stream);
        self.phase = phase;
        Ok(())
    }

    fn unary(
        &mut self,
        stream: &mut UnixStream,
        request: &GuestRequest,
        until: Instant,
    ) -> Result<GuestResponse> {
        let mut io = DeadlineIo { stream, until };
        self.session.write(&mut io, request)?;
        Ok(check_response(request, self.session.read(&mut io)?)?)
    }
}

impl OriginalEntrypointChannel for Channel {
    fn finish_journal_activation(
        self: Box<Self>,
        until: Instant,
    ) -> Result<Box<dyn mvm_vmm::driver::OriginalJournalControl>> {
        journal::finish_activation(*self, until)
    }
    fn activate(&mut self, request: &GuestRequest, until: Instant) -> Result<GuestResponse> {
        let mut stream = self.take(Phase::Authenticated, until)?;
        ensure!(
            matches!(request, GuestRequest::ActivateEnvironment(_)),
            "original activation verb required"
        );
        let response = self.unary(&mut stream, request, until)?;
        ensure!(
            matches!(response, GuestResponse::ActivateEnvironmentAck),
            "original activation was not acknowledged"
        );
        self.finish(stream, Phase::Activated, until)?;
        Ok(response)
    }

    fn entrypoint(
        &mut self,
        request: &GuestRequest,
        until: Instant,
        observer: &mut dyn FnMut(&EntrypointEvent),
    ) -> Result<EntrypointEvent> {
        let mut stream = self.take(Phase::Activated, until)?;
        ensure!(
            matches!(request, GuestRequest::RunEntrypoint { stream_input: false, timeout_secs, .. } if *timeout_secs > 0),
            "original control requires one-shot RunEntrypoint with a positive timeout"
        );
        let terminal = send_entrypoint_on_authenticated_session(
            &mut DeadlineIo {
                stream: &mut stream,
                until,
            },
            &mut self.session,
            request,
            observer,
        )?;
        self.finish(stream, Phase::Terminal, until)?;
        Ok(terminal)
    }

    fn sync_filesystems(&mut self, until: Instant) -> Result<()> {
        let mut stream = self.take(Phase::Terminal, until)?;
        let response = self.unary(&mut stream, &GuestRequest::SyncFilesystems, until)?;
        ensure!(
            matches!(response, GuestResponse::FilesystemsSynced),
            "original filesystems were not synchronized"
        );
        self.finish(stream, Phase::Flushed, until)
    }
}

mod journal;

fn before(until: Instant) -> Result<()> {
    ensure!(Instant::now() < until, "original control deadline elapsed");
    Ok(())
}

// Private to CONNECT's single-byte reads and the session codec's exact frames.
// Recompute the remaining absolute deadline on each underlying socket fragment.
struct DeadlineIo<'a> {
    stream: &'a mut UnixStream,
    until: Instant,
}
impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        mvm_vmm::host::hvf_control_transport::read_exact(self.stream, bytes, self.until)?;
        Ok(bytes.len())
    }
}
impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        mvm_vmm::host::hvf_control_transport::write_all(self.stream, bytes, self.until)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if Instant::now() >= self.until {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests;
