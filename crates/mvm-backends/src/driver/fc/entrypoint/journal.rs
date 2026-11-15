//! Original-identity control using the guest's existing one-request sessions.
use super::*;
use mvm_vmm::driver::OriginalJournalControl;

const MAX_INPUT: usize = 64 << 10;
const MAX_OUTPUT: usize = 128 << 10;

fn event_bytes(event: &EntrypointEvent) -> usize {
    match event {
        EntrypointEvent::Stdout { chunk } | EntrypointEvent::Stderr { chunk } => chunk.len(),
        EntrypointEvent::Control {
            header_json,
            payload,
        } => header_json.len().saturating_add(payload.len()),
        EntrypointEvent::Exit { .. } => 0,
        EntrypointEvent::Error { message, .. } => message.len(),
    }
}

struct Journal {
    original: Arc<Mutex<OwnedFcState>>,
    anchor: Arc<HostLifetimeAnchor>,
    path: PathBuf,
    host: [u8; 32],
    guest: VerifyingKey,
    fenced: bool,
    ready: bool,
}

pub(super) fn finish_activation(
    mut channel: Channel,
    until: Instant,
) -> Result<Box<dyn OriginalJournalControl>> {
    let stream = channel
        .take(Phase::Activated, until)
        .context("original journal activation ACK boundary")?;
    // Closing this acknowledged continuation lets PID 1 initialize the mailbox
    // and enter its normal control accept loop. Never spend a workload call.
    stream
        .shutdown(std::net::Shutdown::Both)
        .context("original journal activation continuation shutdown")?;
    drop(stream);
    {
        let held = channel
            .original
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original custody busy or poisoned"))?;
        current(&held, &channel.anchor, None, until)
            .context("original journal post-activation-close custody")?;
    }
    Ok(Box::new(Journal {
        original: channel.original,
        anchor: channel.anchor,
        path: channel.path,
        host: channel.host,
        guest: channel.first_guest,
        fenced: false,
        ready: false,
    }))
}

impl Journal {
    fn session(&mut self, until: Instant) -> Result<(UnixStream, AuthenticatedSession)> {
        ensure!(!self.fenced, "original journal control fenced");
        self.fenced = true;
        let (stream, session, guest) =
            connect(&self.original, &self.anchor, &self.host, &self.path, until)
                .context("original journal session establishment")?;
        ensure!(
            guest == self.guest,
            "original journal guest key pin differs"
        );
        Ok((stream, session))
    }

    fn complete(&mut self, stream: &UnixStream, until: Instant) -> Result<()> {
        check(&self.original, &self.anchor, stream, until)?;
        self.fenced = false;
        Ok(())
    }
}

impl OriginalJournalControl for Journal {
    fn ready(&mut self, until: Instant) -> Result<()> {
        let (mut stream, mut session) = self.session(until)?;
        let mut io = DeadlineIo {
            stream: &mut stream,
            until,
        };
        session
            .write(&mut io, &GuestRequest::Ping)
            .context("original journal protected Ping write")?;
        let response = session
            .read(&mut io)
            .context("original journal protected Pong read")?;
        ensure!(
            matches!(
                check_response(&GuestRequest::Ping, response)
                    .context("original journal Pong response validation")?,
                GuestResponse::Pong
            ),
            "original journal readiness was not acknowledged"
        );
        self.complete(&stream, until)
            .context("original journal readiness final custody check")?;
        self.ready = true;
        Ok(())
    }

    fn entrypoint(
        &mut self,
        request: &GuestRequest,
        until: Instant,
        observer: &mut dyn FnMut(&EntrypointEvent),
    ) -> Result<EntrypointEvent> {
        ensure!(self.ready, "original journal readiness missing");
        let (mut stream, mut session) = self.session(until)?;
        ensure!(
            matches!(request, GuestRequest::RunEntrypoint { stdin, timeout_secs, stream_input: false, .. }
            if stdin.len() <= MAX_INPUT && *timeout_secs > 0),
            "original journal request exceeds supported shape"
        );
        let mut output = 0usize;
        let mut over_limit = false;
        let terminal = send_entrypoint_on_authenticated_session(
            &mut DeadlineIo {
                stream: &mut stream,
                until,
            },
            &mut session,
            request,
            |event| {
                output = output.saturating_add(event_bytes(event));
                if output > MAX_OUTPUT {
                    over_limit = true;
                }
                if !over_limit {
                    observer(event);
                }
            },
        )?;
        ensure!(
            !over_limit && output.saturating_add(event_bytes(&terminal)) <= MAX_OUTPUT,
            "original journal output exceeds bound"
        );
        self.complete(&stream, until)?;
        Ok(terminal)
    }
}
