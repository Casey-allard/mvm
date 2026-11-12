//! One admitted workload Submit per original guest boot. A lost response or socket
//! cannot create another request or retire its bytes. The retained slot has
//! guest-boot lifetime; it is not a destination journal.
use mvm_contract::protocol::mailbox::{
    CausationId, ContentType, CorrelationId, MailboxMessageKind, PrincipalId,
    local::{
        LocalDirection, LocalDisposition, LocalFrame, LocalRole, LocalSubmit, LocalSubmitResult,
    },
    local_service::MailboxLocalLimits,
};
use mvm_core::mailbox::frame::{
    cast::submit_enrollment::OriginalSubmit,
    local::{decode_local_frame, encode_local_frame, local_request_digest},
    submit::PreparedSubmit,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    os::{
        fd::OwnedFd,
        unix::net::{UnixDatagram, UnixStream},
    },
    time::Instant,
};

const MAX_BODY: usize = 1024;
const MAX_REQUEST: usize = 2048;
const BOOTSTRAP: usize = 2048;
const RESULT_MAX: usize = 256;
const IO_TIMEOUT: std::time::Duration = crate::mailbox_outbox::MAILBOX_IO_TIMEOUT;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadSubmit {
    binding: [u8; 32],
    generation: [u8; 32],
    recipient: PrincipalId,
    content_type: ContentType,
    limits: MailboxLocalLimits,
    max_payload: usize,
    valid_from: i64,
    valid_until: i64,
}
impl WorkloadSubmit {
    fn live(&self, now: i64) -> io::Result<()> {
        if !(self.valid_from..self.valid_until).contains(&now) {
            return Err(super::invalid("original Submit outside admitted time"));
        }
        Ok(())
    }
    fn encode(&self, body: &[u8]) -> io::Result<Vec<u8>> {
        if body.is_empty() || body.len() > self.max_payload.min(MAX_BODY) {
            return Err(super::invalid("Submit body exceeds fixture budget"));
        }
        let request = LocalSubmit {
            originating_binding: self.binding,
            request_id: 1,
            kind: MailboxMessageKind::Cast,
            recipient: self.recipient,
            content_type: self.content_type.clone(),
            expires_at_unix_ms: self.valid_until,
            timeout_ms: 0,
            correlation: CorrelationId::from_bytes([0; 32]),
            causation: CausationId::from_bytes([0; 32]),
            reply_token: vec![],
            body: body.to_vec(),
        };
        encode_local_frame(
            &LocalFrame::Submit(Box::new(request)),
            LocalRole::Submit,
            LocalDirection::GuestToHost,
            &self.limits,
        )
        .map_err(io::Error::other)
    }
}
fn send(socket: &UnixDatagram, bytes: &[u8]) -> io::Result<()> {
    if socket.send(bytes)? != bytes.len() {
        return Err(super::invalid("short original Submit datagram"));
    }
    Ok(())
}
fn receive<const N: usize>(socket: &UnixDatagram, storage: &mut [u8; N]) -> io::Result<usize> {
    let n = socket.recv(storage)?;
    if n == 0 || n == N {
        return Err(super::invalid("invalid original Submit datagram size"));
    }
    Ok(n)
}
pub struct GuestSubmitEndpoint {
    origin: OriginalSubmit,
    context: WorkloadSubmit,
    socket: UnixDatagram,
    pending: Option<PreparedSubmit>,
    accepted: Option<LocalSubmitResult>,
    reported: bool,
}
impl GuestSubmitEndpoint {
    pub fn prepare_original_worker(origin: OriginalSubmit) -> io::Result<(Self, OwnedFd)> {
        let p = origin.enrollment();
        let context = WorkloadSubmit {
            binding: p.binding,
            generation: p.service_generation,
            recipient: p.recipient,
            content_type: p.content_type.clone(),
            limits: p.limits,
            max_payload: p.max_payload as usize,
            valid_from: p.valid_from,
            valid_until: p.valid_until,
        };
        let (socket, workload) = UnixDatagram::pair()?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        let bootstrap = serde_json::to_vec(&context)?;
        if bootstrap.len() > BOOTSTRAP {
            return Err(super::invalid("Submit bootstrap exceeds bound"));
        }
        send(&socket, &bootstrap)?;
        Ok((
            Self {
                origin,
                context,
                socket,
                pending: None,
                accepted: None,
                reported: false,
            },
            workload.into(),
        ))
    }
    fn claim_workload(&mut self) -> io::Result<()> {
        if self.pending.is_some() {
            return Ok(());
        }
        let mut buf = [0; MAX_REQUEST + 1];
        let n = receive(&self.socket, &mut buf)?;
        let bytes = &buf[..n];
        let LocalFrame::Submit(request) = decode_local_frame(
            bytes,
            LocalRole::Submit,
            LocalDirection::GuestToHost,
            &self.context.limits,
        )
        .map_err(io::Error::other)?
        else {
            return Err(super::invalid("expected original Submit"));
        };
        // Only the body comes from the workload. All authority and identifiers
        // come from PID 1's original boot or from this single bounded slot.
        if self.context.encode(&request.body)? != bytes {
            return Err(super::invalid("workload changed the signed Submit scope"));
        }
        self.pending = Some(
            PreparedSubmit::from_claim(bytes.to_vec(), self.context.limits)
                .map_err(io::Error::other)?,
        );
        Ok(())
    }
    fn exchange(&mut self, stream: &mut UnixStream) -> io::Result<()> {
        let now = || chrono::Utc::now().timestamp_millis();
        self.context.live(now())?;
        if self.reported {
            return Err(super::invalid("original one-shot Submit already reported"));
        }
        self.claim_workload()?;
        self.context.live(now())?;
        if self.accepted.is_none() {
            let prior = &mut self.accepted;
            let window = &self.context;
            self.pending
                .as_ref()
                .expect("original claim retained")
                .forward_on(
                    stream,
                    &self.origin.greeting(),
                    &window.generation,
                    |_, result| {
                        window.live(now())?;
                        *prior = Some(result.clone());
                        Ok(())
                    },
                )?;
        }
        // No failure or ephemeral acknowledgment deletes pending. A lost local
        // reply retries publication from this exact original accepted Result.
        let result = self
            .accepted
            .as_ref()
            .ok_or_else(|| super::invalid("Submit was not accepted"))?;
        self.context.live(now())?;
        let bytes = encode_local_frame(
            &LocalFrame::SubmitResult(result.clone()),
            LocalRole::Submit,
            LocalDirection::HostToGuest,
            &self.context.limits,
        )
        .map_err(io::Error::other)?;
        send(&self.socket, &bytes)?;
        self.reported = true;
        Ok(())
    }
    pub fn forward_on_host_port(&mut self, fd: OwnedFd) -> io::Result<()> {
        super::check_host_port(&fd)?;
        let mut stream = UnixStream::from(fd);
        crate::vsock::run_with_stream_deadline(&mut stream, Instant::now() + IO_TIMEOUT, |s| {
            Ok(self.exchange(s)?)
        })
        .map_err(io::Error::other)
    }
}
/// The original warm worker supplies only application bytes. Its private
/// endpoint and the bootstrap give it the bound recipient and local framing.
pub fn submit_original_workload(body: &[u8]) -> io::Result<LocalSubmitResult> {
    let socket = super::exec::original_socket()?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut buf = [0; BOOTSTRAP + 1];
    let n = receive(&socket, &mut buf)?;
    let ctx: WorkloadSubmit = serde_json::from_slice(&buf[..n])?;
    ctx.live(chrono::Utc::now().timestamp_millis())?;
    let encoded = ctx.encode(body)?;
    let digest = local_request_digest(&encoded, &ctx.limits).map_err(io::Error::other)?;
    send(&socket, &encoded)?;
    let mut buf = [0; RESULT_MAX + 1];
    let n = receive(&socket, &mut buf)?;
    let LocalFrame::SubmitResult(r) = decode_local_frame(
        &buf[..n],
        LocalRole::Submit,
        LocalDirection::HostToGuest,
        &ctx.limits,
    )
    .map_err(io::Error::other)?
    else {
        return Err(super::invalid("missing original SubmitResult"));
    };
    ctx.live(chrono::Utc::now().timestamp_millis())?;
    if r.request_id != 1
        || r.semantic_digest != digest
        || r.service_generation != ctx.generation
        || *r.correlation.as_bytes() != [0; 32]
        || !matches!(
            r.disposition,
            LocalDisposition::AcceptedEphemeral | LocalDisposition::DuplicateEphemeral
        )
    {
        return Err(super::invalid("wrong original SubmitResult"));
    }
    Ok(r)
}

#[cfg(test)]
mod tests;
