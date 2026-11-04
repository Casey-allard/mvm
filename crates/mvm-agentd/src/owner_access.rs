//! Separate, bounded guest access desk installed only from a verified VerbGrant.
use crate::entrypoint::CancellationToken;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use mvm_contract::{
    grants::owner_access::{AccessRefusal, OperationGrant, OwnerAccessBinding},
    plan::{Nonce, VerbGrant},
    protocol::owner_access::{
        OwnerAccessCancel, OwnerAccessReply, OwnerAccessRequest, OwnerAccessStatus,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

/// Establish one local monotonic cap at receipt. The authenticated host keeps
/// its independent absolute cap; this conversion requires bounded host/guest
/// wall-clock skew and never promises exact cross-machine timing.
pub fn received_deadline(
    deadline_unix_ms: u64,
    now: DateTime<Utc>,
    monotonic: Instant,
) -> Result<Instant, AccessRefusal> {
    let current = u64::try_from(now.timestamp_millis()).map_err(|_| AccessRefusal::Expired)?;
    let remaining = deadline_unix_ms
        .checked_sub(current)
        .filter(|remaining| *remaining > 0 && *remaining <= 30_000)
        .ok_or(AccessRefusal::Expired)?;
    monotonic
        .checked_add(Duration::from_millis(remaining))
        .ok_or(AccessRefusal::Expired)
}

/// Bounds writes of the existing authenticated frame on its owned socket.
/// A partial write remains fatal to the canonical session; it is not retried
/// with a fresh prefix, sequence, connection or deadline.
#[cfg(unix)]
pub struct AccessWriter<'a, W> {
    socket: &'a mut W,
    deadline: Instant,
}
#[cfg(unix)]
impl<'a, W> AccessWriter<'a, W> {
    pub fn new(socket: &'a mut W, deadline: Instant) -> Self {
        Self { socket, deadline }
    }
}
#[cfg(unix)]
impl<W: std::io::Write + std::os::fd::AsRawFd> std::io::Write for AccessWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(std::io::ErrorKind::TimedOut)?
            .min(Duration::from_millis(50));
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: remaining
                .as_micros()
                .max(1)
                .try_into()
                .expect("bounded socket timeout"),
        };
        // SAFETY: the borrowed socket remains live, and this initialized
        // timeval is read only during the synchronous setsockopt call.
        if unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&timeout)
                    .try_into()
                    .expect("timeval size"),
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.socket.flush()
    }
}

/// Watches only the owned, authenticated one-shot control connection. No
/// request bytes are consumed and no descriptor number can be reused under
/// the watcher. Dropping the guard wakes and joins it before returning.
#[cfg(unix)]
pub struct AccessDisconnect {
    stop: std::os::unix::net::UnixStream,
    worker: Option<std::thread::JoinHandle<()>>,
}
#[cfg(unix)]
impl AccessDisconnect {
    pub fn watch(
        control: &impl std::os::fd::AsFd,
        cancellation: CancellationToken,
        deadline: Instant,
    ) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let control = control.as_fd().try_clone_to_owned()?;
        let (stop, wake) = std::os::unix::net::UnixStream::pair()?;
        let worker = std::thread::Builder::new()
            .name("owner-access-control".into())
            .spawn(move || {
                let mut descriptors = [
                    libc::pollfd {
                        fd: control.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: wake.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                loop {
                    let Some(remaining) = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|duration| !duration.is_zero())
                    else {
                        cancellation.request();
                        return;
                    };
                    let millis = i32::try_from(remaining.as_millis().clamp(1, 50))
                        .expect("bounded poll interval");
                    // SAFETY: two borrowed live descriptors, owned by this thread;
                    // the stop socket wakes the join without a sleep or FD reuse.
                    let status = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, millis) };
                    if descriptors[1].revents != 0 {
                        return;
                    }
                    if descriptors[0].revents != 0
                        || status < 0
                            && std::io::Error::last_os_error().kind()
                                != std::io::ErrorKind::Interrupted
                    {
                        cancellation.request();
                        return;
                    }
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}
#[cfg(unix)]
impl Drop for AccessDisconnect {
    fn drop(&mut self) {
        use std::io::Write;
        let _ = self.stop.write_all(&[1]);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Active {
    sequence: u64,
    token: CancellationToken,
}
/// Owns no subprocess or transport. The canonical guest dispatcher owns both.
#[derive(Default)]
pub struct AccessDesk {
    binding: Option<OwnerAccessBinding>,
    expiry: Option<DateTime<Utc>>,
    monotonic_expiry: Option<Instant>,
    seen: BTreeSet<[u8; 32]>,
    sequence: u64,
    active: BTreeMap<[u8; 32], Active>,
    rate: BTreeMap<(String, String), (Instant, u16)>,
    last: Option<(DateTime<Utc>, Instant)>,
    closed: bool,
}
pub struct AccessTicket {
    id: [u8; 32],
    sequence: u64,
    binding: OwnerAccessBinding,
    deadline: Instant,
    operation: OperationGrant,
    cancellation: CancellationToken,
    request: OwnerAccessRequest,
}
/// An admitted object header cannot execute until the complete exact object
/// has been read back and reconstructed under the original active ticket.
#[cfg(feature = "owner-access-object")]
pub struct AccessObjectTicket {
    ticket: AccessTicket,
    begin: mvm_contract::protocol::owner_access::OwnerAccessObjectBegin,
}
#[cfg(feature = "owner-access-object")]
impl AccessObjectTicket {
    pub fn begin(&self) -> &mvm_contract::protocol::owner_access::OwnerAccessObjectBegin {
        &self.begin
    }
    pub fn binding(&self) -> &OwnerAccessBinding {
        &self.ticket.binding
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.ticket.cancellation()
    }
    pub fn deadline(&self) -> Instant {
        self.ticket.deadline()
    }
}
pub struct FinishedAccess {
    ticket: AccessTicket,
    reply: OwnerAccessReply,
}
impl FinishedAccess {
    pub fn reply(&self) -> &OwnerAccessReply {
        &self.reply
    }
}
impl AccessTicket {
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn operation(&self) -> &OperationGrant {
        &self.operation
    }
    /// Runs only the caller's boot-validated application handle. Consuming the
    /// ticket prevents a second execution through this API. Nothing is emitted
    /// until the complete bounded result has passed the declared reply schema.
    pub fn run(
        self,
        entrypoint: &crate::entrypoint::ValidatedEntrypoint,
        cwd: &std::path::Path,
    ) -> FinishedAccess {
        use crate::{
            entrypoint::{CallCaps, EntrypointCall},
            entrypoint_stream::stream_call_before,
            vsock::EntrypointEvent,
        };
        use mvm_contract::protocol::owner_access::TypedRecord;
        let mut reply = OwnerAccessReply {
            request_id: self.id,
            sequence: self.sequence,
            status: OwnerAccessStatus::Error,
            payload: TypedRecord::default(),
        };
        let remaining = self.deadline.checked_duration_since(Instant::now());
        if self.cancellation.is_requested() {
            reply.status = OwnerAccessStatus::Cancelled;
            return FinishedAccess {
                ticket: self,
                reply,
            };
        }
        let Some(remaining) = remaining.filter(|duration| !duration.is_zero()) else {
            reply.status = OwnerAccessStatus::Timeout;
            return FinishedAccess {
                ticket: self,
                reply,
            };
        };
        let Ok(input) = serde_json::to_vec(&self.request) else {
            return FinishedAccess {
                ticket: self,
                reply,
            };
        };
        let mut output = Vec::new();
        let mut invalid = false;
        let caps = CallCaps {
            stdin_max: self.operation.max_request_bytes as usize + 2048,
            stdout_max: self.operation.max_reply_bytes as usize,
            stderr_max: 0,
            fd3_max: 0,
            kill_grace_period: remaining.min(Duration::from_millis(100)),
            poll_interval: Duration::from_millis(5),
        };
        let terminal = stream_call_before(
            EntrypointCall {
                entrypoint,
                cwd,
                stdin: &input,
                timeout: remaining,
                caps,
                resource_limits: None,
                cancellation: Some(self.cancellation.clone()),
                env: Vec::new(),
                stream_input: false,
            },
            self.deadline,
            &mut |event| match event {
                EntrypointEvent::Stdout { chunk } => {
                    if output
                        .len()
                        .checked_add(chunk.len())
                        .is_none_or(|n| n > self.operation.max_reply_bytes as usize)
                    {
                        invalid = true;
                        self.cancellation.request();
                    } else {
                        output.extend_from_slice(&chunk);
                    }
                }
                EntrypointEvent::Stderr { chunk } if chunk.is_empty() => {}
                _ => {
                    invalid = true;
                    self.cancellation.request();
                }
            },
        );
        if self.cancellation.is_requested() {
            reply.status = OwnerAccessStatus::Cancelled;
        } else if Instant::now() >= self.deadline {
            reply.status = OwnerAccessStatus::Timeout;
        } else if !invalid
            && matches!(terminal, EntrypointEvent::Exit { code: 0 })
            && let Ok(record) = serde_json::from_slice(&output)
            && self.operation.validate_reply(&record).is_ok()
        {
            reply.status = OwnerAccessStatus::Ok;
            reply.payload = record;
        }
        FinishedAccess {
            ticket: self,
            reply,
        }
    }
}
impl AccessDesk {
    pub fn install_verified(
        &mut self,
        grant: &VerbGrant,
        key: &VerifyingKey,
        instance: &str,
        nonce: &Nonce,
        now: DateTime<Utc>,
    ) -> Result<(), AccessRefusal> {
        grant
            .verify(key, instance, nonce, now)
            .map_err(|_| AccessRefusal::Identity)?;
        if now >= grant.not_after {
            return Err(AccessRefusal::Expired);
        }
        let binding = grant
            .owner_access
            .as_ref()
            .ok_or(AccessRefusal::Unavailable)?;
        binding.validate()?;
        if self.binding.as_ref() == Some(binding) {
            if self.closed {
                return Err(AccessRefusal::Unavailable);
            }
            self.expiry = Some(
                self.expiry
                    .map_or(grant.not_after, |old| old.min(grant.not_after)),
            );
            return Ok(());
        }
        self.close();
        if !self.active.is_empty() {
            return Err(AccessRefusal::Unavailable);
        }
        self.binding = Some(binding.clone());
        self.expiry = Some(grant.not_after);
        self.monotonic_expiry = Some(
            Instant::now()
                .checked_add(
                    (grant.not_after - now)
                        .to_std()
                        .map_err(|_| AccessRefusal::Expired)?,
                )
                .ok_or(AccessRefusal::Expired)?,
        );
        self.seen.clear();
        self.sequence = 0;
        self.rate.clear();
        self.last = None;
        self.closed = false;
        Ok(())
    }
    pub fn admit(
        &mut self,
        request: &OwnerAccessRequest,
        now: DateTime<Utc>,
        monotonic: Instant,
    ) -> Result<AccessTicket, AccessRefusal> {
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.grant.object_v1.is_some())
        {
            return Err(AccessRefusal::Unavailable);
        }
        self.admit_inner(request, now, monotonic, false)
    }
    fn admit_inner(
        &mut self,
        request: &OwnerAccessRequest,
        now: DateTime<Utc>,
        monotonic: Instant,
        object: bool,
    ) -> Result<AccessTicket, AccessRefusal> {
        if self.closed {
            return Err(AccessRefusal::Unavailable);
        }
        if self
            .last
            .is_some_and(|(unix, mono)| now < unix || monotonic < mono)
        {
            self.close();
            return Err(AccessRefusal::Expired);
        }
        self.last = Some((now, monotonic));
        if self.expiry.is_none_or(|expiry| now >= expiry)
            || self
                .monotonic_expiry
                .is_none_or(|expiry| monotonic >= expiry)
        {
            self.close();
            return Err(AccessRefusal::Expired);
        }
        let binding = self.binding.as_ref().ok_or(AccessRefusal::Unavailable)?;
        let milliseconds =
            u64::try_from(now.timestamp_millis()).map_err(|_| AccessRefusal::Expired)?;
        let operation = if object {
            request.validate_header(binding, milliseconds)?
        } else {
            request.validate(binding, milliseconds)?
        }
        .clone();
        if self.seen.contains(&request.request_id)
            || request.sequence != self.sequence.checked_add(1).ok_or(AccessRefusal::Limit)?
        {
            return Err(AccessRefusal::Replay);
        }
        if self.seen.len() >= 4096 || !self.active.is_empty() {
            return Err(AccessRefusal::Limit);
        }
        let key = (request.owner.clone(), request.operation.clone());
        let rate = self.rate.entry(key).or_insert((monotonic, 0));
        if monotonic.duration_since(rate.0) >= Duration::from_secs(1) {
            *rate = (monotonic, 0);
        }
        if rate.1 >= operation.max_calls_per_second {
            return Err(AccessRefusal::Limit);
        }
        let remaining = Duration::from_millis(request.deadline_unix_ms - milliseconds);
        let deadline = monotonic
            .checked_add(remaining)
            .ok_or(AccessRefusal::Expired)?
            .min(self.monotonic_expiry.ok_or(AccessRefusal::Expired)?);
        let cancellation = CancellationToken::default();
        self.active.insert(
            request.request_id,
            Active {
                sequence: request.sequence,
                token: cancellation.clone(),
            },
        );
        self.seen.insert(request.request_id);
        self.sequence = request.sequence;
        rate.1 += 1;
        Ok(AccessTicket {
            id: request.request_id,
            sequence: request.sequence,
            binding: binding.clone(),
            deadline,
            operation,
            cancellation,
            request: request.clone(),
        })
    }
    #[cfg(feature = "owner-access-object")]
    pub fn admit_object(
        &mut self,
        begin: &mvm_contract::protocol::owner_access::OwnerAccessObjectBegin,
        now: DateTime<Utc>,
        monotonic: Instant,
    ) -> Result<AccessObjectTicket, AccessRefusal> {
        let binding = self.binding.as_ref().ok_or(AccessRefusal::Unavailable)?;
        begin.validate(
            binding,
            u64::try_from(now.timestamp_millis()).map_err(|_| AccessRefusal::Expired)?,
        )?;
        let ticket = self.admit_inner(&begin.request, now, monotonic, true)?;
        Ok(AccessObjectTicket {
            ticket,
            begin: begin.clone(),
        })
    }
    #[cfg(feature = "owner-access-object")]
    pub fn reconstruct_object(
        &mut self,
        object: AccessObjectTicket,
        bytes: &[u8],
        now: DateTime<Utc>,
        monotonic: Instant,
    ) -> Result<AccessTicket, AccessRefusal> {
        let AccessObjectTicket { mut ticket, begin } = object;
        if self.closed || ticket.cancellation.is_requested() {
            return Err(AccessRefusal::Unavailable);
        }
        if self.binding.as_ref() != Some(&ticket.binding)
            || self
                .active
                .get(&ticket.id)
                .is_none_or(|active| active.sequence != ticket.sequence)
        {
            return Err(AccessRefusal::Identity);
        }
        if self
            .last
            .is_some_and(|(unix, mono)| now < unix || monotonic < mono)
            || monotonic >= ticket.deadline
            || self.expiry.is_none_or(|expiry| now >= expiry)
        {
            self.close();
            return Err(AccessRefusal::Expired);
        }
        self.last = Some((now, monotonic));
        if spiralcore_transfer::object_id(bytes) != begin.object {
            return Err(AccessRefusal::Schema);
        }
        ticket.request = begin.reconstruct(
            bytes,
            &ticket.binding,
            u64::try_from(now.timestamp_millis()).map_err(|_| AccessRefusal::Expired)?,
        )?;
        Ok(ticket)
    }
    pub fn finish(
        &mut self,
        ticket: AccessTicket,
        reply: &OwnerAccessReply,
        now: DateTime<Utc>,
        monotonic: Instant,
    ) -> Result<(), AccessRefusal> {
        if self.binding.as_ref() != Some(&ticket.binding) {
            return Err(AccessRefusal::Identity);
        }
        let active = self.active.get(&ticket.id).ok_or(AccessRefusal::Replay)?;
        if active.sequence != ticket.sequence {
            return Err(AccessRefusal::Replay);
        }
        let cancelled = active.token.is_requested();
        self.active.remove(&ticket.id);
        if self.closed || cancelled {
            return Err(AccessRefusal::Unavailable);
        }
        if monotonic >= ticket.deadline
            || self.expiry.is_none_or(|expiry| now >= expiry)
            || self
                .monotonic_expiry
                .is_none_or(|expiry| monotonic >= expiry)
        {
            return Err(AccessRefusal::Expired);
        }
        if reply.request_id != ticket.id || reply.sequence != ticket.sequence {
            return Err(AccessRefusal::Identity);
        }
        if reply.status == OwnerAccessStatus::Ok {
            ticket.operation.validate_reply(&reply.payload)
        } else if reply.payload.fields.is_empty() {
            Ok(())
        } else {
            Err(AccessRefusal::Schema)
        }
    }
    pub fn cancel(
        &mut self,
        cancel: &OwnerAccessCancel,
        now: DateTime<Utc>,
    ) -> Result<bool, AccessRefusal> {
        let binding = self.binding.as_ref().ok_or(AccessRefusal::Unavailable)?;
        if cancel.policy != binding.policy || cancel.execution != binding.execution {
            return Err(AccessRefusal::Identity);
        }
        if self.expiry.is_none_or(|expiry| now >= expiry) {
            self.close();
            return Err(AccessRefusal::Expired);
        }
        let Some(active) = self.active.get(&cancel.request_id) else {
            return Ok(false);
        };
        if active.sequence != cancel.sequence {
            return Err(AccessRefusal::Replay);
        }
        active.token.request();
        Ok(true)
    }
    pub fn complete_run(
        &mut self,
        executed: FinishedAccess,
        now: DateTime<Utc>,
        monotonic: Instant,
    ) -> Result<OwnerAccessReply, AccessRefusal> {
        let FinishedAccess { ticket, reply } = executed;
        match self.finish(ticket, &reply, now, monotonic) {
            Ok(()) => Ok(reply),
            Err(AccessRefusal::Expired) if reply.status == OwnerAccessStatus::Timeout => Ok(reply),
            Err(AccessRefusal::Unavailable) if reply.status == OwnerAccessStatus::Cancelled => {
                Ok(reply)
            }
            Err(error) => Err(error),
        }
    }
    pub fn close(&mut self) {
        self.closed = true;
        for active in self.active.values() {
            active.token.request();
        }
    }
}
impl Drop for AccessDesk {
    fn drop(&mut self) {
        self.close();
    }
}
