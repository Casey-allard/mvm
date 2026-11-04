//! Object-v1 at the authorized plaintext position. This module delegates every
//! object frame, codec, publication check, and readback to the shared core.
//! Callers retain their aggregate resource lease until both ends are dropped.
use crate::entrypoint::CancellationToken;
use mvm_contract::{
    grants::owner_access::OwnerAccessBinding,
    protocol::owner_access::{OwnerAccessObjectDirection, OwnerAccessRequest},
};
pub use spiralcore_transfer::v1::ObjectMode;
use spiralcore_transfer::{
    Error, Id, Result,
    endpoint::{Authority, Context},
    protocol::Frame,
    resource_profile::ResourceProfile,
    shared_transfer::PreparedPrediction,
    v1::{Capabilities, NegotiatedProfile, ObjectEndpoint, ObjectReceipt, ObjectSender},
};
use std::{path::Path, time::Instant};

/// Construct only after canonical signature/boot/owner admission. The supplied
/// cancellation token must belong to that original active access ticket.
pub struct AccessObjectScope {
    authority: ScopedAuthority,
    profile: NegotiatedProfile,
    target_limit: usize,
}
#[derive(Clone)]
struct ScopedAuthority {
    context: Context,
    cancellation: CancellationToken,
    deadline: Instant,
    unix_deadline: u64,
    last: std::sync::Arc<std::sync::Mutex<(u64, Instant)>>,
}
impl ScopedAuthority {
    fn current(&self) -> Result<()> {
        let now =
            u64::try_from(chrono::Utc::now().timestamp_millis()).map_err(|_| Error::Expired)?;
        self.observe(now, Instant::now())
    }
    fn observe(&self, now: u64, monotonic: Instant) -> Result<()> {
        if self.cancellation.is_requested() {
            return Err(Error::Unauthorized);
        }
        if monotonic >= self.deadline || now >= self.unix_deadline {
            self.cancellation.request();
            return Err(Error::Expired);
        }
        let mut last = self.last.lock().map_err(|_| {
            self.cancellation.request();
            Error::Unauthorized
        })?;
        if now < last.0 || monotonic < last.1 {
            self.cancellation.request();
            return Err(Error::Expired);
        }
        *last = (now, monotonic);
        Ok(())
    }
}
impl Authority for ScopedAuthority {
    fn authorize(&self, context: &Context) -> Result<()> {
        self.current()?;
        if *context != self.context {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
impl AccessObjectScope {
    pub fn new(
        binding: &OwnerAccessBinding,
        request: &OwnerAccessRequest,
        tenant: &str,
        direction: OwnerAccessObjectDirection,
        cancellation: CancellationToken,
        deadline: Instant,
    ) -> Result<Self> {
        let now =
            u64::try_from(chrono::Utc::now().timestamp_millis()).map_err(|_| Error::Expired)?;
        let operation = request
            .validate_header(binding, now)
            .map_err(|_| Error::Unauthorized)?;
        if binding.tenant != tenant {
            return Err(Error::Unauthorized);
        }
        let selected = binding.grant.object_v1.as_ref().ok_or(Error::Unsupported)?;
        selected.validate().map_err(|_| Error::Unsupported)?;
        // Cross-call cache retention requires its own retained shared lease.
        // This first implementation admits only explicitly per-call reuse.
        if selected.cache_reuse_within_execution {
            return Err(Error::Unsupported);
        }
        let mut capabilities = Capabilities::small_v1();
        capabilities.codec_mask &= selected.codec_mask;
        let profile = capabilities.negotiate(&capabilities)?;
        let direction = match direction {
            OwnerAccessObjectDirection::Input => "input",
            OwnerAccessObjectDirection::Reply => "reply",
        };
        let context = Context {
            tenant: tenant.into(),
            domain: "mvm.owner-access.object.v1".into(),
            sender: request.owner.clone(),
            recipient: binding.execution.instance_id.clone(),
            mailbox: format!("{}:{direction}", request.operation),
            capability: binding.policy.plan_id.0.clone(),
            authorization_scope: format!(
                "{}:{}:{}",
                binding.execution.plan_nonce.as_hex(),
                binding.policy.plan_version,
                spiralcore_transfer::hex(&request.request_id)
            ),
            // These are fixed cache-format slots, not invented MVM auth epochs.
            policy_epoch: 0,
            execution_epoch: 0,
        };
        context.namespace()?;
        let deadline = deadline.min(
            crate::owner_access::received_deadline(
                request.deadline_unix_ms,
                chrono::Utc::now(),
                Instant::now(),
            )
            .map_err(|_| Error::Expired)?,
        );
        let authority = ScopedAuthority {
            context,
            cancellation,
            deadline,
            unix_deadline: request.deadline_unix_ms,
            last: std::sync::Arc::new(std::sync::Mutex::new((now, Instant::now()))),
        };
        authority.current()?;
        let target_limit = ResourceProfile::SmallV1
            .max_target_len()
            .min(match direction {
                "input" => operation.max_request_bytes as usize,
                _ => operation.max_reply_bytes as usize,
            });
        Ok(Self {
            authority,
            profile,
            target_limit,
        })
    }
    /// The real shared-core two-endpoint reservation, never an RSS estimate.
    pub fn operation_charge(&self) -> Result<u64> {
        ResourceProfile::SmallV1.operation_charge()
    }
    pub fn sender(
        &self,
        mode: ObjectMode,
        schema: Option<&[u8]>,
        prediction: Option<PreparedPrediction>,
    ) -> Result<ObjectSender> {
        self.authority.current()?;
        let context = &self.authority.context;
        let resources = ResourceProfile::SmallV1;
        match (mode, prediction) {
            (ObjectMode::Runtime, Some(prediction)) => ObjectSender::with_runtime_resource_profile(
                context,
                prediction,
                self.profile,
                resources,
            ),
            (ObjectMode::Combined, Some(prediction)) => {
                ObjectSender::with_combined_resource_profile(
                    context,
                    prediction,
                    schema.ok_or(Error::Malformed)?,
                    spiralcore_transfer::session::SelectionPolicy::CpuConscious,
                    self.profile,
                    resources,
                )
            }
            (ObjectMode::Raw | ObjectMode::Whole, None) => ObjectSender::new_with_resource_profile(
                mode,
                context,
                None,
                self.profile,
                resources,
            ),
            (ObjectMode::Warm, None) => ObjectSender::new_with_resource_profile(
                mode,
                context,
                schema,
                self.profile,
                resources,
            ),
            _ => Err(Error::Malformed),
        }
    }
    pub fn receiver(&self, root: &Path) -> Result<AccessObjectReceiver> {
        self.authority.current()?;
        let resources = ResourceProfile::SmallV1;
        let endpoint = ObjectEndpoint::open_with_resource_profile(
            root,
            resources.receiver_limits(),
            self.authority.clone(),
            self.profile,
            resources,
        )?;
        Ok(AccessObjectReceiver {
            endpoint,
            authority: self.authority.clone(),
            target_limit: self.target_limit,
        })
    }
    pub fn send<F: FnMut(&[Frame]) -> Result<Vec<Frame>>>(
        &self,
        sender: &mut ObjectSender,
        bytes: Vec<u8>,
        transfer: Id,
        mut exchange: F,
    ) -> Result<ObjectReceipt> {
        self.authority.current()?;
        if bytes.len() > self.target_limit {
            return Err(Error::Limit);
        }
        let receipt =
            sender.send_with_receipt(&self.authority.context, bytes, transfer, true, |frames| {
                self.authority.current()?;
                let replies = exchange(frames)?;
                self.authority.current()?;
                Ok(replies)
            })?;
        self.authority.current()?;
        Ok(receipt)
    }
    /// Checkpoint publication is a separate, acknowledged core operation.
    pub fn seed_checkpoint<F: FnMut(&[Frame]) -> Result<Vec<Frame>>>(
        &self,
        sender: &mut ObjectSender,
        transfer: Id,
        mut exchange: F,
    ) -> Result<()> {
        self.authority.current()?;
        sender.seed_checkpoint(&self.authority.context, transfer, |frames| {
            self.authority.current()?;
            exchange(frames)
        })?;
        self.authority.current()
    }
    pub fn seed_schema<F: FnMut(&[Frame]) -> Result<Vec<Frame>>>(
        &self,
        sender: &mut ObjectSender,
        transfer: Id,
        mut exchange: F,
    ) -> Result<()> {
        self.authority.current()?;
        sender.seed_schema(&self.authority.context, transfer, |frames| {
            self.authority.current()?;
            exchange(frames)
        })?;
        self.authority.current()
    }
}
pub struct AccessObjectReceiver {
    endpoint: ObjectEndpoint<ScopedAuthority>,
    authority: ScopedAuthority,
    target_limit: usize,
}
impl AccessObjectReceiver {
    pub fn handle(&mut self, frames: &[Frame]) -> Result<Vec<Frame>> {
        self.authority.current()?;
        if frames.is_empty() || frames.len() > 8 {
            return Err(Error::Limit);
        }
        let now = u64::try_from(chrono::Utc::now().timestamp_millis())
            .map_err(|_| Error::Expired)?
            / 1000;
        let mut replies = Vec::with_capacity(frames.len());
        for frame in frames {
            self.authority.current()?;
            let reply = self.endpoint.handle(&self.authority.context, frame, now)?;
            let published = reply.kind == 103;
            replies.push(reply);
            // The shared protocol permits an offer to find an already verified
            // object. Remaining optimistic batch frames were never consumed.
            if published {
                break;
            }
        }
        Ok(replies)
    }
    pub fn read_object(&mut self, object: Id, expected: usize) -> Result<Vec<u8>> {
        self.authority.current()?;
        if expected > self.target_limit {
            return Err(Error::Limit);
        }
        let bytes = self.endpoint.read_object(&self.authority.context, object)?;
        if bytes.len() != expected {
            return Err(Error::Integrity);
        }
        self.authority.current()?;
        Ok(bytes)
    }
}

/// Canonical control messages only. Implementations must retain the original
/// deadline/token through framing, encryption and every partial syscall.
pub trait GuestObjectChannel {
    fn send(
        &mut self,
        response: &mvm_contract::protocol::owner_access::OwnerAccessObjectResponse,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<()>;
    fn receive(
        &mut self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<mvm_contract::protocol::owner_access::OwnerAccessObjectRequest>;
}
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectWireCounters {
    pub sent: u64,
    pub received: u64,
    pub frames_sent: u32,
    pub frames_received: u32,
}
/// The same authenticated Session framing used by all canonical guest verbs.
#[cfg(unix)]
pub struct CanonicalObjectChannel<'a, S> {
    socket: &'a mut S,
    session: &'a mut crate::vsock::AuthenticatedSession,
    counters: ObjectWireCounters,
}
#[cfg(unix)]
impl<'a, S> CanonicalObjectChannel<'a, S> {
    pub fn new(socket: &'a mut S, session: &'a mut crate::vsock::AuthenticatedSession) -> Self {
        Self {
            socket,
            session,
            counters: ObjectWireCounters::default(),
        }
    }
    pub fn counters(&self) -> ObjectWireCounters {
        self.counters
    }
}
#[cfg(unix)]
struct ObjectIo<'a, S> {
    socket: &'a mut S,
    deadline: Instant,
    cancel: &'a CancellationToken,
    counters: &'a mut ObjectWireCounters,
}
#[cfg(unix)]
impl<S> ObjectIo<'_, S> {
    fn remaining(&self) -> std::io::Result<std::time::Duration> {
        if self.cancel.is_requested() {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .map(|duration| duration.min(std::time::Duration::from_millis(50)))
            .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
    }
}
#[cfg(unix)]
impl<S: std::io::Read + std::os::fd::AsRawFd> std::io::Read for ObjectIo<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let remaining = self.remaining()?;
            let timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: remaining
                    .as_micros()
                    .max(1)
                    .try_into()
                    .expect("bounded socket timeout"),
            };
            // SAFETY: the borrowed socket remains live; the initialized timeval
            // is read only by the synchronous setsockopt call.
            if unsafe {
                libc::setsockopt(
                    self.socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&timeout as *const libc::timeval).cast(),
                    std::mem::size_of_val(&timeout)
                        .try_into()
                        .expect("timeval size"),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            match self.socket.read(bytes) {
                Ok(count) => {
                    self.counters.received = self
                        .counters
                        .received
                        .checked_add(count as u64)
                        .ok_or(std::io::ErrorKind::InvalidData)?;
                    return Ok(count);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
#[cfg(unix)]
impl<S: std::io::Write + std::os::fd::AsRawFd> std::io::Write for ObjectIo<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            self.remaining()?;
            match crate::owner_access::AccessWriter::new(self.socket, self.deadline).write(bytes) {
                Ok(count) => {
                    self.counters.sent = self
                        .counters
                        .sent
                        .checked_add(count as u64)
                        .ok_or(std::io::ErrorKind::InvalidData)?;
                    return Ok(count);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining()?;
        self.socket.flush()
    }
}
#[cfg(unix)]
impl<S: std::io::Read + std::io::Write + std::os::fd::AsRawFd> GuestObjectChannel
    for CanonicalObjectChannel<'_, S>
{
    fn send(
        &mut self,
        response: &mvm_contract::protocol::owner_access::OwnerAccessObjectResponse,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.session
            .write(
                &mut ObjectIo {
                    socket: self.socket,
                    deadline,
                    cancel,
                    counters: &mut self.counters,
                },
                &crate::vsock::GuestResponse::OwnerAccessObject(response.clone()),
            )
            .map_err(|_| Error::Unauthorized)?;
        self.counters.frames_sent = self
            .counters
            .frames_sent
            .checked_add(1)
            .ok_or(Error::Limit)?;
        Ok(())
    }
    fn receive(
        &mut self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<mvm_contract::protocol::owner_access::OwnerAccessObjectRequest> {
        let request = self
            .session
            .read::<crate::vsock::GuestRequest>(&mut ObjectIo {
                socket: self.socket,
                deadline,
                cancel,
                counters: &mut self.counters,
            })
            .map_err(|_| Error::Unauthorized)?;
        self.counters.frames_received = self
            .counters
            .frames_received
            .checked_add(1)
            .ok_or(Error::Limit)?;
        match request {
            crate::vsock::GuestRequest::OwnerAccessObject(request) => Ok(request),
            _ => Err(Error::Unauthorized),
        }
    }
}
#[derive(Debug)]
pub struct GuestObjectReport {
    pub events_received: u8,
    pub application_invocations: u8,
    pub request_bytes: usize,
    pub reply_bytes: usize,
    pub reply_receipt: ObjectReceipt,
}
/// One original admitted request, two sequential shared-core pairs. Publication
/// of input is not execution, and publication of output is not completion until
/// the active ticket passes its original finish gate.
#[cfg(unix)]
pub fn serve_admitted_object<C: GuestObjectChannel>(
    desk: &std::sync::Mutex<crate::owner_access::AccessDesk>,
    ticket: crate::owner_access::AccessObjectTicket,
    entrypoint: &crate::entrypoint::ValidatedEntrypoint,
    cwd: &Path,
    store: &Path,
    control: &impl std::os::fd::AsFd,
    channel: &mut C,
) -> Result<GuestObjectReport> {
    use mvm_contract::protocol::owner_access::{
        OwnerAccessObjectFrames, OwnerAccessObjectRequest as Q, OwnerAccessObjectResponse as R,
        split_object_payload,
    };
    let result = (|| {
        let begin = ticket.begin().clone();
        let binding = ticket.binding().clone();
        let token = ticket.cancellation();
        let deadline = ticket.deadline();
        let id = begin.request.request_id;
        let sequence = begin.request.sequence;
        let mut events = 1u8; // the Begin was consumed by the authenticated dispatcher
        let receive = |channel: &mut C, events: &mut u8| -> Result<Q> {
            if *events >= 16 {
                return Err(Error::Limit);
            }
            *events += 1;
            channel.receive(deadline, &token)
        };
        let current = |request_id: Id, observed: u64| -> Result<()> {
            if request_id != id || observed != sequence {
                Err(Error::Unauthorized)
            } else {
                Ok(())
            }
        };
        let input = AccessObjectScope::new(
            &binding,
            &begin.request,
            &binding.tenant,
            OwnerAccessObjectDirection::Input,
            token.clone(),
            deadline,
        )?;
        let mut receiver = input.receiver(&store.join("input"))?;
        channel.send(
            &R::Ready {
                request_id: id,
                sequence,
            },
            deadline,
            &token,
        )?;
        loop {
            match receive(channel, &mut events)? {
                Q::Frames(frames) => {
                    frames
                        .validate_for(&begin, OwnerAccessObjectDirection::Input)
                        .map_err(|_| Error::Unauthorized)?;
                    let frames = frames
                        .frames
                        .iter()
                        .map(|bytes| Frame::decode(bytes))
                        .collect::<Result<Vec<_>>>()?;
                    let replies = receiver.handle(&frames)?;
                    channel.send(
                        &R::Frames(OwnerAccessObjectFrames {
                            request_id: id,
                            sequence,
                            direction: OwnerAccessObjectDirection::Input,
                            frames: replies
                                .iter()
                                .map(Frame::encode)
                                .collect::<Result<Vec<_>>>()?,
                        }),
                        deadline,
                        &token,
                    )?;
                }
                Q::Commit {
                    request_id,
                    sequence: observed,
                } => {
                    current(request_id, observed)?;
                    break;
                }
                _ => return Err(Error::Unauthorized),
            }
        }
        let bytes = receiver.read_object(begin.object, begin.payload_bytes as usize)?;
        drop(receiver);
        drop(input);
        let ticket = desk
            .lock()
            .map_err(|_| Error::Unauthorized)?
            .reconstruct_object(ticket, &bytes, chrono::Utc::now(), Instant::now())
            .map_err(|_| Error::Unauthorized)?;
        drop(bytes);
        let executed = {
            let _disconnect =
                crate::owner_access::AccessDisconnect::watch(control, token.clone(), deadline)
                    .map_err(|_| Error::Unauthorized)?;
            ticket.run(entrypoint, cwd)
        };
        let reply = executed.reply();
        let status = reply.status;
        let (metadata, field, bytes) =
            split_object_payload(reply.payload.clone()).map_err(|_| Error::Malformed)?;
        let object = spiralcore_transfer::object_id(&bytes);
        let payload_bytes = bytes.len();
        let output = AccessObjectScope::new(
            &binding,
            &begin.request,
            &binding.tenant,
            OwnerAccessObjectDirection::Reply,
            token.clone(),
            deadline,
        )?;
        let mode = if output
            .profile
            .supports(spiralcore_transfer::protocol::Mode::ZstdWholeV1)
        {
            ObjectMode::Whole
        } else {
            ObjectMode::Raw
        };
        let mut sender = output.sender(mode, None, None)?;
        channel.send(
            &R::Reply {
                request_id: id,
                sequence,
                status,
                object,
                payload_bytes: payload_bytes.try_into().map_err(|_| Error::Limit)?,
                record: metadata,
                field,
            },
            deadline,
            &token,
        )?;
        match receive(channel, &mut events)? {
            Q::ReplyReady {
                request_id,
                sequence: observed,
            } => current(request_id, observed)?,
            _ => return Err(Error::Unauthorized),
        }
        let transfer = spiralcore_transfer::hash(
            b"mvm.owner-access.reply-transfer.v1\0",
            &[&id, &sequence.to_le_bytes()],
        );
        let receipt = output.send(&mut sender, bytes, transfer, |frames| {
            // One core frame per canonical message preserves the existing
            // 256KiB JSON cap even for a 60KiB checkpoint data frame.
            let mut replies = Vec::with_capacity(frames.len());
            for frame in frames {
                channel.send(
                    &R::ReplyFrames(OwnerAccessObjectFrames {
                        request_id: id,
                        sequence,
                        direction: OwnerAccessObjectDirection::Reply,
                        frames: vec![frame.encode()?],
                    }),
                    deadline,
                    &token,
                )?;
                let incoming = receive(channel, &mut events)?;
                let Q::Receipt(incoming) = incoming else {
                    return Err(Error::Unauthorized);
                };
                incoming
                    .validate_for(&begin, OwnerAccessObjectDirection::Reply)
                    .map_err(|_| Error::Unauthorized)?;
                for reply in &incoming.frames {
                    replies.push(Frame::decode(reply)?);
                }
                if replies.last().is_some_and(|reply| reply.kind == 103) {
                    break;
                }
            }
            Ok(replies)
        })?;
        drop(sender);
        drop(output);
        desk.lock()
            .map_err(|_| Error::Unauthorized)?
            .complete_run(executed, chrono::Utc::now(), Instant::now())
            .map_err(|_| Error::Unauthorized)?;
        channel.send(
            &R::Completed {
                request_id: id,
                sequence,
                status,
                object,
                payload_bytes: payload_bytes.try_into().map_err(|_| Error::Limit)?,
            },
            deadline,
            &token,
        )?;
        Ok(GuestObjectReport {
            events_received: events,
            application_invocations: 1,
            request_bytes: begin.payload_bytes as usize,
            reply_bytes: payload_bytes,
            reply_receipt: receipt,
        })
    })();
    if result.is_err()
        && let Ok(mut desk) = desk.lock()
    {
        desk.close();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn clock_authority(now: u64, monotonic: Instant) -> ScopedAuthority {
        ScopedAuthority {
            context: Context {
                tenant: "unit-clock".into(),
                domain: "unit-clock".into(),
                sender: "unit-clock".into(),
                recipient: "unit-clock".into(),
                mailbox: "unit-clock".into(),
                capability: "unit-clock".into(),
                authorization_scope: "unit-clock".into(),
                policy_epoch: 0,
                execution_epoch: 0,
            },
            cancellation: CancellationToken::default(),
            deadline: monotonic + std::time::Duration::from_millis(10),
            unix_deadline: now + 10,
            last: std::sync::Arc::new(std::sync::Mutex::new((now, monotonic))),
        }
    }
    #[test]
    fn object_clock_rollback_and_exact_expiry_cancel_the_original_scope() {
        let now = Instant::now();
        let authority = clock_authority(1000, now);
        authority.observe(1000, now).unwrap();
        authority
            .observe(1005, now + std::time::Duration::from_millis(5))
            .unwrap();
        assert_eq!(
            authority.observe(1004, now + std::time::Duration::from_millis(6)),
            Err(Error::Expired)
        );
        assert!(authority.cancellation.is_requested());
        let wall = clock_authority(1000, now);
        assert_eq!(wall.observe(1010, now), Err(Error::Expired));
        assert!(wall.cancellation.is_requested());
        let mono = clock_authority(1000, now);
        assert_eq!(
            mono.observe(1000, now + std::time::Duration::from_millis(10)),
            Err(Error::Expired)
        );
        assert!(mono.cancellation.is_requested());
    }
    #[test]
    fn poisoned_object_clock_never_authorizes_retained_publication() {
        let now = Instant::now();
        let authority = clock_authority(1000, now);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = authority.last.lock().unwrap();
            panic!("owned clock poison fixture")
        }));
        assert_eq!(authority.observe(1000, now), Err(Error::Unauthorized));
        assert!(authority.cancellation.is_requested());
    }
}
