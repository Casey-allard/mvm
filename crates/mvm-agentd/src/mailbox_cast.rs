//! Ephemeral, stop-and-wait Cast delivery to one enrolled workload.
//!
//! The original launcher owns the service and the sole workload socketpair.
//! Closing a physical host stream does not reset the inbox. A different logical
//! owner must obtain a new enrollment and a fresh endpoint. The legacy boot
//! path never constructs this service.
#[cfg(target_os = "linux")]
pub mod exec;

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;

use mvm_contract::protocol::mailbox::{
    MailboxMessageKind, MessageId,
    local::{
        LocalDelivery, LocalDeliveryAck, LocalDirection, LocalFrame, LocalInboxDisposition,
        LocalRole,
    },
    local_service::MailboxLocalLimits,
};
use mvm_core::mailbox::frame::{
    cast::{CastChannel, CastInbox},
    local::{decode_local_frame, encode_local_frame},
};

pub struct GuestCastEndpoint {
    channel: CastChannel,
    inbox: CastInbox,
    workload: UnixDatagram,
    offered: bool,
    limits: MailboxLocalLimits,
}

/// An anonymous descriptor issued by the original guest launcher. Retain this
/// reader across retries in the same workload; its cursor belongs to that
/// logical generation. No filesystem socket name or other recipient is used.
pub struct CastWorkloadReader {
    socket: UnixDatagram,
    context: WorkloadCastContext,
    active: bool,
    receipt: Option<LocalDeliveryAck>,
    last: Option<(u64, MessageId, String)>,
}

/// Plain configuration conveyed by the original launcher together with the
/// workload descriptor. It does not confer a host role or verify peer identity.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCastContext {
    limits: MailboxLocalLimits,
    validity: std::ops::Range<i64>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl GuestCastEndpoint {
    /// The owner provides a verified original channel and its installed
    /// capacity. Both the host-facing decoder and workload path use the
    /// intersection with the signed limits.
    pub fn new(
        mut channel: CastChannel,
        installed: MailboxLocalLimits,
    ) -> io::Result<(Self, CastWorkloadReader)> {
        let limits = channel
            .narrow_guest_limits(installed)
            .map_err(io::Error::other)?;
        let inbox = channel.inbox();
        let context = WorkloadCastContext {
            limits,
            validity: channel.guest_validity(),
        };
        let (workload, socket) = UnixDatagram::pair()?;
        for end in [&workload, &socket] {
            end.set_write_timeout(Some(crate::mailbox_outbox::MAILBOX_IO_TIMEOUT))?;
            end.set_read_timeout(Some(crate::mailbox_outbox::MAILBOX_IO_TIMEOUT))?;
        }
        Ok((
            Self {
                channel,
                inbox,
                workload,
                offered: false,
                limits,
            },
            CastWorkloadReader {
                socket,
                context,
                active: false,
                receipt: None,
                last: None,
            },
        ))
    }

    /// Original PID 1 launch path. Queue context on the private socket before a
    /// Cast can be offered, and give the one workload descriptor to the launcher.
    #[cfg(target_os = "linux")]
    pub fn prepare_original_worker(
        channel: CastChannel,
        installed: MailboxLocalLimits,
    ) -> io::Result<(Self, OwnedFd)> {
        let (endpoint, reader) = Self::new(channel, installed)?;
        let (fd, context) = reader.into_launch_fd()?;
        exec::queue_context(&endpoint.workload, &context)?;
        Ok((endpoint, fd))
    }

    /// The installed listener supplies an accepted descriptor. Verify the
    /// actual vsock family, host CID, canonical local port and socket type
    /// before reading any bytes. Never use the greeting to authorize the peer.
    #[cfg(target_os = "linux")]
    pub fn receive_on_host_port(&mut self, fd: OwnedFd) -> io::Result<()> {
        use nix::sys::socket::{
            SockType as SocketType, VsockAddr, getpeername, getsockname, getsockopt,
            sockopt::SockType,
        };
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let peer: VsockAddr = getpeername(fd.as_raw_fd())?;
        let local: VsockAddr = getsockname(fd.as_raw_fd())?;
        if peer.cid() != crate::vsock::HOST_CID
            || local.port() != mvm_contract::protocol::mailbox::MAILBOX_PORT
            || getsockopt(&fd, SockType)? != SocketType::Stream
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "expected original host mailbox port",
            ));
        }
        let mut stream = UnixStream::from(fd);
        crate::vsock::run_with_stream_deadline(
            &mut stream,
            std::time::Instant::now() + crate::mailbox_outbox::MAILBOX_IO_TIMEOUT,
            |stream| {
                Ok(self.channel.receive_on(
                    stream,
                    || chrono::Utc::now().timestamp_millis(),
                    &mut self.inbox,
                )?)
            },
        )
        .map_err(io::Error::other)
    }

    /// Offer the oldest unread Cast. The inbox stays full across a failed
    /// callback, timeout, stale receipt or truncated packet. Host admission
    /// and this local handoff have distinct acknowledgments.
    pub fn offer_to_workload(&mut self) -> io::Result<bool> {
        self.inbox
            .consume_with(|item| {
                let now = chrono::Utc::now().timestamp_millis();
                if !self.offered
                    && (!self.channel.guest_validity().contains(&now)
                        || now >= item.expires_at_unix_ms)
                {
                    return Err(invalid("expired Cast cannot be offered to workload"));
                }
                offer(&self.workload, &self.limits, item, &mut self.offered)
            })
            .map(|consumed| consumed.is_some())
    }
}

fn send(socket: &UnixDatagram, bytes: &[u8]) -> io::Result<()> {
    let accepted = socket.send(bytes)?;
    #[cfg(test)]
    tests::record_write(accepted);
    if accepted != bytes.len() {
        return Err(invalid("incomplete workload datagram"));
    }
    Ok(())
}

fn offer(
    socket: &UnixDatagram,
    limits: &MailboxLocalLimits,
    delivery: &LocalDelivery,
    offered: &mut bool,
) -> io::Result<()> {
    // One write credit per original inbox item, including across timeouts.
    if !*offered {
        let framed = encode_local_frame(
            &LocalFrame::Deliver(Box::new(delivery.clone())),
            LocalRole::Deliver,
            LocalDirection::HostToGuest,
            limits,
        )
        .map_err(io::Error::other)?;
        send(socket, &framed)?;
        *offered = true;
    }
    // A canonical DeliveryAck is fixed-size: prefix, opcode, sequence, ID,
    // disposition. One extra byte detects silent datagram truncation.
    let mut buf = [0; 4 + 1 + 8 + 32 + 1 + 1];
    let len = socket.recv(&mut buf)?;
    #[cfg(test)]
    tests::ACK_READ.with(|count| count.set(count.get() + len));
    let ack = decode_local_frame(
        &buf[..len],
        LocalRole::Deliver,
        LocalDirection::GuestToHost,
        limits,
    )
    .map_err(io::Error::other)?;
    match ack {
        LocalFrame::DeliveryAck(ack)
            if ack.message_id == delivery.message_id
                && ack.delivery_sequence == delivery.delivery_sequence =>
        {
            *offered = false;
            if ack.disposition == LocalInboxDisposition::Accepted {
                Ok(())
            } else {
                Err(invalid("workload refused original Cast"))
            }
        }
        _ => Err(invalid("workload did not accept this original Cast")),
    }
}

impl CastWorkloadReader {
    /// Transfer a fresh workload endpoint across exec using the admitted
    /// launcher's descriptor handoff. An existing cursor must stay in place.
    pub fn into_launch_fd(self) -> io::Result<(OwnedFd, WorkloadCastContext)> {
        if self.active {
            return Err(invalid("workload generation already active"));
        }
        Ok((self.socket.into(), self.context))
    }

    /// Called by the original workload with its inherited descriptor and
    /// admitted limits. This reconstructs no host, guest, or routing authority.
    pub fn from_launch_fd(fd: OwnedFd, context: WorkloadCastContext) -> io::Result<Self> {
        context.limits.validate().map_err(io::Error::other)?;
        if context.validity.is_empty() {
            return Err(invalid("invalid workload Cast validity"));
        }
        let socket = UnixDatagram::from(fd);
        if !socket.local_addr()?.is_unnamed()
            || !socket.peer_addr()?.is_unnamed()
            || !is_datagram(&socket)?
        {
            return Err(invalid("expected original anonymous workload datagram"));
        }
        socket.set_read_timeout(Some(crate::mailbox_outbox::MAILBOX_IO_TIMEOUT))?;
        socket.set_write_timeout(Some(crate::mailbox_outbox::MAILBOX_IO_TIMEOUT))?;
        Ok(Self {
            socket,
            context,
            active: false,
            receipt: None,
            last: None,
        })
    }

    /// Supply the exact Cast to the workload and send its local receipt only
    /// after the callback succeeds. An identical retry re-ACKs without a
    /// second callback. If the callback applies an effect and returns an error,
    /// a retry may apply it again. No crash journal or processing receipt exists.
    pub fn receive_with(
        &mut self,
        consume: impl FnOnce(&LocalDelivery) -> io::Result<()>,
    ) -> io::Result<bool> {
        self.active = true;
        let max = self.context.limits.max_frame_bytes as usize + 4;
        let mut bytes = vec![0; max + 1];
        let len = self.socket.recv(&mut bytes)?;
        if len > max {
            return Err(invalid("oversize workload frame"));
        }
        bytes.truncate(len);
        let LocalFrame::Deliver(item) = decode_local_frame(
            &bytes,
            LocalRole::Deliver,
            LocalDirection::HostToGuest,
            &self.context.limits,
        )
        .map_err(io::Error::other)?
        else {
            return Err(invalid("expected Cast delivery"));
        };
        if item.kind != MailboxMessageKind::Cast {
            return Err(invalid("expected Cast delivery"));
        }
        let digest = mvm_core::crypto::image_verify::sha256_generated_bytes(&bytes)?;
        let key = (item.delivery_sequence, item.message_id, digest);
        let duplicate = self.last.as_ref() == Some(&key);
        if !duplicate {
            let next = self
                .last
                .as_ref()
                .map_or(Some(1), |(n, _, _)| n.checked_add(1));
            if next != Some(item.delivery_sequence)
                || self
                    .last
                    .as_ref()
                    .is_some_and(|(_, id, _)| *id == item.message_id)
            {
                return Err(invalid(
                    "conflicting or out-of-order original workload Cast",
                ));
            }
            let now = chrono::Utc::now().timestamp_millis();
            if !self.context.validity.contains(&now) || now >= item.expires_at_unix_ms {
                self.record_verdict(
                    item.delivery_sequence,
                    item.message_id,
                    LocalInboxDisposition::Expired,
                )?;
                return Err(invalid("expired Cast cannot be read by workload"));
            }
            if let Err(error) = consume(&item) {
                self.record_verdict(
                    item.delivery_sequence,
                    item.message_id,
                    LocalInboxDisposition::Unavailable,
                )?;
                return Err(error);
            }
            self.last = Some(key);
        }
        self.record_verdict(
            item.delivery_sequence,
            item.message_id,
            LocalInboxDisposition::Accepted,
        )?;
        Ok(!duplicate)
    }

    /// Recover an ambiguous positive or negative local receipt on the same
    /// original reader without resending the body or rerunning its callback.
    pub fn repeat_last_verdict(&self) -> io::Result<()> {
        let ack = self
            .receipt
            .clone()
            .ok_or_else(|| invalid("no local verdict to repeat"))?;
        let ack = LocalFrame::DeliveryAck(ack);
        let bytes = encode_local_frame(
            &ack,
            LocalRole::Deliver,
            LocalDirection::GuestToHost,
            &self.context.limits,
        )
        .map_err(io::Error::other)?;
        send(&self.socket, &bytes)
    }
    fn record_verdict(
        &mut self,
        seq: u64,
        id: MessageId,
        disposition: LocalInboxDisposition,
    ) -> io::Result<()> {
        self.receipt = Some(LocalDeliveryAck {
            delivery_sequence: seq,
            message_id: id,
            disposition,
        });
        self.repeat_last_verdict()
    }
}

fn is_datagram(socket: &UnixDatagram) -> io::Result<bool> {
    let socket = socket2::SockRef::from(socket);
    Ok(socket.local_addr()?.domain() == socket2::Domain::UNIX
        && socket.peer_addr()?.domain() == socket2::Domain::UNIX
        && socket.r#type()? == socket2::Type::DGRAM)
}

#[cfg(test)]
mod tests;
