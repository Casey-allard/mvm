//! Opt-in installed-helper witness for the guest-facing mailbox stream.
//! A single joined dial thread owns one fixed-size snapshot per helper.
use mvm_core::protocol::mailbox_worker_control::MailboxWorkerOwner;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixDatagram;

/// A trusted test launcher supplies one end of an anonymous connected Unix
/// datagram socketpair as coordinator stdout. No path is opened by the helper.
pub const ENABLE_ENV: &str = "MVM_WITNESS_OWNED_MAILBOX_IO_V1";
pub const SCOPE: &str = "mvm/owned-mailbox/guest-5257/post-mux-host-stream/v1";
const MAX_REPORT: usize = 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestStreamCounts {
    pub guest_to_host_read_bytes: u64,
    pub host_to_guest_write_accepted_bytes: u64,
    pub dial_attempts: u64,
    pub failed_dials: u64,
    pub zero_data_connections: u64,
    pub read_errors: u64,
    pub write_errors: u64,
    pub overflow: bool,
}

fn add(value: &mut u64, n: u64, overflow: &mut bool) {
    match value.checked_add(n) {
        Some(next) => *value = next,
        None => {
            *value = u64::MAX;
            *overflow = true;
        }
    }
}

impl GuestStreamCounts {
    pub(super) fn dial(&mut self) {
        add(&mut self.dial_attempts, 1, &mut self.overflow);
    }
    pub(super) fn failed_dial(&mut self) {
        add(&mut self.failed_dials, 1, &mut self.overflow);
    }
    pub(super) fn empty_connection(&mut self) {
        add(&mut self.zero_data_connections, 1, &mut self.overflow);
    }
}

pub(super) struct Measured<'a, S> {
    stream: S,
    counts: &'a mut GuestStreamCounts,
    moved_bytes: bool,
}
impl<'a, S> Measured<'a, S> {
    pub(super) fn new(stream: S, counts: &'a mut GuestStreamCounts) -> Self {
        Self {
            stream,
            counts,
            moved_bytes: false,
        }
    }
}
impl<S> Drop for Measured<'_, S> {
    fn drop(&mut self) {
        if !self.moved_bytes {
            self.counts.empty_connection();
        }
    }
}
impl<S: Read> Read for Measured<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.stream.read(buf);
        match &result {
            Ok(n) if *n > 0 => {
                self.moved_bytes = true;
                add(
                    &mut self.counts.guest_to_host_read_bytes,
                    *n as u64,
                    &mut self.counts.overflow,
                );
            }
            Err(e) if e.kind() != io::ErrorKind::Interrupted => {
                add(&mut self.counts.read_errors, 1, &mut self.counts.overflow)
            }
            _ => {}
        }
        result
    }
}
impl<S: Write> Write for Measured<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = self.stream.write(buf);
        match &result {
            Ok(n) if *n > 0 => {
                self.moved_bytes = true;
                add(
                    &mut self.counts.host_to_guest_write_accepted_bytes,
                    *n as u64,
                    &mut self.counts.overflow,
                );
            }
            Ok(0) if !buf.is_empty() => {
                add(&mut self.counts.write_errors, 1, &mut self.counts.overflow)
            }
            Err(e) if e.kind() != io::ErrorKind::Interrupted => {
                add(&mut self.counts.write_errors, 1, &mut self.counts.overflow)
            }
            _ => {}
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn original_tag(owner: &MailboxWorkerOwner) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"mvm/owned-mailbox/guest-io/original/v1\0");
    h.update(owner.daemon_boot_nonce);
    h.update(owner.generation.to_be_bytes());
    h.update(owner.lease);
    h.update(owner.context_commitment);
    h.finalize().into()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    original: [u8; 32],
    counts: GuestStreamCounts,
}
fn invalid(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

pub(crate) fn inherited_report_socket() -> io::Result<Option<UnixDatagram>> {
    if std::env::var_os(ENABLE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return Ok(None);
    }
    let fd: OwnedFd = std::io::stdout().as_fd().try_clone_to_owned()?;
    if rustix::net::sockopt::socket_type(&fd)? != rustix::net::SocketType::DGRAM {
        return Err(invalid("expected private witness datagram"));
    }
    let socket = UnixDatagram::from(fd);
    if !socket.local_addr()?.is_unnamed() || !socket.peer_addr()?.is_unnamed() {
        return Err(invalid("expected anonymous witness socketpair"));
    }
    socket.set_nonblocking(true)?;
    Ok(Some(socket))
}
pub(crate) fn send_original(
    socket: &UnixDatagram,
    owner: &MailboxWorkerOwner,
    counts: GuestStreamCounts,
) -> io::Result<()> {
    let raw = serde_json::to_vec(&Receipt {
        version: 1,
        original: original_tag(owner),
        counts,
    })?;
    if raw.len() > MAX_REPORT || socket.send(&raw)? != raw.len() {
        return Err(invalid("incomplete guest IO witness report"));
    }
    Ok(())
}

/// Called after signed collection of the expected helper and coordinator drain.
pub fn receive_original(
    socket: &UnixDatagram,
    owner: &MailboxWorkerOwner,
) -> io::Result<GuestStreamCounts> {
    socket.set_nonblocking(true)?;
    let mut buf = [0u8; MAX_REPORT + 1];
    let size = socket.recv(&mut buf)?;
    if size > MAX_REPORT {
        return Err(invalid("oversize guest IO witness report"));
    }
    let receipt: Receipt = serde_json::from_slice(&buf[..size])?;
    if receipt.version != 1 || receipt.original != original_tag(owner) || receipt.counts.overflow {
        return Err(invalid("invalid original or overflowing guest IO report"));
    }
    let next = socket.recv(&mut buf);
    // Darwin reports one ECONNRESET once all queued datagrams have been
    // consumed and the original writer is closed. Only after receipt
    // validation, clear that notification and still require an empty queue.
    #[cfg(target_os = "macos")]
    let next = match next {
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => socket.recv(&mut buf),
        result => result,
    };
    match next {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(receipt.counts),
        Err(e) => Err(e),
        Ok(_) => Err(invalid("duplicate guest IO report")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Scripted {
        reads: VecDeque<io::Result<usize>>,
        writes: VecDeque<io::Result<usize>>,
    }
    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = self.reads.pop_front().expect("unexpected read")?;
            buf[..count].fill(0);
            Ok(count)
        }
    }
    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let count = self.writes.pop_front().expect("unexpected write")?;
            assert!(count <= buf.len());
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn owner(n: u8) -> MailboxWorkerOwner {
        MailboxWorkerOwner {
            generation: 1,
            daemon_boot_nonce: [1; 32],
            lease: [n; 32],
            context_commitment: [3; 32],
        }
    }

    #[test]
    fn measured_guest_stream_preserves_partial_io_errors_eof_and_isolation() {
        let mut totals = GuestStreamCounts::default();
        totals.dial();
        totals.failed_dial();
        totals.dial();
        let partial = Scripted {
            reads: [
                Ok(2),
                Err(io::ErrorKind::Interrupted.into()),
                Ok(1),
                Err(io::ErrorKind::ConnectionReset.into()),
            ]
            .into(),
            writes: [
                Ok(1),
                Err(io::ErrorKind::Interrupted.into()),
                Ok(2),
                Err(io::ErrorKind::BrokenPipe.into()),
            ]
            .into(),
        };
        let mut stream = Measured::new(partial, &mut totals);
        assert_eq!(
            stream.read_exact(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            stream.write_all(&[0; 4]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(stream);
        totals.dial();
        let mut empty = Measured::new(
            Scripted {
                reads: [Ok(0)].into(),
                writes: [Ok(0)].into(),
            },
            &mut totals,
        );
        assert_eq!(empty.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(
            empty.write_all(&[1]).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        drop(empty);
        assert_eq!(
            totals,
            GuestStreamCounts {
                guest_to_host_read_bytes: 3,
                host_to_guest_write_accepted_bytes: 3,
                dial_attempts: 3,
                failed_dials: 1,
                zero_data_connections: 1,
                read_errors: 1,
                write_errors: 2,
                overflow: false
            }
        );
        let mut next_session = GuestStreamCounts::default();
        assert_eq!(next_session.guest_to_host_read_bytes, 0);
        next_session.guest_to_host_read_bytes = u64::MAX - 1;
        assert_eq!(
            Measured::new(&b"xx"[..], &mut next_session)
                .read(&mut [0; 2])
                .unwrap(),
            2
        );
        assert!(next_session.overflow);
        assert_eq!(next_session.guest_to_host_read_bytes, u64::MAX);
        assert!(!totals.overflow);
    }
    #[test]
    fn original_report_after_writer_exit_distinguishes_missing_single_and_duplicate() {
        let original = owner(7);
        for sent in 0..=2 {
            let (tx, rx) = UnixDatagram::pair().unwrap();
            let totals = GuestStreamCounts {
                guest_to_host_read_bytes: 37,
                ..Default::default()
            };
            for _ in 0..sent {
                send_original(&tx, &original, totals.clone()).unwrap();
            }
            drop(tx);
            let result = receive_original(&rx, &original);
            match sent {
                1 => assert_eq!(result.unwrap(), totals),
                _ => assert!(result.is_err()),
            }
        }
    }

    #[test]
    fn report_datagram_requires_one_complete_original_nonoverflowing_session() {
        let (writer, reader) = UnixDatagram::pair().unwrap();
        let a = owner(4);
        let b = owner(5);
        let counts = GuestStreamCounts {
            guest_to_host_read_bytes: 203,
            ..GuestStreamCounts::default()
        };
        send_original(&writer, &a, counts.clone()).unwrap();
        assert_eq!(receive_original(&reader, &a).unwrap(), counts);
        assert_eq!(
            receive_original(&reader, &a).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        send_original(&writer, &b, counts.clone()).unwrap();
        assert!(receive_original(&reader, &a).is_err());
        send_original(
            &writer,
            &a,
            GuestStreamCounts {
                overflow: true,
                ..counts.clone()
            },
        )
        .unwrap();
        assert!(receive_original(&reader, &a).is_err());
        writer.send(&[0; MAX_REPORT + 2]).unwrap();
        assert!(receive_original(&reader, &a).is_err());
        send_original(&writer, &a, counts.clone()).unwrap();
        send_original(&writer, &a, counts).unwrap();
        assert!(receive_original(&reader, &a).is_err());
    }
}
