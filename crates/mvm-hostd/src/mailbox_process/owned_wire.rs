//! Private FD3 control for the original parent and its owned mailbox child.
//! One big-endian u32 byte length precedes each JSON document. A failed
//! transfer may have consumed a partial frame: discard that session.

use super::MailboxProcessConfig;
use mvm_contract::protocol::{mailbox::MailboxGrant, mailbox_worker::MailboxWorkerOwner};
use mvm_core::vm_backend::HostDialRoute;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{self, Cursor, Error, ErrorKind, Read, Write};
use std::os::{fd::AsRawFd, unix::net::UnixStream};
use std::path::PathBuf;
use std::time::Instant;

const FRAME_LIMIT: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareOwnedV1 {
    pub owner: MailboxWorkerOwner,
    pub grant: MailboxGrant,
    pub socket: PathBuf,
    pub route: HostDialRoute,
    pub vm_state_dir: PathBuf,
    pub expected_parent: u32,
}

impl PrepareOwnedV1 {
    pub fn validate(&self, config: &MailboxProcessConfig, actual_parent: u32) -> io::Result<()> {
        self.validate_binding(config,actual_parent)?;
        self.grant.require_implemented_local_service().map_err(|e|Error::new(ErrorKind::Unsupported,e))
    }

    pub(super) fn validate_binding(&self,config:&MailboxProcessConfig,actual_parent:u32)->io::Result<()>{
        let same_route = match (&self.route, &config.route) {
            (HostDialRoute::PortSocket(a), HostDialRoute::PortSocket(b))
            | (HostDialRoute::Mux(a), HostDialRoute::Mux(b)) => a.as_os_str() == b.as_os_str(),
            _ => false,
        };
        if self.expected_parent == 0
            || self.expected_parent != actual_parent
            || self.grant != config.grant
            || !same_route
            || self.vm_state_dir.as_os_str() != config.vm_state_dir.as_os_str()
            || self.socket.as_os_str() != config.socket.as_os_str()
            || self.socket.as_os_str()
                != mvm_core::config::vm_mailbox_socket_at(&self.vm_state_dir).as_os_str()
        {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "owned mailbox config mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", deny_unknown_fields)]
pub enum OwnedStatusV1 {
    Ready {
        owner: MailboxWorkerOwner,
    },
    /// The helper has exclusively bound the addressed ingress. Emit only
    /// after selecting the dedicated authenticated parent-only handler.
    ReadyCastSourceV1 {
        owner: MailboxWorkerOwner,
        direction_commitment: [u8; 32],
    },
    ReadyCastDestinationV1 {
        owner: MailboxWorkerOwner,
        direction_commitment: [u8; 32],
    },
    Failed {
        owner: MailboxWorkerOwner,
    },
}

// The entry mode selects v1; direction fixes the expected document type.
pub fn read_prepare(stream: &UnixStream, deadline: Instant) -> io::Result<PrepareOwnedV1> {
    read_frame(stream, deadline)
}

pub fn write_prepare(
    stream: &UnixStream,
    prepare: &PrepareOwnedV1,
    deadline: Instant,
) -> io::Result<()> {
    write_frame(stream, prepare, deadline)
}

pub fn write_status(
    stream: &UnixStream,
    status: &OwnedStatusV1,
    deadline: Instant,
) -> io::Result<()> {
    write_frame(stream, status, deadline)
}

pub fn read_ready(
    stream: &UnixStream,
    owner: &MailboxWorkerOwner,
    deadline: Instant,
) -> io::Result<()> {
    match validate_status(read_frame(stream, deadline)?, owner)? {
        ReadyIngress::Legacy => Ok(()),
        ReadyIngress::CastSource(_) | ReadyIngress::CastDestination(_) => Err(Error::new(
            ErrorKind::PermissionDenied,
            "expected legacy readiness",
        )),
    }
}
/// Poll one framed status on the broker's nonblocking socket. Preserve a
/// partial header/body across Query calls until a complete status is available.
pub(crate) fn poll_ready(
    stream: &mut UnixStream,
    pending: &mut Vec<u8>,
    owner: &MailboxWorkerOwner,
) -> io::Result<Option<ReadyIngress>> {
    use std::io::Read;
    let mut chunk = [0u8; 512];
    loop {
        let end = if pending.len() < 4 {
            4
        } else {
            let size = u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
            if size == 0 || size > FRAME_LIMIT {
                return Err(ErrorKind::InvalidData.into());
            }
            4 + size
        };
        if pending.len() == end {
            let status =
                serde_json::from_slice(&pending[4..]).map_err(|_| ErrorKind::InvalidData)?;
            return validate_status(status, owner).map(Some);
        }
        let left = (end - pending.len()).min(chunk.len());
        match stream.read(&mut chunk[..left]) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadyIngress {
    Legacy,
    CastDestination([u8; 32]),
    CastSource([u8; 32]),
}
fn validate_status(status: OwnedStatusV1, owner: &MailboxWorkerOwner) -> io::Result<ReadyIngress> {
    match status {
        OwnedStatusV1::Ready { owner: received } if received == *owner => Ok(ReadyIngress::Legacy),
        OwnedStatusV1::ReadyCastSourceV1 { owner: received, direction_commitment }
            if received == *owner && direction_commitment != [0; 32] => {
                Ok(ReadyIngress::CastSource(direction_commitment))
            }
        OwnedStatusV1::ReadyCastDestinationV1 {
            owner: received,
            direction_commitment,
        } if received == *owner && direction_commitment != [0; 32] => {
            Ok(ReadyIngress::CastDestination(direction_commitment))
        }
        OwnedStatusV1::Failed { owner: received } if received == *owner => {
            Err(Error::other("owned helper failed"))
        }
        _ => Err(Error::new(
            ErrorKind::PermissionDenied,
            "owned helper status mismatch",
        )),
    }
}

fn read_frame<T: DeserializeOwned>(s: &UnixStream, deadline: Instant) -> io::Result<T> {
    let mut header = [0; 4];
    let mut stream = DeadlineStream::new(s, deadline);
    stream.read_exact(&mut header)?;
    let n = u32::from_be_bytes(header) as usize;
    if n == 0 || n > FRAME_LIMIT {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid control frame size",
        ));
    }
    let mut bytes = [0; FRAME_LIMIT];
    stream.read_exact(&mut bytes[..n])?;
    serde_json::from_slice(&bytes[..n])
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid control frame"))
}

fn write_frame<T: Serialize>(s: &UnixStream, value: &T, deadline: Instant) -> io::Result<()> {
    let mut bytes = [0; 4 + FRAME_LIMIT];
    let mut body = Cursor::new(&mut bytes[4..]);
    serde_json::to_writer(&mut body, value).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            "control frame cannot be encoded within bound",
        )
    })?;
    let n = body.position() as usize;
    bytes[..4].copy_from_slice(&(n as u32).to_be_bytes());
    DeadlineStream::new(s, deadline).write_all(&bytes[..4 + n])
}

/// Use the existing bounded control I/O on a separate, already connected
/// data socket without creating a watchdog thread or changing its FD flags.
pub(crate) struct DeadlineStream<'a> {
    socket: &'a UnixStream,
    deadline: Instant,
}
impl<'a> DeadlineStream<'a> {
    pub(crate) fn new(socket: &'a UnixStream, deadline: Instant) -> Self {
        Self { socket, deadline }
    }
}
impl Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        attempt(self.socket, libc::POLLIN, self.deadline, || {
            // SAFETY: the borrowed socket and writable buffer stay live.
            unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            }
        })
    }
}
impl Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        attempt(self.socket, libc::POLLOUT, self.deadline, || {
            // SAFETY: the borrowed socket and readable buffer stay live.
            unsafe {
                libc::send(
                    self.socket.as_raw_fd(),
                    buf.as_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            }
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Per-call nonblocking I/O also works on blocking descriptors. No socket
// option or descriptor flag is changed for another owner of the socket.
fn attempt(
    s: &UnixStream,
    events: libc::c_short,
    deadline: Instant,
    mut op: impl FnMut() -> isize,
) -> io::Result<usize> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(ErrorKind::TimedOut.into());
        }
        let n = op();
        if n >= 0 {
            return Ok(n as usize);
        }
        match Error::last_os_error() {
            e if e.kind() == ErrorKind::Interrupted => continue,
            e if e.kind() == ErrorKind::WouldBlock => {}
            e => return Err(e),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let ms = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: s.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: poll points to one valid entry and the borrowed FD stays live.
        if unsafe { libc::poll(&mut poll, 1, ms) } < 0 {
            let e = Error::last_os_error();
            if e.kind() != ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId};
    use std::io::Write;
    use std::net::Shutdown;
    use std::time::Duration;

    fn owner() -> MailboxWorkerOwner {
        MailboxWorkerOwner {
            daemon_boot_nonce: [1; 32],
            lease: [2; 32],
            generation: 7,
            context_commitment: [3; 32],
        }
    }
    fn until() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[test]
    fn config_binds_to_original_parent_grant_paths_and_backend_route() {
        let keys = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(keys.path()).unwrap();
        let state = tempfile::tempdir().unwrap();
        let mailbox = MailboxId::from_bytes([5; 32]);
        let epoch = ExecutionEpoch::new(1).unwrap();
        let grant = MailboxGrant {
            mailbox,
            epoch,
            authority_key: crate::mailbox_launch::authority_key_for(keys.path(), &mailbox, epoch)
                .unwrap()
                .to_bytes(),
            local_service: None,
        };
        let route = HostDialRoute::Mux(state.path().join("vsock.sock"));
        let config =
            super::super::build_config(keys.path(), &grant, state.path(), route.clone()).unwrap();
        let prepare = PrepareOwnedV1 {
            owner: owner(),
            grant,
            socket: config.socket.clone(),
            route,
            vm_state_dir: state.path().to_owned(),
            expected_parent: 27,
        };
        let (a, b) = UnixStream::pair().unwrap();
        write_prepare(&a, &prepare, until()).unwrap();
        let mut received = read_prepare(&b, until()).unwrap();
        received.validate(&config, 27).unwrap();
        assert!(received.validate(&config, 28).is_err());
        received.grant.epoch = ExecutionEpoch::new(2).unwrap();
        assert!(received.validate(&config, 27).is_err());
        received.grant = grant;
        received.route = HostDialRoute::PortSocket(state.path().join("vsock.sock"));
        assert!(received.validate(&config, 27).is_err());
        received.route = config.route.clone();
        received.socket.push("other");
        assert!(received.validate(&config, 27).is_err());
        received.socket = config.socket.clone();
        received.vm_state_dir.push(".");
        assert!(received.validate(&config, 27).is_err());
    }

    #[test]
    fn ready_requires_the_original_tuple_and_success_status() {
        let (a, b) = UnixStream::pair().unwrap();
        write_status(&a, &OwnedStatusV1::Ready { owner: owner() }, until()).unwrap();
        read_ready(&b, &owner(), until()).unwrap();
        let mut foreign = owner();
        foreign.lease[0] ^= 1;
        write_status(&a, &OwnedStatusV1::Ready { owner: foreign }, until()).unwrap();
        assert_eq!(
            read_ready(&b, &owner(), until()).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        write_status(&a, &OwnedStatusV1::Failed { owner: owner() }, until()).unwrap();
        assert!(read_ready(&b, &owner(), until()).is_err());
    }

    #[test]
    fn private_status_rejects_extra_or_duplicate_fields() {
        let owner_json = serde_json::to_string(&owner()).unwrap();
        for body in [
            format!(r#"{{"status":"Ready","owner":{owner_json},"extra":true}}"#),
            format!(r#"{{"status":"Ready","owner":{owner_json},"owner":{owner_json}}}"#),
        ] {
            let (mut a, b) = UnixStream::pair().unwrap();
            a.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
            a.write_all(body.as_bytes()).unwrap();
            assert_eq!(
                read_ready(&b, &owner(), until()).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn stalled_parent_write_honors_its_deadline() {
        let (mut sender, _receiver) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        let pad = [0_u8; 4096];
        loop {
            match sender.write(&pad) {
                Ok(n) => assert!(n > 0),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("filling control socket: {e}"),
            }
        }
        let deadline = Instant::now() + Duration::from_millis(25);
        assert_eq!(
            write_status(&sender, &OwnedStatusV1::Ready { owner: owner() }, deadline)
                .unwrap_err()
                .kind(),
            ErrorKind::TimedOut
        );
    }

    #[test]
    fn truncated_oversized_and_partial_control_frames_fail_closed() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&4097u32.to_be_bytes()).unwrap();
        assert_eq!(
            read_ready(&b, &owner(), until()).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&8u32.to_be_bytes()).unwrap();
        a.write_all(b"{").unwrap();
        let deadline = Instant::now() + Duration::from_millis(25);
        assert_eq!(
            read_ready(&b, &owner(), deadline).unwrap_err().kind(),
            ErrorKind::TimedOut
        );
        a.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            read_ready(&b, &owner(), until()).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}
