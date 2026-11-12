//! Addressed ingress for one original destination helper. Legacy mailbox
//! commands and data clients are not recognized on this socket.
use super::owned_wire::{DeadlineStream, OwnedStatusV1, write_status};
use crate::mailbox_launch::{
    DerivedMailboxKeys,
    cast_pair::development::{EndpointRole, InstalledDirection, destination::DestinationRole},
};
use mvm_contract::protocol::mailbox::local::LocalInboxDisposition;
use mvm_core::mailbox::{
    OpenContext, ReplayIdentity, ReplayProtector,
    frame::{self, Refusal},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::{Duration, Instant},
};

const TURN: Duration = Duration::from_secs(5);
const BODY: usize = crate::mailbox_process::installed_profile::PAIR_FRAME_BYTES;
const ENVELOPE: usize = crate::broker::mailbox_workers::cast_credit::CAST_BODY_LIMIT;
const RETAIN: usize = crate::mailbox_process::installed_profile::PAIR_REPLAY_ENTRIES as usize;

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "original Cast owner unavailable",
    )
}
fn fence(ctrl: &UnixStream, parent: u32) -> io::Result<()> {
    // SAFETY: getppid has no preconditions. Only poll the inherited FD.
    if unsafe { libc::getppid() } as u32 != parent {
        return Err(denied());
    }
    let mut p = libc::pollfd {
        fd: ctrl.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let n = unsafe { libc::poll(&mut p, 1, 0) };
        if n == 0 {
            return Ok(());
        }
        if n > 0 {
            return Err(denied());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}
fn original_peer(stream: &UnixStream, parent: u32) -> io::Result<()> {
    if mvm_vmm::host::uds_peer::connected_peer_pid(stream)?
        != i32::try_from(parent).map_err(|_| denied())?
    {
        return Err(denied());
    }
    Ok(())
}
fn bind(path: &Path) -> io::Result<UnixListener> {
    let dir = std::fs::symlink_metadata(path.parent().ok_or_else(denied)?)?;
    // SAFETY: geteuid has no preconditions.
    if !dir.is_dir() || dir.mode() & 0o022 != 0 || dir.uid() != unsafe { libc::geteuid() } {
        return Err(denied());
    }
    // An existing socket, including a live unrelated listener, is never taken
    // over. The original VM state directory owns removal at final teardown.
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    l.set_nonblocking(true)?;
    Ok(l)
}
fn bound_route(
    route: &mvm_core::vm_backend::HostDialRoute,
    deadline: Instant,
) -> io::Result<UnixStream> {
    use mvm_core::vm_backend::HostDialRoute;
    match route {
        HostDialRoute::PortSocket(p) => mvm_agentd::vsock::connect_unix_before(p, deadline),
        HostDialRoute::Mux(p) => mvm_agentd::vsock::connect_to_port_before(
            p.to_str().ok_or_else(denied)?,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
            deadline,
        ),
    }
    .map_err(io::Error::other)
}

struct LiveIo<'a> {
    io: DeadlineStream<'a>,
    ctrl: &'a UnixStream,
    parent: u32,
}
impl Read for LiveIo<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        fence(self.ctrl, self.parent)?;
        self.io.read(b)
    }
}
impl Write for LiveIo<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        fence(self.ctrl, self.parent)?;
        self.io.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        fence(self.ctrl, self.parent)?;
        self.io.flush()
    }
}
struct Trial<'a> {
    prior: &'a BTreeSet<ReplayIdentity>,
    new: Option<ReplayIdentity>,
}
impl ReplayProtector for Trial<'_> {
    fn check_and_record(&mut self, id: ReplayIdentity) -> bool {
        if self.new.is_some() || self.prior.contains(&id) {
            false
        } else {
            self.new = Some(id);
            true
        }
    }
}
#[derive(Default)]
struct History {
    ids: BTreeSet<ReplayIdentity>,
    accepted: BTreeSet<[u8; 32]>,
}
trait CurrentPolicy {
    fn sample(&self, role: &DestinationRole) -> io::Result<(OpenContext, OpenContext)>;
}
struct ImmutableOwner<'a> {
    control: &'a UnixStream,
    pid: u32,
}
impl CurrentPolicy for ImmutableOwner<'_> {
    fn sample(&self, role: &DestinationRole) -> io::Result<(OpenContext, OpenContext)> {
        fence(self.control, self.pid)?;
        role.policies(crate::mailbox_launch::now_unix_ms())
            .map_err(io::Error::other)
    }
}

enum TurnFailure {
    Definite(Refusal),
    Unknown(io::Error),
}
impl From<Refusal> for TurnFailure {
    fn from(r: Refusal) -> Self {
        Self::Definite(r)
    }
}
/// A terminal peer result is written by the caller only *after* this returns
/// and its body, decoded envelope and opened plaintext have gone out of scope.
fn deliver<R: Read, S: Read + Write>(
    r: &mut R,
    role: &DestinationRole,
    keys: &DerivedMailboxKeys,
    key: &InstalledDirection,
    history: &mut History,
    policy: &impl CurrentPolicy,
    dial: impl FnOnce() -> io::Result<S>,
) -> Result<(), TurnFailure> {
    let mut header = [0; 4];
    r.read_exact(&mut header).map_err(TurnFailure::Unknown)?;
    let len = u32::from_be_bytes(header) as usize;
    if !(5..=BODY).contains(&len) {
        return Err(Refusal::Oversized(BODY).into());
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(TurnFailure::Unknown)?;
    let cap_len = u32::from_be_bytes(body[..4].try_into().expect("bounded prefix")) as usize;
    let env_len = len
        .checked_sub(4)
        .and_then(|n| n.checked_sub(cap_len))
        .ok_or(Refusal::Malformed)?;
    if cap_len == 0 || env_len == 0 || env_len > ENVELOPE {
        return Err(Refusal::Malformed.into());
    }
    let (send, env) = frame::decode_frame(&body)?;
    let g = role.grants();
    if &send != g.send
        || mvm_core::mailbox::encode_envelope(&env).map_err(|_| Refusal::Malformed)?
            != body[len - env_len..]
        || serde_json::to_vec(&send).map_err(|_| Refusal::Malformed)? != body[4..4 + cap_len]
    {
        return Err(Refusal::Malformed.into());
    }
    let fingerprint: [u8; 32] = Sha256::digest(&body).into();
    drop(body);
    drop(send);
    let (a, b) = policy
        .sample(role)
        .map_err(|_| Refusal::Mailbox("current destination policy refused".into()))?;
    role.channel.authorize_addressed(g, &a, &b)?;
    if env.routing.expires_at_unix_ms <= b.now_unix_ms || !key.admits_routing(&env.routing) {
        return Err(Refusal::Mailbox("expired or changed original route".into()).into());
    }
    if history.accepted.contains(&fingerprint) {
        return Ok(());
    }
    if history.ids.len() >= RETAIN {
        return Err(Refusal::QueueFull(RETAIN).into());
    }
    let seq = u64::try_from(history.ids.len() + 1)
        .ok()
        .and_then(std::num::NonZeroU64::new)
        .ok_or(Refusal::Malformed)?;
    let mut trial = Trial {
        prior: &history.ids,
        new: None,
    };
    let proof = keys
        .open_original_cast(&role.channel, env, g, key, &a, &b, &mut trial, seq)
        .map_err(|_| Refusal::Mailbox("destination admission refused".into()))?;
    let replay = trial.new.ok_or(Refusal::Malformed)?;
    let mut guest = dial().map_err(|_| Refusal::Mailbox("original guest unavailable".into()))?;
    let sample = std::cell::OnceCell::new();
    let ack = proof
        .dispatch_on(&role.channel, &mut guest, || {
            let p = policy.sample(role)?;
            let (a, b) = sample.get_or_init(|| p);
            Ok((a, b))
        })
        .map_err(TurnFailure::Unknown)?;
    match ack.disposition {
        LocalInboxDisposition::Accepted => {
            history.ids.insert(replay);
            history.accepted.insert(fingerprint);
            Ok(())
        }
        LocalInboxDisposition::Full => Err(Refusal::QueueFull(1).into()),
        LocalInboxDisposition::Expired | LocalInboxDisposition::Unavailable => {
            Err(Refusal::Mailbox("guest did not accept Cast".into()).into())
        }
    }
}
pub(super) fn run(
    original: super::owned::BoundCastEndpoint<'_>,
    role: DestinationRole,
    control: &UnixStream,
    parent: u32,
    deadline: Instant,
) -> io::Result<crate::mailbox_service::guest_io::GuestStreamCounts> {
    fence(control, parent)?;
    let l = bind(&original.config.socket)?;
    let key = original
        .direction
        .installed(&role.direction, EndpointRole::Destination, &original.owner)
        .map_err(io::Error::other)?;
    write_status(
        control,
        &OwnedStatusV1::ReadyCastDestinationV1 {
            owner: original.owner.clone(),
            direction_commitment: role.direction.commitment(),
        },
        deadline,
    )?;
    let mut counts = crate::mailbox_service::guest_io::GuestStreamCounts::default();
    let mut history = History::default();
    let policy = ImmutableOwner {
        control,
        pid: parent,
    };
    loop {
        let mut fds = [control.as_raw_fd(), l.as_raw_fd()].map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 500) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds[0].revents != 0 {
            return Ok(counts);
        }
        fence(control, parent)?;
        if fds[1].revents == 0 {
            continue;
        }
        let incoming = match l.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };
        if original_peer(&incoming, parent).is_err() {
            continue;
        }
        let until = Instant::now() + TURN;
        let mut peer = LiveIo {
            io: DeadlineStream::new(&incoming, until),
            ctrl: control,
            parent,
        };
        let guest = std::cell::OnceCell::new();
        let verdict = match deliver(
            &mut peer,
            &role,
            &original.config.keys,
            key,
            &mut history,
            &policy,
            || {
                fence(control, parent)?;
                counts.dial();
                let s = bound_route(&original.config.route, until)
                    .inspect_err(|_| counts.failed_dial())?;
                let s = guest.get_or_init(|| s);
                Ok(crate::mailbox_service::guest_io::Measured::new(
                    LiveIo {
                        io: DeadlineStream::new(s, until),
                        ctrl: control,
                        parent,
                    },
                    &mut counts,
                ))
            },
        ) {
            Ok(()) => Ok(()),
            Err(TurnFailure::Definite(r)) => Err(r),
            // The guest may have accepted. No terminal verdict or second turn
            // under this owner; original collection fences the unknown work.
            Err(TurnFailure::Unknown(e)) => return Err(e),
        };
        serde_json::to_writer(&mut peer, &verdict).map_err(io::Error::other)?;
        peer.flush()?;
    }
}

#[cfg(test)]
pub(crate) fn qualify(
    role: &DestinationRole,
    keys: &DerivedMailboxKeys,
    key: &InstalledDirection,
    env: &mvm_contract::protocol::mailbox::MailboxEnvelope,
    original: &[u8],
) {
    use std::{cell::Cell, net::Shutdown};
    struct Current {
        samples: Cell<usize>,
        deny_after_first: bool,
    }
    impl CurrentPolicy for Current {
        fn sample(&self, role: &DestinationRole) -> io::Result<(OpenContext, OpenContext)> {
            let n = self.samples.get();
            self.samples.set(n + 1);
            let (a, mut b) = role
                .policies(crate::mailbox_launch::now_unix_ms())
                .map_err(io::Error::other)?;
            if self.deny_after_first && n > 0 {
                b.revoked_capabilities
                    .push(role.grants().receive.grant.revocation_id);
            }
            Ok((a, b))
        }
    }
    let frame = frame::encode_frame(role.grants().send, env).unwrap();
    let framed = |body: &[u8]| [(body.len() as u32).to_be_bytes().as_slice(), body].concat();
    let mut history = History::default();
    let current = Current {
        samples: Cell::new(0),
        deny_after_first: false,
    };
    let mut wrong = framed(&frame);
    wrong[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        deliver(
            &mut &wrong[..],
            role,
            keys,
            key,
            &mut history,
            &current,
            || -> io::Result<UnixStream> { panic!("refused input dialed the guest") }
        ),
        Err(TurnFailure::Definite(_))
    ));
    let (mut client, mut peer) = UnixStream::pair().unwrap();
    let (host, mut guest) = UnixStream::pair().unwrap();
    for s in [&client, &peer, &host, &guest] {
        s.set_read_timeout(Some(TURN)).unwrap();
        s.set_write_timeout(Some(TURN)).unwrap();
    }
    let start = Instant::now();
    std::thread::scope(|threads| {
        let remote = threads.spawn(|| {
            let mut inbox = role.channel.inbox();
            role.channel
                .receive_on(&mut guest, crate::mailbox_launch::now_unix_ms, &mut inbox)
                .unwrap();
            inbox
                .consume_with(|v| Ok::<_, ()>(v.body.clone()))
                .unwrap()
                .unwrap()
        });
        let source = threads.spawn(|| {
            let result = frame::strict_peer_verdict(&mut client, &frame).unwrap();
            assert!(result.is_ok());
        });
        let ok = deliver(&mut peer, role, keys, key, &mut history, &current, || {
            Ok(host)
        });
        assert!(ok.is_ok());
        let reply = serde_json::to_vec(&Result::<(), Refusal>::Ok(())).unwrap();
        peer.write_all(&reply).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        source.join().unwrap();
        assert_eq!(remote.join().unwrap(), original);
        eprintln!(
            "ORIGINAL_DESTINATION_COMPONENT payload={} framed_bytes_written={} verdict_bytes_read={} receive_through_join_ns={}",
            original.len(),
            frame.len() + 4,
            reply.len(),
            start.elapsed().as_nanos()
        );
    });
    assert_eq!(current.samples.get(), 2);
    let same = framed(&frame);
    assert!(
        deliver(
            &mut same.as_slice(),
            role,
            keys,
            key,
            &mut history,
            &current,
            || -> io::Result<UnixStream> { panic!("duplicate redelivered") }
        )
        .is_ok()
    );
    assert_eq!(history.accepted.len(), 1);
    let blocked = Current {
        samples: Cell::new(0),
        deny_after_first: true,
    };
    let mut fresh = History::default();
    let (h, mut guest) = UnixStream::pair().unwrap();
    guest.set_read_timeout(Some(TURN)).unwrap();
    std::thread::scope(|threads| {
        let r = threads.spawn(|| {
            let mut inbox = role.channel.inbox();
            assert!(
                role.channel
                    .receive_on(&mut guest, crate::mailbox_launch::now_unix_ms, &mut inbox)
                    .is_err()
            );
            assert!(inbox.take().is_none());
        });
        let denied = deliver(
            &mut same.as_slice(),
            role,
            keys,
            key,
            &mut fresh,
            &blocked,
            || Ok(h),
        );
        assert!(matches!(denied, Err(TurnFailure::Unknown(_))));
        r.join().unwrap();
    });
    assert_eq!(blocked.samples.get(), 2);
    assert!(fresh.ids.is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_socket_and_unrelated_process_identity_cannot_be_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mailbox.sock");
        let first = bind(&p).unwrap();
        assert!(bind(&p).is_err());
        let c = UnixStream::connect(&p).unwrap();
        let (s, _) = first.accept().unwrap();
        original_peer(&s, std::process::id()).unwrap();
        assert!(original_peer(&s, std::process::id() + 1).is_err());
        drop(c);
    }
}
