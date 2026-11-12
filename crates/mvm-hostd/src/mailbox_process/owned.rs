//! The mailbox worker's private bootstrap and lifetime channel.
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use super::owned_wire::{OwnedStatusV1, read_prepare, write_status};
use crate::mailbox_launch::{LAUNCH_LIMITS, ServePaths, serve_owned_with_counts};

use mvm_vmm::host::mailbox_worker_transport::MAX_CONFIG_BYTES as INPUT_LIMIT;

fn inherited_control() -> io::Result<UnixStream> {
    // Duplicate only a descriptor the kernel confirms is open. Invoking the
    // helper directly without the installed owner's FD 3 must fail cleanly.
    let fd = unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 4) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new descriptor owned by this call.
    let socket = UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
    // FD 3 was made inheritable for the one exec into this helper.
    // SAFETY: only the close-on-exec flag of the still-open original changes.
    if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // A connected local stream socket is the only supported capability.
    let mut kind: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: getsockopt writes at most the size of kind to its valid address.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut address_len = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: the buffer is long enough for every native socket address.
    if unsafe { libc::getpeername(fd, address.as_mut_ptr().cast(), &mut address_len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the whole buffer started zeroed and getpeername succeeded.
    let family = unsafe { address.assume_init() }.ss_family as libc::c_int;
    if kind != libc::SOCK_STREAM || family != libc::AF_UNIX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a private Unix stream",
        ));
    }
    socket.set_nonblocking(false)?;
    Ok(socket)
}

fn config_input(
    input: &mut (impl Read + AsFd),
    control: &UnixStream,
    deadline: Instant,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the supplied stat buffer on success.
    if unsafe { libc::fstat(input.as_fd().as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a config pipe",
        ));
    }
    let mut config = Zeroizing::new(Vec::with_capacity(INPUT_LIMIT));
    let mut chunk = Zeroizing::new([0_u8; 4096]);
    let mut pollfds = [input.as_fd().as_raw_fd(), control.as_raw_fd()].map(|fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    });
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // SAFETY: both entries refer to live descriptors for the entire poll.
        let result = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                2,
                left.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfds[1].revents != 0 {
            return Err(io::Error::other(
                "mailbox owner closed or sent unexpected input",
            ));
        }
        if pollfds[0].revents == 0 {
            continue;
        }
        let count = match input.read(&mut *chunk) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if count == 0 {
            return Ok(config);
        }
        if count > INPUT_LIMIT - config.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mailbox config exceeds limit",
            ));
        }
        config.extend_from_slice(&chunk[..count]);
    }
}

/// Serve a canonical mailbox under its original parent's exclusive control.
/// EOF is the lifetime fence, including while config is still being written.
pub fn run(lease: mvm_vmm::host::installed_owner::HolderLease) -> io::Result<()> {
    run_profile(lease, false)
}
pub fn run_profile(
    _lease: mvm_vmm::host::installed_owner::HolderLease,
    paired: bool,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut control = inherited_control()?;
    let prepare = read_prepare(&control, deadline)?;
    let report = crate::mailbox_service::guest_io::inherited_report_socket()?;
    let start = || -> io::Result<_> {
        let raw = config_input(&mut std::io::stdin().lock(), &control, deadline)?;
        let config = super::parse(&raw)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mailbox config"))?;
        drop(raw);
        // Acquire only from the original helper's inherited Prepare and the
        // approved, delegated configuration. Legacy launch consumes its keys.
        let original = BoundCastEndpoint::from_original(&prepare, config, &_lease)?;
        let config = original.config;
        serve_owned_with_counts(
            config.grant,
            config.keys,
            ServePaths {
                socket: config.socket,
                route: config.route,
            },
            if paired {
                super::installed_profile::pair_queue_limits()
            } else {
                LAUNCH_LIMITS
            },
            report.is_some(),
            paired.then_some(super::installed_profile::PAIR_REPLAY_ENTRIES),
        )
    };
    let launch = match start() {
        Ok(launch) => launch,
        Err(error) => {
            let _ = write_status(
                &control,
                &OwnedStatusV1::Failed {
                    owner: prepare.owner,
                },
                deadline,
            );
            return Err(error);
        }
    };
    write_status(
        &control,
        &OwnedStatusV1::Ready {
            owner: prepare.owner.clone(),
        },
        deadline,
    )?;
    let mut byte = [0];
    let closed = loop {
        match control.read(&mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) => break Err(io::Error::other("unexpected mailbox owner command")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(e),
        }
    };
    let counts = launch.shutdown_with_counts()?;
    closed?;
    if let (Some(socket), Some(counts)) = (report, counts) {
        if let Err(error) =
            crate::mailbox_service::guest_io::send_original(&socket, &prepare.owner, counts)
        {
            tracing::warn!(%error, "guest stream measurement unavailable after helper shutdown");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn owned_config_is_bounded_and_requires_eof() {
        for length in [INPUT_LIMIT, INPUT_LIMIT + 1] {
            let (mut reader, mut writer) = io::pipe().unwrap();
            let (_owner, control) = UnixStream::pair().unwrap();
            let sender = std::thread::spawn(move || writer.write_all(&vec![7; length]));
            let result = config_input(
                &mut reader,
                &control,
                Instant::now() + Duration::from_secs(1),
            );
            drop(reader);
            sender.join().unwrap().unwrap();
            if length == INPUT_LIMIT {
                assert_eq!(result.unwrap().as_slice(), &[7; INPUT_LIMIT]);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn owner_eof_interrupts_open_config_pipe() {
        let (mut reader, _writer) = io::pipe().unwrap();
        let (owner, control) = UnixStream::pair().unwrap();
        drop(owner);
        let error = config_input(
            &mut reader,
            &control,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn stalled_config_hits_original_deadline() {
        let (mut reader, _writer) = io::pipe().unwrap();
        let (_owner, control) = UnixStream::pair().unwrap();
        let error = config_input(
            &mut reader,
            &control,
            Instant::now() + Duration::from_millis(10),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}

/// This endpoint token can only be constructed within the worker process's
/// validated inherited-control launch path. It cannot be manufactured by the
/// control-plane router, and its plaintext never leaves this endpoint module.
pub struct BoundCastEndpoint<'lease> {
    owner: mvm_contract::protocol::mailbox_worker::MailboxWorkerOwner,
    config: super::MailboxProcessConfig,
    _lease: &'lease mvm_vmm::host::installed_owner::HolderLease,
}
impl<'lease> BoundCastEndpoint<'lease> {
    fn from_original(
        prepare: &super::owned_wire::PrepareOwnedV1,
        config: super::MailboxProcessConfig,
        lease: &'lease mvm_vmm::host::installed_owner::HolderLease,
    ) -> io::Result<Self> {
        // SAFETY: getppid has no preconditions.
        prepare.validate(&config, unsafe { libc::getppid() } as u32)?;
        Ok(Self {
            owner: prepare.owner.clone(),
            config,
            _lease: lease,
        })
    }

    /// Open only under the receiver's retained original keys. This is a
    /// destination operation; the worker's approved ingress must authenticate
    /// the routed request and supply both current policy views, sequence and
    /// original replay owner. ReliableV1 activation still uses the canonical
    /// installation gate in PrepareOwnedV1::validate.
    pub fn open_addressed<'turn>(
        &'turn self,
        routed: &'turn crate::mailbox_launch::cast_pair::RoutedCast<'turn>,
        source: &mvm_core::mailbox::OpenContext,
        destination: &mvm_core::mailbox::OpenContext,
        replay: &mut impl mvm_core::mailbox::ReplayProtector,
        sequence: std::num::NonZeroU64,
    ) -> io::Result<BoundOpenedCast<'turn>> {
        let channel = routed.channel();
        if self.config.grant.local_service.is_none()
            || !channel.is_bounded_destination(
                &self.config.grant,
                crate::broker::mailbox_workers::cast_credit::CAST_BODY_LIMIT,
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong original addressed Cast endpoint",
            ));
        }
        let input = routed
            .for_original_destination(&self.owner, source, destination)
            .map_err(io::Error::other)?;
        let (a, b) = routed
            .policies(source, destination)
            .map_err(io::Error::other)?;
        let proof = self.config.keys.open_original_cast(
            channel,
            input.envelope.clone(),
            input.grants,
            &a,
            &b,
            replay,
            sequence,
        )?;
        Ok(BoundOpenedCast {
            proof,
            routed,
            endpoint: self,
        })
    }
}

/// Rust ownership keeps the coordinator credit AND original holder lease alive
/// alongside the verified plaintext until actual handoff or explicit discard.
/// Crossing processes requires a protected original-credit protocol; one
/// cannot serialize this in-process object or release its credit early.
pub struct BoundOpenedCast<'turn> {
    proof: mvm_core::mailbox::frame::cast::route::AddressedVerifiedCast,
    routed: &'turn crate::mailbox_launch::cast_pair::RoutedCast<'turn>,
    endpoint: &'turn BoundCastEndpoint<'turn>,
}
impl BoundOpenedCast<'_> {
    /// Private until the original worker's authenticated backend role stream is
    /// wired. The public coordinator cannot substitute an arbitrary writer.
    #[allow(dead_code)]
    fn deliver_on_original_stream<'a>(
        &'a self,
        stream: &mut (impl std::io::Read + std::io::Write),
        policy: impl FnOnce() -> io::Result<(
            &'a mvm_core::mailbox::OpenContext,
            &'a mvm_core::mailbox::OpenContext,
        )>,
    ) -> io::Result<mvm_contract::protocol::mailbox::local::LocalDeliveryAck> {
        let sample = std::cell::OnceCell::new();
        self.proof.dispatch_on(self.routed.channel(), stream, || {
            let (source, dest) = policy()?;
            self.routed
                .for_original_destination(&self.endpoint.owner, source, dest)
                .map_err(io::Error::other)?;
            let (a, b) = self
                .routed
                .policies(source, dest)
                .map_err(io::Error::other)?;
            let current = sample.get_or_init(|| (a, b));
            Ok((&current.0, &current.1))
        })
    }
}
