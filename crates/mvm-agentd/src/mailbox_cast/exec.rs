//! One private Cast datagram alongside the ordinary application pipes.
//! The launcher creates it only after checking the original enrollment.
use super::{CastWorkloadReader, WorkloadCastContext};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::process::Command;

const SELECTOR: &str = "MVM_ORIGINAL_CAST_FD_V1";
const FLAG: &str = "--mvm-original-cast-fd-v1";
const BOOTSTRAP_MAX: usize = 1024;

/// Registered *after* the normal close-all hook. Holding the original through
/// spawn prevents descriptor reuse between configuration and the child's exec.
pub fn inherit_original_in_child(command: &mut Command, original: OwnedFd) -> io::Result<()> {
    if original.as_raw_fd() < 3 {
        return Err(io::Error::other(
            "Cast descriptor aliases application stdio",
        ));
    }
    // SAFETY: only fcntl runs in the forked child. OwnedFd remains captured by
    // the command and its parent descriptor never has CLOEXEC cleared.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(original.as_raw_fd(), libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

pub(crate) fn configure_worker(command: &mut Command, fd: OwnedFd) -> io::Result<()> {
    command.arg(FLAG).arg(fd.as_raw_fd().to_string());
    inherit_original_in_child(command, fd)
}

/// Local origin check for the supplemental descriptor. Only PID 1 owns the
/// agent end. Neither this check nor a descriptor selector admits a host role.
pub fn validate_original_parent(fd: BorrowedFd<'_>) -> io::Result<()> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let peer = getsockopt(&fd, PeerCredentials)?;
    if peer.pid() != 1 || unsafe { libc::getppid() } != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Cast descriptor has no original PID 1 peer",
        ));
    }
    let socket = UnixDatagram::from(fd.try_clone_to_owned()?);
    if !super::is_datagram(&socket)?
        || !socket.local_addr()?.is_unnamed()
        || !socket.peer_addr()?.is_unnamed()
    {
        return Err(io::Error::other("expected a private connected datagram"));
    }
    Ok(())
}

// Taking ownership of arbitrary numbers from argv/environment is unsound:
// another library may already own them. A CLOEXEC duplicate gives this call
// its own custody. The source number closes on the next successful exec.
fn duplicate_inherited(raw: RawFd) -> io::Result<OwnedFd> {
    if raw < 3 {
        return Err(io::Error::other("invalid Cast descriptor"));
    }
    // SAFETY: fcntl validates the input number; success allocates a fresh fd.
    let cloned = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if cloned < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(cloned) })
}

/// Called only by the OCI wrapper, after image environment configuration and
/// the normal close-all hook. An image-provided selector cannot survive.
pub fn configure_oci(
    command: &mut Command,
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> io::Result<()> {
    command.env_remove(SELECTOR);
    let Some(first) = args.next() else {
        return Ok(());
    };
    if first != FLAG {
        return Err(io::Error::other("unexpected OCI wrapper argument"));
    }
    let raw: RawFd = args
        .next()
        .and_then(|x| x.into_string().ok())
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| io::Error::other("missing original Cast descriptor"))?;
    if args.next().is_some() {
        return Err(io::Error::other("extra OCI wrapper argument"));
    }
    let fd = duplicate_inherited(raw)?;
    validate_original_parent(fd.as_fd())?;
    command.env(SELECTOR, fd.as_raw_fd().to_string());
    inherit_original_in_child(command, fd)
}

/// Application API. The number only locates a descriptor: the original kernel
/// peer and the private launcher's first bounded datagram supply its context.
pub fn original_workload_reader() -> io::Result<CastWorkloadReader> {
    let raw: RawFd = std::env::var(SELECTOR)
        .ok()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| io::Error::other("no original Cast descriptor"))?;
    let fd = duplicate_inherited(raw)?;
    validate_original_parent(fd.as_fd())?;
    // SAFETY: the source is the already validated inherited descriptor. Restoring
    // CLOEXEC prevents it from leaking when the admitted process execs again.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = UnixDatagram::from(fd);
    socket.set_read_timeout(Some(crate::mailbox_outbox::MAILBOX_IO_TIMEOUT))?;
    let mut packet = [0; BOOTSTRAP_MAX + 1];
    let n = socket.recv(&mut packet)?;
    if n > BOOTSTRAP_MAX {
        return Err(io::Error::other("Cast bootstrap exceeds bound"));
    }
    let context: WorkloadCastContext = serde_json::from_slice(&packet[..n])?;
    CastWorkloadReader::from_launch_fd(socket.into(), context)
}

pub(super) fn queue_context(
    socket: &UnixDatagram,
    context: &WorkloadCastContext,
) -> io::Result<()> {
    let packet = serde_json::to_vec(context)?;
    if packet.len() > BOOTSTRAP_MAX || socket.send(&packet)? != packet.len() {
        return Err(io::Error::other("original Cast bootstrap send failed"));
    }
    Ok(())
}
