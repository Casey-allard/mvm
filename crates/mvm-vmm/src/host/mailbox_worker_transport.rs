//! Inactive worker-owner IPC foundation. Use only a verified private canonical
//! tenant-control connection and a previously verified signed request.
//! This transports data and one pipe writer; it does not establish child custody.
use mvm_core::protocol::broker_control::ControlResponse;
use mvm_core::protocol::mailbox_worker_control::{
    MAX_WORKER_CONTROL_BYTES, MailboxWorkerRequest, MailboxWorkerResult, MailboxWorkerState,
    verify_result,
};
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::net::UnixStream,
    time::Instant,
};
const MARKER: u8 = 0x4d;
const CONTROL_WORDS: usize = 32;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn remaining(deadline: Instant) -> io::Result<std::time::Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "worker control deadline"))
}
fn ready(fd: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let duration = remaining(deadline)?;
        let ms = duration.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, borrowed descriptor remains live.
        let n = unsafe { libc::poll(&mut p, 1, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        remaining(deadline)?;
        if n > 0 {
            return Ok(());
        }
    }
}
fn peer(stream: &UnixStream) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let uid = {
        // SAFETY: correctly sized ucred and socklen output live for call.
        let mut cred: libc::ucred = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if len as usize != mem::size_of_val(&cred) {
            return Err(invalid("invalid peer credentials"));
        }
        cred.uid
    };
    #[cfg(not(target_os = "linux"))]
    let uid = {
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: valid output pointers and borrowed Unix socket.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        uid
    };
    // SAFETY: geteuid has no pointer arguments or ownership effects.
    if uid != 0 && uid != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "foreign worker control peer",
        ));
    }
    Ok(())
}
fn pipe_writer(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: stat points to initialized writable storage; fd remains owned.
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_GETFL takes no third argument and does not consume fd.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFIFO || flags & libc::O_ACCMODE != libc::O_WRONLY {
        return Err(invalid("delegation requires anonymous pipe writer"));
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: fstatfs observes this same live descriptor; anonymous pipes
        // belong to kernel pipefs, unlike filesystem FIFOs (even unlinked ones).
        let mut filesystem: libc::statfs = unsafe { mem::zeroed() };
        if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if filesystem.f_type != 0x5049_5045
        /* Linux uapi/linux/magic.h: PIPEFS_MAGIC */
        {
            return Err(invalid("delegated FIFO is not kernel pipefs"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "anonymous pipe provenance requires qualified platform primitive",
        ))
    }
}
fn prepare_received(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl operates on a live owned descriptor; preserves prior flags.
    let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(io::Error::last_os_error());
    }
    pipe_writer(fd)?;
    // SAFETY: F_GETFL/F_SETFL retain prior open-file-description flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn send_chunk(
    stream: &UnixStream,
    bytes: &[u8],
    fd: Option<&OwnedFd>,
    deadline: Instant,
) -> io::Result<usize> {
    loop {
        ready(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        let mut control = [0usize; CONTROL_WORDS];
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zeroed msghdr is valid before assigning all used fields.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd {
            msg.msg_control = control.as_mut_ptr().cast();
            // SAFETY: aligned fixed control buffer exceeds CMSG_SPACE(one int).
            unsafe {
                msg.msg_controllen = libc::CMSG_SPACE(mem::size_of::<RawFd>() as _) as _;
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as _) as _;
                libc::CMSG_DATA(c)
                    .cast::<RawFd>()
                    .write_unaligned(fd.as_raw_fd());
            }
        }
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::MSG_DONTWAIT;
        // SAFETY: iovec and optional cmsghdr point to live initialized storage.
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, flags) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(e);
        }
        remaining(deadline)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "worker control write zero",
            ));
        }
        return Ok(n as usize);
    }
}
/// Consumes the daemon's writer copy even on error. The caller must retain the
/// original Child/credit and run owned cleanup after any uncertain handoff.
pub fn send_response(
    stream: &mut UnixStream,
    result: &MailboxWorkerResult,
    fd: Option<OwnedFd>,
    deadline: Instant,
) -> io::Result<()> {
    peer(stream)?;
    remaining(deadline)?;
    if result.delegates_config != fd.is_some() {
        return Err(invalid("worker descriptor count disagrees with result"));
    }
    if fd.is_some() && !matches!(result.state, MailboxWorkerState::Starting) {
        return Err(invalid("only Starting can delegate config"));
    }
    if let Some(ref fd) = fd {
        pipe_writer(fd)?
    }
    let body = serde_json::to_vec(&ControlResponse::MailboxWorkerV1(Box::new(result.clone())))
        .map_err(invalid_encoding)?;
    if body.is_empty() || body.len() > MAX_WORKER_CONTROL_BYTES {
        return Err(invalid("worker frame length"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let one: libc::c_int = 1;
        // SAFETY: correct scalar buffer for SO_NOSIGPIPE; borrowed socket live.
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&one as *const libc::c_int).cast(),
                mem::size_of_val(&one) as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    send_chunk(stream, &[MARKER], fd.as_ref(), deadline)?;
    drop(fd);
    let len = (body.len() as u32).to_be_bytes();
    for bytes in [&len[..], &body[..]] {
        let mut offset = 0;
        while offset < bytes.len() {
            offset += send_chunk(stream, &bytes[offset..], None, deadline)?
        }
    }
    Ok(())
}
fn invalid_encoding(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
/// Reads with recvmsg throughout, including JSON: ancillary rights smuggled on
/// later bytes are refused and closed instead of silently discarded by read().
fn receive_chunk(
    stream: &UnixStream,
    bytes: &mut [u8],
    allow_rights: bool,
    deadline: Instant,
) -> io::Result<(usize, Option<OwnedFd>)> {
    loop {
        ready(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        let mut control = [0usize; CONTROL_WORDS];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zeroed msghdr, all active pointers assigned to bounded buffers.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as _;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::MSG_DONTWAIT;
        // SAFETY: kernel may write only the bounded iovec/control areas.
        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, flags) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(e);
        }
        let mut received = Vec::<OwnedFd>::new();
        let mut bad = msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
        let size = msg.msg_controllen as usize;
        let capacity = mem::size_of_val(&control);
        if size > capacity {
            bad = true
        }
        let mut offset = 0usize;
        // Parse every rights record before returning errors so all installed FDs
        // enter RAII custody. Kernel-generated cmsg headers are still bounded.
        while offset + mem::size_of::<libc::cmsghdr>() <= size.min(capacity) {
            // SAFETY: offset checked within aligned fixed buffer; unaligned read
            // avoids depending on platform-specific cmsghdr alignment.
            let c = unsafe {
                control
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<libc::cmsghdr>()
                    .read_unaligned()
            };
            let header = unsafe { libc::CMSG_LEN(0) } as usize;
            #[allow(
                clippy::unnecessary_cast,
                reason = "cmsg_len is socklen_t on Darwin and usize on Linux"
            )]
            let length = c.cmsg_len as usize;
            if length < header || length > size.min(capacity) - offset {
                bad = true;
                break;
            }
            if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_RIGHTS {
                let payload = length - header;
                if !payload.is_multiple_of(mem::size_of::<RawFd>()) {
                    bad = true
                }
                for i in 0..payload / mem::size_of::<RawFd>() {
                    // SAFETY: complete integer within this validated cmsg;
                    // recvmsg transferred ownership of each installed FD.
                    let raw = unsafe {
                        control
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset + header + i * mem::size_of::<RawFd>())
                            .cast::<RawFd>()
                            .read_unaligned()
                    };
                    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
                    if prepare_received(&fd).is_err() {
                        bad = true
                    }
                    received.push(fd);
                }
            } else {
                bad = true
            }
            let aligned = unsafe { libc::CMSG_SPACE((length - header) as _) } as usize;
            if aligned == 0 {
                bad = true;
                break;
            }
            offset += aligned;
        }
        remaining(deadline)?;
        if bad || received.len() > 1 || (!allow_rights && !received.is_empty()) {
            return Err(invalid("invalid worker ancillary data"));
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "worker control EOF",
            ));
        }
        return Ok((n as usize, received.pop()));
    }
}
fn receive_exact(stream: &UnixStream, bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        offset += receive_chunk(stream, &mut bytes[offset..], false, deadline)?.0
    }
    Ok(())
}
/// The original request must already be host-verified; trust the original private
/// daemon connection, never a path/response/PID supplied by an untrusted peer.
pub fn recv_response(
    stream: &mut UnixStream,
    request: &MailboxWorkerRequest,
    deadline: Instant,
) -> io::Result<(MailboxWorkerResult, Option<OwnedFd>)> {
    peer(stream)?;
    let mut marker = [0];
    let (_, fd) = receive_chunk(stream, &mut marker, true, deadline)?;
    if marker[0] != MARKER {
        return Err(invalid("worker control marker"));
    }
    let mut len = [0; 4];
    receive_exact(stream, &mut len, deadline)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_WORKER_CONTROL_BYTES {
        return Err(invalid("worker frame length"));
    }
    let mut body = vec![0; len];
    receive_exact(stream, &mut body, deadline)?;
    let response: ControlResponse = serde_json::from_slice(&body).map_err(invalid_encoding)?;
    let ControlResponse::MailboxWorkerV1(result) = response else {
        return Err(invalid("unexpected legacy response in worker control"));
    };
    let result = *result;
    verify_result(request, &result).map_err(|_| invalid("worker response correlation"))?;
    if result.delegates_config != fd.is_some() {
        return Err(invalid("worker descriptor count disagrees with result"));
    }
    Ok((result, fd))
}
