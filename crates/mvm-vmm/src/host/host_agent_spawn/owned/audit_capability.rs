//! Private version-one original-process observation handoff. No authority or
//! process-exit/cleanup receipt can be constructed from these descriptors.

use rustix::event::{PollFd, PollFlags, Timespec, poll};
#[cfg(target_os = "linux")]
use rustix::{
    io::{FdFlags, fcntl_getfd, fcntl_setfd},
    net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg},
};
use std::{
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use std::{io::IoSliceMut, mem::MaybeUninit};

#[cfg(target_os = "linux")]
const SIDEBAND_V1: u8 = 0xA1;

/// Native compatibility only; never a permission or resource grant.
pub(crate) fn require_supported_platform() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        darwin::require_supported_platform()
    }
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// This is deliberately private. An arbitrary received descriptor is not an
/// original-process capability; only the retained registration may bind it.
#[cfg(target_os = "linux")]
pub(crate) fn receive_signer_event(stream: &UnixStream, deadline: Instant) -> io::Result<OwnedFd> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        let timeout = Timespec::try_from(remaining)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut ready = [PollFd::new(stream, PollFlags::IN)];
        match poll(&mut ready, Some(&timeout)) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
            Ok(_) if ready[0].revents().contains(PollFlags::NVAL) => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }

        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }

        // One rights header only. Alignment padding can admit a second fd on
        // some platforms, so count rights rather than trusting this capacity.
        // Rustix owns/drains every received right on every rejection path.
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut byte = [0];
        let flags = RecvFlags::DONTWAIT;
        #[cfg(target_os = "linux")]
        let flags = flags | RecvFlags::CMSG_CLOEXEC;
        let message = match recvmsg(
            stream,
            &mut [IoSliceMut::new(&mut byte)],
            &mut control,
            flags,
        ) {
            Ok(message) => message,
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => continue,
            Err(error) => return Err(error.into()),
        };
        let mut descriptor = None;
        let mut rights = 0usize;
        let mut unexpected = false;
        for message in control.drain() {
            match message {
                RecvAncillaryMessage::ScmRights(fds) => {
                    for fd in fds {
                        rights += 1;
                        if descriptor.is_none() {
                            descriptor = Some(fd);
                        }
                        // All additional owned fd values drop here.
                    }
                }
                _ => unexpected = true,
            }
        }
        if message.bytes != 1
            || byte[0] != SIDEBAND_V1
            || rights != 1
            || unexpected
            || message
                .flags
                .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original signer sideband refused",
            ));
        }
        let descriptor = descriptor.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        // Also required on Darwin; no inherited copy escapes this private
        // receipt before CLOEXEC has been restored.
        fcntl_setfd(&descriptor, fcntl_getfd(&descriptor)? | FdFlags::CLOEXEC)?;
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        return Ok(descriptor);
    }
}

#[cfg(target_os = "macos")]
#[path = "audit_capability/darwin.rs"]
mod darwin;

#[cfg(target_os = "macos")]
pub(crate) fn receive_signer_event(stream: &UnixStream, deadline: Instant) -> io::Result<OwnedFd> {
    require_supported_platform()?;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        let timeout = Timespec::try_from(remaining)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut ready = [PollFd::new(stream, PollFlags::IN)];
        match poll(&mut ready, Some(&timeout)) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
            Ok(_) if ready[0].revents().contains(PollFlags::NVAL) => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        match darwin::receive_now(stream) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            received => {
                let descriptor = received?;
                require_live_event(&descriptor)?;
                if Instant::now() >= deadline {
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
                return Ok(descriptor);
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn receive_signer_event(
    _stream: &UnixStream,
    _deadline: Instant,
) -> io::Result<OwnedFd> {
    // Executed Darwin qualification: kqueue SCM_RIGHTS returns EINVAL and
    // pinned Rustix's truncated ancillary drain can panic. Refuse BEFORE I/O;
    // no PID-only or generic descriptor fallback is admitted.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "original audit capability transport unsupported",
    ))
}

/// Poll only: consuming kevent would erase Darwin's independent exit event.
pub(crate) fn require_live_event(fd: impl AsFd) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let stat = rustix::fs::fstat(fd.as_fd())?;
        let flags = rustix::fs::fcntl_getfl(fd.as_fd())?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Fifo
            || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original liveness read pipe required",
            ));
        }
    }
    let timeout = Timespec::try_from(Duration::ZERO)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut events = [PollFd::new(&fd, PollFlags::IN)];
    match poll(&mut events, Some(&timeout)) {
        Ok(0) if events[0].revents().is_empty() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "original audit liveness observation refused",
        )),
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "audit_capability_tests.rs"]
mod tests;
