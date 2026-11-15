//! Safe pipe observations shared by original owned-helper startup paths.
//!
//! A live read pipe is an admission observation only. EOF never proves Child
//! collection, successful cleanup or permission to refund a reservation.
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{FileType, OFlags},
    io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd},
};
use std::{
    io::{self, Read},
    os::fd::{AsFd, OwnedFd},
    process::ChildStdout,
    time::Instant,
};

fn pipe_mode(fd: impl AsFd, mode: OFlags) -> io::Result<()> {
    let stat = rustix::fs::fstat(fd.as_fd())?;
    let flags = rustix::fs::fcntl_getfl(fd.as_fd())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Fifo || flags & OFlags::ACCMODE != mode {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "owned liveness pipe mode required",
        ));
    }
    Ok(())
}

/// Validate this process's actual stdout writer before keys, threads or Ready.
/// It remains this process's writer; no duplicate or numeric FD is constructed.
pub fn prepare_stdout_writer() -> io::Result<()> {
    let stdout = io::stdout();
    pipe_mode(stdout.as_fd(), OFlags::WRONLY)?;
    fcntl_setfd(
        stdout.as_fd(),
        fcntl_getfd(stdout.as_fd())? | FdFlags::CLOEXEC,
    )?;
    Ok(())
}

/// Duplicate an already-held readonly pipe as an observation, never authority.
pub fn duplicate_read_pipe(fd: impl AsFd) -> io::Result<OwnedFd> {
    pipe_mode(fd.as_fd(), OFlags::RDONLY)?;
    Ok(fcntl_dupfd_cloexec(fd.as_fd(), 3)?)
}

/// Nonconsuming check: data, EOF, HUP, errors and ambiguity are all refusal.
pub fn require_live_read_pipe(fd: impl AsFd) -> io::Result<()> {
    pipe_mode(fd.as_fd(), OFlags::RDONLY)?;
    let mut events = [PollFd::new(&fd, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    match poll(&mut events, Some(&timeout)) {
        Ok(0) if events[0].revents().is_empty() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "owned liveness pipe fenced",
        )),
        Err(error) => Err(error.into()),
    }
}

fn remaining(deadline: Instant) -> io::Result<Timespec> {
    let duration = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    Timespec::try_from(duration).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn read_exact_until(
    stdout: &mut ChildStdout,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let timeout = remaining(deadline)?;
        let mut events = [PollFd::new(&*stdout, PollFlags::IN)];
        match poll(&mut events, Some(&timeout)) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
            Ok(_)
                if events[0]
                    .revents()
                    .intersects(PollFlags::ERR | PollFlags::NVAL) =>
            {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        remaining(deadline)?;
        match stdout.read(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    remaining(deadline)?;
    Ok(())
}

/// Read only the existing bounded length/body startup frame, with no read-ahead.
/// JSON, nonce, original Child and parent validation remain caller-owned.
pub fn read_ready_frame(stdout: &mut ChildStdout, deadline: Instant) -> io::Result<Vec<u8>> {
    remaining(deadline)?;
    pipe_mode(stdout.as_fd(), OFlags::RDONLY)?;
    let flags = rustix::fs::fcntl_getfl(stdout.as_fd())?;
    rustix::fs::fcntl_setfl(stdout.as_fd(), flags | OFlags::NONBLOCK)?;
    let mut header = [0; 4];
    read_exact_until(stdout, &mut header, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if !(1..=256).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owned readiness length refused",
        ));
    }
    remaining(deadline)?;
    let mut body = vec![0; length];
    read_exact_until(stdout, &mut body, deadline)?;
    Ok(body)
}
