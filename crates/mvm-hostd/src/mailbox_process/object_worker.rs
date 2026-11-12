//! Transfer both held Firecracker process descriptors on the original helper's private stdin
//! socket. The subsequent role bootstrap binds each descriptor to its original PID and birth.
use crate::mailbox_launch::object_pair::bootstrap::ObjectWorkerBootstrapV1;
use anyhow::{Context, Result, ensure};
use mvm_vmm::host::network_endpoint_spawn::EndpointPid;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, BorrowedFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const TAG: [u8; 1] = [1];

fn before_deadline<T>(until: Instant, mut io: impl FnMut() -> rustix::io::Result<T>) -> Result<T> {
    loop {
        let left = until
            .checked_duration_since(Instant::now())
            .context("object helper handoff timed out")?;
        match io() {
            Ok(value) => return Ok(value),
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::AGAIN) => std::thread::sleep(left.min(Duration::from_millis(2))),
            Err(e) => return Err(e.into()),
        }
    }
}

pub(crate) fn send_originals(
    channel: &UnixStream,
    originals: [BorrowedFd<'_>; 2],
    until: Instant,
) -> Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    ensure!(
        control.push(SendAncillaryMessage::ScmRights(&originals)),
        "object worker rights buffer"
    );
    let n = before_deadline(until, || {
        sendmsg(
            channel,
            &[IoSlice::new(&TAG)],
            &mut control,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
    })?;
    ensure!(n == TAG.len(), "incomplete original handle handoff");
    Ok(())
}

pub(crate) struct Originals([OwnedFd; 2]);

pub(crate) fn receive_originals(channel: &UnixStream, until: Instant) -> Result<Originals> {
    let mut tag = [0];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = before_deadline(until, || {
        recvmsg(
            channel,
            &mut [IoSliceMut::new(&mut tag)],
            &mut control,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        )
    })?;
    ensure!(
        msg.bytes == 1
            && tag == TAG
            && !msg
                .flags
                .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC),
        "missing or truncated original worker handoff"
    );
    let mut messages = control.drain();
    let Some(RecvAncillaryMessage::ScmRights(mut fds)) = messages.next() else {
        anyhow::bail!("missing original VMM handles");
    };
    let pair = Originals([
        fds.next().context("missing caller VMM handle")?,
        fds.next().context("missing callee VMM handle")?,
    ]);
    ensure!(
        fds.next().is_none() && messages.next().is_none(),
        "extra original worker control data"
    );
    Ok(pair)
}

impl Originals {
    pub(crate) fn require_live(&self, originals: [EndpointPid; 2]) -> Result<()> {
        ensure!(
            originals[0].pid != originals[1].pid,
            "original VM handles must be distinct"
        );
        for (handle, original) in self.0.iter().zip(originals) {
            ensure!(
                original.pid > 1 && original.started.is_some(),
                "invalid original VMM identity"
            );
            let info =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{}", handle.as_raw_fd()))?;
            // The kernel reports -1 here after the original process dies.
            let pid = info
                .lines()
                .find_map(|l| l.strip_prefix("Pid:"))
                .and_then(|v| v.trim().parse::<i32>().ok());
            ensure!(
                pid == Some(original.pid) && original.is_live_and_ours(),
                "original VMM identity changed"
            );
            require_running(handle)?;
            // SAFETY: signal zero checks this held pidfd without delivering a signal.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    0,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("original VMM handle no longer live");
            }
        }
        Ok(())
    }
}

fn require_running(fd: &OwnedFd) -> Result<()> {
    let mut watched = [PollFd::new(fd, PollFlags::IN)];
    ensure!(
        poll(&mut watched, Some(&Timespec::default()))? == 0,
        "original process has exited"
    );
    Ok(())
}

// Two separately signed plans (1 MiB apiece), role, enrollment and local credentials.
const MAX_CONFIG: usize = 3 * 1024 * 1024;

fn read_body(channel: &UnixStream, cap: usize, until: Instant) -> Result<Zeroizing<Vec<u8>>> {
    // Allocate once so old copies of secret bytes cannot survive a reallocation.
    let mut bytes = Zeroizing::new(vec![0; cap + 1]);
    let mut used = 0;
    loop {
        let n = before_deadline(until, || {
            rustix::net::recv(channel, &mut bytes[used..], RecvFlags::DONTWAIT).map(|(_, n)| n)
        })?;
        if n == 0 {
            break;
        }
        used += n;
        ensure!(used <= cap, "oversized original object worker bootstrap");
    }
    ensure!(used > 0, "missing original object worker bootstrap");
    bytes.truncate(used);
    Ok(bytes)
}

pub(crate) fn send_launch(
    channel: &UnixStream,
    config: &ObjectWorkerBootstrapV1,
    originals: [BorrowedFd<'_>; 2],
    until: Instant,
) -> Result<()> {
    let mut storage = Zeroizing::new(vec![0u8; MAX_CONFIG]);
    let mut cursor = std::io::Cursor::new(&mut storage[..]);
    serde_json::to_writer(&mut cursor, config)
        .context("object worker config exceeds launch buffer or cannot be serialized")?;
    let len = cursor.position() as usize;
    send_originals(channel, originals, until)?;
    let mut remaining = &storage[..len];
    while !remaining.is_empty() {
        let n = before_deadline(until, || {
            rustix::net::send(
                channel,
                remaining,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
        })?;
        ensure!(n > 0, "original child did not receive launch config");
        remaining = &remaining[n..];
    }
    channel.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

pub(crate) struct Controller(OwnedFd);

impl Controller {
    fn capture(channel: &UnixStream) -> Result<Self> {
        // The socketpair was created by the actual parent before spawning this helper.
        let peer = rustix::net::sockopt::socket_peercred(channel)?;
        ensure!(
            Some(peer.pid) == rustix::process::getppid()
                && peer.uid == rustix::process::geteuid()
                && peer.pid.as_raw_nonzero().get() > 1,
            "object worker control socket is not owned by its launcher"
        );
        let fd = rustix::process::pidfd_open(peer.pid, rustix::process::PidfdFlags::empty())?;
        ensure!(
            Some(peer.pid) == rustix::process::getppid(),
            "object launcher exited during startup"
        );
        let controller = Self(fd);
        controller.require_live(channel)?;
        Ok(controller)
    }

    pub(crate) fn require_live(&self, channel: &UnixStream) -> Result<()> {
        require_running(&self.0)?;
        // Linux reports HUP when the parent closes the socket, but allows SHUT_WR at the end of config.
        let mut socket = [PollFd::new(channel, PollFlags::empty())];
        ensure!(
            poll(&mut socket, Some(&Timespec::default()))? == 0,
            "original object controller disconnected"
        );
        Ok(())
    }
}

pub(crate) struct WorkerLaunch {
    pub(crate) config: ObjectWorkerBootstrapV1,
    originals: Originals,
    controller: Controller,
    channel: UnixStream,
}

impl WorkerLaunch {
    pub(crate) fn receive(channel: UnixStream, until: Instant) -> Result<Self> {
        let controller = Controller::capture(&channel)?;
        let originals = receive_originals(&channel, until)?;
        let body = read_body(&channel, MAX_CONFIG, until)?;
        // Deserializer messages can quote private input; only report the structural failure.
        let config = serde_json::from_slice(&body)
            .map_err(|_| anyhow::anyhow!("invalid original object worker bootstrap"))?;
        let launch = Self {
            config,
            originals,
            controller,
            channel,
        };
        launch.require_live()?;
        ensure!(
            Instant::now() < until,
            "original object worker bootstrap timed out"
        );
        Ok(launch)
    }

    pub(crate) fn require_live(&self) -> Result<()> {
        self.controller.require_live(&self.channel)?;
        let identities = [self.config.caller_vmm, self.config.callee_vmm].map(|id| EndpointPid {
            pid: i32::try_from(id.pid).unwrap_or(-1),
            started: Some(id.birth),
        });
        self.originals.require_live(identities)
    }
}

#[cfg(test)]
#[path = "object_worker/handoff_tests.rs"]
mod tests;
