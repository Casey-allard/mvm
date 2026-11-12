//! The selected macOS helper takes two independent, read-only observations
//! from the original launcher. Darwin's control socket stays full duplex.
use super::*;
use mvm_core::mailbox::object_pair::role::ObjectParticipantRole;
use mvm_vmm::host::{
    hvf_stop::mailbox::OriginalMailboxObservation,
    process_exit::{ProcessExitObserver, ProcessExitWait},
};

pub(super) fn peer(stream: &UnixStream) -> Result<(i32, u32)> {
    let pid = mvm_vmm::host::uds_peer::connected_peer_pid(stream)?;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the borrowed socket is live and both credential outputs are writable.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((pid, uid))
}

pub(super) struct Controller {
    pid: rustix::process::Pid,
    observer: std::sync::Mutex<Option<ProcessExitObserver>>,
}
impl Controller {
    pub(super) fn capture(channel: &UnixStream) -> Result<Self> {
        let parent = rustix::process::getppid().context("no original controller")?;
        let (pid, uid) = peer(channel)?;
        ensure!(
            pid == parent.as_raw_nonzero().get()
                && pid > 1
                && uid == rustix::process::geteuid().as_raw(),
            "different original controller"
        );
        let observer = ProcessExitObserver::arm(pid)?;
        ensure!(
            rustix::process::getppid() == Some(parent)
                && observer.wait_event(Instant::now())? == ProcessExitWait::TimedOut,
            "original controller exited"
        );
        Ok(Self {
            pid: parent,
            observer: std::sync::Mutex::new(Some(observer)),
        })
    }
    pub(super) fn require_live(&self, channel: &UnixStream) -> Result<()> {
        ensure!(
            rustix::process::getppid() == Some(self.pid),
            "original worker lost its parent"
        );
        let mut observer = self
            .observer
            .lock()
            .map_err(|_| anyhow::anyhow!("original controller observer poisoned"))?;
        let mut pending = [0u8; 1];
        let quiet = matches!(
            rustix::net::recv(
                channel,
                &mut pending[..],
                RecvFlags::DONTWAIT | RecvFlags::PEEK
            ),
            Err(rustix::io::Errno::AGAIN)
        );
        if !quiet
            || !matches!(
                observer
                    .as_ref()
                    .context("original controller retired")?
                    .wait_event(Instant::now()),
                Ok(ProcessExitWait::TimedOut)
            )
        {
            *observer = None;
            anyhow::bail!("original controller disconnected or changed");
        }
        Ok(())
    }
}
pub(super) fn write_length(channel: &UnixStream, len: usize, until: Instant) -> Result<()> {
    let bytes = u32::try_from(len)?.to_be_bytes();
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        let n = before_deadline(until, || rustix::net::send(channel, rest, SEND_FLAGS))?;
        ensure!(n > 0, "short object config prefix");
        rest = &rest[n..];
    }
    Ok(())
}
fn read_exact(channel: &UnixStream, mut rest: &mut [u8], until: Instant) -> Result<()> {
    while !rest.is_empty() {
        let (n, _) = before_deadline(until, || {
            rustix::net::recv(channel, &mut *rest, RecvFlags::DONTWAIT)
        })?;
        ensure!(n > 0, "incomplete original object config");
        rest = &mut rest[n..];
    }
    Ok(())
}
pub(super) fn read_body(
    channel: &UnixStream,
    cap: usize,
    until: Instant,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut len = [0u8; 4];
    read_exact(channel, &mut len, until)?;
    let len = u32::from_be_bytes(len) as usize;
    ensure!(len > 0 && len <= cap, "invalid object worker config length");
    let mut body = Zeroizing::new(vec![0; len]);
    read_exact(channel, &mut body, until)?;
    Ok(body)
}

pub(super) struct Originals([OriginalMailboxObservation; 2]);
impl Originals {
    pub(super) fn observe(
        config: &ObjectWorkerBootstrapV1,
        until: Instant,
        controller: impl Fn() -> Result<()>,
    ) -> Result<Self> {
        controller()?;
        let authority = config.validate_current()?;
        let targets = config
            .hvf
            .as_ref()
            .context("missing original HVF mailbox targets")?;
        let names = match config.role.role.role {
            ObjectParticipantRole::Caller => [&authority.local_state, &authority.peer_state],
            ObjectParticipantRole::Callee => [&authority.peer_state, &authority.local_state],
        };
        let ids = [config.caller_vmm, config.callee_vmm];
        ensure!(
            ids[0].pid != ids[1].pid,
            "object worker requires two originals"
        );
        for ((target, state), id) in targets.iter().zip(names).zip(ids) {
            ensure!(
                target.child_pid() == id.pid
                    && target.matches_operator(&config.plan_verifier)
                    && state.file_name().and_then(|v| v.to_str())
                        == Some(target.instance().vm_id.as_str()),
                "original HVF target differs"
            );
        }
        controller()?;
        let caller = targets[0].observe_at(&config.home, until)?;
        controller()?;
        let callee = targets[1].observe_at(&config.home, until)?;
        controller()?;
        Ok(Self([caller, callee]))
    }
    pub(super) fn require_live(&self, ids: [EndpointPid; 2]) -> Result<()> {
        for (original, id) in self.0.iter().zip(ids) {
            ensure!(
                id.started.is_some() && id.is_live_and_ours(),
                "original HVF generation changed"
            );
            original.require_current()?;
        }
        Ok(())
    }
    pub(super) fn open_mailbox(
        &self,
        role: ObjectParticipantRole,
        until: Instant,
    ) -> Result<UnixStream> {
        self.0[match role {
            ObjectParticipantRole::Caller => 0,
            ObjectParticipantRole::Callee => 1,
        }]
        .open_mailbox(until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
    };
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    #[test]
    fn framed_private_config_refuses_truncated_and_excess_before_service() {
        for (length, data, ok) in [
            (3u32, b"abc".as_slice(), true),
            (4, b"xx", false),
            (8, b"", false),
        ] {
            let (mut parent, child) = UnixStream::pair().unwrap();
            parent.write_all(&length.to_be_bytes()).unwrap();
            parent.write_all(data).unwrap();
            parent.shutdown(std::net::Shutdown::Write).unwrap();
            assert_eq!(read_body(&child, 4, deadline()).is_ok(), ok);
        }
    }
    #[test]
    fn original_darwin_controller_requires_full_connection_after_config() {
        const CHILD: &str = "MVM_TEST_ORIGINAL_FULL_DUPLEX_HVF";
        if std::env::var_os(CHILD).is_some() {
            let channel = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
            let c = Controller::capture(&channel).unwrap();
            c.require_live(&channel).unwrap();
            (&channel).write_all(b"R").unwrap();
            let until = deadline();
            while c.require_live(&channel).is_ok() {
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(c.require_live(&channel).is_err());
            return;
        }
        let (mut parent, child) = UnixStream::pair().unwrap();
        assert!(Controller::capture(&parent).is_err());
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","mailbox_process::object_worker::hvf::tests::original_darwin_controller_requires_full_connection_after_config"]).env(CHILD,"1").stdin(std::process::Stdio::from(OwnedFd::from(child))).stdout(Stdio::null()).spawn().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(6)))
            .unwrap();
        let mut ready = [0];
        parent.read_exact(&mut ready).unwrap();
        assert_eq!(ready, *b"R");
        drop(parent);
        assert!(child.wait().unwrap().success());
    }
    #[test]
    fn received_links_are_distinct_unnamed_original_and_cloexec() {
        let (parent, controller) = UnixStream::pair().unwrap();
        let (a, _a) = UnixStream::pair().unwrap();
        let (b, _b) = UnixStream::pair().unwrap();
        for (second, ok) in [(&b, true), (&a, false)] {
            send_rights(&parent, 2, [a.as_fd(), second.as_fd()], deadline()).unwrap();
            let links = receive_links(&controller);
            assert_eq!(links.is_ok(), ok);
            if let Ok(links) = links {
                for l in &links {
                    assert!(
                        rustix::io::fcntl_getfd(l)
                            .unwrap()
                            .contains(rustix::io::FdFlags::CLOEXEC)
                    );
                }
            }
        }
    }
}
