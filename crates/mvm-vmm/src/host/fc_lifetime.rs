//! Foreground per-VM Firecracker child custody over original private stdio.
//! These records are host-local continuity, not admission or guest authority.

use super::process_exit::{
    ProcessExitObserver, ProcessExitWait, collect_after_exit_event, require_owned_child_custody,
};
use anyhow::{Context, Result, ensure};
use mvm_core::host_lifetime::HostLaunchBinding;
use rand::Rng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const VERSION: u8 = 1;
const CONFIG_LIMIT: usize = 65_536;
const CONTROL_LIMIT: usize = 1024;
const STOP_LIMIT: Duration = Duration::from_secs(2);

/// Original parent-owned output file, never a privileged destination pathname.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputFile {
    pub parent_pid: u32,
    pub fd: i32,
    pub object: (u64, u64),
    pub uid: u32,
}

/// Fixed native process inputs from the canonically admitted runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcGuardianConfig {
    pub binding: HostLaunchBinding,
    pub program: PathBuf,
    pub api_socket: PathBuf,
    pub state_dir: PathBuf,
    pub holder_object: (u64, u64),
    pub holder_uid: u32,
    pub console: OutputFile,
    pub stderr: OutputFile,
}
impl FcGuardianConfig {
    fn validate(&self) -> Result<()> {
        mvm_core::naming::validate_vm_name(&self.binding.vm_name)?;
        ensure!(
            self.binding.backend == mvm_core::vm_backend::BackendKind::Firecracker
                && self.binding.generation > 0
                && self.binding.grant_serial > 0
                && self.binding.cpus > 0
                && self.binding.memory_mib > 0,
            "guardian native binding invalid"
        );
        for path in [&self.program, &self.api_socket, &self.state_dir] {
            ensure!(
                path.is_absolute() && path.as_os_str().as_encoded_bytes().len() <= 4096,
                "guardian native path invalid"
            );
        }
        ensure!(
            self.console.object != self.stderr.object
                && self.console.object != self.holder_object
                && self.stderr.object != self.holder_object,
            "guardian output objects overlap"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    version: u8,
    nonce: [u8; 32],
    config: FcGuardianConfig,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stop {
    version: u8,
    nonce: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u8,
    nonce: [u8; 32],
    binding: HostLaunchBinding,
    event: Event,
}

#[derive(Serialize, Deserialize)]
enum Event {
    Ready {
        pid: u32,
    },
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

/// Produced only by the original controller after exact helper/child collection.
#[derive(Clone)]
pub struct ConfirmedExit {
    binding: HostLaunchBinding,
    native_pid: Option<u32>,
}
impl ConfirmedExit {
    pub fn binding(&self) -> &HostLaunchBinding {
        &self.binding
    }
    /// Observed diagnostic metadata, absent if startup framing was incomplete.
    pub fn native_pid(&self) -> Option<u32> {
        self.native_pid
    }
}

/// Actual scope/sudo launcher and its exclusive control pipes.
#[must_use = "retain the launcher until explicit confirmed exit"]
pub struct OwnedFcLauncher {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    binding: HostLaunchBinding,
    native_pid: Option<u32>,
    confirmed: Option<ConfirmedExit>,
    stop_started: bool,
}

pub struct LaunchFailure {
    reason: anyhow::Error,
    owner: OwnedFcLauncher,
}
impl LaunchFailure {
    pub fn owner_mut(&mut self) -> &mut OwnedFcLauncher {
        &mut self.owner
    }
    pub fn into_parts(self) -> (anyhow::Error, OwnedFcLauncher) {
        (self.reason, self.owner)
    }
}
impl fmt::Debug for LaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FcLaunchFailure").finish_non_exhaustive()
    }
}
impl fmt::Display for LaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "owned Firecracker startup failed: {}", self.reason)
    }
}
impl std::error::Error for LaunchFailure {}

impl OwnedFcLauncher {
    /// Keep the original pre-Prepare child when scope confirmation fails.
    pub fn hold_unprepared(mut child: Child, binding: HostLaunchBinding) -> Self {
        Self {
            input: child.stdin.take(),
            output: child.stdout.take(),
            child: Some(child),
            binding,
            native_pid: None,
            confirmed: None,
            stop_started: false,
        }
    }
    /// The caller must select/verify the real guardian before constructing its command.
    pub fn start(mut child: Child, config: FcGuardianConfig, deadline: Instant) -> Result<Self> {
        let mut owner = Self {
            input: child.stdin.take(),
            output: child.stdout.take(),
            child: Some(child),
            binding: config.binding.clone(),
            native_pid: None,
            confirmed: None,
            stop_started: false,
        };
        let result = (|| {
            require_owned_child_custody()?;
            config.validate()?;
            let mut nonce = [0; 32];
            rand::rng().fill_bytes(&mut nonce);
            write_frame(
                owner.input.as_mut().context("guardian input missing")?,
                &Prepare {
                    version: VERSION,
                    nonce,
                    config,
                },
                CONFIG_LIMIT,
                deadline,
            )?;
            let reply: Reply = read_frame(
                owner.output.as_mut().context("guardian output missing")?,
                CONTROL_LIMIT,
                deadline,
            )?;
            owner.verify_reply(&reply, nonce)?;
            match reply.event {
                Event::Ready { pid } if pid > 1 => owner.native_pid = Some(pid),
                _ => anyhow::bail!("guardian did not retain a native child"),
            }
            ensure!(
                owner
                    .child
                    .as_mut()
                    .context("launcher missing")?
                    .try_wait()?
                    .is_none(),
                "guardian launcher exited during startup"
            );
            Ok(())
        })();
        match result {
            Ok(()) => Ok(owner),
            Err(reason) => Err(LaunchFailure { reason, owner }.into()),
        }
    }

    fn verify_reply(&self, reply: &Reply, nonce: [u8; 32]) -> Result<()> {
        ensure!(
            reply.version == VERSION && reply.nonce == nonce && reply.binding == self.binding,
            "guardian continuity response differs"
        );
        Ok(())
    }

    pub fn native_pid(&self) -> Option<u32> {
        self.native_pid
    }

    /// Never sends a numeric signal; the guardian signals only its unreaped Child.
    pub fn stop(&mut self, deadline: Instant) -> Result<ConfirmedExit> {
        if let Some(proof) = &self.confirmed {
            return Ok(proof.clone());
        }
        require_owned_child_custody()?;
        ensure!(Instant::now() < deadline, "guardian stop deadline");
        if self.stop_started || self.native_pid.is_none() {
            self.stop_started = true;
            return self.stop_after_eof(deadline);
        }
        let child = self.child.as_mut().context("original launcher missing")?;
        ensure!(
            child.try_wait()?.is_none(),
            "guardian exited without confirmed terminal response"
        );
        let observer = ProcessExitObserver::arm(child.id().try_into()?)?;
        let mut nonce = [0; 32];
        rand::rng().fill_bytes(&mut nonce);
        self.stop_started = true;
        write_frame(
            self.input.as_mut().context("guardian input missing")?,
            &Stop {
                version: VERSION,
                nonce,
            },
            CONTROL_LIMIT,
            deadline,
        )?;
        let reply: Reply = read_frame(
            self.output.as_mut().context("guardian output missing")?,
            CONTROL_LIMIT,
            deadline,
        )?;
        self.verify_reply(&reply, nonce)?;
        ensure!(
            matches!(reply.event, Event::Exited { .. }),
            "guardian did not confirm native exit"
        );
        ensure!(
            observer.wait_event(deadline)? == ProcessExitWait::Exited,
            "guardian launcher exit deadline"
        );
        let child = self.child.as_mut().context("launcher missing")?;
        require_owned_child_custody()?;
        let status = collect_after_exit_event(deadline, || child.try_wait())?
            .context("guardian launcher was not positively reaped")?;
        ensure!(
            status.success(),
            "guardian launcher failed after terminal response"
        );
        let proof = ConfirmedExit {
            binding: self.binding.clone(),
            native_pid: self.native_pid,
        };
        self.confirmed = Some(proof.clone());
        self.input.take();
        self.output.take();
        Ok(proof)
    }

    fn stop_after_eof(&mut self, deadline: Instant) -> Result<ConfirmedExit> {
        // Only the verified original guardian chain can turn this EOF into
        // success after collecting its native Child. EOF itself proves nothing.
        self.input.take();
        let child = self.child.as_mut().context("original launcher missing")?;
        let status = if let Some(status) = child.try_wait()? {
            status
        } else {
            let observer = ProcessExitObserver::arm(child.id().try_into()?)?;
            ensure!(
                observer.wait_event(deadline)? == ProcessExitWait::Exited,
                "guardian original EOF cleanup deadline"
            );
            require_owned_child_custody()?;
            collect_after_exit_event(deadline, || child.try_wait())?
                .context("guardian original EOF exit was not positively reaped")?
        };
        ensure!(status.success(), "guardian original EOF cleanup failed");
        let proof = ConfirmedExit {
            binding: self.binding.clone(),
            native_pid: self.native_pid,
        };
        self.confirmed = Some(proof.clone());
        self.output.take();
        Ok(proof)
    }
}

impl Drop for OwnedFcLauncher {
    fn drop(&mut self) {
        if self.confirmed.is_none() {
            // EOF asks the actual guardian to clean only its owned child. Keep
            // the exact unreaped launcher handle; a timeout is never a refund.
            self.input.take();
            std::mem::forget((self.child.take(), self.output.take()));
        }
    }
}

fn poll(fd: i32, events: i16, deadline: Instant) -> Result<()> {
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .context("guardian I/O deadline")?;
        ensure!(!left.is_zero(), "guardian I/O deadline");
        let millis = left
            .as_millis()
            .saturating_add(u128::from(left.subsec_nanos() % 1_000_000 != 0))
            .min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one initialized live descriptor record, bounded wait.
        let result = unsafe { libc::poll(&mut pfd, 1, millis) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error()).context("guardian descriptor poll");
        }
    }
}
fn nonblocking(fd: i32) -> Result<()> {
    // SAFETY: borrowed live descriptor; preserve all existing status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(flags >= 0, "guardian descriptor flags unavailable");
    // SAFETY: set nonblocking only on this owned control description.
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "guardian nonblocking failed"
    );
    Ok(())
}
fn write_all<W: Write + AsRawFd>(
    writer: &mut W,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<()> {
    nonblocking(writer.as_raw_fd())?;
    while !bytes.is_empty() {
        poll(writer.as_raw_fd(), libc::POLLOUT, deadline)?;
        match writer.write(bytes) {
            Ok(0) => anyhow::bail!("guardian control write closed"),
            Ok(n) => bytes = &bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e).context("guardian control write"),
        }
    }
    Ok(())
}
fn read_exact<R: Read + AsRawFd>(
    reader: &mut R,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    nonblocking(reader.as_raw_fd())?;
    while !bytes.is_empty() {
        poll(reader.as_raw_fd(), libc::POLLIN, deadline)?;
        match reader.read(bytes) {
            Ok(0) => anyhow::bail!("guardian control closed"),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e).context("guardian control read"),
        }
    }
    Ok(())
}
fn write_frame<W: Write + AsRawFd, T: Serialize>(
    writer: &mut W,
    value: &T,
    limit: usize,
    deadline: Instant,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encode guardian control")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "guardian control exceeds limit"
    );
    write_all(writer, &u32::try_from(bytes.len())?.to_be_bytes(), deadline)?;
    write_all(writer, &bytes, deadline)
}
fn read_frame<R: Read + AsRawFd, T: DeserializeOwned>(
    reader: &mut R,
    limit: usize,
    deadline: Instant,
) -> Result<T> {
    let mut prefix = [0; 4];
    read_exact(reader, &mut prefix, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))?;
    ensure!(
        length > 0 && length <= limit,
        "guardian control exceeds limit"
    );
    let mut bytes = vec![0; length];
    read_exact(reader, &mut bytes, deadline)?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid guardian control"))
}

fn reopen_output(source: &OutputFile) -> Result<File> {
    ensure!(
        source.parent_pid > 1 && (3..=65535).contains(&source.fd),
        "invalid original output descriptor"
    );
    let file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/{}/fd/{}", source.parent_pid, source.fd))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && (meta.dev(), meta.ino()) == source.object
            && meta.uid() == source.uid
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o600,
        "guardian original output differs"
    );
    Ok(file)
}

/// Thin native-bin entry. No shell recipe or arbitrary command is accepted.
pub fn run_guardian() -> Result<()> {
    // SAFETY: geteuid reads current credentials without mutating the process.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native Firecracker guardian requires the canonical privileged launch"
    );
    let mut args = std::env::args_os().skip(1);
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--holder-fd")),
        "guardian requires original holder"
    );
    let raw = args
        .next()
        .context("guardian holder descriptor missing")?
        .to_str()
        .context("guardian descriptor invalid")?
        .parse::<i32>()
        .context("guardian descriptor invalid")?;
    ensure!(
        args.next().is_none() && (3..=65535).contains(&raw),
        "guardian arguments invalid"
    );
    // SAFETY: the fixed privileged launcher exclusively transfers this inherited fd.
    let holder = unsafe { File::from_raw_fd(raw) };
    // SAFETY: this newly adopted live descriptor is exclusively owned here.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0,
        "guardian holder flags unavailable"
    );
    let mut input = duplicate_stdio(0)?;
    let mut output = duplicate_stdio(1)?;
    let prepare: Prepare = read_frame(
        &mut input,
        CONFIG_LIMIT,
        Instant::now() + Duration::from_secs(3),
    )?;
    ensure!(prepare.version == VERSION, "guardian version differs");
    let config = &prepare.config;
    config.validate()?;
    let metadata = holder.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.uid() == config.holder_uid
            && (metadata.dev(), metadata.ino()) == config.holder_object,
        "guardian inherited holder differs"
    );
    // SAFETY: acquire nonblocking SH on the same inherited holder description.
    ensure!(
        unsafe { libc::flock(raw, libc::LOCK_SH | libc::LOCK_NB) } == 0,
        "guardian inherited holder lock refused"
    );
    require_owned_child_custody()?;
    let console = reopen_output(&config.console)?;
    let stderr = reopen_output(&config.stderr)?;
    let mut command = mvm_core::env_hygiene::helper_command(&config.program);
    command
        .arg("--api-sock")
        .arg(&config.api_socket)
        .current_dir(&config.state_dir)
        .stdin(Stdio::null())
        .stdout(console)
        .stderr(stderr);
    // SAFETY: the closure performs only fcntl on a live inherited descriptor.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(raw, libc::F_GETFD);
            if flags < 0 || libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().context("spawn owned Firecracker child")?;
    serve_child(child, holder, prepare, &mut input, &mut output)
}

fn reap_child(child: &mut Child, deadline: Instant) -> Result<ExitStatus> {
    require_owned_child_custody()?;
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    let observer = ProcessExitObserver::arm(child.id().try_into()?)?;
    // Exclusive reaping/default SIGCHLD keep the original Child PID occupied.
    if child.try_wait()?.is_none() {
        child.kill().context("stop original Firecracker child")?;
    }
    ensure!(
        observer.wait_event(deadline)? == ProcessExitWait::Exited,
        "owned Firecracker exit deadline"
    );
    collect_after_exit_event(deadline, || child.try_wait())?
        .context("owned Firecracker was not positively reaped")
}

fn serve_child<R: Read + AsRawFd, W: Write + AsRawFd>(
    mut child: Child,
    holder: File,
    prepare: Prepare,
    input: &mut R,
    output: &mut W,
) -> Result<()> {
    let mut stop_started = false;
    let result = (|| {
        let startup = Instant::now() + Duration::from_secs(3);
        write_frame(
            output,
            &Reply {
                version: VERSION,
                nonce: prepare.nonce,
                binding: prepare.config.binding.clone(),
                event: Event::Ready { pid: child.id() },
            },
            CONTROL_LIMIT,
            startup,
        )?;
        // Idle has no allocation or traffic. EOF still asks only this Child to stop.
        nonblocking(input.as_raw_fd())?;
        let mut prefix = [0; 4];
        loop {
            match input.read(&mut prefix[..1]) {
                Ok(0) => {
                    stop_started = true;
                    return reap_child(&mut child, Instant::now() + STOP_LIMIT).map(|_| ());
                }
                Ok(1) => break,
                Ok(_) => anyhow::bail!("guardian prefix read invalid"),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait_idle(input.as_raw_fd())?;
                }
                Err(e) => return Err(e).context("guardian lifetime input"),
            }
        }
        let deadline = Instant::now() + STOP_LIMIT;
        read_exact(input, &mut prefix[1..], deadline)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))?;
        ensure!(
            length > 0 && length <= CONTROL_LIMIT,
            "guardian stop frame exceeds limit"
        );
        let mut bytes = vec![0; length];
        read_exact(input, &mut bytes, deadline)?;
        let stop: Stop =
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid guardian stop"))?;
        ensure!(stop.version == VERSION, "guardian stop version differs");
        stop_started = true;
        let status = reap_child(&mut child, deadline)?;
        write_frame(
            output,
            &Reply {
                version: VERSION,
                nonce: stop.nonce,
                binding: prepare.config.binding.clone(),
                event: Event::Exited {
                    code: status.code(),
                    signal: status.signal(),
                },
            },
            CONTROL_LIMIT,
            deadline,
        )
    })();
    if result.is_err()
        && (stop_started || reap_child(&mut child, Instant::now() + STOP_LIMIT).is_err())
    {
        std::mem::forget((child, holder));
    }
    result
}

fn wait_idle(fd: i32) -> Result<()> {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: an idle lifetime wait has one live descriptor, no frame or allocation.
        let result = unsafe { libc::poll(&mut pfd, 1, -1) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error()).context("guardian idle wait");
        }
    }
}

fn duplicate_stdio(raw: i32) -> Result<File> {
    // SAFETY: duplicate the fixed live stdio description into an owned CLOEXEC
    // File. Poll/read must not pass through Stdin's hidden buffered read-ahead.
    let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    ensure!(duplicate >= 0, "guardian stdio duplication failed");
    // SAFETY: fcntl returned a new descriptor owned only by this File.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

#[cfg(test)]
mod tests;
