//! Private installed-parent bootstrap and terminal cleanup on original stdio.
//! The serialized projection is not authority: the parent retains the actual
//! typed handoff and the child adopts its original inherited holder.

use super::*;
use crate::host::process_exit::{ProcessExitObserver, ProcessExitWait};
use mvm_core::host_lifetime::{
    EndpointPartitionProjection, HostLeaseExpectation, PreparedEndpointHandoff,
    PreparedHostLifetimeLease,
};
use serde::de::DeserializeOwned;
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    process::{ChildStdin, ChildStdout},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

const CONFIG_LIMIT: usize = 65_536;
const CONTROL_LIMIT: usize = 1024;
const STARTUP_LIMIT: Duration = Duration::from_secs(10);

#[cfg(test)]
#[path = "installed/tests.rs"]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    version: u8,
    nonce: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    version: u8,
    nonce: [u8; 32],
    projection: EndpointPartitionProjection,
    directory: i32,
    holder: i32,
    expected: HostLeaseExpectation,
    config: serde_json::Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u8,
    nonce: [u8; 32],
    session: [u8; 32],
    serial: u64,
    handshake: EndpointHandshake,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Drained {
    version: u8,
    nonce: [u8; 32],
    session: [u8; 32],
    serial: u64,
}

/// Four fixed-capacity serialized-control buffers. This is a bootstrap-buffer
/// floor, not the complete codec/TLS/parser/worker resource declaration.
pub const INSTALLED_CONTROL_BUFFER_BYTES: u64 = 4 * CONFIG_LIMIT as u64;

/// Spawn only through the existing canonical endpoint binary/config path while
/// retaining the original typed partition and holder through terminal cleanup.
pub fn spawn_network_endpoint_installed(
    mut params: SubstitutionSpawnParams<'_>,
    handoff: PreparedEndpointHandoff,
) -> Result<OwnedEndpoint> {
    let deadline = Instant::now() + STARTUP_LIMIT;
    owned::require_child_custody()?;
    handoff.check_current()?;
    let projection = handoff.partition().projection();
    if params.lifetime != EndpointLifetime::Launcher
        || params.vm_name != projection.binding.vm_name
        || projection.profile != 2
        || projection.limits.host_metadata_bytes < INSTALLED_CONTROL_BUFFER_BYTES
        || params.telemetry
        || params.tools.is_some_and(|rules| !rules.is_empty())
        || !params.ingress.is_empty()
        || !params.secrets.is_empty()
    {
        bail!("installed endpoint shape or declared resource floor unsupported")
    }
    let identity = params
        .flowmux_identity
        .as_ref()
        .context("installed endpoint identity missing")?;
    if identity.session_id != hex::encode(projection.session) {
        bail!("installed endpoint canonical session differs")
    }
    let policy = params
        .network_policy
        .context("installed endpoint policy missing")?;
    let plan = params
        .admitted_network_plan
        .as_ref()
        .context("installed endpoint original admitted facts missing")?;
    plan.validate_for(policy, params.tenant, params.vm_name)?;
    if plan.plan_id.0 != projection.admitted_plan_id || policy.payload_mapping().is_none() {
        bail!("installed endpoint differs from original admitted mapping")
    }
    let env_path = mvm_core::config::vm_substitution_env_path(params.vm_name);
    owned::refuse_existing_evidence(&params, &env_path)?;
    if params.egress_proxy.is_none() {
        params.egress_proxy = EgressProxySpawnConfig::from_host_config()?;
    }
    if let Some(proxy) = &params.egress_proxy {
        proxy.resolve()?;
    }
    params.session_marker = Some(params.state_dir.join(SUBST_SESSION_FILE));
    let config = build_endpoint_config_json(&params);
    let bin = resolve_network_endpoint_path()?;
    let log = owned::create_evidence(&endpoint_stderr_log_path(params.state_dir))?;
    let mut command = owned::endpoint_command(
        mvm_core::env_hygiene::helper_command(&bin),
        EndpointLifetime::Launcher,
        params.state_dir,
        log,
    );
    command.arg("--installed-partition");
    let fds = vec![
        handoff.holder().directory().as_raw_fd(),
        handoff.holder().holder().as_raw_fd(),
    ];
    if fds.iter().any(|fd| *fd <= 2) || fds[0] == fds[1] {
        bail!("installed endpoint descriptors differ")
    }
    crate::host::restore_image::inherit_descriptors(&mut command, fds);
    handoff.check_current()?;
    if Instant::now() >= deadline {
        bail!("installed endpoint original startup deadline")
    }
    let child = command
        .spawn()
        .context("spawn original installed endpoint")?;
    let mut endpoint = OwnedEndpoint::new(child);
    // Install supporting custody BEFORE any fallible post-spawn operation.
    endpoint.installed = Some(InstalledCustody {
        handoff,
        input: None,
        output: None,
        nonce: [0; 32],
        drained: false,
    });
    let result: Result<()> = (|| {
        endpoint.arm()?;
        let child = endpoint
            .child
            .as_mut()
            .context("original endpoint child missing")?;
        let input = child.stdin.take();
        let output = child.stdout.take();
        let installed = endpoint
            .installed
            .as_mut()
            .context("installed endpoint custody missing")?;
        installed.input = input;
        installed.output = output;
        let challenge: Challenge = read_frame(
            installed
                .output
                .as_mut()
                .context("installed output missing")?,
            CONTROL_LIMIT,
            deadline,
        )?;
        if challenge.version != 1 || challenge.nonce == [0; 32] {
            bail!("invalid installed endpoint challenge")
        }
        installed.nonce = challenge.nonce;
        installed.handoff.check_current()?;
        write_frame(
            installed
                .input
                .as_mut()
                .context("installed input missing")?,
            &Prepare {
                version: 1,
                nonce: challenge.nonce,
                projection: installed.handoff.partition().projection().clone(),
                directory: installed.handoff.holder().directory().as_raw_fd(),
                holder: installed.handoff.holder().holder().as_raw_fd(),
                expected: installed.handoff.holder().expectation().clone(),
                config,
            },
            CONFIG_LIMIT,
            deadline,
        )?;
        let ready: Ready = read_frame(
            installed
                .output
                .as_mut()
                .context("installed output missing")?,
            CONFIG_LIMIT,
            deadline,
        )?;
        let expected = installed.handoff.partition().projection();
        if ready.version != 1
            || ready.nonce != challenge.nonce
            || ready.session != expected.session
            || ready.serial != expected.partition_serial
        {
            bail!("installed endpoint readiness lineage differs")
        }
        installed.handoff.check_current()?;
        endpoint.ensure_running()?;
        owned::create_evidence(&params.state_dir.join(SUBST_PID_FILE))?
            .write_all(EndpointPid::of_child(endpoint.id()).render().as_bytes())?;
        let env = Zeroizing::new(serde_json::to_vec(&ready.handshake.env)?);
        owned::create_evidence(&env_path)?.write_all(&env)?;
        record_secret_fingerprints(params.vm_name, ready.handshake.input_fingerprints);
        Ok(())
    })();
    match result {
        Ok(()) => Ok(endpoint),
        Err(reason) => Err(owned::OwnedEndpointSpawnError { reason, endpoint }.into()),
    }
}

#[derive(Debug)]
pub(super) struct InstalledCustody {
    pub(super) handoff: PreparedEndpointHandoff,
    pub(super) input: Option<ChildStdin>,
    pub(super) output: Option<ChildStdout>,
    nonce: [u8; 32],
    pub(super) drained: bool,
}
impl InstalledCustody {
    pub(super) fn read_drained(&mut self, deadline: Instant) -> Result<()> {
        if self.drained {
            return Ok(());
        }
        let done: Drained = read_frame(
            self.output.as_mut().context("installed output missing")?,
            CONTROL_LIMIT,
            deadline,
        )?;
        let expected = self.handoff.partition().projection();
        if done.version != 1
            || done.nonce != self.nonce
            || done.session != expected.session
            || done.serial != expected.partition_serial
        {
            bail!("installed endpoint cleanup lineage differs")
        }
        self.drained = true;
        Ok(())
    }
}

/// Child-side private capability. Only fixed original pipe stdio is accepted;
/// no path, PID, arbitrary reader or decoded quota constructor exists.
pub struct InstalledEndpointChild {
    input: File,
    output: File,
    _holder: PreparedHostLifetimeLease,
    parent: ProcessExitObserver,
    projection: EndpointPartitionProjection,
    config: Option<serde_json::Value>,
    nonce: [u8; 32],
    phase: u8,
    fenced: AtomicBool,
    startup_deadline: Instant,
}
impl InstalledEndpointChild {
    pub fn from_stdio() -> Result<Self> {
        let deadline = Instant::now() + STARTUP_LIMIT;
        for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: metadata inspection only of the fixed live stdio descriptor.
            if unsafe { libc::fstat(fd, &mut metadata) } != 0
                || metadata.st_mode & libc::S_IFMT != libc::S_IFIFO
            {
                bail!("installed endpoint requires original anonymous pipe stdio")
            }
        }
        let mut input = duplicate_stdio(libc::STDIN_FILENO)?;
        let mut output = duplicate_stdio(libc::STDOUT_FILENO)?;
        // SAFETY: getppid returns the current kernel parent, never an argv PID.
        let pid = unsafe { libc::getppid() };
        if pid <= 1 {
            bail!("installed endpoint has no original live parent")
        }
        let parent = ProcessExitObserver::arm(pid)?;
        let mut nonce = [0; 32];
        use rand::Rng;
        rand::rng().fill_bytes(&mut nonce);
        write_frame(
            &mut output,
            &Challenge { version: 1, nonce },
            CONTROL_LIMIT,
            deadline,
        )?;
        let prepared: Prepare = read_frame(&mut input, CONFIG_LIMIT, deadline)?;
        if prepared.version != 1
            || prepared.nonce != nonce
            || parent.wait_event(Instant::now())? != ProcessExitWait::TimedOut
        {
            bail!("installed endpoint parent challenge differs")
        }
        let descriptors = [
            prepared.directory,
            prepared.holder,
            input.as_raw_fd(),
            output.as_raw_fd(),
        ];
        let mut identities = std::collections::BTreeSet::new();
        for (index, fd) in descriptors.into_iter().enumerate() {
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: no descriptor conversion precedes this complete alias check.
            if fd <= 2
                || unsafe { libc::fstat(fd, &mut metadata) } != 0
                || !identities.insert((metadata.st_dev, metadata.st_ino))
                || (index == 0 && metadata.st_mode & libc::S_IFMT != libc::S_IFDIR)
                || (index == 1 && metadata.st_mode & libc::S_IFMT != libc::S_IFREG)
            {
                bail!("installed endpoint descriptor namespace differs")
            }
        }
        // SAFETY: the complete preflight established distinct original inherited
        // files, and each number is adopted exactly once by this private startup.
        let directory = unsafe { File::from_raw_fd(prepared.directory) };
        // SAFETY: same exclusive inherited-file contract as directory above.
        let holder = unsafe { File::from_raw_fd(prepared.holder) };
        let holder = PreparedHostLifetimeLease::bind(directory, holder, prepared.expected)?;
        holder.verify_current()?;
        Ok(Self {
            input,
            output,
            _holder: holder,
            parent,
            projection: prepared.projection,
            config: Some(prepared.config),
            nonce,
            phase: 0,
            fenced: AtomicBool::new(false),
            startup_deadline: deadline,
        })
    }
    pub fn projection(&self) -> &EndpointPartitionProjection {
        &self.projection
    }
    pub fn take_config(&mut self) -> Result<serde_json::Value> {
        self.config
            .take()
            .context("installed endpoint config already consumed")
    }
    pub fn control_fd(&self) -> i32 {
        self.input.as_raw_fd()
    }
    pub fn check_parent(&self) -> Result<()> {
        if self.fenced.load(Ordering::Acquire)
            || self.parent.wait_event(Instant::now())? != ProcessExitWait::TimedOut
            || parent_closed(&self.input)?
        {
            self.fenced.store(true, Ordering::Release);
            bail!("installed endpoint parent admission closed")
        }
        Ok(())
    }
    pub fn parent_closed(&self) -> Result<bool> {
        parent_closed(&self.input)
    }
    pub fn send_ready(&mut self, handshake: EndpointHandshake, deadline: Instant) -> Result<()> {
        let deadline = deadline.min(self.startup_deadline);
        if self.phase != 0 || self.config.is_some() {
            bail!("installed endpoint readiness phase differs")
        }
        self.check_parent()?;
        write_frame(
            &mut self.output,
            &Ready {
                version: 1,
                nonce: self.nonce,
                session: self.projection.session,
                serial: self.projection.partition_serial,
                handshake,
            },
            CONFIG_LIMIT,
            deadline,
        )?;
        self.phase = 1;
        Ok(())
    }
    /// Call only after actual tasks/readers joined and verified payload-store
    /// accounting is zero. The parent additionally requires positive Child exit.
    pub fn send_drained(&mut self, deadline: Instant) -> Result<()> {
        if self.phase != 1 || !self.parent_closed()? {
            bail!("installed endpoint drain phase differs")
        }
        self.fenced.store(true, Ordering::Release);
        write_frame(
            &mut self.output,
            &Drained {
                version: 1,
                nonce: self.nonce,
                session: self.projection.session,
                serial: self.projection.partition_serial,
            },
            CONTROL_LIMIT,
            deadline,
        )?;
        self.phase = 2;
        Ok(())
    }
}

fn parent_closed(input: &File) -> Result<bool> {
    let mut poll = libc::pollfd {
        fd: input.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live borrowed pipe, nonblocking observation; no byte is consumed.
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("installed parent pipe observation");
    }
    Ok(result > 0) // EOF, unexpected extra bytes or invalid/hung-up pipe all fence.
}
fn duplicate_stdio(raw: i32) -> Result<File> {
    // SAFETY: fixed stdio is duplicated into an original owned CLOEXEC file.
    let fd = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicate installed stdio");
    }
    // SAFETY: fcntl returned this new owned descriptor, used without buffering.
    Ok(unsafe { File::from_raw_fd(fd) })
}

struct BoundedBytes {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("installed control frame limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn write_frame<W: Write + AsRawFd, T: Serialize>(
    writer: &mut W,
    value: &T,
    limit: usize,
    deadline: Instant,
) -> Result<()> {
    let mut bounded = BoundedBytes {
        bytes: Zeroizing::new(Vec::with_capacity(limit)),
        limit,
    };
    serde_json::to_writer(&mut bounded, value)
        .map_err(|_| anyhow!("installed control encoding exceeds bound"))?;
    write_all(
        writer,
        &u32::try_from(bounded.bytes.len())?.to_be_bytes(),
        deadline,
    )?;
    write_all(writer, &bounded.bytes, deadline)
}
fn write_all<W: Write + AsRawFd>(
    writer: &mut W,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<()> {
    owned_pipe_nonblocking(writer.as_raw_fd())?;
    while !bytes.is_empty() {
        owned_pipe_ready(writer.as_raw_fd(), libc::POLLOUT, deadline)?;
        match writer.write(bytes) {
            Ok(0) => bail!("installed control write closed"),
            Ok(n) => bytes = &bytes[n..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error).context("installed control write"),
        }
    }
    Ok(())
}
fn read_frame<R: Read + AsRawFd, T: DeserializeOwned>(
    reader: &mut R,
    limit: usize,
    deadline: Instant,
) -> Result<T> {
    let mut prefix = [0; 4];
    read_exact(reader, &mut prefix, deadline)?;
    let len = usize::try_from(u32::from_be_bytes(prefix))?;
    if len == 0 || len > limit {
        bail!("installed control frame exceeds bound")
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    read_exact(reader, &mut bytes, deadline)?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid installed control frame"))
}
fn read_exact<R: Read + AsRawFd>(
    reader: &mut R,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    owned_pipe_nonblocking(reader.as_raw_fd())?;
    while !bytes.is_empty() {
        owned_pipe_ready(reader.as_raw_fd(), libc::POLLIN, deadline)?;
        match reader.read(bytes) {
            Ok(0) => bail!("installed control read closed"),
            Ok(n) => bytes = &mut bytes[n..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error).context("installed control read"),
        }
    }
    Ok(())
}
