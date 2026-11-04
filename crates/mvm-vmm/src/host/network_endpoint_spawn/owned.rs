//! Child-owned endpoint lifecycle. The detached compatibility path is separate.

use super::*;
use crate::host::process_exit::{ProcessExitObserver, ProcessExitWait, collect_after_exit_event};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::time::Instant;
use zeroize::Zeroizing;

const HANDSHAKE_LIMIT: usize = 1024 * 1024;
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const DROP_TIMEOUT: Duration = Duration::from_millis(100);

/// Original partition custody after matched Drained and positive Child exit.
/// This is not a disk-cleanup receipt; the parent keeps it through that barrier.
#[derive(Debug)]
#[must_use = "retain the original partition through parent disk cleanup"]
pub struct EndpointRetirement {
    handoff: mvm_core::host_lifetime::PreparedEndpointHandoff,
}
impl EndpointRetirement {
    pub fn projection(&self) -> &mvm_core::host_lifetime::EndpointPartitionProjection {
        self.handoff.partition().projection()
    }

    pub fn retains_partition_guard(
        &self,
        guard: &std::sync::Arc<dyn mvm_core::host_lifetime::EndpointPartitionGuard>,
    ) -> bool {
        self.handoff.partition().retains_guard(guard)
    }
}

/// Exclusive custody of the endpoint child, including its collected exit status.
///
/// No other thread may reap this child or change SIGCHLD disposition while this
/// owner exists. Sidecars are evidence, not handles: this type never removes them.
/// Explicit shutdown is required before the supervisor publishes finalization.
#[derive(Debug)]
#[must_use = "retain the endpoint until explicit shutdown confirms its exit"]
pub struct OwnedEndpoint {
    pub(super) child: Option<Child>,
    child_id: u32,
    pub(super) installed: Option<super::installed::InstalledCustody>,
    observer: Option<ProcessExitObserver>,
    exit_observed: bool,
    status: Option<ExitStatus>,
    signals_forbidden: bool,
    kill_requested: bool,
    #[cfg(test)]
    faults: Faults,
}

impl OwnedEndpoint {
    pub(super) fn new(child: Child) -> Self {
        let child_id = child.id();
        Self {
            child: Some(child),
            child_id,
            installed: None,
            observer: None,
            exit_observed: false,
            status: None,
            signals_forbidden: false,
            kill_requested: false,
            #[cfg(test)]
            faults: Faults::default(),
        }
    }

    /// The original child ID; never reconstructed from a sidecar.
    pub fn id(&self) -> u32 {
        self.child_id
    }

    /// The exact status collected by `Child::try_wait`, if already reaped.
    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.status
    }

    /// Transfer the original handoff once, after actual child and local drain
    /// barriers. No status/metadata argument can construct this receipt.
    pub fn take_retirement(&mut self) -> Result<EndpointRetirement> {
        if !self.exit_observed || !self.status.is_some_and(|status| status.success()) {
            bail!("original installed endpoint exit not confirmed")
        }
        if !self.installed.as_ref().is_some_and(|owner| owner.drained) {
            bail!("original installed endpoint drain unavailable or already consumed")
        }
        let installed = self
            .installed
            .take()
            .context("original installed endpoint custody unavailable")?;
        Ok(EndpointRetirement {
            handoff: installed.handoff,
        })
    }

    fn collect(&mut self) -> Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        #[cfg(test)]
        if self.faults.wait_error {
            self.signals_forbidden = true;
            bail!("injected owned child wait failure");
        }
        match self
            .child
            .as_mut()
            .context("original endpoint child unavailable")?
            .try_wait()
        {
            Ok(status) => {
                self.status = status;
                self.exit_observed |= status.is_some();
                Ok(status)
            }
            Err(error) => {
                // A failed wait cannot authorize a numeric signal, even if the
                // error is transient: another reaper may have released the PID.
                self.signals_forbidden = true;
                Err(error).context("collect owned endpoint exit status")
            }
        }
    }

    pub(super) fn arm(&mut self) -> Result<()> {
        if self.observer.is_none() && self.collect()?.is_none() {
            let pid = libc::pid_t::try_from(self.child_id)
                .context("endpoint child ID does not fit process ID")?;
            self.observer = Some(ProcessExitObserver::arm(pid)?);
        }
        Ok(())
    }

    pub(super) fn ensure_running(&mut self) -> Result<()> {
        if let Some(status) = self.collect()? {
            bail!("owned endpoint exited during startup: {status}");
        }
        Ok(())
    }

    /// Confirm the endpoint has exited and collect its status, or retain custody
    /// and all evidence on failure. A previously collected nonzero exit is an
    /// error, not a successful shutdown. A kill requested here is intentional.
    pub fn shutdown(&mut self) -> Result<()> {
        if self.installed.is_some() {
            return self.shutdown_installed(Instant::now() + STOP_TIMEOUT);
        }
        self.stop(Instant::now() + STOP_TIMEOUT)
    }

    /// Fence new installed child work without refunding any retained resources.
    pub fn close_admission(&mut self) -> Result<()> {
        let installed = self
            .installed
            .as_mut()
            .context("endpoint has no installed control owner")?;
        installed.input.take();
        Ok(())
    }

    fn shutdown_installed(&mut self, deadline: Instant) -> Result<()> {
        self.close_admission()?;
        self.installed
            .as_mut()
            .context("installed custody unavailable")?
            .read_drained(deadline)?;
        self.arm()?;
        if self.collect()?.is_none() {
            let observer = self
                .observer
                .as_ref()
                .context("original endpoint observer missing")?;
            if observer.wait_event(deadline)? != ProcessExitWait::Exited {
                bail!("installed endpoint child exit unconfirmed")
            }
            let status = collect_after_exit_event(deadline, || self.collect())?
                .context("installed endpoint exit not collected")?;
            self.check_status(status)?;
        }
        let status = self.status.context("installed endpoint exit missing")?;
        if !status.success() {
            bail!("installed endpoint did not exit cleanly")
        }
        Ok(())
    }

    fn stop(&mut self, deadline: Instant) -> Result<()> {
        if let Some(status) = self.collect()? {
            return self.check_status(status);
        }
        // Try to arm before signaling. If registration fails, still terminate
        // the exclusively owned child, but retain the owner and report failure
        // rather than treating the kill request as proof of exit.
        let armed = self.arm();
        if let Some(status) = self.collect()? {
            return self.check_status(status);
        }
        // try_wait immediately precedes signaling. With exclusive reaping and
        // default SIGCHLD, even a concurrently exited child retains its PID.
        if !self.exit_observed && !self.kill_requested {
            if self.signals_forbidden {
                bail!("endpoint child custody is uncertain; refusing further signals");
            }
            require_child_custody()?;
            #[cfg(test)]
            {
                self.faults.signal_attempts += 1;
                if self.faults.kill_error {
                    bail!("injected owned child kill failure");
                }
            }
            self.child
                .as_mut()
                .context("original endpoint child unavailable")?
                .kill()
                .context("kill owned endpoint")?;
            self.kill_requested = true;
        }
        armed?;
        #[cfg(test)]
        if self.faults.timeout {
            bail!("injected endpoint exit event timeout");
        }
        let observer = self
            .observer
            .as_ref()
            .ok_or_else(|| anyhow!("owned endpoint has no exit observer"))?;
        if observer.wait_event(deadline)? == ProcessExitWait::TimedOut {
            bail!("owned endpoint shutdown timed out; exit is unconfirmed");
        }
        self.exit_observed = true;
        // Never block in wait, even after an event. Only a collected status is
        // proof; an event with no collectable status remains an error.
        let status = collect_after_exit_event(deadline, || self.collect())?
            .ok_or_else(|| anyhow!("endpoint exit event has no collectable child status"))?;
        self.check_status(status)
    }

    fn check_status(&self, status: ExitStatus) -> Result<()> {
        if status.success() || (self.kill_requested && status.signal() == Some(libc::SIGKILL)) {
            Ok(())
        } else {
            Err(anyhow!("owned endpoint exited unsuccessfully: {status}"))
        }
    }
}

impl Drop for OwnedEndpoint {
    fn drop(&mut self) {
        if self.status.is_none() {
            let _ = self.stop(Instant::now() + DROP_TIMEOUT);
        }
        if self.installed.as_ref().is_some_and(|owner| {
            !owner.drained || self.status.is_none_or(|status| !status.success())
        }) {
            // Actual child death alone does not prove owned stores cleaned.
            // Keep one original partition/holder/child quarantine until process
            // exit; neither partial startup nor Drop publishes retirement.
            std::mem::forget((self.installed.take(), self.child.take()));
        }
    }
}

/// A startup failure that still carries the actual child when rollback was
/// uncertain. Downcast the spawn error and retry `endpoint_mut().shutdown()`;
/// do not finalize runtime state while cleanup remains unconfirmed.
#[derive(Debug)]
pub struct OwnedEndpointSpawnError {
    pub(super) reason: anyhow::Error,
    pub(super) endpoint: OwnedEndpoint,
}

impl OwnedEndpointSpawnError {
    /// Access the retained child owner after a failed startup.
    pub fn endpoint_mut(&mut self) -> &mut OwnedEndpoint {
        &mut self.endpoint
    }
}

impl fmt::Display for OwnedEndpointSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "owned endpoint startup failed: {}", self.reason)
    }
}

impl std::error::Error for OwnedEndpointSpawnError {}

/// Spawn an endpoint without detaching its ownership from the supervisor.
///
/// Uses the compatibility path's configuration and command assembly, but never
/// its reaping handshake reader, PID guard, or stale-sidecar deletion.
pub fn spawn_network_endpoint_owned(
    mut params: SubstitutionSpawnParams<'_>,
) -> Result<OwnedEndpoint> {
    require_child_custody()?;
    if params.lifetime != EndpointLifetime::Launcher {
        bail!(
            "owned endpoint requires launcher lifetime; a VM keeper does not own the serving child"
        );
    }
    let env_path = mvm_core::config::vm_substitution_env_path(params.vm_name);
    refuse_existing_evidence(&params, &env_path)?;
    if params.egress_proxy.is_none() {
        params.egress_proxy = EgressProxySpawnConfig::from_host_config()?;
    }
    if let Some(proxy) = &params.egress_proxy {
        proxy.resolve()?;
    }
    params.session_marker = Some(params.state_dir.join(SUBST_SESSION_FILE));
    let config = Zeroizing::new(serde_json::to_vec(&build_endpoint_config_json(&params))?);
    if config.len() > HANDSHAKE_LIMIT {
        bail!("owned endpoint configuration exceeds byte limit");
    }
    let bin = resolve_network_endpoint_path()?;
    spawn_prepared(params, &env_path, &bin, &config, handshake_timeout())
}

fn spawn_prepared(
    params: SubstitutionSpawnParams<'_>,
    env_path: &Path,
    bin: &Path,
    config: &[u8],
    timeout: Duration,
) -> Result<OwnedEndpoint> {
    let deadline = handshake_deadline(timeout)?;
    let log = create_evidence(&endpoint_stderr_log_path(params.state_dir))?;
    let child = endpoint_command(
        mvm_core::env_hygiene::helper_command(bin),
        params.lifetime,
        params.state_dir,
        log,
    )
    .spawn()
    .context("spawn owned endpoint")?;
    let mut endpoint = OwnedEndpoint::new(child);
    let result: Result<()> = (|| {
        // Write evidence before any fallible handshake operation. The owned
        // lifecycle never signals through this file — custody is direct — but
        // it remains even when rollback is uncertain, and the start time
        // beside the pid is what lets a later reap tell this process from
        // whatever is handed its pid after it exits.
        create_evidence(&params.state_dir.join(SUBST_PID_FILE))?
            .write_all(EndpointPid::of_child(endpoint.id()).render().as_bytes())?;
        endpoint.arm()?;
        let handshake = exchange_until(&mut endpoint, config, deadline)?;
        if let Some(parent) = env_path.parent() {
            std::fs::create_dir_all(parent).context("create endpoint environment directory")?;
        }
        let env = serde_json::to_vec(&handshake.env)
            .map_err(|_| anyhow!("encode endpoint environment"))?;
        create_evidence(env_path)?.write_all(&env)?;
        endpoint.ensure_running()?;
        record_secret_fingerprints(params.vm_name, handshake.input_fingerprints);
        Ok(())
    })();
    if let Err(reason) = result {
        let reason = match endpoint.shutdown() {
            Ok(()) => reason,
            Err(cleanup) => reason.context(format!("endpoint rollback unconfirmed: {cleanup}")),
        };
        return Err(OwnedEndpointSpawnError { reason, endpoint }.into());
    }
    Ok(endpoint)
}

/// Configure an endpoint command built by `helper_command`: its lifetime and
/// stdio. Both spawn paths share it, so the endpoint's process shape cannot
/// drift between them.
pub(super) fn endpoint_command(
    mut cmd: std::process::Command,
    lifetime: EndpointLifetime,
    state_dir: &Path,
    log_file: std::fs::File,
) -> std::process::Command {
    select_lifetime(&mut cmd, lifetime, state_dir);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(log_file);
    cmd
}

pub(super) fn create_evidence(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("create owned endpoint evidence without replacing existing state")
}

pub(super) fn refuse_existing_evidence(
    params: &SubstitutionSpawnParams<'_>,
    env: &Path,
) -> Result<()> {
    let mut paths = vec![
        params.state_dir.join(SUBST_PID_FILE),
        params.state_dir.join(SUBST_SESSION_FILE),
        session_ready_socket_path(params.state_dir),
        connector_socket_path(params.state_dir),
        endpoint_stderr_log_path(params.state_dir),
        env.to_owned(),
    ];
    if let EndpointTransport::Uds { path } = &params.transport {
        paths.push(path.clone());
    }
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect endpoint evidence"),
            Ok(_) => bail!("refusing existing endpoint evidence; reconcile previous owner first"),
        }
    }
    Ok(())
}

pub(super) fn require_child_custody() -> Result<()> {
    crate::host::process_exit::require_owned_child_custody()
        .context("query endpoint child custody")?;
    Ok(())
}

pub(crate) fn nonblocking(fd: libc::c_int) -> Result<()> {
    // SAFETY: fd is borrowed from an owned live pipe.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: the same pipe remains owned while its status flags are changed.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error()).context("set owned endpoint pipe nonblocking");
    }
    Ok(())
}

pub(crate) fn ready(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("owned endpoint handshake timed out");
        }
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = remaining.as_millis().saturating_add(1);
        let timeout = libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX);
        // SAFETY: one valid poll descriptor, borrowed only for this call.
        let count = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if count > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                bail!("owned endpoint pipe descriptor is invalid");
            }
            return Ok(());
        }
        if count < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error()).context("wait for endpoint pipe readiness");
        }
    }
}

fn handshake_deadline(timeout: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("owned endpoint handshake timeout exceeds clock range"))
}

fn exchange_until(
    endpoint: &mut OwnedEndpoint,
    config: &[u8],
    deadline: Instant,
) -> Result<EndpointHandshake> {
    let mut stdin = endpoint
        .child
        .as_mut()
        .context("original endpoint child unavailable")?
        .stdin
        .take()
        .ok_or_else(|| anyhow!("endpoint stdin missing"))?;
    let mut stdout = endpoint
        .child
        .as_mut()
        .context("original endpoint child unavailable")?
        .stdout
        .take()
        .ok_or_else(|| anyhow!("endpoint stdout missing"))?;
    nonblocking(stdin.as_raw_fd())?;
    nonblocking(stdout.as_raw_fd())?;
    let mut pending = config;
    while !pending.is_empty() {
        endpoint.ensure_running()?;
        ready(stdin.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stdin.write(pending) {
            Ok(0) => bail!("owned endpoint config pipe closed"),
            Ok(n) => pending = &pending[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e).context("write owned endpoint config"),
        }
    }
    drop(stdin);
    let mut line = Zeroizing::new(Vec::new());
    let mut buffer = [0_u8; 4096];
    loop {
        endpoint.ensure_running()?;
        ready(stdout.as_raw_fd(), libc::POLLIN, deadline)?;
        match stdout.read(&mut buffer) {
            Ok(0) => bail!("owned endpoint closed stdout before ready handshake"),
            Ok(n) => {
                let bytes = &buffer[..n];
                let end = bytes.iter().position(|byte| *byte == b'\n');
                let bytes = &bytes[..end.unwrap_or(n)];
                if line.len() + bytes.len() > HANDSHAKE_LIMIT {
                    bail!("owned endpoint handshake exceeds byte limit");
                }
                line.extend_from_slice(bytes);
                if end.is_some() {
                    endpoint.ensure_running()?;
                    // Never include parse diagnostics, stdout or stderr: a
                    // malformed helper response can contain real credentials.
                    return serde_json::from_slice(&line)
                        .map_err(|_| anyhow!("invalid owned endpoint handshake"));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e).context("read owned endpoint handshake"),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[derive(Debug, Default)]
struct Faults {
    kill_error: bool,
    wait_error: bool,
    timeout: bool,
    signal_attempts: usize,
}
