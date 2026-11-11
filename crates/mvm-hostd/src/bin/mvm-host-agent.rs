//! `mvm-host-agent` — the resident per-tenant host-services daemon.
//!
//! One process per tenant (not per VM). It binds a host-only control UDS,
//! accepts host-signed `RegisterVm`/`DeregisterVm` messages, and for each
//! registered VM binds that VM's `BROKER_PORT` socket and serves
//! `host.audit.v1` (and future host services) on it. A tenant's microVMs are
//! *registrations*, not processes.
//!
//! Spawn contract:
//!
//! 1. The supervisor cosign-verifies this binary at spawn (supervisor side).
//! 2. It spawns this process under the tenant's cgroup + namespaces + seccomp
//!    + setpriv (supervisor side).
//! 3. It writes a JSON [`HostAgentConfig`] to stdin, then closes stdin.
//! 4. This process binds the control UDS (mode 0700) and serves until killed.
//!
//! It holds **no signing key** — it verifies control messages against the host
//! signer *public* key and forwards audit/signing requests to its supervised
//! signer-helper child. The moat (keyless parser / key-holding signer) is
//! preserved; this is the keyless half.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};

use mvm_hostd::audit_signer::config::SignerHelperConfig;
use mvm_hostd::broker::daemon::{HostAgentConfig, HostAgentDaemon};
use mvm_hostd::host_agent_idle::IdleProposal;
use mvm_hostd::watcher_jobs::{WatcherDrainReceipt, WatcherJobOwner};
use mvm_vmm::host::installed_owner::{
    Epoch, HolderLease, InstallationBinding, InstallationOwner, Recovery, spawn_with_resource_lease,
};

#[cfg(all(test, unix))]
#[path = "mvm-host-agent/signer_custody_tests.rs"]
mod signer_custody_tests;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const HOST_AGENT_WORKER_ENV: &str = "MVM_HOST_AGENT_WORKER";
const SIGNER_HELPER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_RESTART_BACKOFF: Duration = Duration::from_millis(250);

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-host-agent stdin read failed")?;
    Ok(buf)
}

fn is_worker_mode() -> bool {
    std::env::var(HOST_AGENT_WORKER_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn worker_pid_path(cfg: &HostAgentConfig) -> PathBuf {
    mvm_core::config::host_agent_worker_pid(&cfg.tenant_id)
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    // SAFETY: kill(pid, 0) only probes process existence/permission and does
    // not deliver a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn kill_process_group(pgid: libc::pid_t, sig: libc::c_int) {
    // SAFETY: negative pid targets the process group created for the worker by
    // setsid() below. Errors are intentionally ignored by callers during cleanup.
    unsafe {
        libc::kill(-pgid, sig);
    }
}

fn reap_stale_worker_group(pid_path: &Path) {
    if let Some(pid) = read_pid(pid_path)
        && pid_alive(pid)
    {
        kill_process_group(pid, libc::SIGTERM);
        std::thread::sleep(Duration::from_millis(50));
        kill_process_group(pid, libc::SIGKILL);
    }
    let _ = std::fs::remove_file(pid_path);
}

async fn wait_for_worker_ready(
    child: &mut Child,
    control_socket: &Path,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::UnixStream::connect(control_socket)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .context("poll mvm-host-agent worker status")?
        {
            anyhow::bail!("mvm-host-agent worker exited before readiness: {status}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    anyhow::bail!(
        "mvm-host-agent worker did not bind {} within {:?}",
        control_socket.display(),
        timeout
    )
}

async fn spawn_worker(raw_cfg: &[u8]) -> Result<Child> {
    let bin = std::env::current_exe().context("resolve mvm-host-agent current_exe")?;
    let mut command = Command::from(mvm_core::env_hygiene::helper_command(&bin));
    command
        .env(HOST_AGENT_WORKER_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    // SAFETY: pre_exec runs after fork and before exec. The closure only calls
    // setsid(), which is async-signal-safe, to put the worker and its helper
    // descendants in a process group the supervisor can reap.
    unsafe {
        command.as_std_mut().pre_exec(|| {
            let rc = libc::setsid();
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn mvm-host-agent worker {}", bin.display()))?;
    let mut stdin = child
        .stdin
        .take()
        .context("mvm-host-agent worker stdin was not piped")?;
    stdin
        .write_all(raw_cfg)
        .await
        .context("pipe HostAgentConfig to mvm-host-agent worker")?;
    drop(stdin);
    Ok(child)
}

// One fixed stack and two one-shot results per tenant's existing signer role.
// The actor starts before spawning, so a failed/canceled async requester never
// becomes the owner of a spawned Child or a cancelable task carrying one.
const SIGNER_ACTOR_STACK_BYTES: usize = 256 * 1024;
const SIGNER_CONFIG_MAX_BYTES: usize = 64 * 1024;

enum SignerReadiness {
    Ready,
    NotStarted(String),
    Failed(String),
}

#[derive(Clone, Copy)]
enum SignerOutcome {
    NotStarted,
    Collected(std::process::ExitStatus),
}

struct SignerChild {
    lifeline: Option<std::os::unix::net::UnixStream>,
    completion: oneshot::Receiver<SignerOutcome>,
    outcome: Option<SignerOutcome>,
    completion_lost: bool,
    readiness_error: Option<String>,
}
impl SignerChild {
    fn request_stop(&mut self) {
        if let Some(lifeline) = self.lifeline.take() {
            let _ = lifeline.shutdown(std::net::Shutdown::Both);
        }
    }
    async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if self.completion_lost {
            return Err(std::io::Error::other(
                "signer actor lost completion; original collection is unproven",
            ));
        }
        if self.outcome.is_none() {
            match (&mut self.completion).await {
                Ok(outcome) => self.outcome = Some(outcome),
                Err(_) => {
                    self.completion_lost = true;
                    return Err(std::io::Error::other(
                        "signer actor lost completion; original collection is unproven",
                    ));
                }
            }
        }
        match self.outcome {
            Some(SignerOutcome::Collected(status)) => Ok(status),
            Some(SignerOutcome::NotStarted) => {
                Err(std::io::Error::other("signer was never spawned"))
            }
            None => unreachable!("terminal outcome was just recorded"),
        }
    }
    #[cfg(test)]
    async fn kill(&mut self) -> std::io::Result<()> {
        self.request_stop();
        self.wait().await.map(|_| ())
    }
}
impl Drop for SignerChild {
    fn drop(&mut self) {
        // Only the bounded lifeline closes here. The noncancelable actor still
        // owns and collects the original Child, even if every waiter disappears.
        self.request_stop();
    }
}

struct OriginalSignerChild {
    child: std::process::Child,
    parent_lease: Option<HolderLease>,
    completion: Option<oneshot::Sender<SignerOutcome>>,
    status: Option<std::process::ExitStatus>,
    custody_uncertain: bool,
    exit_observed: bool,
}
impl OriginalSignerChild {
    fn collect(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if self.custody_uncertain {
            return Err(std::io::Error::other("signer child custody is uncertain"));
        }
        if self.status.is_some() {
            return Ok(self.status);
        }
        if let Err(error) = mvm_vmm::host::process_exit::require_owned_child_custody() {
            self.custody_uncertain = true;
            return Err(error);
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.finish(status);
                Ok(Some(status))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                self.custody_uncertain = true;
                Err(error)
            }
        }
    }
    fn collect_after_event(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.exit_observed = true;
        if self.custody_uncertain {
            return Err(std::io::Error::other("signer child custody is uncertain"));
        }
        if let Err(error) = mvm_vmm::host::process_exit::require_owned_child_custody() {
            self.custody_uncertain = true;
            return Err(error);
        }
        // The event can precede collectability on Darwin. Waiting here blocks
        // only this original owner's thread, never the async runtime or a lock.
        match self.child.wait() {
            Ok(status) => {
                self.finish(status);
                Ok(status)
            }
            Err(error) => {
                self.custody_uncertain = true;
                Err(error)
            }
        }
    }
    fn finish(&mut self, status: std::process::ExitStatus) {
        self.status = Some(status);
        self.parent_lease.take();
        tracing::info!(
            event = "signer_original_child_collected",
            status = %status,
            "mvm-signer-helper original Child collected"
        );
        #[cfg(test)]
        signer_custody_tests::record_collection(status);
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(SignerOutcome::Collected(status));
        }
    }
}
impl Drop for OriginalSignerChild {
    fn drop(&mut self) {
        if self.status.is_some() {
            return;
        }
        // This guard exists only on the dedicated actor thread. After a
        // fallible setup, cancellation, observation error or unwind, do not let
        // std::Child::drop silently discard custody. Never restore an uncertain
        // numeric identity by retrying a wait or signaling a reused PID.
        if !self.custody_uncertain
            && mvm_vmm::host::process_exit::require_owned_child_custody().is_ok()
        {
            if self.collect().ok().flatten().is_some() {
                return;
            }
            if !self.custody_uncertain {
                if !self.exit_observed {
                    let _ = self.child.kill();
                }
                match self.child.wait() {
                    Ok(status) => {
                        self.finish(status);
                        return;
                    }
                    Err(_) => self.custody_uncertain = true,
                }
            }
        }
        // Quarantine this single original owner, including its completion
        // sender. No completion/credit/replacement can be manufactured from a
        // failed wait. There is no polling or additional thread allocation.
        loop {
            std::thread::park();
        }
    }
}

fn signer_stop_requested(wake: &mut std::os::unix::net::UnixStream) -> std::io::Result<bool> {
    let mut byte = [0];
    match wake.read(&mut byte) {
        Ok(0) => Ok(true),
        Ok(_) => Err(std::io::Error::other("unexpected signer lifeline bytes")),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error),
    }
}

fn write_signer_config(
    stdin: &mut std::process::ChildStdin,
    wake: &mut std::os::unix::net::UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use std::io::Write;
    let flags = rustix::fs::fcntl_getfl(&*stdin)?;
    rustix::fs::fcntl_setfl(&*stdin, flags | rustix::fs::OFlags::NONBLOCK)?;
    let mut offset = 0;
    while offset < bytes.len() {
        if signer_stop_requested(wake)? || Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "signer startup canceled or expired",
            ));
        }
        match stdin.write(&bytes[offset..]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let timeout =
                    Timespec::try_from(deadline.saturating_duration_since(Instant::now()))
                        .map_err(std::io::Error::other)?;
                let mut fds = [
                    PollFd::new(&*stdin, PollFlags::OUT),
                    PollFd::new(&*wake, PollFlags::IN),
                ];
                match poll(&mut fds, Some(&timeout)) {
                    Ok(_) => (),
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn probe_signer_socket(
    path: &Path,
    wake: &std::os::unix::net::UnixStream,
    deadline: Instant,
) -> std::io::Result<()> {
    // Only this actor endpoint is duplicated, never the facade endpoint whose
    // final close is the cancellation signal. No Child moves into this future.
    let cancellation = wake.try_clone()?;
    tokio::runtime::Handle::current().block_on(async {
        use tokio::io::AsyncReadExt;
        let mut cancellation = tokio::net::UnixStream::from_std(cancellation)?;
        let socket = tokio::net::UnixSocket::new_stream()?;
        let mut byte = [0];
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "signer readiness deadline"))
            }
            _ = cancellation.read(&mut byte) => {
                Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "signer readiness canceled"))
            }
            connected = socket.connect(path) => {
                let connected = connected?;
                // SO_ERROR==0 alone can describe an unconnected Unix socket
                // after backlog EAGAIN. Require actual connection completion.
                connected.peer_addr()?;
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "signer readiness deadline"));
                }
                Ok(())
            }
        }
    })
}

struct SignerActorStart {
    bin: PathBuf,
    uds_path: PathBuf,
    bytes: Vec<u8>,
    resources: Arc<InstallationBinding>,
    startup_deadline: Instant,
}

fn run_signer_actor(
    start: SignerActorStart,
    mut wake: std::os::unix::net::UnixStream,
    ready: oneshot::Sender<SignerReadiness>,
    completion: oneshot::Sender<SignerOutcome>,
) {
    use mvm_vmm::host::process_exit::{ProcessExitObserver, wait_process_exit_events};
    use std::os::fd::AsFd;
    let SignerActorStart {
        bin,
        uds_path,
        bytes,
        resources,
        startup_deadline,
    } = start;
    let spawned = (|| -> std::io::Result<(std::process::Child, HolderLease)> {
        mvm_vmm::host::process_exit::require_owned_child_custody()?;
        if signer_stop_requested(&mut wake)? || Instant::now() >= startup_deadline {
            return Err(std::io::Error::other(
                "signer startup canceled before spawn",
            ));
        }
        let mut command = mvm_core::env_hygiene::helper_command(&bin);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let lease = HolderLease::acquire(&resources.root, resources.key, resources.generation)
            .map_err(std::io::Error::other)?;
        spawn_with_resource_lease(command, lease)
    })();
    let (child, parent_lease) = match spawned {
        Ok(originals) => originals,
        Err(error) => {
            let _ = completion.send(SignerOutcome::NotStarted);
            let _ = ready.send(SignerReadiness::NotStarted(error.to_string()));
            return;
        }
    };
    let mut owner = OriginalSignerChild {
        child,
        parent_lease: Some(parent_lease),
        completion: Some(completion),
        status: None,
        custody_uncertain: false,
        exit_observed: false,
    };
    let mut ready = Some(ready);
    let serving = (|| -> Result<()> {
        let observer = ProcessExitObserver::arm(owner.child.id().try_into()?)?;
        let mut stdin = owner
            .child
            .stdin
            .take()
            .context("mvm-signer-helper stdin was not piped")?;
        write_signer_config(&mut stdin, &mut wake, &bytes, startup_deadline)?;
        drop(stdin);
        drop(bytes);
        // Keep the existing 25ms bounded UDS-connect readiness probe. Child
        // exit and requester cancellation are event-driven, not PID probes.
        loop {
            if let Some(status) = owner.collect()? {
                anyhow::bail!("mvm-signer-helper exited before readiness: {status}");
            }
            if signer_stop_requested(&mut wake)? || Instant::now() >= startup_deadline {
                anyhow::bail!(
                    "mvm-signer-helper startup canceled or exceeded its original readiness deadline"
                );
            }
            #[cfg(test)]
            signer_custody_tests::record_connect_attempt();
            if probe_signer_socket(&uds_path, &wake, startup_deadline).is_ok() {
                if signer_stop_requested(&mut wake)? || Instant::now() >= startup_deadline {
                    anyhow::bail!("signer readiness canceled or expired before publication");
                }
                break;
            }
            let probe = startup_deadline.min(Instant::now() + Duration::from_millis(25));
            let events = wait_process_exit_events(&[&observer], Some(wake.as_fd()), Some(probe))?;
            if events.exited.contains(&0) {
                let status = owner.collect_after_event()?;
                anyhow::bail!("mvm-signer-helper exited before readiness: {status}");
            }
        }
        ready
            .take()
            .expect("one startup result")
            .send(SignerReadiness::Ready)
            .map_err(|_| anyhow::anyhow!("signer startup requester disappeared"))?;
        loop {
            if owner.collect()?.is_some() {
                return Ok(());
            }
            let events = wait_process_exit_events(&[&observer], Some(wake.as_fd()), None)?;
            if events.exited.contains(&0) {
                owner.collect_after_event()?;
                return Ok(());
            }
            if events.wake_ready && signer_stop_requested(&mut wake)? {
                return Ok(());
            }
        }
    })();
    if let Err(error) = serving
        && let Some(ready) = ready.take()
    {
        let _ = ready.send(SignerReadiness::Failed(format!("{error:#}")));
    }
    // The actor's guard stops and collects before it can emit terminal status.
    // An unconfirmed wait retains the guard here instead of returning/retrying.
}

async fn spawn_signer_helper(
    cfg: &HostAgentConfig,
    resources: Arc<InstallationBinding>,
) -> Result<SignerChild> {
    let startup_deadline = Instant::now() + SIGNER_HELPER_READY_TIMEOUT;
    let bin = signer_helper_bin_path()?;
    let helper_cfg = SignerHelperConfig {
        tenant_id: cfg.tenant_id.clone(),
        uds_path: cfg.signer_helper_uds_path.clone(),
        software_chain_key_path: Some(cfg.software_chain_key_path.clone()),
        max_frame_bytes: cfg.max_frame_bytes,
    };
    let bytes = serde_json::to_vec(&helper_cfg)?;
    anyhow::ensure!(
        bytes.len() <= SIGNER_CONFIG_MAX_BYTES,
        "signer configuration exceeds bounded actor workspace"
    );
    let (lifeline, wake) = std::os::unix::net::UnixStream::pair()?;
    wake.set_nonblocking(true)?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let (completion_tx, completion_rx) = oneshot::channel();
    let uds = cfg.signer_helper_uds_path.clone();
    // Capture only the existing I/O reactor for nonblocking UDS probing. The
    // actor owns its Child independently of any cancellable async operation.
    let runtime = tokio::runtime::Handle::current();
    // No Child exists until this successfully started thread runs.
    std::thread::Builder::new()
        .name("mvm-signer-owner".into())
        .stack_size(SIGNER_ACTOR_STACK_BYTES)
        .spawn(move || {
            let _runtime = runtime.enter();
            run_signer_actor(
                SignerActorStart {
                    bin,
                    uds_path: uds,
                    bytes,
                    resources,
                    startup_deadline,
                },
                wake,
                ready_tx,
                completion_tx,
            )
        })?;
    let mut child = SignerChild {
        lifeline: Some(lifeline),
        completion: completion_rx,
        outcome: None,
        completion_lost: false,
        readiness_error: None,
    };
    match tokio::time::timeout_at(tokio::time::Instant::from_std(startup_deadline), ready_rx).await
    {
        Ok(Ok(SignerReadiness::Ready)) => (),
        Ok(Ok(SignerReadiness::NotStarted(error))) => return Err(anyhow::anyhow!(error)),
        result => {
            child.readiness_error = Some(match result {
                Ok(Ok(SignerReadiness::Failed(error))) => error,
                _ => "signer readiness unresolved at original deadline".into(),
            });
            child.request_stop();
        }
    }
    if Instant::now() >= startup_deadline && child.readiness_error.is_none() {
        child.readiness_error = Some("signer readiness observed after original deadline".into());
        child.request_stop();
    }
    Ok(child)
}

fn signer_helper_bin_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("MVM_SIGNER_HELPER_PATH")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    let current = std::env::current_exe().context("resolve mvm-host-agent current_exe")?;
    Ok(current.with_file_name("mvm-signer-helper"))
}

struct SignerDrainReceipt;

struct SignerSupervisionHandle {
    stop: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<SignerDrainReceipt>>,
    receipt: Option<SignerDrainReceipt>,
    unresolved: bool,
    active_stop: Arc<std::sync::Mutex<Option<std::os::unix::net::UnixStream>>>,
}

impl SignerSupervisionHandle {
    fn spawn(
        cfg: HostAgentConfig,
        daemon: Arc<Mutex<HostAgentDaemon>>,
        first_ready: oneshot::Sender<Result<()>>,
        resources: Arc<InstallationBinding>,
    ) -> Self {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let active_stop = Arc::new(std::sync::Mutex::new(None));
        let task = tokio::spawn(supervise_signer_helper(
            cfg,
            daemon,
            first_ready,
            resources,
            stopped,
            active_stop.clone(),
        ));
        Self {
            stop,
            task: Some(task),
            receipt: None,
            unresolved: false,
            active_stop,
        }
    }

    fn request_stop(&self) {
        self.stop.send_replace(true);
        if let Some(control) = self
            .active_stop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            // Same-end owned control, never a PID or opposite lifeline clone.
            // This also interrupts a supervisor blocked in canonical helper RPC.
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
    }

    async fn drain(&mut self) -> Result<()> {
        self.request_stop();
        if let Some(task) = self.task.as_mut() {
            let result = task.await;
            self.task = None;
            match result {
                Ok(receipt) => self.receipt = Some(receipt),
                Err(_) => self.unresolved = true,
            }
        }
        anyhow::ensure!(
            self.receipt.is_some() && !self.unresolved,
            "original signer drain remains unresolved"
        );
        Ok(())
    }
}

impl Drop for SignerSupervisionHandle {
    fn drop(&mut self) {
        self.request_stop();
    }
}

fn stop_requested(stop: &tokio::sync::watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}

async fn wait_for_stop(stop: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if stop_requested(stop) || stop.changed().await.is_err() {
            return;
        }
    }
}

async fn supervise_signer_helper(
    cfg: HostAgentConfig,
    daemon: Arc<Mutex<HostAgentDaemon>>,
    first_ready: oneshot::Sender<Result<()>>,
    resources: Arc<InstallationBinding>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    active_stop: Arc<std::sync::Mutex<Option<std::os::unix::net::UnixStream>>>,
) -> SignerDrainReceipt {
    let mut first_ready = Some(first_ready);
    loop {
        if stop_requested(&stop) {
            return SignerDrainReceipt;
        }
        match spawn_signer_helper(&cfg, resources.clone()).await {
            Ok(mut child) => {
                if child.readiness_error.is_none() {
                    match child
                        .lifeline
                        .as_ref()
                        .map(std::os::unix::net::UnixStream::try_clone)
                        .transpose()
                    {
                        Ok(control) => {
                            *active_stop
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = control
                        }
                        Err(error) => {
                            child.readiness_error =
                                Some(format!("signer stop control unavailable: {error}"));
                            child.request_stop();
                        }
                    }
                }
                if stop_requested(&stop) {
                    child.request_stop();
                    if child.wait().await.is_err() {
                        let _retained_owner = child;
                        std::future::pending::<()>().await;
                    }
                    return SignerDrainReceipt;
                }
                if let Some(reason) = child.readiness_error.take() {
                    tracing::warn!(tenant_id = %cfg.tenant_id, %reason, "signer startup unresolved; retaining original owner before retry");
                    if let Err(error) = child.wait().await
                        && !matches!(child.outcome, Some(SignerOutcome::NotStarted))
                    {
                        tracing::error!(tenant_id = %cfg.tenant_id, %error, "signer collection unproven; replacement fenced");
                        let _retained_owner = child;
                        std::future::pending::<()>().await;
                        unreachable!("unresolved signer owner cannot restart");
                    }
                    // Only the actor's actual collected status permits retry.
                    tokio::select! {
                        biased;
                        () = wait_for_stop(&mut stop) => return SignerDrainReceipt,
                        () = tokio::time::sleep(Duration::from_millis(500)) => {}
                    }
                    continue;
                }
                let lane = { daemon.lock().await.mutation_lane() };
                // The same original lane orders replay against prepared
                // registration/journal mutations. No daemon lock covers RPC.
                let rebound = match lane.acquire_owned().await {
                    Ok(permit) => {
                        let replay = { daemon.lock().await.signer_registration_replay() };
                        tokio::task::spawn_blocking(move || {
                            let _permit = permit;
                            replay.execute()
                        })
                        .await
                        .map_err(|_| anyhow::anyhow!("original signer replay task failed"))
                        .and_then(|result| result)
                    }
                    Err(_) => Err(anyhow::anyhow!("original mutation lane closed")),
                };
                match rebound {
                    Ok(count) => {
                        tracing::info!(
                            tenant_id = %cfg.tenant_id,
                            registrations = count,
                            "mvm-signer-helper ready"
                        );
                        if let Some(tx) = first_ready.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            tenant_id = %cfg.tenant_id,
                            error = %e,
                            "mvm-signer-helper registration replay failed"
                        );
                        // Rebinding failed after a real spawn. Fence and
                        // collect that original helper before an ordinary
                        // startup error or a retry can replace it.
                        child.request_stop();
                        if let Err(error) = child.wait().await {
                            tracing::error!(tenant_id = %cfg.tenant_id, %error, "signer cleanup unproven; replacement fenced");
                            let _retained_owner = child;
                            std::future::pending::<()>().await;
                            unreachable!("unresolved signer owner cannot restart");
                        }
                        if let Some(tx) = first_ready.take() {
                            let _ = tx.send(Err(e));
                            return SignerDrainReceipt;
                        }
                        tokio::select! {
                            biased;
                            () = wait_for_stop(&mut stop) => return SignerDrainReceipt,
                            () = tokio::time::sleep(Duration::from_millis(500)) => {}
                        }
                        continue;
                    }
                }

                let exit = tokio::select! {
                    biased;
                    () = wait_for_stop(&mut stop) => None,
                    status = child.wait() => Some(status),
                };
                let Some(exit) = exit else {
                    child.request_stop();
                    if child.wait().await.is_err() {
                        let _retained_owner = child;
                        std::future::pending::<()>().await;
                    }
                    return SignerDrainReceipt;
                };
                match exit {
                    Ok(status) => tracing::warn!(
                        tenant_id = %cfg.tenant_id,
                        status = %status,
                        "mvm-signer-helper exited; restarting"
                    ),
                    Err(e) => {
                        tracing::error!(tenant_id = %cfg.tenant_id, error = %e, "mvm-signer-helper collection unproven; replacement fenced");
                        let _retained_owner = child;
                        std::future::pending::<()>().await;
                    }
                }
            }
            Err(e) => {
                if let Some(tx) = first_ready.take() {
                    let _ = tx.send(Err(e));
                    return SignerDrainReceipt;
                }
                tracing::warn!(
                    tenant_id = %cfg.tenant_id,
                    error = %e,
                    "mvm-signer-helper spawn failed; retrying"
                );
            }
        }
        active_stop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        tokio::select! {
            biased;
            () = wait_for_stop(&mut stop) => return SignerDrainReceipt,
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

/// Retains all three original tasks and their finite cleanup-job owners.
/// Joining is cancellation-safe: completed handles are cached before the next
/// await, so expiry of the coordinator grace never drops or re-polls a task.
struct WatcherSet {
    stop: tokio::sync::watch::Sender<bool>,
    daemon: Arc<Mutex<HostAgentDaemon>>,
    watched_sessions: Arc<std::sync::atomic::AtomicUsize>,
    idle_timeout: Option<Duration>,
    idle: Option<tokio::task::JoinHandle<Option<IdleProposal>>>,
    sessions: Option<
        tokio::task::JoinHandle<
            Result<WatcherDrainReceipt, mvm_hostd::watcher_jobs::WatcherDrainError>,
        >,
    >,
    health: Option<
        tokio::task::JoinHandle<
            Result<WatcherDrainReceipt, mvm_hostd::watcher_jobs::WatcherDrainError>,
        >,
    >,
    session_jobs: WatcherJobOwner,
    health_jobs: WatcherJobOwner,
    session_receipt: Option<WatcherDrainReceipt>,
    health_receipt: Option<WatcherDrainReceipt>,
    failure: Option<String>,
}

impl WatcherSet {
    fn spawn(
        daemon: Arc<Mutex<HostAgentDaemon>>,
        tenant: String,
        resources: Arc<InstallationBinding>,
    ) -> Self {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let watched_sessions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let idle_timeout = mvm_hostd::host_agent_idle::idle_timeout();
        let session_jobs = WatcherJobOwner::new();
        let health_jobs = WatcherJobOwner::new();
        let idle = tokio::spawn(mvm_hostd::host_agent_idle::run_idle_watcher_until(
            daemon.clone(),
            watched_sessions.clone(),
            idle_timeout,
            stopped.clone(),
        ));
        let sessions = tokio::spawn(mvm_hostd::host_agent_idle::run_session_watcher_owned(
            tenant,
            watched_sessions.clone(),
            stopped.clone(),
            session_jobs.clone(),
            resources.clone(),
            daemon.clone(),
        ));
        let health = tokio::spawn(mvm_hostd::host_agent_idle::run_health_watcher_owned(
            daemon.clone(),
            stopped,
            health_jobs.clone(),
            resources,
        ));
        Self {
            stop,
            daemon,
            watched_sessions,
            idle_timeout,
            idle: Some(idle),
            sessions: Some(sessions),
            health: Some(health),
            session_jobs,
            health_jobs,
            session_receipt: None,
            health_receipt: None,
            failure: None,
        }
    }

    async fn idle_proposal(&mut self) -> Result<Option<IdleProposal>> {
        let Some(idle) = self.idle.as_mut() else {
            return std::future::pending().await;
        };
        let result = idle.await;
        self.idle = None;
        result.map_err(|_| anyhow::anyhow!("idle observer failed without a completion receipt"))
    }

    fn rearm_idle(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.idle.is_none() && !*self.stop.borrow(),
            "idle observer cannot restart"
        );
        self.idle = Some(tokio::spawn(
            mvm_hostd::host_agent_idle::run_idle_watcher_until(
                self.daemon.clone(),
                self.watched_sessions.clone(),
                self.idle_timeout,
                self.stop.subscribe(),
            ),
        ));
        Ok(())
    }

    fn request_stop(&self) {
        // Fence actual job reservations before broadcasting loop cancellation.
        self.session_jobs.request_stop();
        self.health_jobs.request_stop();
        self.stop.send_replace(true);
    }

    fn has_inflight_jobs(&self) -> Result<bool> {
        Ok(self.session_jobs.has_inflight_job()? || self.health_jobs.has_inflight_job()?)
    }

    async fn drain(&mut self) -> Result<()> {
        self.request_stop();
        if let Some(idle) = self.idle.as_mut() {
            let result = idle.await;
            self.idle = None;
            if result.is_err() {
                self.failure
                    .get_or_insert_with(|| "idle watcher task failed".into());
            }
        }
        if let Some(sessions) = self.sessions.as_mut() {
            let result = sessions.await;
            self.sessions = None;
            match result {
                Ok(Ok(receipt)) => self.session_receipt = Some(receipt),
                _ => {
                    self.failure
                        .get_or_insert_with(|| "session watcher collection unresolved".into());
                }
            }
        }
        if let Some(health) = self.health.as_mut() {
            let result = health.await;
            self.health = None;
            match result {
                Ok(Ok(receipt)) => self.health_receipt = Some(receipt),
                _ => {
                    self.failure
                        .get_or_insert_with(|| "health watcher collection unresolved".into());
                }
            }
        }
        anyhow::ensure!(
            self.failure.is_none(),
            "watcher drain remains unresolved: {:?}",
            self.failure
        );
        anyhow::ensure!(
            self.session_receipt.is_some() && self.health_receipt.is_some(),
            "original watcher receipts absent"
        );
        Ok(())
    }
}

impl Drop for WatcherSet {
    fn drop(&mut self) {
        // Cancellation requests stop; it is never a collection receipt. The
        // finite job actors retain their original children and resource leases.
        self.request_stop();
    }
}

/// The listener loop stays owned while Draining still permits canonical
/// cleanup/query operations. Stopping it never aborts an accepted mutation.
struct ControlLoopHandle {
    stop: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    completed: bool,
    failed: bool,
    terminal_error: Option<String>,
}

impl ControlLoopHandle {
    fn spawn(daemon: Arc<Mutex<HostAgentDaemon>>, listener: tokio::net::UnixListener) -> Self {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(HostAgentDaemon::run_shared_on_listener_until(
            daemon, listener, stopped,
        ));
        Self {
            stop,
            task: Some(task),
            completed: false,
            failed: false,
            terminal_error: None,
        }
    }

    async fn observe_exit(&mut self) -> Result<()> {
        if let Some(task) = self.task.as_mut() {
            let result = task.await;
            self.task = None;
            match result {
                Ok(result) => {
                    self.completed = true;
                    self.terminal_error = result.err().map(|error| error.to_string());
                }
                Err(_) => self.failed = true,
            }
        }
        anyhow::ensure!(
            self.completed && !self.failed,
            "original control loop completion unresolved"
        );
        if let Some(error) = &self.terminal_error {
            anyhow::bail!("original control loop failed: {error}");
        }
        Ok(())
    }

    async fn drain(&mut self) -> Result<()> {
        self.stop.send_replace(true);
        let _operation_result = self.observe_exit().await;
        // A joined loop may have returned an operation error. Its completion
        // is separate from that error; accepted effects have their own ledger.
        anyhow::ensure!(
            self.completed && !self.failed,
            "original control loop completion unresolved"
        );
        Ok(())
    }
}

impl Drop for ControlLoopHandle {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

struct WorkerResources {
    home: PathBuf,
    owner: InstallationOwner,
    epoch: Epoch,
    recovery: Recovery,
    binding: Arc<InstallationBinding>,
}

impl WorkerResources {
    fn open(cfg: &HostAgentConfig) -> Result<Self> {
        let home = PathBuf::from(mvm_core::config::mvm_home());
        let descriptor = cfg.resource_descriptor(&home)?;
        let mut owner = InstallationOwner::open(&descriptor.root, descriptor.key).with_context(|| {
            format!(
                "open existing canonical host-agent provisioning at {}; missing or legacy provisioning requires canonical reconciliation",
                descriptor.root.display()
            )
        })?;
        let recovery = owner
            .reconcile()
            .context("original host-agent resource exclusion unavailable")?;
        let epoch = owner
            .begin()
            .context("begin original host-agent resource epoch")?;
        let binding = Arc::new(owner.active_binding(epoch)?);
        tracing::info!(
            resource_recovery = ?recovery,
            "host-agent resource fence reconciled; this is not original child collection"
        );
        Ok(Self {
            home,
            owner,
            epoch,
            recovery,
            binding,
        })
    }
}

const COOPERATIVE_DRAIN_GRACE: Duration = Duration::from_secs(10);
const LIFECYCLE_IO_BUDGET: Duration = Duration::from_secs(5);

/// Lives outside the cancellation-prone grace future. Every original task,
/// resource epoch and metadata writer remains owned after timeout or error.
struct WorkerCoordinator {
    cfg: HostAgentConfig,
    resources: WorkerResources,
    lifecycle: mvm_core::tenant_lifecycle::LifecycleCoordinator,
    generation: mvm_core::tenant_lifecycle::LifecycleGeneration,
    daemon: Arc<Mutex<HostAgentDaemon>>,
    signer: Option<SignerSupervisionHandle>,
    watchers: Option<WatcherSet>,
    control: Option<ControlLoopHandle>,
    accepted: mvm_hostd::broker::daemon::AcceptedWorkDrain,
    custody: mvm_hostd::broker::daemon::DaemonCustodyOwner,
    services_receipt: Option<mvm_hostd::broker::daemon::DaemonServicesDrainReceipt>,
    resource_finished: bool,
    startup_journal_count: usize,
}

impl WorkerCoordinator {
    fn open(cfg: HostAgentConfig) -> Result<Self> {
        use mvm_core::tenant_lifecycle::{LifecycleCoordinator, LifecycleGeneration};
        let verifying_key = cfg.load_verifying_key()?;
        let resources = WorkerResources::open(&cfg)?;
        let generation = LifecycleGeneration::new(rand::random(), resources.epoch.generation())?;
        let lifecycle = LifecycleCoordinator::prepare_after_exclusion(
            &resources.home,
            &cfg.tenant_id,
            generation.clone(),
            256,
            Instant::now() + LIFECYCLE_IO_BUDGET,
        )?;
        let daemon =
            HostAgentDaemon::new(cfg.tenant_id.clone(), verifying_key, cfg.max_frame_bytes)
                .with_signer_helper(cfg.signer_helper_uds_path.clone())
                .with_registration_journal(cfg.registration_journal_path()?)
                .with_resource_binding(resources.binding.clone())
                .with_lifecycle_coordination(&resources.home, generation.clone())?;
        // No async task or Child exists yet. The original resource EX owner
        // excludes the previous daemon; this is a checked legacy observation,
        // never a new signed-plan or mailbox authority.
        let startup_journal_count = daemon.checked_journal_registration_count()?;
        let accepted = daemon.accepted_work_drain()?;
        let custody = daemon.custody_owner();
        Ok(Self {
            cfg,
            resources,
            lifecycle,
            generation,
            daemon: Arc::new(Mutex::new(daemon)),
            signer: None,
            watchers: None,
            control: None,
            accepted,
            custody,
            services_receipt: None,
            resource_finished: false,
            startup_journal_count,
        })
    }

    fn prepare_metadata_before_spawn(&self) -> Result<()> {
        use mvm_core::tenant_lifecycle::LifecyclePhase;
        let deadline = Instant::now() + LIFECYCLE_IO_BUDGET;
        let snapshot = self.lifecycle.snapshot(deadline)?;
        let _inventory = mvm_hostd::host_agent_idle::checked_session_inventory(
            &self.resources.home,
            &self.cfg.tenant_id,
            deadline,
        )?;
        anyhow::ensure!(
            snapshot.pending().is_empty(),
            "original launch reservations require canonical reconciliation"
        );
        if snapshot.generation() == &self.generation
            && snapshot.phase() == LifecyclePhase::Preparing
        {
            anyhow::ensure!(
                !snapshot.unresolved(),
                "new resource epoch is unresolved before spawn"
            );
            return Ok(());
        }
        let previous = snapshot.generation().clone();
        if snapshot.phase() != LifecyclePhase::Drained {
            self.lifecycle
                .begin_drain(&previous, snapshot.revision(), deadline, |state| {
                    anyhow::ensure!(
                        state.pending().is_empty(),
                        "original launches remain unresolved"
                    );
                    Ok(())
                })?;
            let fenced = self.lifecycle.snapshot(deadline)?;
            // Actual original resource exclusion and Recovery are retained in
            // self.resources. This retires only old coordination metadata; it
            // deliberately does not call the live Child-collection API.
            self.lifecycle.retire_after_resource_reconciliation(
                &previous,
                fenced.revision(),
                deadline,
                |state| {
                    let _actual_resource_recovery = self.resources.recovery;
                    anyhow::ensure!(
                        state.pending().is_empty(),
                        "original launches remain unresolved"
                    );
                    Ok(())
                },
            )?;
        }
        self.lifecycle
            .prepare_generation_after_reconciliation(&self.generation, deadline)
    }

    async fn start_owned_services(&mut self) -> Result<()> {
        self.prepare_metadata_before_spawn()?;
        let (ready_tx, ready_rx) = oneshot::channel();
        self.signer = Some(SignerSupervisionHandle::spawn(
            self.cfg.clone(),
            self.daemon.clone(),
            ready_tx,
            self.resources.binding.clone(),
        ));
        ready_rx
            .await
            .context("original signer supervisor stopped before readiness")??;
        let restored =
            HostAgentDaemon::restore_journaled_registrations_shared(self.daemon.clone()).await?;
        anyhow::ensure!(
            restored == self.startup_journal_count,
            "canonical journal inventory changed during startup"
        );
        // Stage the real bound listener before Active; no accept loop exists
        // yet, and local activation remains closed throughout preparation.
        let listener =
            mvm_hostd::broker::daemon::bind_host_agent_listener(&self.cfg.control_socket, 0o700)?;
        let deadline = Instant::now() + LIFECYCLE_IO_BUDGET;
        let _inventory = mvm_hostd::host_agent_idle::checked_session_inventory(
            &self.resources.home,
            &self.cfg.tenant_id,
            deadline,
        )?;
        self.lifecycle
            .activate_after_reconciliation(&self.generation, deadline)?;
        let gate = mvm_core::tenant_lifecycle::TenantLifecycleGate::new(
            &self.resources.home,
            &self.cfg.tenant_id,
        )?;
        gate.with_active(&self.generation, deadline, || {
            self.daemon
                .try_lock()
                .map_err(|_| anyhow::anyhow!("original daemon readiness contended"))?
                .open_local_admission(&self.generation)
        })?;
        self.control = Some(ControlLoopHandle::spawn(self.daemon.clone(), listener));
        self.watchers = Some(WatcherSet::spawn(
            self.daemon.clone(),
            self.cfg.tenant_id.clone(),
            self.resources.binding.clone(),
        ));
        tracing::info!(tenant_id = %self.cfg.tenant_id, registrations = restored, "host-agent original services Active");
        Ok(())
    }

    fn begin_drain(&self, idle: bool) -> Result<Option<Instant>> {
        let grace_deadline = Instant::now() + COOPERATIVE_DRAIN_GRACE;
        let metadata_deadline = Instant::now() + LIFECYCLE_IO_BUDGET;
        let snapshot = self.lifecycle.snapshot(metadata_deadline)?;
        anyhow::ensure!(
            snapshot.generation() == &self.generation,
            "original coordinator generation changed"
        );
        let inventory = if idle {
            Some(mvm_hostd::host_agent_idle::checked_session_inventory(
                &self.resources.home,
                &self.cfg.tenant_id,
                metadata_deadline,
            )?)
        } else {
            None
        };
        let checked = std::cell::Cell::new(false);
        let fenced = self.lifecycle.begin_drain(
            &self.generation,
            snapshot.revision(),
            metadata_deadline,
            |state| {
                let daemon = self
                    .daemon
                    .try_lock()
                    .map_err(|_| anyhow::anyhow!("original daemon drain check contended"))?;
                if let Some(inventory) = &inventory {
                    daemon.require_no_injected_mailbox_owner()?;
                    anyhow::ensure!(
                        state.pending().is_empty() && inventory.owned_running() == 0,
                        "original canonical session work remains live"
                    );
                    anyhow::ensure!(
                        daemon.checked_registration_count()? == 0 && !daemon.has_accepted_work()?,
                        "original daemon work remains live"
                    );
                    if let Some(watchers) = &self.watchers {
                        anyhow::ensure!(
                            !watchers.has_inflight_jobs()?,
                            "original watcher job remains live"
                        );
                    }
                }
                // Only staged original checks occurred. This local marker
                // distinguishes refused idle from uncertainty after state I/O.
                checked.set(true);
                Ok(())
            },
        );
        if let Err(error) = fenced {
            if idle && !checked.get() {
                let current = self.lifecycle.snapshot(metadata_deadline)?;
                if current.generation() == &self.generation
                    && current.phase() == mvm_core::tenant_lifecycle::LifecyclePhase::Active
                {
                    return Ok(None);
                }
            }
            return Err(error).context("original global drain fence unresolved");
        }
        // Global Draining is durable. The async collection path installs its
        // local fence outside the file gate, retaining this original grace even
        // if the daemon mutex is temporarily unavailable.
        Ok(Some(grace_deadline))
    }

    async fn collect_originals(&mut self) -> Result<()> {
        // Usage counters cannot stand in for the injected owner's actual
        // receipt. This production path currently has no injected child owner.
        {
            let mut daemon = self.daemon.lock().await;
            daemon.close_local_admission()?;
            daemon.require_no_injected_mailbox_owner()?;
        }
        if let Some(watchers) = self.watchers.as_mut() {
            watchers.drain().await?;
        }
        if self.services_receipt.is_none() {
            self.services_receipt = Some(self.custody.drain_services().await?);
        }
        let pending = self
            .lifecycle
            .snapshot(Instant::now() + LIFECYCLE_IO_BUDGET)?;
        anyhow::ensure!(
            pending.generation() == &self.generation
                && pending.phase() == mvm_core::tenant_lifecycle::LifecyclePhase::Draining
                && pending.pending().is_empty(),
            "original launch cleanup remains unresolved"
        );
        // Keep the original cleanup/query listener and signer alive if any
        // previously accepted turn is still unresolved. Final loop ownership
        // rechecks again after stopping acceptance to cover a late cleanup turn.
        self.accepted.drain().await?;
        if let Some(control) = self.control.as_mut() {
            control.drain().await?;
        }
        self.accepted.drain().await?;
        if let Some(signer) = self.signer.as_mut() {
            signer.drain().await?;
        }
        if !self.resource_finished {
            self.resources
                .owner
                .finish(self.resources.epoch)
                .context("original host-agent resource holders remain unresolved")?;
            self.resource_finished = true;
        }
        // This is the live-owner path. Historical crash retirement uses the
        // distinct resource-reconciliation API, never this collection method.
        self.lifecycle.finish_drain_after_collection(
            &self.generation,
            Instant::now() + LIFECYCLE_IO_BUDGET,
            |_| Ok(()),
        )?;
        Ok(())
    }

    async fn finish_after_fence(&mut self, grace_deadline: Instant) {
        if let Some(watchers) = &self.watchers {
            watchers.request_stop();
        }
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(grace_deadline),
            self.collect_originals(),
        )
        .await
        {
            Ok(Ok(())) => return,
            Ok(Err(_)) | Err(_) => {
                // The original grace is not renewed. This is a distinct
                // bounded metadata I/O budget, not another cleanup grace.
                let persisted = self
                    .lifecycle
                    .mark_unresolved(&self.generation, Instant::now() + LIFECYCLE_IO_BUDGET)
                    .is_ok();
                tracing::error!(
                    persisted,
                    "host-agent shutdown unresolved; original coordinator retained"
                );
            }
        }
        // Cancellation-safe owners cache actual completed joins/statuses. Wait
        // those same owners after grace, without a timer/restart/credit refund.
        if self.collect_originals().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

enum WorkerExit {
    Idle,
}

enum WorkerEvent {
    Idle(Result<Option<IdleProposal>>),
    Control(Result<()>),
}

impl WorkerCoordinator {
    async fn drain_error(&mut self, error: anyhow::Error) -> Result<WorkerExit> {
        let grace = match self.begin_drain(false) {
            Ok(Some(deadline)) => deadline,
            Ok(None) | Err(_) => {
                tracing::error!(
                    "original global drain fence unresolved; live service coordinator retained"
                );
                // No publication success, exit, replacement or renewed grace
                // is inferred from an unsuccessful global fence.
                std::future::pending::<()>().await;
                unreachable!("retained unresolved global fence cannot return");
            }
        };
        self.finish_after_fence(grace).await;
        Err(error)
    }

    async fn run(&mut self) -> Result<WorkerExit> {
        if let Err(error) = self.start_owned_services().await {
            return self.drain_error(error).await;
        }
        loop {
            let event = {
                let control = self
                    .control
                    .as_mut()
                    .context("original control loop absent")?;
                let watchers = self
                    .watchers
                    .as_mut()
                    .context("original watcher set absent")?;
                tokio::select! {
                    result = control.observe_exit() => WorkerEvent::Control(result),
                    proposal = watchers.idle_proposal() => WorkerEvent::Idle(proposal),
                }
            };
            match event {
                WorkerEvent::Control(result) => {
                    let error = result.err().unwrap_or_else(|| {
                        anyhow::anyhow!("original control loop stopped unexpectedly")
                    });
                    return self.drain_error(error).await;
                }
                WorkerEvent::Idle(Err(error)) => return self.drain_error(error).await,
                WorkerEvent::Idle(Ok(None)) => continue,
                WorkerEvent::Idle(Ok(Some(proposal))) => {
                    let _original_idle_observation = proposal.observed_at();
                    match self.begin_drain(true) {
                        Ok(Some(deadline)) => {
                            self.finish_after_fence(deadline).await;
                            return Ok(WorkerExit::Idle);
                        }
                        Ok(None) => self
                            .watchers
                            .as_mut()
                            .context("original watcher set absent")?
                            .rearm_idle()?,
                        Err(_) => {
                            tracing::error!(
                                "idle fence unresolved; original live service coordinator retained"
                            );
                            std::future::pending::<()>().await;
                        }
                    }
                }
            }
        }
    }
}

async fn run_worker_once(cfg: HostAgentConfig) -> Result<WorkerExit> {
    let mut coordinator = WorkerCoordinator::open(cfg)?;
    // The owner is outside every cancellation-prone grace/operation future.
    // Returning is possible only after the coordinator's actual drain path.
    coordinator.run().await
}

async fn supervise_worker(cfg: HostAgentConfig, raw_cfg: Vec<u8>) -> Result<()> {
    let worker_pid_path = worker_pid_path(&cfg);
    reap_stale_worker_group(&worker_pid_path);
    let mut startup_failures = 0u32;

    loop {
        let mut worker = spawn_worker(&raw_cfg).await?;
        let worker_pid = worker
            .id()
            .context("mvm-host-agent worker pid missing after spawn")?
            as libc::pid_t;
        if let Some(parent) = worker_pid_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create worker pid dir {}", parent.display()))?;
        }
        std::fs::write(&worker_pid_path, worker_pid.to_string())
            .with_context(|| format!("write {}", worker_pid_path.display()))?;

        match wait_for_worker_ready(&mut worker, &cfg.control_socket, WORKER_READY_TIMEOUT).await {
            Ok(()) => {
                startup_failures = 0;
                match worker.wait().await {
                    Ok(status) if mvm_hostd::host_agent_idle::is_idle_shutdown(status.code()) => {
                        reap_stale_worker_group(&worker_pid_path);
                        let _ = std::fs::remove_file(&worker_pid_path);
                        tracing::info!(tenant_id = %cfg.tenant_id, "mvm-host-agent idle; daemon exiting");
                        return Ok(());
                    }
                    Ok(status) => tracing::warn!(
                        tenant_id = %cfg.tenant_id,
                        status = %status,
                        "mvm-host-agent worker exited; restarting"
                    ),
                    Err(e) => tracing::warn!(
                        tenant_id = %cfg.tenant_id,
                        error = %e,
                        "mvm-host-agent worker wait failed; restarting"
                    ),
                }
            }
            Err(e) => {
                startup_failures += 1;
                tracing::warn!(
                    tenant_id = %cfg.tenant_id,
                    error = %e,
                    failures = startup_failures,
                    "mvm-host-agent worker failed before readiness; restarting"
                );
                if startup_failures >= 3 {
                    reap_stale_worker_group(&worker_pid_path);
                    let _ = worker.wait().await;
                    let _ = std::fs::remove_file(&worker_pid_path);
                    return Err(e);
                }
            }
        }

        reap_stale_worker_group(&worker_pid_path);
        let _ = worker.wait().await;
        tokio::time::sleep(WORKER_RESTART_BACKOFF).await;
    }
}

fn main() -> Result<()> {
    // NB: deliberately NOT armed with the parent-death watchdog the sibling
    // moat bins use. The worker is designed to outlive a wrapper restart — the
    // wrapper can be killed and re-spawned while the worker keeps serving the
    // broker socket, reconnecting via the pid file rather than re-parenting.
    // The worker cannot tell "wrapper restarting" from "everything gone" by
    // getppid alone, so a getppid-based self-reap would kill it mid-restart
    // (it breaks wrapper_restart_restores_journaled_registration_and_chain).
    // Instead the worker self-terminates via the idle watcher (host_agent_idle)
    // once it has had no VM registrations for the configured idle timeout; the
    // age-based reaper remains the long-tail backstop for any trees that escape
    // that window.

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let raw = read_stdin_blocking()?;
    let cfg: HostAgentConfig =
        serde_json::from_slice(&raw).context("mvm-host-agent config parse failed")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-host-agent")
        .build()
        .context("mvm-host-agent supervisor tokio runtime build failed")?;
    if is_worker_mode() {
        match runtime.block_on(run_worker_once(cfg))? {
            WorkerExit::Idle => {
                std::process::exit(mvm_hostd::host_agent_idle::IDLE_SHUTDOWN_EXIT_CODE)
            }
        }
    } else {
        runtime.block_on(supervise_worker(cfg, raw))?;
    }
    Ok(())
}
