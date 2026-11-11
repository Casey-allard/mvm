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

fn run_signer_actor(
    bin: PathBuf,
    uds_path: PathBuf,
    bytes: Vec<u8>,
    mut wake: std::os::unix::net::UnixStream,
    startup_deadline: Instant,
    ready: oneshot::Sender<SignerReadiness>,
    completion: oneshot::Sender<SignerOutcome>,
) {
    use mvm_vmm::host::process_exit::{ProcessExitObserver, wait_process_exit_events};
    use std::os::fd::AsFd;
    let spawned = (|| -> std::io::Result<std::process::Child> {
        mvm_vmm::host::process_exit::require_owned_child_custody()?;
        if signer_stop_requested(&mut wake)? || Instant::now() >= startup_deadline {
            return Err(std::io::Error::other(
                "signer startup canceled before spawn",
            ));
        }
        mvm_core::env_hygiene::helper_command(&bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    })();
    let child = match spawned {
        Ok(child) => child,
        Err(error) => {
            let _ = completion.send(SignerOutcome::NotStarted);
            let _ = ready.send(SignerReadiness::NotStarted(error.to_string()));
            return;
        }
    };
    let mut owner = OriginalSignerChild {
        child,
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

async fn spawn_signer_helper(cfg: &HostAgentConfig) -> Result<SignerChild> {
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
                bin,
                uds,
                bytes,
                wake,
                startup_deadline,
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

async fn supervise_signer_helper(
    cfg: HostAgentConfig,
    daemon: Arc<Mutex<HostAgentDaemon>>,
    first_ready: oneshot::Sender<Result<()>>,
) {
    let mut first_ready = Some(first_ready);
    loop {
        match spawn_signer_helper(&cfg).await {
            Ok(mut child) => {
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
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                let rebound = {
                    let daemon = daemon.lock().await;
                    daemon.rebind_signer_helper_registrations()
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
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                }

                match child.wait().await {
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
                    return;
                }
                tracing::warn!(
                    tenant_id = %cfg.tenant_id,
                    error = %e,
                    "mvm-signer-helper spawn failed; retrying"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn run_worker_once(cfg: HostAgentConfig) -> Result<()> {
    let verifying_key = cfg.load_verifying_key()?;
    tracing::info!(
        tenant_id = %cfg.tenant_id,
        control_socket = %cfg.control_socket.display(),
        signer_helper_uds_path = %cfg.signer_helper_uds_path.display(),
        "mvm-host-agent worker starting"
    );

    let registration_journal = cfg.registration_journal_path()?;
    let daemon = Arc::new(Mutex::new(
        HostAgentDaemon::new(cfg.tenant_id.clone(), verifying_key, cfg.max_frame_bytes)
            .with_signer_helper(cfg.signer_helper_uds_path.clone())
            .with_registration_journal(registration_journal),
    ));
    let (ready_tx, ready_rx) = oneshot::channel();
    tokio::spawn(supervise_signer_helper(
        cfg.clone(),
        daemon.clone(),
        ready_tx,
    ));
    ready_rx
        .await
        .context("mvm-signer-helper supervisor stopped before readiness")??;
    let restored = {
        let mut daemon = daemon.lock().await;
        daemon.restore_journaled_registrations()
    }?;
    tracing::info!(
        tenant_id = %cfg.tenant_id,
        registrations = restored,
        "mvm-host-agent registration journal restored"
    );
    let watched_sessions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    tokio::spawn(mvm_hostd::host_agent_idle::run_idle_watcher(
        daemon.clone(),
        watched_sessions.clone(),
        mvm_hostd::host_agent_idle::idle_timeout(),
    ));
    tokio::spawn(mvm_hostd::host_agent_idle::run_session_watcher(
        cfg.tenant_id.clone(),
        watched_sessions,
    ));
    tokio::spawn(mvm_hostd::host_agent_idle::run_health_watcher(
        daemon.clone(),
    ));
    HostAgentDaemon::run_shared(daemon, &cfg.control_socket).await?;

    Ok(())
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
        runtime.block_on(run_worker_once(cfg))?;
    } else {
        runtime.block_on(supervise_worker(cfg, raw))?;
    }
    Ok(())
}
