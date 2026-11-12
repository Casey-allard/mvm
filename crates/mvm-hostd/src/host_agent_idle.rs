//! Idle-registration self-termination logic for `mvm-host-agent`.
//!
//! A detached host-agent worker (setsid, ppid=1) leaks when its VMs are gone
//! and the CLI that would ordinarily reap it dies abnormally. This module
//! implements the decision logic: once zero VM registrations and zero watched
//! sessions have persisted for the configured idle timeout the worker exits with [`IDLE_SHUTDOWN_EXIT_CODE`]
//! so the wrapper can tear down the tree rather than restart it.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, watch};

use crate::broker::daemon::HostAgentDaemon;
use crate::watcher_jobs::{WatcherDrainError, WatcherDrainReceipt, WatcherJobOwner};
use mvm_vmm::host::aux_bin::{CliSpawn, HostProcess};
use mvm_vmm::host::installed_owner::{HolderLease, InstallationBinding};

struct OwnedSessionReaper {
    jobs: WatcherJobOwner,
    resources: Arc<InstallationBinding>,
    daemon: Arc<Mutex<HostAgentDaemon>>,
}

impl crate::host_agent_sessions::SessionReaper for OwnedSessionReaper {
    fn reap(&self) {
        let result = (|| -> anyhow::Result<()> {
            let mut command = crate::health_probe::mvmctl_command_for(
                &HostProcess::current(),
                CliSpawn::SessionReap,
            )?;
            command.args(["machine", "session", "reap"]);
            spawn_owned_watcher_command(&self.daemon, &self.jobs, &self.resources, command)
        })();
        if let Err(error) = result {
            tracing::warn!(%error, "canonical session reap not admitted by retained watcher owner");
        }
    }
}

struct OwnedMachineRestarter {
    jobs: WatcherJobOwner,
    resources: Arc<InstallationBinding>,
    daemon: Arc<Mutex<HostAgentDaemon>>,
}

#[derive(Clone)]
struct WatcherPassAdmission {
    daemon: Arc<Mutex<HostAgentDaemon>>,
    resources: Arc<InstallationBinding>,
}

impl WatcherPassAdmission {
    fn admit(&self) -> anyhow::Result<crate::broker::daemon::AcceptedDaemonWork> {
        admit_watcher_turn(&self.daemon, &self.resources)
    }
}

impl crate::health_probe::Restarter for OwnedMachineRestarter {
    fn restart(&self, vm_name: &str) {
        let result = (|| -> anyhow::Result<()> {
            let mut command = crate::health_probe::mvmctl_command_for(
                &HostProcess::current(),
                CliSpawn::HealthRestart,
            )?;
            command.args(["machine", "restart", vm_name]);
            spawn_owned_watcher_command(&self.daemon, &self.jobs, &self.resources, command)
        })();
        if let Err(error) = result {
            tracing::warn!(vm = %vm_name, %error, "canonical health restart not admitted by retained watcher owner");
        }
    }
}

fn spawn_owned_watcher_command(
    daemon: &Arc<Mutex<HostAgentDaemon>>,
    jobs: &WatcherJobOwner,
    resources: &InstallationBinding,
    mut command: std::process::Command,
) -> anyhow::Result<()> {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut accepted = admit_watcher_turn(daemon, resources)?;
    let result = (|| -> anyhow::Result<()> {
        let lease = HolderLease::acquire(&resources.root, resources.key, resources.generation)?;
        jobs.try_spawn(command, lease)?;
        Ok(())
    })();
    // Success means the finite actor now represents this job; Err starts no
    // Child for this command. Neither outcome is command semantic success.
    accepted.settle()?;
    result
}

fn admit_watcher_turn(
    daemon: &Arc<Mutex<HostAgentDaemon>>,
    resources: &InstallationBinding,
) -> anyhow::Result<crate::broker::daemon::AcceptedDaemonWork> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut accepted = reserve_watcher_turn_before(daemon, deadline)?;
    // No file gate or daemon mutex is held during resource/thread preparation.
    let lease = match HolderLease::acquire(&resources.root, resources.key, resources.generation) {
        Ok(lease) => lease,
        Err(error) => {
            accepted.settle()?; // No effect or Child has started.
            return Err(error.into());
        }
    };
    accepted.attach_resource(lease)?;
    Ok(accepted)
}

/// Session and health passes run on blocking workers. Their two-second timers can
/// repeatedly coincide. Retry only daemon mutex contention; a closed generation,
/// unavailable ledger or filesystem failure is an immediate refusal.
fn reserve_watcher_turn_before(
    daemon: &Mutex<HostAgentDaemon>,
    deadline: Instant,
) -> anyhow::Result<crate::broker::daemon::AcceptedDaemonWork> {
    let mut backoff = Duration::from_millis(1);
    loop {
        anyhow::ensure!(
            Instant::now() < deadline,
            "watcher admission deadline expired"
        );
        let binding = daemon
            .try_lock()
            .ok()
            .map(|original| original.coordination_binding())
            .transpose()?;
        if let Some((gate, generation)) = binding {
            // Active authorization and the original ledger reservation share the same
            // lifecycle gate. Never wait for the daemon mutex inside that file gate.
            if let Some(turn) = gate.with_active(&generation, deadline, || {
                let Ok(original) = daemon.try_lock() else {
                    return Ok(None);
                };
                original.reserve_accepted_work(&generation).map(Some)
            })? {
                return Ok(turn);
            }
        }
        // Both locks are released. Recheck the original generation on every attempt.
        std::thread::sleep(backoff.min(deadline.saturating_duration_since(Instant::now())));
        backoff = (backoff * 2).min(Duration::from_millis(32));
    }
}

async fn drain_watcher_jobs(
    jobs: WatcherJobOwner,
) -> Result<WatcherDrainReceipt, WatcherDrainError> {
    // This original blocking job remains owned if the async caller is canceled.
    // The worker coordinator also retains its own owner and this task's handle.
    tokio::task::spawn_blocking(move || jobs.drain(None))
        .await
        .map_err(|_| WatcherDrainError::Unresolved)?
}

/// A bounded checked observation, never admission or child-collection proof.
/// Its caller must pair it with unchanged lifecycle mutation revision and the
/// original daemon/inflight/job-owner state before proposing an idle fence.
pub struct CheckedSessionInventory {
    owned_running: usize,
    known_other_running: usize,
}

impl CheckedSessionInventory {
    pub fn owned_running(&self) -> usize {
        self.owned_running
    }

    pub fn known_other_running(&self) -> usize {
        self.known_other_running
    }
}

fn read_inventory_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    const LIMIT: usize = 65_536;
    let before = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        before.is_file() && before.nlink() == 1,
        "inventory is not a private regular file"
    );
    mvm_core::private_fs::require_current_owner(&before)?;
    anyhow::ensure!(
        mvm_core::private_fs::mode_bits(path, &before)? & 0o077 == 0
            && before.len() <= LIMIT as u64,
        "inventory file mode or size is unsupported"
    );
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    anyhow::ensure!(
        opened.is_file()
            && opened.nlink() == 1
            && opened.len() <= LIMIT as u64
            && opened.dev() == before.dev()
            && opened.ino() == before.ino(),
        "inventory file changed during open"
    );
    mvm_core::private_fs::require_current_owner(&opened)?;
    anyhow::ensure!(
        mvm_core::private_fs::mode_bits(path, &opened)? & 0o077 == 0,
        "opened inventory file is not private"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= LIMIT, "inventory read exceeds limit");
    Ok(bytes)
}

fn require_inventory_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(metadata.is_dir(), "inventory directory is not plain");
    mvm_core::private_fs::require_current_owner(&metadata)?;
    anyhow::ensure!(
        mvm_core::private_fs::mode_bits(path, &metadata)? == 0o700,
        "inventory directory is not private"
    );
    Ok(())
}

fn checked_started_backend(
    home: &Path,
    vm: &str,
) -> anyhow::Result<mvm_core::vm_backend::BackendKind> {
    use std::os::unix::fs::MetadataExt;
    let directory = mvm_core::config::vm_state_dir_at(home, vm);
    let mut kind = None;
    for descriptor in mvm_runtime::catalog::started_vm_probe_descriptors() {
        let Some(marker) = descriptor.marker_file else {
            continue;
        };
        let path = directory.join(marker);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.len() > 0
                && metadata.len() <= 4096,
            "backend marker is unsupported"
        );
        mvm_core::private_fs::require_current_owner(&metadata)?;
        anyhow::ensure!(
            mvm_core::private_fs::mode_bits(&path, &metadata)? & 0o022 == 0,
            "backend marker is writable by another identity"
        );
        anyhow::ensure!(
            kind.is_none_or(|previous| previous == descriptor.kind),
            "backend ownership is ambiguous"
        );
        kind = Some(descriptor.kind);
    }
    kind.ok_or_else(|| anyhow::anyhow!("covered session backend is unknown"))
}

/// Read canonical session/plan metadata under the original captured home.
/// Unknown, unreadable, malformed, oversized or truncated input is an error,
/// never zero. 4096 directory entries is a scan work bound, not fleet capacity.
pub fn checked_session_inventory(
    home: &Path,
    tenant: &str,
    deadline: Instant,
) -> anyhow::Result<CheckedSessionInventory> {
    use crate::host_agent_lifecycle::{LifecycleCoverage, classify_admitted_plan};
    use mvm_core::session::{SessionRecord, SessionState};
    anyhow::ensure!(
        home.is_absolute() && Instant::now() < deadline,
        "inventory requires original absolute home and unexpired deadline"
    );
    require_inventory_directory(home)?;
    let directory = home.join("run/sessions");
    let mut inventory = CheckedSessionInventory {
        owned_running: 0,
        known_other_running: 0,
    };
    match std::fs::symlink_metadata(home.join("run")) {
        Ok(_) => require_inventory_directory(&home.join("run"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                Instant::now() < deadline,
                "session inventory deadline expired"
            );
            return Ok(inventory);
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = match std::fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                Instant::now() < deadline,
                "session inventory deadline expired"
            );
            return Ok(inventory);
        }
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_dir(),
        "session inventory directory is not plain"
    );
    mvm_core::private_fs::require_current_owner(&metadata)?;
    anyhow::ensure!(
        mvm_core::private_fs::mode_bits(&directory, &metadata)? == 0o700,
        "session inventory directory is not private"
    );
    let mut identities = std::collections::HashSet::new();
    for (index, entry) in std::fs::read_dir(&directory)?.enumerate() {
        anyhow::ensure!(
            index < 4096 && Instant::now() < deadline,
            "session inventory work or time bound exceeded"
        );
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let record: SessionRecord = serde_json::from_slice(&read_inventory_file(&path)?)?;
        mvm_core::session::SessionId::parse(&record.id.to_string())?;
        chrono::DateTime::parse_from_rfc3339(&record.started_at)?;
        if let Some(invoked) = &record.last_invoke_at {
            chrono::DateTime::parse_from_rfc3339(invoked)?;
        }
        anyhow::ensure!(
            path.file_name()
                .is_some_and(|name| name == format!("{}.json", record.id).as_str())
                && identities.insert(record.id.clone()),
            "session inventory identity mismatch"
        );
        if record.state != SessionState::Running {
            continue;
        }
        super::broker::daemon::validate_vm_id(&record.vm_name)?;
        let vm_directory = mvm_core::config::vm_state_dir_at(home, &record.vm_name);
        require_inventory_directory(&home.join("vms"))?;
        require_inventory_directory(&vm_directory)?;
        let plan_path = vm_directory.join(crate::audit::plan_persist::PLAN_FILENAME);
        let bytes = read_inventory_file(&plan_path)?;
        let plan = mvm_core::plan::plan_from_admitted_json(std::str::from_utf8(&bytes)?)?;
        let coverage = classify_admitted_plan(&plan)?;
        let admitted_kind = mvm_runtime::catalog::descriptor_for_selector(&plan.runtime_profile.0)
            .ok_or_else(|| anyhow::anyhow!("admitted session backend is unknown"))?
            .kind;
        let backend = checked_started_backend(home, &record.vm_name)?;
        anyhow::ensure!(
            backend == admitted_kind,
            "actual session backend does not match canonical plan"
        );
        if plan.tenant.0 != tenant || matches!(coverage, LifecycleCoverage::KnownOther(_)) {
            inventory.known_other_running = inventory
                .known_other_running
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("session inventory count overflow"))?;
            continue;
        }
        inventory.owned_running = inventory
            .owned_running
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("session inventory count overflow"))?;
    }
    anyhow::ensure!(
        Instant::now() < deadline,
        "session inventory deadline expired"
    );
    Ok(inventory)
}

/// Exit code the worker uses when it self-terminates due to idle timeout.
///
/// A distinct value lets the wrapper distinguish "idle — tear down the tree"
/// from a crash (non-zero) or a clean stop (0). The wrapper must not restart
/// on this code.
pub const IDLE_SHUTDOWN_EXIT_CODE: i32 = 42;

/// Map the raw `MVM_HOST_AGENT_IDLE_TIMEOUT` env value to a `Duration`.
///
/// - `None` (env var unset) → `Some(300s)` — the default 5-minute warm window
///   keeps short-lived dev workflows from racing against idle reap.
/// - `Some("0")` → `None` — disables idle-exit entirely.
/// - `Some(positive integer)` → `Some(n seconds)`.
/// - `Some(unparseable / negative)` → `Some(300s)` — safe fallback to default.
pub fn parse_idle_timeout(raw: Option<&str>) -> Option<Duration> {
    const DEFAULT: Duration = Duration::from_secs(300);
    // Trim once up front so the disable sentinel and the integer parse agree on
    // a whitespace-padded value (e.g. `" 0 "` must still disable).
    match raw.map(str::trim) {
        None => Some(DEFAULT),
        Some("0") => None,
        Some(s) => match s.parse::<i64>() {
            Ok(n) if n > 0 => Some(Duration::from_secs(n as u64)),
            _ => Some(DEFAULT),
        },
    }
}

/// Read `MVM_HOST_AGENT_IDLE_TIMEOUT` from the environment and return the
/// resolved idle timeout.
pub fn idle_timeout() -> Option<Duration> {
    parse_idle_timeout(std::env::var("MVM_HOST_AGENT_IDLE_TIMEOUT").ok().as_deref())
}

/// Return `true` when the daemon should self-exit due to idleness.
///
/// All four conditions must hold simultaneously:
/// - `timeout` is `Some` (idle-exit is enabled),
/// - `count == 0` (no live registrations),
/// - `zero_since` is `Some` (we have been at zero continuously since that
///   instant — a transient dip that recovered resets the clock),
/// - the elapsed time since `zero_since` has reached `timeout`.
pub fn should_idle_exit(
    count: usize,
    zero_since: Option<Instant>,
    now: Instant,
    timeout: Option<Duration>,
) -> bool {
    timeout.is_some_and(|t| count == 0 && zero_since.is_some_and(|z| now.duration_since(z) >= t))
}

/// Return `true` when the worker exit code signals an idle self-termination.
///
/// The wrapper uses this to distinguish idle teardown (no restart) from a
/// crash (back off + restart).
pub fn is_idle_shutdown(code: Option<i32>) -> bool {
    code == Some(IDLE_SHUTDOWN_EXIT_CODE)
}

/// Advisory idle observation. This is not admission or shutdown authority:
/// the coordinator must revalidate inventory under the lifecycle/daemon gate.
#[derive(Debug, Clone, Copy)]
pub struct IdleProposal {
    observed_at: Instant,
}

impl IdleProposal {
    /// The original monotonic observation, never a replacement drain deadline.
    #[must_use]
    pub fn observed_at(self) -> Instant {
        self.observed_at
    }
}

/// Return an idle proposal after observing no work for `timeout`.
///
/// Compatibility entry point for owners without a cooperative stop channel.
/// It never exits the process. A disabled watcher returns no proposal.
///
/// The lock over `daemon` is held only for the `registration_count()` read and
/// is dropped before every sleep, so it never serialises against broker request
/// handling.
pub async fn run_idle_watcher(
    daemon: Arc<Mutex<HostAgentDaemon>>,
    watched_sessions: Arc<AtomicUsize>,
    timeout: Option<Duration>,
) -> Option<IdleProposal> {
    let (_keepalive, stop) = watch::channel(false);
    run_idle_watcher_until(daemon, watched_sessions, timeout, stop).await
}

/// Stop-aware idle observer. True or sender closure prevents new proposals.
pub async fn run_idle_watcher_until(
    daemon: Arc<Mutex<HostAgentDaemon>>,
    watched_sessions: Arc<AtomicUsize>,
    timeout: Option<Duration>,
    mut stop: watch::Receiver<bool>,
) -> Option<IdleProposal> {
    let Some(timeout) = timeout else {
        return None;
    };
    const PROBE: Duration = Duration::from_millis(500);
    let mut zero_since: Option<Instant> = None;
    loop {
        if *stop.borrow() || stop.has_changed().is_err() {
            return None;
        }
        // Ownership-marker filesystem probes and actual service retirement run
        // outside the daemon mutex. Unknown original state conservatively blocks idle.
        if let Err(error) = HostAgentDaemon::reap_dead_registrations_shared(daemon.clone()).await {
            tracing::warn!(%error, "dead host-agent registration reap failed");
        }
        let registrations = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return None; }
                continue;
            }
            original = daemon.lock() => original.registration_count(),
        };
        let count = registrations.saturating_add(watched_sessions.load(Ordering::Relaxed));
        if count > 0 {
            zero_since = None;
        } else if zero_since.is_none() {
            zero_since = Some(Instant::now());
        }
        if should_idle_exit(count, zero_since, Instant::now(), Some(timeout)) {
            if *stop.borrow() || stop.has_changed().is_err() {
                return None;
            }
            return Some(IdleProposal {
                observed_at: Instant::now(),
            });
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return None;
                }
            }
            () = tokio::time::sleep(PROBE) => {}
        }
    }
}

/// Sibling watcher that enforces the idle timeout of this tenant's sessions on
/// the backends with no per-VM supervisor, and publishes how many it watches
/// into `watched_sessions` for [`run_idle_watcher`].
///
/// The session store is files on disk, so each pass runs inside
/// `spawn_blocking`; the watcher is moved in and back out so its record of the
/// last sweep survives.
pub async fn run_session_watcher(tenant: String, watched_sessions: Arc<AtomicUsize>) {
    let (_keepalive, stop) = watch::channel(false);
    run_session_watcher_until(tenant, watched_sessions, stop).await;
}

/// Stop new passes cooperatively and retain any already-started blocking pass.
pub async fn run_session_watcher_until(
    tenant: String,
    watched_sessions: Arc<AtomicUsize>,
    stop: watch::Receiver<bool>,
) {
    session_watcher_passes(
        tenant,
        watched_sessions,
        stop,
        crate::host_agent_sessions::CliSessionReaper,
        None,
    )
    .await;
}

/// Original bounded cleanup jobs finish before this watcher yields a receipt.
pub async fn run_session_watcher_owned(
    tenant: String,
    watched_sessions: Arc<AtomicUsize>,
    stop: watch::Receiver<bool>,
    jobs: WatcherJobOwner,
    resources: Arc<InstallationBinding>,
    daemon: Arc<Mutex<HostAgentDaemon>>,
) -> Result<WatcherDrainReceipt, WatcherDrainError> {
    session_watcher_passes(
        tenant,
        watched_sessions,
        stop,
        OwnedSessionReaper {
            jobs: jobs.clone(),
            resources: resources.clone(),
            daemon: daemon.clone(),
        },
        Some(WatcherPassAdmission {
            daemon,
            resources: resources.clone(),
        }),
    )
    .await;
    drain_watcher_jobs(jobs).await
}

async fn session_watcher_passes<R: crate::host_agent_sessions::SessionReaper + Send + 'static>(
    tenant: String,
    watched_sessions: Arc<AtomicUsize>,
    mut stop: watch::Receiver<bool>,
    reaper: R,
    admission: Option<WatcherPassAdmission>,
) {
    use crate::host_agent_sessions::{SessionSweepWatcher, TenantSessions};

    const PROBE: Duration = Duration::from_secs(2);
    let mut ticker = tokio::time::interval(PROBE);
    let mut watcher = Some(SessionSweepWatcher::new(
        TenantSessions::new(tenant),
        reaper,
    ));
    loop {
        if *stop.borrow() || stop.has_changed().is_err() {
            return;
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
                continue;
            }
            _ = ticker.tick() => {}
        }
        let Some(current) = watcher.take() else {
            return;
        };
        let admission = admission.clone();
        let pass = tokio::task::spawn_blocking(move || {
            let mut current = current;
            let accepted = match admission
                .as_ref()
                .map(WatcherPassAdmission::admit)
                .transpose()
            {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "session pass admission unavailable");
                    return (current, usize::MAX);
                }
            };
            let watched = match mvm_core::session::list_sessions() {
                Ok(records) => current.step(&records, chrono::Utc::now()),
                Err(error) => {
                    tracing::warn!(%error, "session watcher: could not list sessions");
                    0
                }
            };
            let watched = if accepted.is_some_and(|mut accepted| accepted.settle().is_err()) {
                usize::MAX
            } else {
                watched
            };
            (current, watched)
        })
        .await;
        match pass {
            Ok((current, watched)) => {
                watched_sessions.store(watched, Ordering::Relaxed);
                watcher = Some(current);
            }
            Err(error) => {
                // This Atomic is advisory, never shutdown authority. The
                // coordinator's checked inventory still refuses Unknown, and
                // an abandoned original pass leaves its accepted turn charged.
                tracing::warn!(%error, "session watcher pass failed; no longer watching sessions");
                watched_sessions.store(0, Ordering::Relaxed);
                return;
            }
        }
    }
}

/// Sibling watcher that periodically probes each healthchecked VM and records
/// its observed health.
///
/// Spawn alongside [`run_idle_watcher`] after the daemon is serving. The probe
/// itself (`AgentExec` over vsock) is **blocking** I/O, so each pass runs inside
/// `spawn_blocking` to keep the tokio reactor free; the [`HealthProber`] is
/// moved in and back out so its per-VM tracker state persists across passes.
///
/// The lock over `daemon` is held only for the `registered_vm_ids()` read and is
/// released before the blocking probe pass, so it never serialises against
/// broker request handling.
///
/// [`HealthProber`]: crate::health_probe::HealthProber
pub async fn run_health_watcher(daemon: Arc<Mutex<HostAgentDaemon>>) {
    let (_keepalive, stop) = watch::channel(false);
    run_health_watcher_until(daemon, stop).await;
}

/// Stop new probes cooperatively; await an already-started blocking pass.
pub async fn run_health_watcher_until(
    daemon: Arc<Mutex<HostAgentDaemon>>,
    stop: watch::Receiver<bool>,
) {
    health_watcher_passes(
        daemon,
        stop,
        Arc::new(crate::health_probe::MachineRestarter),
        None,
    )
    .await;
}

/// Original bounded restart jobs finish before this watcher yields a receipt.
pub async fn run_health_watcher_owned(
    daemon: Arc<Mutex<HostAgentDaemon>>,
    stop: watch::Receiver<bool>,
    jobs: WatcherJobOwner,
    resources: Arc<InstallationBinding>,
) -> Result<WatcherDrainReceipt, WatcherDrainError> {
    health_watcher_passes(
        daemon.clone(),
        stop,
        Arc::new(OwnedMachineRestarter {
            jobs: jobs.clone(),
            resources: resources.clone(),
            daemon: daemon.clone(),
        }),
        Some(WatcherPassAdmission { daemon, resources }),
    )
    .await;
    drain_watcher_jobs(jobs).await
}

async fn health_watcher_passes(
    daemon: Arc<Mutex<HostAgentDaemon>>,
    mut stop: watch::Receiver<bool>,
    restarter: Arc<dyn crate::health_probe::Restarter + Send + Sync>,
    admission: Option<WatcherPassAdmission>,
) {
    use crate::health_probe::{AgentExec, HealthProber, now_unix};

    const PROBE: Duration = Duration::from_secs(2);
    let mut ticker = tokio::time::interval(PROBE);
    let mut prober = HealthProber::new();
    loop {
        if *stop.borrow() || stop.has_changed().is_err() {
            return;
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
                continue;
            }
            _ = ticker.tick() => {}
        }
        // Snapshot the live set and the health-audit sink together under one
        // brief lock, then release it before the blocking pass — the sink is
        // self-contained (it does its own blocking helper round-trip inside the
        // pass), so a health append never runs under the daemon lock.
        let (vm_ids, audit) = {
            let d = daemon.lock().await;
            match d.registered_vm_ids() {
                Ok(ids) => (ids, d.health_audit_sink()),
                Err(error) => {
                    tracing::warn!(%error, "original VM map unavailable; health pass skipped");
                    continue;
                }
            }
        };
        if vm_ids.is_empty() {
            continue;
        }
        if *stop.borrow() || stop.has_changed().is_err() {
            return;
        }
        // Move the prober into the blocking pass and take it back afterwards so
        // its tracker state survives. A panic in the pass costs the tracker
        // history but not the watcher loop. Owned restart adapters reserve a
        // finite original job and retain its Child/resource lease; the pass
        // only reports scheduling, never successful restart or collection.
        let restarter = restarter.clone();
        let admission = admission.clone();
        prober = tokio::task::spawn_blocking(move || {
            let accepted = match admission
                .as_ref()
                .map(WatcherPassAdmission::admit)
                .transpose()
            {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "health pass admission unavailable");
                    return prober;
                }
            };
            let now = now_unix();
            // Scheduling (per due probe, inside `tick`) is decoupled from firing
            // (every tick, inside `act`): `tick` schedules a restart into the
            // future, and `act` fires any gate that has since elapsed. A restart
            // scheduled this pass therefore fires on a later pass, not this one.
            prober.tick(&vm_ids, now, &AgentExec, &audit);
            prober.act(&vm_ids, now, restarter.as_ref());
            if let Some(mut accepted) = accepted {
                let _ = accepted.settle();
            }
            prober
        })
        .await
        .unwrap_or_else(|_| HealthProber::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_watcher_waits_for_transient_daemon_contention_before_admitting()
    -> anyhow::Result<()> {
        use mvm_core::tenant_lifecycle::{LifecycleCoordinator, LifecycleGeneration};
        use mvm_vmm::host::installed_owner::{InstallationKey, InstallationOwner};
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        let home = temp.path();
        std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700))?;
        let key = InstallationKey {
            installation: [1; 32],
            profile: [2; 32],
        };
        let mut owner = InstallationOwner::initialize(&home.join("resources"), key)?;
        let epoch = owner.begin()?;
        let binding = owner.active_binding(epoch)?;
        let generation = LifecycleGeneration::new([3; 32], epoch.generation())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let lifecycle = LifecycleCoordinator::prepare_after_exclusion(
            home,
            "local",
            generation.clone(),
            1,
            deadline,
        )?;
        lifecycle.activate_after_reconciliation(&generation, deadline)?;
        let signer = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let mut original = HostAgentDaemon::new("local", signer.verifying_key(), 65_536)
            .with_lifecycle_coordination(home, generation.clone())?;
        original.open_local_admission(&generation)?;
        let daemon = Arc::new(Mutex::new(original));
        let held = daemon.try_lock().unwrap();
        let (entered, ready) = std::sync::mpsc::sync_channel(0);
        let probe = daemon.clone();
        std::thread::scope(|scope| -> anyhow::Result<()> {
            let observer = scope.spawn(move || {
                entered.send(()).unwrap();
                admit_watcher_turn(&probe, &binding)
            });
            ready.recv()?;
            std::thread::sleep(Duration::from_millis(40));
            drop(held);
            let mut turn = observer.join().unwrap()?;
            assert!(daemon.try_lock().unwrap().has_accepted_work()?);
            turn.settle()?;
            assert!(!daemon.try_lock().unwrap().has_accepted_work()?);
            Ok(())
        })?;
        let revision = lifecycle.snapshot(deadline)?.revision();
        lifecycle.begin_drain(&generation, revision, deadline, |_| Ok(()))?;
        assert!(reserve_watcher_turn_before(&daemon, deadline).is_err());
        assert!(!daemon.try_lock().unwrap().has_accepted_work()?);
        owner.finish(epoch)?;
        Ok(())
    }

    #[test]
    fn watcher_deadline_preserves_unknown_until_original_lock_is_available() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let daemon = Mutex::new(HostAgentDaemon::new(
            "local",
            signer.verifying_key(),
            65_536,
        ));
        let held = daemon.try_lock().unwrap();
        let deadline = Instant::now() + Duration::from_millis(15);
        let error = reserve_watcher_turn_before(&daemon, deadline)
            .err()
            .unwrap();
        assert!(Instant::now() >= deadline);
        assert!(
            error
                .to_string()
                .contains("watcher admission deadline expired")
        );
        assert!(!held.has_accepted_work().unwrap());
    }

    // --- parse_idle_timeout ---

    #[test]
    fn parse_none_gives_default() {
        assert_eq!(parse_idle_timeout(None), Some(Duration::from_secs(300)));
    }

    #[test]
    fn parse_zero_disables() {
        assert_eq!(parse_idle_timeout(Some("0")), None);
    }

    #[test]
    fn parse_whitespace_padded_zero_disables() {
        assert_eq!(parse_idle_timeout(Some(" 0 ")), None);
        assert_eq!(parse_idle_timeout(Some("\t0\n")), None);
    }

    #[test]
    fn parse_positive_integer() {
        assert_eq!(parse_idle_timeout(Some("5")), Some(Duration::from_secs(5)));
    }

    #[test]
    fn parse_unparseable_falls_back_to_default() {
        assert_eq!(
            parse_idle_timeout(Some("abc")),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn parse_negative_falls_back_to_default() {
        assert_eq!(
            parse_idle_timeout(Some("-3")),
            Some(Duration::from_secs(300))
        );
    }

    // --- should_idle_exit ---

    #[test]
    fn disabled_timeout_never_exits() {
        let base = Instant::now();
        // Simulate count == 0 with an old zero_since: disabled means no exit.
        let zero_since = base.checked_sub(Duration::from_secs(600));
        assert!(!should_idle_exit(0, zero_since, base, None));
    }

    #[test]
    fn nonzero_count_never_exits() {
        let base = Instant::now();
        let timeout = Some(Duration::from_secs(10));
        let zero_since = base.checked_sub(Duration::from_secs(600));
        assert!(!should_idle_exit(1, zero_since, base, timeout));
    }

    #[test]
    fn zero_count_no_zero_since_does_not_exit() {
        let base = Instant::now();
        let timeout = Some(Duration::from_secs(10));
        assert!(!should_idle_exit(0, None, base, timeout));
    }

    #[test]
    fn zero_count_idle_under_timeout_does_not_exit() {
        let timeout = Duration::from_secs(60);
        let base = Instant::now();
        // zero_since is only 1 second ago — still under the 60s threshold.
        let zero_since = base.checked_sub(Duration::from_secs(1));
        assert!(!should_idle_exit(0, zero_since, base, Some(timeout)));
    }

    #[test]
    fn zero_count_idle_over_timeout_exits() {
        let timeout = Duration::from_secs(60);
        let base = Instant::now();
        // zero_since is 120 seconds ago — well past the threshold.
        let zero_since = base.checked_sub(Duration::from_secs(120));
        assert!(should_idle_exit(0, zero_since, base, Some(timeout)));
    }

    #[test]
    fn zero_count_idle_exactly_at_timeout_exits() {
        let timeout = Duration::from_secs(60);
        let base = Instant::now();
        // zero_since is exactly `timeout` ago — boundary inclusive.
        let zero_since = base.checked_sub(timeout);
        assert!(should_idle_exit(0, zero_since, base, Some(timeout)));
    }

    // --- is_idle_shutdown ---

    #[test]
    fn idle_shutdown_code_is_recognized() {
        assert!(is_idle_shutdown(Some(IDLE_SHUTDOWN_EXIT_CODE)));
    }

    #[test]
    fn zero_exit_is_not_idle_shutdown() {
        assert!(!is_idle_shutdown(Some(0)));
    }

    #[test]
    fn one_exit_is_not_idle_shutdown() {
        assert!(!is_idle_shutdown(Some(1)));
    }

    #[test]
    fn none_exit_is_not_idle_shutdown() {
        assert!(!is_idle_shutdown(None));
    }
}
