use super::*;
use crate::host::network_endpoint_spawn::{owned_pipe_nonblocking, owned_pipe_ready};
use crate::host::process_exit::{
    ProcessExitObserver, ProcessExitWait, collect_after_exit_event, require_owned_child_custody,
};
use anyhow::ensure;
use mvm_core::host_lifetime::PreparedHostLifetimeLease;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

mod audit_capability;
mod inventory;
use audit_capability::receive_signer_event;
pub(crate) use audit_capability::require_live_event;
pub use inventory::RegisteredAuditFile;
use mvm_core::protocol::audit_signer::SignedAuditInventory;

/// Trusted installed DI retaining the actual aggregate helper reservation.
pub trait HostAgentParentPermit: Send + Sync {
    fn check_current(&self, tenant: &str) -> Result<()>;
    /// Per-process address-space reservation for the original daemon and its one signer.
    fn owned_process_address_space_limit(
        &self,
        _tenant: &str,
    ) -> Result<Option<std::num::NonZeroU64>> {
        Ok(None)
    }
    /// Funded bytes retained for each VM's original signed audit JSONL.
    fn owned_audit_chain_bytes(&self, _tenant: &str) -> Result<Option<std::num::NonZeroU64>> {
        Ok(None)
    }
    fn check_registration(&self, params: &HostAgentServicesParams<'_>) -> Result<()>;
    /// Borrow the captured settings under this original permit's lifetime.
    /// An installed consumer cannot keep the snapshot after its owner.
    fn installed_endpoint_settings(
        &self,
        _params: &HostAgentServicesParams<'_>,
    ) -> Result<&crate::host::network_endpoint_spawn::InstalledEndpointSettings> {
        anyhow::bail!("original installed endpoint settings unavailable")
    }
}
pub struct OwnedHostAgentInputs {
    pub tenant: String,
    pub holder: PreparedHostLifetimeLease,
    pub parent: Arc<dyn HostAgentParentPermit>,
}

/// Intermediate owned resource profile; the parent must preflight selected
/// services before VM activation. This is a restriction, never admission.
pub fn validate_owned_host_agent_services(params: &HostAgentServicesParams<'_>) -> Result<()> {
    ensure!(
        params.services.len() <= 2
            && (params.services.len() < 2 || params.services[0] != params.services[1]),
        "owned unique service profile limit"
    );
    ensure!(
        params.capability_bindings.len() <= 16,
        "owned capability profile limit"
    );
    ensure!(
        params
            .capability_bindings
            .iter()
            .all(|binding| binding.capability.service.as_str().len()
                + binding.capability.verb.len()
                <= 128),
        "owned capability identity bytes"
    );
    ensure!(
        params.service_proxies.is_empty(),
        "owned controller service profile unqualified"
    );
    ensure!(
        params
            .services
            .iter()
            .all(|service| owned_host_agent_service(service.as_str())),
        "owned host service resource profile unqualified"
    );
    Ok(())
}
pub fn owned_host_agent_service(service: &str) -> bool {
    matches!(service, "host.audit.v1" | "host.time.v1")
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Sending,
    Active,
    Closing,
    Uncertain,
}
struct Slot {
    serial: u64,
    phase: Phase,
}
#[derive(Default)]
struct Ledger {
    closed: bool,
    fenced: bool,
    next: u64,
    slots: BTreeMap<String, Slot>,
}
struct Process {
    child: Child,
    owner: Option<ChildStdin>,
    status: Option<std::process::ExitStatus>,
    signer_pid: Option<u32>,
    #[cfg(target_os = "macos")]
    liveness: Option<std::os::fd::OwnedFd>,
}
/// Transferable process observation offered by the private owned-helper wire.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedAuditSideband {
    Unavailable,
    PidfdV1,
    DarwinPipeV1,
}
impl OwnedAuditSideband {
    pub fn supported() -> std::io::Result<Self> {
        match audit_capability::require_supported_platform() {
            Ok(()) => Ok(if cfg!(target_os = "macos") {
                Self::DarwinPipeV1
            } else {
                Self::PidfdV1
            }),
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => Ok(Self::Unavailable),
            Err(error) => Err(error),
        }
    }
}

struct Shared {
    audit_chain_bytes: Option<std::num::NonZeroU64>,
    address_space_limit: Option<std::num::NonZeroU64>,
    tenant: String,
    control_socket: PathBuf,
    signer_socket: PathBuf,
    audit_sideband: OwnedAuditSideband,
    key: Zeroizing<[u8; 32]>,
    parent: Arc<dyn HostAgentParentPermit>,
    holder: PreparedHostLifetimeLease,
    _spawn_lock: File,
    process: Mutex<Process>,
    ledger: Mutex<Ledger>,
    quarantined: AtomicBool,
}
impl Shared {
    fn fence(&self) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.fenced = true;
            ledger.closed = true;
        }
    }
    fn quarantine(self: &Arc<Self>) {
        self.fence();
        if !self.quarantined.swap(true, Ordering::AcqRel) {
            std::mem::forget(self.clone());
        }
    }
    fn running(&self) -> Result<()> {
        require_owned_child_custody()?;
        let mut process = self
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child state poisoned"))?;
        #[cfg(target_os = "macos")]
        {
            let current = process
                .liveness
                .as_ref()
                .context("original daemon liveness absent")
                .and_then(|pipe| {
                    crate::host::owned_liveness::require_live_read_pipe(pipe).map_err(Into::into)
                });
            if let Err(error) = current {
                drop(process);
                self.fence();
                return Err(error);
            }
        }
        if process.status.is_none() {
            process.status = process.child.try_wait()?;
        }
        ensure!(
            process.status.is_none(),
            "original host-agent child exited unexpectedly"
        );
        Ok(())
    }
}

/// Original Child custody of one installed tenant helper and its signer.
#[must_use]
pub struct OwnedHostAgent {
    shared: Arc<Shared>,
    stopped: bool,
}
/// Shared registration access; cloning never starts another daemon.
#[derive(Clone)]
pub struct OwnedHostAgentRegistrar {
    shared: Arc<Shared>,
    registered: Option<Arc<dyn RegisteredEndpointOwner>>,
}
/// Trusted embedding observes the authenticated per-VM registration before endpoint handoff.
pub trait RegisteredEndpointOwner: Send + Sync {
    fn bind_registration(
        &self,
        registrar: &OwnedHostAgentRegistrar,
        registration: &OwnedVmRegistration,
        params: &HostAgentServicesParams<'_>,
    ) -> Result<()>;
    /// Called after confirmed deregistration while the exact registration still owns its slot.
    /// An error leaves the same terminal receipt available for a retry.
    fn retired_audit(
        &self,
        _registration: &OwnedVmRegistration,
        _file: &RegisteredAuditFile,
    ) -> Result<()> {
        Ok(())
    }
}
/// Exact local registration serial, never reconstructed from markers.
#[must_use]
pub struct OwnedVmRegistration {
    shared: Arc<Shared>,
    vm: String,
    serial: u64,
    commitment: [u8; 32],
    directories: RegisteredDirectories,
    archive_owner: Option<Arc<dyn RegisteredEndpointOwner>>,
    archive: Option<RegisteredAuditFile>,
    retired: bool,
    audit: Mutex<AuditPreparation>,
}

struct RegisteredDirectories {
    state: File,
    socket_parent: File,
}

impl RegisteredDirectories {
    fn capture(state: &Path, socket: &Path) -> Result<Self> {
        let parent = socket
            .parent()
            .context("registered socket parent missing")?;
        Ok(Self {
            state: crate::host::restore_image::open_trusted_dir(state)?,
            socket_parent: crate::host::restore_image::open_trusted_dir(parent)?,
        })
    }

    fn check(&self, state: &Path, socket: &Path) -> Result<()> {
        let current = Self::capture(state, socket)?;
        for (held, current) in [
            (&self.state, &current.state),
            (&self.socket_parent, &current.socket_parent),
        ] {
            let held = held.metadata()?;
            let current = current.metadata()?;
            ensure!(
                (held.dev(), held.ino()) == (current.dev(), current.ino()),
                "original registration directory changed"
            );
        }
        Ok(())
    }
}

#[derive(Default)]
struct AuditPreparation {
    signer: Option<std::os::fd::OwnedFd>,
    claimed: bool,
    in_use: std::sync::Weak<()>,
}

/// One-shot original kernel observations bound to this actual registration.
/// It is not a process-exit receipt, signal capability or independent grant.
#[must_use]
pub struct PreparedEndpointAudit {
    shared: Arc<Shared>,
    vm: String,
    serial: u64,
    signer_pid: u32,
    signer: std::os::fd::OwnedFd,
    daemon: std::os::fd::OwnedFd,
    _registration_pin: Arc<()>,
}
impl fmt::Debug for PreparedEndpointAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedEndpointAudit { original_registration_bound: true }")
    }
}

impl PreparedEndpointAudit {
    /// Fresh admission observation; no descriptor or owner is exported.
    pub fn check_current(&self) -> Result<()> {
        let active = || -> Result<()> {
            let ledger = self
                .shared
                .ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
            ensure!(
                !ledger.closed
                    && !ledger.fenced
                    && ledger.slots.get(&self.vm).is_some_and(
                        |slot| slot.serial == self.serial && slot.phase == Phase::Active
                    ),
                "original audit registration is not active"
            );
            Ok(())
        };
        let result = (|| {
            active()?;
            self.shared.parent.check_current(&self.shared.tenant)?;
            self.shared.holder.verify_current()?;
            require_live_event(&self.signer)?;
            require_live_event(&self.daemon)?;
            active()
        })();
        if result.is_err() {
            self.shared.fence();
        }
        result
    }

    pub(crate) fn event_descriptors(&self) -> [std::os::fd::BorrowedFd<'_>; 2] {
        use std::os::fd::AsFd;
        [self.signer.as_fd(), self.daemon.as_fd()]
    }
    pub fn signer_pid(&self) -> u32 {
        self.signer_pid
    }
    pub fn socket(&self) -> &Path {
        &self.shared.signer_socket
    }
    pub fn tenant(&self) -> &str {
        &self.shared.tenant
    }
    pub fn vm(&self) -> &str {
        &self.vm
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedReady {
    nonce: [u8; 16],
    pid: u32,
    signer_pid: u32,
    audit_sideband: OwnedAuditSideband,
    #[cfg(target_os = "macos")]
    liveness: String,
}
impl OwnedReady {
    fn validate(
        &self,
        nonce: [u8; 16],
        daemon_pid: u32,
        audit_sideband: OwnedAuditSideband,
    ) -> Result<()> {
        #[cfg(target_os = "macos")]
        ensure!(
            self.liveness == "pipe_v1",
            "original daemon liveness mapping refused"
        );
        ensure!(
            self.nonce == nonce
                && self.pid == daemon_pid
                && self.signer_pid > 1
                && self.signer_pid != daemon_pid,
            "owned readiness identity mismatch"
        );
        ensure!(
            self.audit_sideband == audit_sideband,
            "owned readiness audit sideband differs"
        );
        Ok(())
    }
}
impl fmt::Debug for OwnedHostAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedHostAgent")
            .field("tenant", &self.shared.tenant)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub struct OwnedHostAgentSpawnError {
    reason: anyhow::Error,
    agent: OwnedHostAgent,
}
impl OwnedHostAgentSpawnError {
    pub fn agent_mut(&mut self) -> &mut OwnedHostAgent {
        &mut self.agent
    }
}
impl fmt::Display for OwnedHostAgentSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "owned host-agent startup failed: {}", self.reason)
    }
}
impl std::error::Error for OwnedHostAgentSpawnError {}
pub struct OwnedRegistrationError {
    reason: anyhow::Error,
    registration: OwnedVmRegistration,
}
impl OwnedRegistrationError {
    /// Move the original registration into the Runtime cleanup slot.
    pub fn into_parts(self) -> (anyhow::Error, OwnedVmRegistration) {
        (self.reason, self.registration)
    }

    pub fn registration_mut(&mut self) -> &mut OwnedVmRegistration {
        &mut self.registration
    }
}
impl fmt::Debug for OwnedRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRegistrationError")
            .finish_non_exhaustive()
    }
}
impl fmt::Display for OwnedRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "owned registration failed: {}", self.reason)
    }
}
impl std::error::Error for OwnedRegistrationError {}

fn absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect owned host-agent evidence"),
        Ok(_) => bail!("refusing preexisting host-agent evidence"),
    }
}
fn refuse_existing(tenant: &str) -> Result<()> {
    let directory = mvm_core::config::host_agent_dir(tenant);
    for path in [
        directory.join(DAEMON_PID_FILE),
        mvm_core::config::host_agent_worker_pid(tenant),
        directory.join("registrations.json"),
        mvm_core::config::host_agent_control_socket(tenant),
        mvm_core::config::host_agent_signer_helper_socket(tenant),
    ] {
        absent(&path)?;
    }
    Ok(())
}
fn config(tenant: &str) -> serde_json::Value {
    serde_json::json!({
        "tenant_id": tenant,
        "control_socket": mvm_core::config::host_agent_control_socket(tenant),
        "registration_journal_path": mvm_core::config::host_agent_dir(tenant).join("registrations.json"),
        "host_signer_public_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_PUB),
        "signer_helper_uds_path": mvm_core::config::host_agent_signer_helper_socket(tenant),
        "software_chain_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY),
    })
}
fn inherited_file(file: &File) -> Result<File> {
    // SAFETY: duplicates a borrowed live descriptor without changing its flags.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicate original helper holder");
    }
    // SAFETY: fcntl returned a new owned descriptor, at least 3.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn signing_key() -> Result<Zeroizing<[u8; 32]>> {
    let path = mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() == 32,
        "owned host signing key size/type"
    );
    let mut bytes = Zeroizing::new([0; 32]);
    file.read_exact(bytes.as_mut())?;
    ensure!(
        file.read(&mut [0; 1])? == 0,
        "owned host signing key changed size"
    );
    Ok(bytes)
}

impl OwnedHostAgent {
    pub const fn supports_process_address_space_limit() -> bool {
        cfg!(target_os = "linux")
    }

    pub fn spawn(inputs: OwnedHostAgentInputs) -> Result<Self> {
        let audit_sideband = OwnedAuditSideband::supported()?;
        mvm_core::naming::validate_vm_name(&inputs.tenant)?;
        ensure!(
            mvm_core::config::mvm_home_strict()?.as_os_str().len() <= 4096,
            "owned helper home path limit"
        );
        ensure!(
            host_agent_daemon_enabled(),
            "installed host-agent refuses the fork path"
        );
        inputs.parent.check_current(&inputs.tenant)?;
        inputs.holder.verify_current()?;
        let audit_chain_bytes = inputs.parent.owned_audit_chain_bytes(&inputs.tenant)?;
        let address_space_limit = inputs
            .parent
            .owned_process_address_space_limit(&inputs.tenant)?;
        ensure!(
            address_space_limit.is_none() || Self::supports_process_address_space_limit(),
            "funded daemon and signer require native address-space enforcement"
        );
        require_owned_child_custody()?;
        refuse_existing(&inputs.tenant)?;
        let directory = mvm_core::config::host_agent_dir(&inputs.tenant);
        mvm_core::private_fs::create_owned_private_dir(mvm_core::config::mvm_home_strict()?)?;
        mvm_core::private_fs::create_owned_private_dir(mvm_core::config::host_agent_root())?;
        mvm_core::private_fs::create_owned_private_dir(&directory)?;
        let key = signing_key()?;
        mvm_core::config::secure_host_agent_socket_dir(&inputs.tenant)?;
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(SPAWN_LOCK))?;
        // SAFETY: the lock is an owned descriptor retained throughout Child custody.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error()).context("owned host-agent spawn lock");
        }
        refuse_existing(&inputs.tenant)?;
        inputs.parent.check_current(&inputs.tenant)?;
        inputs.holder.verify_current()?;
        let bin = crate::host::broker_services_spawn::resolve_subprocess_bin_for(
            HOST_AGENT_BIN,
            "MVM_HOST_AGENT_PATH",
            &crate::host::aux_bin::HostProcess::current(),
        )?;
        let nonce: [u8; 16] = rand::random();
        let bytes = Zeroizing::new(serde_json::to_vec(
            &serde_json::json!({ "config": config(&inputs.tenant), "nonce":nonce, "audit_chain_bytes": audit_chain_bytes, "address_space_limit":address_space_limit }),
        )?);
        ensure!(
            bytes.len() <= CONTROL_MAX_FRAME_BYTES,
            "owned host-agent config limit"
        );
        let mut command = mvm_core::env_hygiene::helper_command(&bin);
        command
            .arg("--installed-owned")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let descriptors = [
            inherited_file(inputs.holder.directory())?,
            inherited_file(inputs.holder.holder())?,
        ];
        let inherited = [descriptors[0].as_raw_fd(), descriptors[1].as_raw_fd()];
        // SAFETY: post-fork only fcntl touches these still-owned descriptors. The
        // parent's CLOEXEC flags remain unchanged; both exec generations retain SH.
        unsafe {
            command.pre_exec(move || {
                for fd in inherited {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        inputs.parent.check_current(&inputs.tenant)?;
        inputs.holder.verify_current()?;
        #[cfg(target_os = "linux")]
        if let Some(limit) = address_space_limit {
            crate::host::process_limits::limit_original_address_space(&mut command, limit.get())?;
        }
        let mut child = command.spawn().context("spawn original host-agent child")?;
        drop(descriptors);
        let owner = child.stdin.take();
        let socket = mvm_core::config::host_agent_control_socket(&inputs.tenant);
        let signer_socket = mvm_core::config::host_agent_signer_helper_socket(&inputs.tenant);
        let mut agent = Self {
            shared: Arc::new(Shared {
                address_space_limit,
                audit_chain_bytes,
                tenant: inputs.tenant,
                control_socket: socket,
                signer_socket,
                audit_sideband,
                key,
                parent: inputs.parent,
                holder: inputs.holder,
                _spawn_lock: lock,
                process: Mutex::new(Process {
                    child,
                    owner,
                    status: None,
                    signer_pid: None,
                    #[cfg(target_os = "macos")]
                    liveness: None,
                }),
                ledger: Mutex::new(Ledger::default()),
                quarantined: AtomicBool::new(false),
            }),
            stopped: false,
        };
        if let Err(reason) = agent.ready(&bytes, nonce) {
            agent.shared.fence();
            return Err(OwnedHostAgentSpawnError { reason, agent }.into());
        }
        Ok(agent)
    }
    fn ready(&mut self, bytes: &[u8], nonce: [u8; 16]) -> Result<()> {
        let deadline = Instant::now() + DAEMON_READY_TIMEOUT;
        let mut process = self
            .shared
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child state poisoned"))?;
        let mut owner = process.owner.take().context("owned stdin absent")?;
        let mut stdout = process.child.stdout.take().context("owned stdout absent")?;
        owned_pipe_nonblocking(owner.as_raw_fd())?;
        owned_pipe_nonblocking(stdout.as_raw_fd())?;
        let mut startup = Vec::with_capacity(bytes.len() + 4);
        startup.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
        startup.extend_from_slice(bytes);
        let exchange = (|| -> Result<()> {
            let mut pending = startup.as_slice();
            while !pending.is_empty() {
                owned_pipe_ready(owner.as_raw_fd(), libc::POLLOUT, deadline)?;
                match owner.write(pending) {
                    Ok(0) => bail!("owned config pipe closed"),
                    Ok(count) => pending = &pending[count..],
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error).context("owned config pipe"),
                }
            }
            #[cfg(not(target_os = "macos"))]
            let bytes = {
                let mut header = [0; 4];
                read_until(&mut stdout, &mut header, deadline)?;
                let length = usize::try_from(u32::from_be_bytes(header))?;
                ensure!((1..=256).contains(&length), "owned readiness limit");
                let mut bytes = vec![0; length];
                read_until(&mut stdout, &mut bytes, deadline)?;
                bytes
            };
            #[cfg(target_os = "macos")]
            let bytes = crate::host::owned_liveness::read_ready_frame(&mut stdout, deadline)?;
            let ready: OwnedReady = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid owned readiness"))?;
            ready.validate(nonce, process.child.id(), self.shared.audit_sideband)?;
            ensure!(
                process.child.try_wait()?.is_none(),
                "owned readiness identity mismatch"
            );
            self.shared.parent.check_current(&self.shared.tenant)?;
            self.shared.holder.verify_current()?;
            #[cfg(target_os = "macos")]
            {
                crate::host::owned_liveness::require_live_read_pipe(&stdout)?;
                process.liveness = Some(crate::host::owned_liveness::duplicate_read_pipe(&stdout)?);
            }
            process.signer_pid = Some(ready.signer_pid);
            Ok(())
        })();
        process.owner = Some(owner);
        exchange
    }
    pub fn registrar(&self) -> OwnedHostAgentRegistrar {
        OwnedHostAgentRegistrar {
            shared: self.shared.clone(),
            registered: None,
        }
    }
    /// Original Child identity for observation only; never a cleanup handle.
    pub fn child_id(&self) -> Result<u32> {
        Ok(self
            .shared
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("owned child state poisoned"))?
            .child
            .id())
    }
    pub fn shutdown(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        {
            let mut ledger = self
                .shared
                .ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
            ledger.closed = true;
            ensure!(
                ledger.slots.is_empty(),
                "owned helper still has registrations"
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = stop_process(&self.shared, deadline);
        if result.is_ok() {
            self.stopped = true;
        } else {
            self.shared.fence();
        }
        result
    }
}
impl Drop for OwnedHostAgent {
    fn drop(&mut self) {
        if !self.stopped && self.shutdown().is_err() {
            self.shared.quarantine();
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn read_until(
    reader: &mut std::process::ChildStdout,
    mut output: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !output.is_empty() {
        owned_pipe_ready(reader.as_raw_fd(), libc::POLLIN, deadline)?;
        match reader.read(output) {
            Ok(0) => bail!("owned readiness pipe closed"),
            Ok(count) => output = &mut output[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error).context("owned readiness pipe"),
        }
    }
    Ok(())
}
fn stop_process(shared: &Shared, deadline: Instant) -> Result<()> {
    require_owned_child_custody()?;
    let mut process = shared
        .process
        .lock()
        .map_err(|_| anyhow::anyhow!("owned child state poisoned"))?;
    if process.status.is_none() {
        process.status = process.child.try_wait()?;
    }
    if process.status.is_none() {
        let observer = ProcessExitObserver::arm(libc::pid_t::try_from(process.child.id())?)?;
        drop(process.owner.take());
        ensure!(
            observer.wait_event(deadline)? == ProcessExitWait::Exited,
            "owned host-agent exit timed out"
        );
        process.status = collect_after_exit_event(deadline, || process.child.try_wait())?;
    }
    ensure!(
        process
            .status
            .context("owned host-agent exit unconfirmed")?
            .success(),
        "owned host-agent exited unsuccessfully"
    );
    Ok(())
}

fn registration(params: &HostAgentServicesParams<'_>, tenant: &str) -> RegisterVm {
    RegisterVm {
        vm_id: params.vm_name.into(),
        workload_id: Some(params.workload_id.into()),
        tenant_id: tenant.into(),
        broker_listen_socket: params.broker_listen_socket.to_string_lossy().into_owned(),
        workload_chain_path: mvm_core::config::workload_audit_path(tenant, params.vm_name)
            .to_string_lossy()
            .into_owned(),
        workload_chain_head_path: Some(
            params
                .state_dir
                .join(AUDIT_SIGNER_HEAD_FILE)
                .to_string_lossy()
                .into_owned(),
        ),
        audit_signer_uds_path: None,
        services_bindings: params.services.to_vec(),
        capability_bindings: params.capability_bindings.to_vec(),
        service_proxies: params.service_proxies.to_vec(),
        assurance: None,
    }
}
struct RegistrationSize(usize);
impl Write for RegistrationSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > 16384usize.saturating_sub(self.0) {
            return Err(std::io::Error::other("owned registration input limit"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn registration_bounds(params: &HostAgentServicesParams<'_>) -> Result<()> {
    ensure!(
        params.workload_id.len() <= 63
            && params.state_dir.as_os_str().len() <= 4096
            && params.broker_listen_socket.as_os_str().len() <= 4096
            && mvm_core::config::mvm_home().len() <= 4096,
        "owned registration path or identity limit"
    );
    ensure!(
        params.services.len() <= 64
            && params.capability_bindings.len() <= 64
            && params.service_proxies.len()
                <= mvm_contract::protocol::broker_control::MAX_SERVICE_PROXIES,
        "owned registration bindings limit"
    );
    serde_json::to_writer(
        &mut RegistrationSize(0),
        &(
            params.workload_id,
            params.vm_name,
            params.tenant_id,
            params.state_dir,
            params.broker_listen_socket,
            params.services,
            params.capability_bindings,
            params.service_proxies,
        ),
    )?;
    Ok(())
}

struct RegistrationCommitment {
    bytes: usize,
    hash: Sha256,
}
impl Write for RegistrationCommitment {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > CONTROL_MAX_FRAME_BYTES.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("owned canonical registration limit"));
        }
        self.bytes += bytes.len();
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn registration_commitment(request: &RegisterVm) -> Result<[u8; 32]> {
    let mut output = RegistrationCommitment {
        bytes: 0,
        hash: Sha256::new(),
    };
    // Local retained-facts identity only: this digest grants no authority and
    // changes neither the canonical Register value nor its signed wire bytes.
    output
        .hash
        .update(b"mvm.installed-host-agent.registration.v1\0");
    serde_json::to_writer(&mut output, request)?;
    Ok(output.hash.finalize().into())
}

fn owned_control(
    shared: &Shared,
    request: ControlRequest,
    registration: Option<&HostAgentServicesParams<'_>>,
) -> Result<(
    Option<std::os::fd::OwnedFd>,
    Option<Box<SignedAuditInventory>>,
)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let signed = broker_control::sign(request, &shared.key)?;
    let mut stream =
        crate::host::hvf_control_transport::connect_path(&shared.control_socket, deadline)?;
    shared.running()?;
    let child = shared
        .process
        .lock()
        .map_err(|_| anyhow::anyhow!("owned child state poisoned"))?
        .child
        .id();
    ensure!(
        u32::try_from(crate::host::uds_peer::connected_peer_pid(&stream)?)? == child,
        "control peer is not the original host-agent child"
    );
    if let Some(params) = registration {
        shared.parent.check_registration(params)?;
        shared.holder.verify_current()?;
    }
    crate::host::hvf_control_transport::write_frame_with_limit(
        &mut stream,
        &signed,
        deadline,
        CONTROL_MAX_FRAME_BYTES,
    )?;
    match crate::host::hvf_control_transport::read_frame_with_limit::<ControlResponse>(
        &mut stream,
        deadline,
        CONTROL_MAX_FRAME_BYTES,
    )? {
        ControlResponse::Ok => {
            let inventory = if shared.audit_chain_bytes.is_some() {
                Some(crate::host::hvf_control_transport::read_frame_with_limit(
                    &mut stream,
                    deadline,
                    4096,
                )?)
            } else {
                None
            };
            let signer = if registration.is_some()
                && shared.audit_sideband != OwnedAuditSideband::Unavailable
            {
                Some(receive_signer_event(&stream, deadline)?)
            } else {
                None
            };
            Ok((signer, inventory))
        }
        ControlResponse::Err { message } => bail!("owned host-agent refused control: {message}"),
    }
}
impl OwnedHostAgentRegistrar {
    pub fn audit_chain_bytes(&self) -> Option<std::num::NonZeroU64> {
        self.shared.audit_chain_bytes
    }

    /// Pre-exec ceiling inherited by the signer, subject to stricter host limits.
    pub fn process_address_space_limit(&self) -> Option<std::num::NonZeroU64> {
        self.shared.address_space_limit
    }

    /// Attach the original resource owner before passing this registrar to the runner.
    /// The underlying tenant daemon and its signed registration protocol stay the same.
    pub fn with_registration_owner(
        mut self,
        owner: Arc<dyn RegisteredEndpointOwner>,
    ) -> Result<Self> {
        ensure!(
            self.registered.is_none(),
            "registration observer already selected"
        );
        self.check_current_for_tenant(&self.shared.tenant)?;
        self.registered = Some(owner);
        Ok(self)
    }

    /// Both handles came from the same originally held tenant agent.
    pub fn same_original(&self, expected: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &expected.shared)
    }

    /// Compare this live tenant daemon with the holder retained by its issuer.
    pub fn check_original_holder(&self, expected: &PreparedHostLifetimeLease) -> Result<()> {
        self.check_current_for_tenant(&self.shared.tenant)?;
        expected.verify_current()?;
        let actual = &self.shared.holder;
        ensure!(
            actual.directory_object_id() == expected.directory_object_id()
                && actual.holder_object_id() == expected.holder_object_id()
                && actual.expectation() == expected.expectation(),
            "original host agent installation holder differs"
        );
        expected.verify_current()?;
        self.check_current_for_tenant(&self.shared.tenant)
    }

    /// Fresh observation for installed provisioning; never a future admission grant.
    pub fn check_current_for_tenant(&self, tenant: &str) -> Result<()> {
        ensure!(tenant == self.shared.tenant, "owned helper tenant mismatch");
        let admission = || -> Result<()> {
            let ledger = self
                .shared
                .ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
            ensure!(
                !ledger.closed && !ledger.fenced,
                "owned helper admission closed"
            );
            Ok(())
        };
        admission()?;
        self.shared.parent.check_current(tenant)?;
        self.shared.holder.verify_current()?;
        self.shared.running()?;
        admission()
    }

    pub fn register(&self, params: HostAgentServicesParams<'_>) -> Result<OwnedVmRegistration> {
        ensure!(
            params.tenant_id == Some(self.shared.tenant.as_str()),
            "owned registration tenant mismatch"
        );
        mvm_core::naming::validate_vm_name(params.vm_name)?;
        self.shared.parent.check_registration(&params)?;
        validate_owned_host_agent_services(&params)?;
        registration_bounds(&params)?;
        let directories =
            RegisteredDirectories::capture(params.state_dir, params.broker_listen_socket)?;
        let request = registration(&params, &self.shared.tenant);
        let commitment = registration_commitment(&request)?;
        self.shared.holder.verify_current()?;
        self.shared.running()?;
        for file in [
            crate::host::broker_services_spawn::BROKER_PID_FILE,
            crate::host::broker_services_spawn::AUDIT_SIGNER_PID_FILE,
            HOST_AGENT_TENANT_REF,
            mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE,
        ] {
            absent(&params.state_dir.join(file))?;
        }
        absent(params.broker_listen_socket)?;
        let serial = {
            let mut ledger = self
                .shared
                .ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
            ensure!(
                !ledger.closed
                    && !ledger.fenced
                    && ledger.slots.len() < 2
                    && !ledger.slots.contains_key(params.vm_name),
                "owned registration admission closed or busy"
            );
            ledger.next = ledger
                .next
                .checked_add(1)
                .context("owned registration serial exhausted")?;
            let serial = ledger.next;
            ledger.slots.insert(
                params.vm_name.into(),
                Slot {
                    serial,
                    phase: Phase::Sending,
                },
            );
            serial
        };
        let mut guard = OwnedVmRegistration {
            shared: self.shared.clone(),
            vm: params.vm_name.into(),
            serial,
            commitment,
            directories,
            archive_owner: self.registered.clone(),
            archive: None,
            retired: false,
            audit: Mutex::new(AuditPreparation::default()),
        };
        let result = owned_control(
            &self.shared,
            ControlRequest::Register(Box::new(request.clone())),
            Some(&params),
        )
        .and_then(|(event, inventory)| {
            if let Some(limit) = self.shared.audit_chain_bytes {
                guard.archive = Some(RegisteredAuditFile::capture(
                    &request,
                    inventory
                        .as_deref()
                        .context("original audit inventory missing")?,
                    limit.get(),
                )?);
            }
            if let Some(event) = event {
                require_live_event(&event)?;
                guard
                    .audit
                    .lock()
                    .map_err(|_| anyhow::anyhow!("audit preparation poisoned"))?
                    .signer = Some(event);
            }
            self.shared.running()
        })
        .and_then(|()| {
            guard
                .directories
                .check(params.state_dir, params.broker_listen_socket)
        })
        .and_then(|()| self.shared.parent.check_registration(&params))
        .and_then(|()| self.shared.holder.verify_current());
        let mut ledger = self
            .shared
            .ledger
            .lock()
            .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
        let closed = ledger.closed;
        let slot = ledger
            .slots
            .get_mut(params.vm_name)
            .context("owned registration slot vanished")?;
        ensure!(
            slot.serial == serial && slot.phase == Phase::Sending,
            "owned registration identity changed"
        );
        slot.phase = if result.is_ok() {
            Phase::Active
        } else {
            Phase::Uncertain
        };
        if result.is_err() || closed {
            ledger.fenced = true;
            ledger.closed = true;
            drop(ledger);
            let reason = result
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("helper closed during registration"));
            return Err(OwnedRegistrationError {
                reason,
                registration: guard,
            }
            .into());
        }
        drop(ledger);
        if let Some(owner) = &self.registered {
            let result = owner
                .bind_registration(self, &guard, &params)
                .and_then(|()| guard.check_current_for(self, &params));
            if let Err(reason) = result {
                return Err(OwnedRegistrationError {
                    reason,
                    registration: guard,
                }
                .into());
            }
        }
        Ok(guard)
    }
}
impl OwnedVmRegistration {
    pub fn registered_audit(&self) -> Option<&RegisteredAuditFile> {
        self.archive.as_ref()
    }

    /// Borrow both protected directory identities captured before this signed registration.
    /// The first is the VM state directory, the second the original broker socket parent.
    pub fn original_directories(
        &self,
        original: &OwnedHostAgentRegistrar,
        params: &HostAgentServicesParams<'_>,
    ) -> Result<(&File, &File)> {
        self.check_current_for(original, params)?;
        Ok((&self.directories.state, &self.directories.socket_parent))
    }

    /// Burn this registration's single endpoint handoff before preparing any
    /// observer. Failure or Drop never permits a second independent claim.
    pub fn prepare_endpoint_audit(
        &self,
        original: &OwnedHostAgentRegistrar,
        params: &HostAgentServicesParams<'_>,
    ) -> Result<PreparedEndpointAudit> {
        self.check_current_for(original, params)?;
        if self.shared.audit_sideband == OwnedAuditSideband::Unavailable {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "original audit sideband is unsupported on this host",
            )
            .into());
        }
        let (signer, registration_pin) = {
            let mut audit = self
                .audit
                .lock()
                .map_err(|_| anyhow::anyhow!("audit preparation poisoned"))?;
            ensure!(!audit.claimed, "original endpoint audit already claimed");
            audit.claimed = true;
            let signer = audit
                .signer
                .take()
                .context("original signer event unavailable")?;
            let pin = Arc::new(());
            audit.in_use = Arc::downgrade(&pin);
            (signer, pin)
        };
        let (daemon, signer_pid) = {
            // The actual Child remains unreaped under this same process
            // mutex while the new independent observer is armed.
            require_owned_child_custody()?;
            let process = self
                .shared
                .process
                .lock()
                .map_err(|_| anyhow::anyhow!("owned child state poisoned"))?;
            ensure!(
                process.status.is_none(),
                "original daemon already collected"
            );
            #[cfg(not(target_os = "macos"))]
            let daemon = {
                let observer = ProcessExitObserver::arm(i32::try_from(process.child.id())?)?;
                let event = observer
                    .event_fd()
                    .context("original daemon already exited")?;
                require_live_event(event)?;
                rustix::io::fcntl_dupfd_cloexec(event, 3)?
            };
            #[cfg(target_os = "macos")]
            let daemon = {
                let reader = process
                    .liveness
                    .as_ref()
                    .context("original daemon liveness absent")?;
                crate::host::owned_liveness::require_live_read_pipe(reader)?;
                crate::host::owned_liveness::duplicate_read_pipe(reader)?
            };
            (
                daemon,
                process
                    .signer_pid
                    .context("original signer readiness missing")?,
            )
        };
        self.check_current_for(original, params)?;
        let prepared = PreparedEndpointAudit {
            shared: self.shared.clone(),
            vm: self.vm.clone(),
            serial: self.serial,
            signer_pid,
            signer,
            daemon,
            _registration_pin: registration_pin,
        };
        prepared.check_current()?;
        Ok(prepared)
    }

    pub fn check_current_for(
        &self,
        original: &OwnedHostAgentRegistrar,
        params: &HostAgentServicesParams<'_>,
    ) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.shared, &original.shared)
                && !self.retired
                && params.tenant_id == Some(self.shared.tenant.as_str())
                && params.vm_name == self.vm,
            "owned registration original identity differs"
        );
        let active = || -> Result<()> {
            let ledger = self
                .shared
                .ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
            ensure!(
                !ledger.closed
                    && !ledger.fenced
                    && ledger.slots.get(&self.vm).is_some_and(|slot| {
                        slot.serial == self.serial && slot.phase == Phase::Active
                    }),
                "owned registration is not current and active"
            );
            Ok(())
        };
        active()?;
        validate_owned_host_agent_services(params)?;
        registration_bounds(params)?;
        ensure!(
            registration_commitment(&registration(params, &self.shared.tenant))? == self.commitment,
            "owned registration original facts differ"
        );
        // No parent/filesystem/process observation runs under the ledger.
        self.shared.parent.check_current(&self.shared.tenant)?;
        self.shared.parent.check_registration(params)?;
        self.directories
            .check(params.state_dir, params.broker_listen_socket)?;
        self.shared.holder.verify_current()?;
        self.shared.running()?;
        active()
    }

    pub(crate) fn installed_endpoint_settings(
        &self,
        original: &OwnedHostAgentRegistrar,
        params: &HostAgentServicesParams<'_>,
    ) -> Result<&crate::host::network_endpoint_spawn::InstalledEndpointSettings> {
        self.check_current_for(original, params)?;
        let settings = self.shared.parent.installed_endpoint_settings(params)?;
        self.check_current_for(original, params)?;
        Ok(settings)
    }

    pub(crate) fn check_flowmux_host_anchor(
        &self,
        original: &OwnedHostAgentRegistrar,
        params: &HostAgentServicesParams<'_>,
        candidate: &[u8; 32],
    ) -> Result<()> {
        ensure!(
            candidate == &self.original_host_public_key(original, params)?,
            "installed FlowMux host anchor differs from original registered signer"
        );
        self.check_current_for(original, params)
    }

    pub(crate) fn original_host_public_key(
        &self,
        original: &OwnedHostAgentRegistrar,
        params: &HostAgentServicesParams<'_>,
    ) -> Result<[u8; 32]> {
        self.check_current_for(original, params)?;
        let public = ed25519_dalek::SigningKey::from_bytes(&self.shared.key)
            .verifying_key()
            .to_bytes();
        self.check_current_for(original, params)?;
        Ok(public)
    }

    pub fn shutdown(&mut self) -> Result<()> {
        if self.retired {
            return Ok(());
        }
        {
            // Serialize the no-live-endpoint check with token preparation;
            // no transport or parent I/O occurs under either short mutex.
            let audit = self
                .audit
                .lock()
                .map_err(|_| anyhow::anyhow!("audit preparation poisoned"))?;
            ensure!(
                audit.in_use.upgrade().is_none(),
                "original audit endpoint still live"
            );
            let mut ledger = self
                .shared
                .ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
            let slot = ledger
                .slots
                .get_mut(&self.vm)
                .context("owned registration slot absent")?;
            ensure!(
                slot.serial == self.serial
                    && (slot.phase != Phase::Closing
                        || self
                            .archive
                            .as_ref()
                            .and_then(RegisteredAuditFile::terminal)
                            .is_some()),
                "owned registration identity or phase changed"
            );
            slot.phase = Phase::Closing;
        }
        let mut callback_pending = false;
        let result = (|| -> Result<()> {
            if self
                .archive
                .as_ref()
                .and_then(RegisteredAuditFile::terminal)
                .is_none()
            {
                self.shared.running()?;
                let (_, terminal) = owned_control(
                    &self.shared,
                    ControlRequest::Deregister(DeregisterVm {
                        vm_id: self.vm.clone(),
                    }),
                    None,
                )?;
                self.shared.running()?;
                if let Some(limit) = self.shared.audit_chain_bytes {
                    self.archive
                        .as_mut()
                        .context("original audit enrollment unavailable")?
                        .close(
                            terminal
                                .as_deref()
                                .context("missing signed audit terminal")?,
                            limit.get(),
                        )?;
                }
            }
            if let (Some(owner), Some(file)) = (&self.archive_owner, &self.archive) {
                let limit = self
                    .shared
                    .audit_chain_bytes
                    .context("original audit limit missing")?;
                file.check_terminal(limit.get())?;
                if let Err(error) = owner.retired_audit(self, file) {
                    file.check_terminal(limit.get())?;
                    callback_pending = true;
                    return Err(error);
                }
                file.check_terminal(limit.get())?;
            }
            Ok(())
        })();
        let mut ledger = self
            .shared
            .ledger
            .lock()
            .map_err(|_| anyhow::anyhow!("owned registration ledger poisoned"))?;
        ensure!(
            ledger
                .slots
                .get(&self.vm)
                .is_some_and(|slot| slot.serial == self.serial && slot.phase == Phase::Closing),
            "owned registration completion identity changed"
        );
        if let Err(error) = result {
            // Closing retains this one slot until the consumer durably adopts the file.
            if callback_pending {
                return Err(error);
            }
            if let Some(slot) = ledger.slots.get_mut(&self.vm) {
                slot.phase = Phase::Uncertain;
            }
            ledger.fenced = true;
            ledger.closed = true;
            return Err(error);
        }
        ledger.slots.remove(&self.vm);
        self.retired = true;
        drop(ledger);
        // A retained, already-retired guard must not retain an unused signer
        // observation across later registrations. Recover poison only to close
        // this owned fd after positive signed cleanup; never reopen admission.
        self.audit
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .signer
            .take();
        Ok(())
    }
}
impl Drop for OwnedVmRegistration {
    fn drop(&mut self) {
        if !self.retired && self.shutdown().is_err() {
            self.shared.quarantine();
        }
    }
}

#[cfg(test)]
mod ready_tests {
    use super::{OwnedAuditSideband, OwnedReady, RegisteredDirectories};

    #[test]
    fn retained_state_and_socket_directories_refuse_name_replacement() {
        use std::os::unix::fs::DirBuilderExt;
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join("state");
        let sockets = home.path().join("sockets");
        let socket = sockets.join("agent.sock");
        for path in [&state, &sockets] {
            std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        let original = RegisteredDirectories::capture(&state, &socket).unwrap();
        original.check(&state, &socket).unwrap();
        for path in [&state, &sockets] {
            let saved = path.with_extension("held");
            std::fs::rename(path, &saved).unwrap();
            std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
            assert!(original.check(&state, &socket).is_err());
            std::fs::remove_dir(path).unwrap();
            std::fs::rename(saved, path).unwrap();
            original.check(&state, &socket).unwrap();
        }
    }

    #[test]
    fn readiness_requires_an_explicit_audit_sideband_mode() {
        let mut wire = serde_json::json!({
            "nonce": ([7_u8; 16]),
            "pid": 41,
            "signer_pid": 42,
            "audit_sideband": OwnedAuditSideband::Unavailable,
        });
        #[cfg(target_os = "macos")]
        {
            wire["liveness"] = serde_json::json!("pipe_v1");
        }
        assert!(serde_json::from_value::<OwnedReady>(wire.clone()).is_ok());
        wire.as_object_mut().unwrap().remove("audit_sideband");
        assert!(serde_json::from_value::<OwnedReady>(wire).is_err());
    }

    #[test]
    fn owned_ready_rejects_foreign_nonce_daemon_and_invalid_signer_metadata() {
        let mut ready = OwnedReady {
            nonce: [7; 16],
            pid: 41,
            signer_pid: 42,
            audit_sideband: OwnedAuditSideband::PidfdV1,
            #[cfg(target_os = "macos")]
            liveness: "pipe_v1".into(),
        };
        let sideband = ready.audit_sideband;
        ready.validate([7; 16], 41, sideband).unwrap();
        assert!(
            ready
                .validate([7; 16], 41, OwnedAuditSideband::Unavailable)
                .is_err()
        );
        assert!(ready.validate([8; 16], 41, sideband).is_err());
        assert!(ready.validate([7; 16], 43, sideband).is_err());
        for signer in [0, 1, 41] {
            ready.signer_pid = signer;
            assert!(ready.validate([7; 16], 41, sideband).is_err());
        }
        assert!(
            serde_json::from_str::<OwnedReady>(
                r#"{"nonce":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"pid":41}"#
            )
            .is_err()
        );
    }
}
