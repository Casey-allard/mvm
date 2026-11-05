use super::*;
use crate::host::network_endpoint_spawn::{owned_pipe_nonblocking, owned_pipe_ready};
use crate::host::process_exit::{
    ProcessExitObserver, ProcessExitWait, collect_after_exit_event, require_owned_child_custody,
};
use anyhow::ensure;
use mvm_core::host_lifetime::PreparedHostLifetimeLease;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

/// Trusted installed DI retaining the actual aggregate helper reservation.
pub trait HostAgentParentPermit: Send + Sync {
    fn check_current(&self, tenant: &str) -> Result<()>;
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
}
struct Shared {
    tenant: String,
    socket: PathBuf,
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
}
/// Exact local registration serial, never reconstructed from markers.
#[must_use]
pub struct OwnedVmRegistration {
    shared: Arc<Shared>,
    vm: String,
    serial: u64,
    retired: bool,
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
    pub fn spawn(inputs: OwnedHostAgentInputs) -> Result<Self> {
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
            &serde_json::json!({ "config": config(&inputs.tenant), "nonce":nonce }),
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
        let mut child = command.spawn().context("spawn original host-agent child")?;
        drop(descriptors);
        let owner = child.stdin.take();
        let socket = mvm_core::config::host_agent_control_socket(&inputs.tenant);
        let mut agent = Self {
            shared: Arc::new(Shared {
                tenant: inputs.tenant,
                socket,
                key,
                parent: inputs.parent,
                holder: inputs.holder,
                _spawn_lock: lock,
                process: Mutex::new(Process {
                    child,
                    owner,
                    status: None,
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
            let mut header = [0; 4];
            read_until(&mut stdout, &mut header, deadline)?;
            let length = usize::try_from(u32::from_be_bytes(header))?;
            ensure!((1..=256).contains(&length), "owned readiness limit");
            let mut bytes = vec![0; length];
            read_until(&mut stdout, &mut bytes, deadline)?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Ready {
                nonce: [u8; 16],
                pid: u32,
            }
            let ready: Ready = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid owned readiness"))?;
            ensure!(
                ready.nonce == nonce
                    && ready.pid == process.child.id()
                    && process.child.try_wait()?.is_none(),
                "owned readiness identity mismatch"
            );
            self.shared.parent.check_current(&self.shared.tenant)?;
            self.shared.holder.verify_current()?;
            Ok(())
        })();
        process.owner = Some(owner);
        exchange
    }
    pub fn registrar(&self) -> OwnedHostAgentRegistrar {
        OwnedHostAgentRegistrar {
            shared: self.shared.clone(),
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
        tool_decision_socket: Some(
            mvm_core::config::vm_socket_dir_at(params.state_dir)
                .join(crate::host::network_endpoint_spawn::SUBST_CONNECTOR_SOCKET)
                .to_string_lossy()
                .into_owned(),
        ),
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

fn owned_control(
    shared: &Shared,
    request: ControlRequest,
    registration: Option<&HostAgentServicesParams<'_>>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let signed = broker_control::sign(request, &shared.key)?;
    let mut stream = crate::host::hvf_control_transport::connect_path(&shared.socket, deadline)?;
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
        ControlResponse::Ok => Ok(()),
        ControlResponse::Err { message } => bail!("owned host-agent refused control: {message}"),
    }
}
impl OwnedHostAgentRegistrar {
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
        let guard = OwnedVmRegistration {
            shared: self.shared.clone(),
            vm: params.vm_name.into(),
            serial,
            retired: false,
        };
        let result = owned_control(
            &self.shared,
            ControlRequest::Register(Box::new(registration(&params, &self.shared.tenant))),
            Some(&params),
        )
        .and_then(|()| self.shared.running())
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
        Ok(guard)
    }
}
impl OwnedVmRegistration {
    pub fn shutdown(&mut self) -> Result<()> {
        if self.retired {
            return Ok(());
        }
        {
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
                slot.serial == self.serial && slot.phase != Phase::Closing,
                "owned registration identity or phase changed"
            );
            slot.phase = Phase::Closing;
        }
        let result = self
            .shared
            .running()
            .and_then(|()| {
                owned_control(
                    &self.shared,
                    ControlRequest::Deregister(DeregisterVm {
                        vm_id: self.vm.clone(),
                    }),
                    None,
                )
            })
            .and_then(|()| self.shared.running());
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
            if let Some(slot) = ledger.slots.get_mut(&self.vm) {
                slot.phase = Phase::Uncertain;
            }
            ledger.fenced = true;
            ledger.closed = true;
            return Err(error);
        }
        ledger.slots.remove(&self.vm);
        self.retired = true;
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
