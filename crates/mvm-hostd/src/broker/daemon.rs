//! Resident per-tenant host-agent daemon.
//!
//! One daemon per tenant, not one process per VM. VMs register with it over
//! the host-signed control plane ([`mvm_core::protocol::broker_control`]); on each `RegisterVm` it
//! binds that VM's `BROKER_PORT` socket and serves host-services on it, and on
//! `DeregisterVm` it unbinds and drops the VM. A tenant's many microVMs are
//! *registrations* in the `vm_id` map, not processes — `O(active tenants)`
//! daemons, not `O(VMs)`.
//!
//! Identity is **server-derived**: each VM's socket has its own serve task with
//! its own `Registry` (its `host.audit.v1` handler points at *its own*
//! audit-signer / chain). The `vm_id` a dispatched call is attributed to comes
//! from *which socket accepted it* — established at `RegisterVm` time — never
//! from a field in the guest frame. So one guest cannot reach another VM's
//! bindings or write another VM's chain, even though they share this daemon.
//!
//! The daemon holds **no keys** (the moat): it parses untrusted guest frames
//! but only forwards audit entries to the per-VM audit-signer that holds the
//! signing key. This slice is the daemon + its register/deregister core; the
//! `mvm-backend` `ensure_daemon`/`register_vm` seam that replaces the per-VM
//! `spawn_broker` fork is the next slice.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;
use mvm_core::protocol::audit_signer::{
    SignerHelperAppendEntry, SignerHelperDeregisterVm, SignerHelperRegisterVm, SignerHelperRequest,
    SignerHelperResponse,
};
use mvm_core::protocol::broker_control;
use mvm_core::protocol::broker_control::{
    ControlRequest, ControlResponse, RegisterVm, SignedControl,
};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::warn;

use crate::audit_signer::helper_client::SignerHelperClient;

use super::control_prepare::{JournalSnapshots, MutationCell, MutationIoStage, VmMapPhase};
use super::server::{read_frame, write_frame};

/// Audit category for daemon-emitted health entries. Health probing is
/// mvm-hostd lifecycle activity, so it files under the host-asserted `host`
/// category — distinct from a workload's own `workload_audit` emissions — with
/// the event name carried in the entry's fields. Must stay in the
/// audit-signer allow-list.
const HEALTH_AUDIT_CATEGORY: &str = "host";

/// Retired service name remains reserved so old signed registrations fail closed.
const RETIRED_HOST_TOOL_SERVICE: &str = "host.tool.v1";

/// Default control-frame cap — Register/Deregister are tiny; this bounds a
/// hostile/garbled control message.
const CONTROL_MAX_FRAME_BYTES: usize = 64 * 1024;

/// Default per-VM guest dispatch frame cap.
fn default_max_frame_bytes() -> usize {
    64 * 1024
}

/// Startup config the `mvm-host-agent` daemon reads on stdin: which tenant it
/// serves, where to bind its control socket, and the host signer public key it
/// verifies control messages against. The supervisor writes this once at spawn.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAgentConfig {
    /// The single tenant this daemon serves (it is per-tenant).
    pub tenant_id: String,
    /// The per-tenant control UDS to bind (mode 0700, host-only).
    pub control_socket: PathBuf,
    /// Persistent registration snapshot, independent of the socket namespace.
    /// Omitted by legacy configs whose sockets live beside their durable state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_journal_path: Option<PathBuf>,
    /// Path to the host signer's 32-byte Ed25519 public key, used to verify
    /// every control message.
    pub host_signer_public_key_path: PathBuf,
    /// UDS bound by this daemon's supervised signer helper child.
    pub signer_helper_uds_path: PathBuf,
    /// Tenant signing key path handed to the signer helper child. The
    /// host-agent never reads this key; it only passes the path across the
    /// process moat.
    pub software_chain_key_path: PathBuf,
    /// Per-VM guest dispatch frame cap.
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

/// Deterministic coordination labels selected from the original host config.
/// These fields are neither capabilities nor evidence of fresh provisioning.
pub struct HostAgentResourceDescriptor {
    pub root: PathBuf,
    pub key: mvm_vmm::host::installed_owner::InstallationKey,
}

impl HostAgentConfig {
    /// Derive the versioned resource namespace without creating or repairing it.
    /// Production opens existing provisioning; fresh fixture creation is explicit.
    pub fn resource_descriptor(&self, home: &Path) -> Result<HostAgentResourceDescriptor> {
        let descriptor = mvm_vmm::host::host_agent_installation::descriptor(home, &self.tenant_id)?;
        Ok(HostAgentResourceDescriptor {
            root: descriptor.root,
            key: descriptor.key,
        })
    }

    /// Resolve durable recovery state. Only legacy configs derive it from the
    /// control socket; new launchers supply the persistent tenant-state path.
    pub fn registration_journal_path(&self) -> Result<PathBuf> {
        if let Some(path) = &self.registration_journal_path {
            return Ok(path.clone());
        }
        let dir = self
            .control_socket
            .parent()
            .context("host-agent control socket path must have a parent directory")?;
        Ok(dir.join("registrations.json"))
    }

    /// Load the verifying key from `host_signer_public_key_path`.
    pub fn load_verifying_key(&self) -> Result<VerifyingKey> {
        let bytes = std::fs::read(&self.host_signer_public_key_path).with_context(|| {
            format!(
                "read host signer pubkey {}",
                self.host_signer_public_key_path.display()
            )
        })?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("host signer pubkey must be 32 bytes, got {}", bytes.len())
        })?;
        VerifyingKey::from_bytes(&arr).context("host signer pubkey is not a valid Ed25519 key")
    }
}

struct AcceptedWorkState {
    next: u64,
    closed: bool,
    rows: HashMap<u64, Option<mvm_vmm::host::installed_owner::HolderLease>>,
}

struct AcceptedWorkOwner {
    state: std::sync::Mutex<AcceptedWorkState>,
    unresolved: std::sync::atomic::AtomicBool,
    changed: tokio::sync::watch::Sender<()>,
}

/// One original daemon turn, not a capability or a child-collection result.
/// Drop retains its row; only known no-spawn or represented original ownership
/// permits explicit settlement. Resource acquisition/effects happen outside gates.
pub(crate) struct AcceptedDaemonWork {
    owner: Arc<AcceptedWorkOwner>,
    id: u64,
    settled: bool,
}

impl AcceptedDaemonWork {
    pub(crate) fn attach_resource(
        &self,
        lease: mvm_vmm::host::installed_owner::HolderLease,
    ) -> Result<()> {
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("daemon accepted-work state unavailable"))?;
        let row = state
            .rows
            .get_mut(&self.id)
            .context("original accepted-work row missing")?;
        anyhow::ensure!(row.is_none(), "accepted-work resource already attached");
        *row = Some(lease);
        Ok(())
    }

    /// Original accepted-turn bookkeeping only, never a Child receipt.
    pub(crate) fn is_settled(&self) -> bool {
        self.settled
    }

    pub(crate) fn settle(&mut self) -> Result<()> {
        if self.settled {
            return Ok(());
        }
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("daemon accepted-work state unavailable"))?;
        let lease = state
            .rows
            .remove(&self.id)
            .context("original accepted-work row missing")?;
        self.settled = true;
        drop(state);
        drop(lease);
        self.owner.changed.send_replace(());
        Ok(())
    }
}

impl Drop for AcceptedDaemonWork {
    fn drop(&mut self) {
        if !self.settled {
            self.owner
                .unresolved
                .store(true, std::sync::atomic::Ordering::Release);
            self.owner.changed.send_replace(());
        }
    }
}

/// Retains the original accepted-turn ledger while its represented operations
/// finish. Empty means no accepted turn remains; it is not a Child receipt.
pub struct AcceptedWorkDrain {
    owner: Arc<AcceptedWorkOwner>,
}

impl AcceptedWorkDrain {
    /// Wait outside all lifecycle and daemon locks. Notification carries no
    /// authority; each wake rechecks this original ledger and sticky errors.
    pub async fn drain(&self) -> Result<()> {
        let mut changed = self.owner.changed.subscribe();
        loop {
            anyhow::ensure!(
                !self
                    .owner
                    .unresolved
                    .load(std::sync::atomic::Ordering::Acquire),
                "original accepted daemon work is unresolved"
            );
            let empty = self
                .owner
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("original accepted-work ledger poisoned"))?
                .rows
                .is_empty();
            if empty {
                return Ok(());
            }
            changed
                .changed()
                .await
                .context("original accepted-work notification closed")?;
        }
    }
}

#[derive(Clone)]
struct DaemonLifecycleAdmission {
    gate: mvm_core::tenant_lifecycle::TenantLifecycleGate,
    generation: mvm_core::tenant_lifecycle::LifecycleGeneration,
}

/// An opaque clone of the SAME original custody cell. It supplies no new
/// budget, signed permission, readiness, or process collection proof.
#[derive(Clone)]
pub struct DaemonCustodyOwner {
    cell: Arc<MutationCell>,
}

/// Actual original service listener/connection joins, not OS-child collection.
pub struct DaemonServicesDrainReceipt {
    _private: (),
}

impl DaemonCustodyOwner {
    pub fn request_stop(&self) {
        self.cell.request_stop();
    }

    pub async fn drain_services(&self) -> Result<DaemonServicesDrainReceipt> {
        self.cell.drain_services().await?;
        Ok(DaemonServicesDrainReceipt { _private: () })
    }
}

impl Drop for HostAgentDaemon {
    fn drop(&mut self) {
        self.custody.request_stop();
        // The original map remains in its field under the coordinator's Arc,
        // including if a borrowed retirement currently holds that field.
    }
}

/// The resident per-tenant host-agent daemon.
pub struct HostAgentDaemon {
    tenant_id: String,
    verifying_key: VerifyingKey,
    signer_helper_uds_path: Option<PathBuf>,
    registration_journal: Option<RegistrationJournal>,
    max_frame_bytes: usize,
    lifecycle_admission: Option<DaemonLifecycleAdmission>,
    work: Arc<AcceptedWorkOwner>,
    resources: Option<Arc<mvm_vmm::host::installed_owner::InstallationBinding>>,
    mutation_lane: Arc<tokio::sync::Semaphore>,
    connection_slots: Arc<tokio::sync::Semaphore>,
    custody: Arc<MutationCell>,
    registrations: HashMap<String, RegisterVm>,
    mailbox_workers: Option<Arc<super::mailbox_workers::MailboxWorkers>>,
}

#[derive(Debug, Clone)]
struct RegistrationJournal {
    path: PathBuf,
}

impl RegistrationJournal {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn load(&self) -> Result<Vec<RegisterVm>> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let before = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            before.is_file()
                && before.nlink() == 1
                && before.len() <= CONTROL_MAX_FRAME_BYTES as u64,
            "registration journal is not a bounded canonical regular file"
        );
        mvm_core::private_fs::require_current_owner(&before)?;
        // Preserve existing canonical legacy 0644 journals, but never trust a
        // journal writable by another identity or a redirected leaf.
        anyhow::ensure!(
            mvm_core::private_fs::mode_bits(&self.path, &before)? & 0o022 == 0,
            "registration journal is writable by another identity"
        );
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.path)?;
        let opened = file.metadata()?;
        anyhow::ensure!(
            opened.is_file()
                && opened.nlink() == 1
                && opened.dev() == before.dev()
                && opened.ino() == before.ino()
                && opened.len() <= CONTROL_MAX_FRAME_BYTES as u64,
            "registration journal changed during checked open"
        );
        mvm_core::private_fs::require_current_owner(&opened)?;
        anyhow::ensure!(
            mvm_core::private_fs::mode_bits(&self.path, &opened)? & 0o022 == 0,
            "opened registration journal is writable by another identity"
        );
        let mut bytes = Vec::new();
        file.by_ref()
            .take(CONTROL_MAX_FRAME_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= CONTROL_MAX_FRAME_BYTES,
            "registration journal exceeds checked inventory bound"
        );
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&bytes).context("decode bounded canonical registration journal")
    }

    fn store<'a>(&self, registrations: impl IntoIterator<Item = &'a RegisterVm>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create registration journal dir {}", parent.display()))?;
        }

        let mut registrations: Vec<RegisterVm> = registrations.into_iter().cloned().collect();
        registrations.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));

        let mut bytes = serde_json::to_vec_pretty(&registrations)
            .context("encode registration journal snapshot")?;
        bytes.push(b'\n');

        let tmp_path = self.tmp_path()?;
        std::fs::write(&tmp_path, bytes)
            .with_context(|| format!("write registration journal temp {}", tmp_path.display()))?;
        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e).with_context(|| {
                format!(
                    "replace registration journal {} with {}",
                    self.path.display(),
                    tmp_path.display()
                )
            });
        }
        Ok(())
    }

    fn tmp_path(&self) -> Result<PathBuf> {
        let file_name = self
            .path
            .file_name()
            .context("registration journal path must have a file name")?
            .to_string_lossy();
        let mut tmp_path = self.path.clone();
        tmp_path.set_file_name(format!("{file_name}.{}.tmp", std::process::id()));
        Ok(tmp_path)
    }
}

/// An owned copy of original verified control context. These fields are
/// coordination inputs, never a new signature/admission or a cleanup receipt.
#[derive(Clone)]
pub(crate) struct RegistrationSnapshot {
    pub(crate) registration: RegisterVm,
    pub(crate) tenant: String,
    pub(crate) helper: Option<PathBuf>,
    pub(crate) max_frame_bytes: usize,
    pub(crate) connection_slots: Arc<tokio::sync::Semaphore>,
}

/// Original canonical replay snapshot. Construction does no I/O; execution
/// belongs outside daemon/file locks and under the original mutation permit.
pub struct SignerRegistrationReplay {
    helper: Option<PathBuf>,
    registrations: Vec<RegisterVm>,
}

impl SignerRegistrationReplay {
    pub fn execute(self) -> Result<usize> {
        let Some(path) = self.helper else {
            return Ok(0);
        };
        let count = self.registrations.len();
        for registration in self.registrations {
            register_helper_vm_at(&path, &registration)
                .context("replay original canonical signer registration")?;
        }
        Ok(count)
    }
}

pub(crate) fn register_helper_vm_at(path: &Path, r: &RegisterVm) -> Result<()> {
    let req = SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
        request_id: format!("register-{}", r.vm_id),
        vm_id: r.vm_id.clone(),
        tenant_id: r.tenant_id.clone(),
        workload_id: r.workload_id.clone().unwrap_or_else(|| r.vm_id.clone()),
        workload_chain_path: r.workload_chain_path.clone(),
        chain_head_secondary_path: r.workload_chain_head_path.clone().unwrap_or_else(|| {
            Path::new(&r.workload_chain_path)
                .with_extension("head")
                .to_string_lossy()
                .into_owned()
        }),
    });
    match SignerHelperClient::new(path.to_path_buf()).send(&req)? {
        SignerHelperResponse::Registered { .. } => Ok(()),
        SignerHelperResponse::Err { message, .. } => {
            bail!("signer-helper register refused: {message}")
        }
        other => bail!("signer-helper returned unexpected register response: {other:?}"),
    }
}

pub(crate) fn deregister_helper_vm_at(path: &Path, vm_id: &str) -> Result<()> {
    let req = SignerHelperRequest::DeregisterVm(SignerHelperDeregisterVm {
        request_id: format!("deregister-{vm_id}"),
        vm_id: vm_id.to_string(),
    });
    match SignerHelperClient::new(path.to_path_buf()).send(&req)? {
        SignerHelperResponse::Deregistered { .. } => Ok(()),
        SignerHelperResponse::Err { message, .. } => {
            bail!("signer-helper deregister refused: {message}")
        }
        other => bail!("signer-helper returned unexpected deregister response: {other:?}"),
    }
}

/// Canonical side-effect-free validation shared by legacy and staged control.
/// The caller still verifies the original signed control and current generation.
pub(crate) fn validate_registration(tenant_id: &str, r: &RegisterVm) -> Result<()> {
    // The daemon is per-tenant: refuse a registration for another tenant.
    if r.tenant_id != tenant_id {
        bail!(
            "register for tenant {:?} on a daemon for tenant {:?}",
            r.tenant_id,
            tenant_id
        );
    }
    // `vm_id` names the per-VM chain file; even though the register message
    // is host-signed, validate it as a defense-in-depth path-injection
    // guard before it reaches any filesystem path.
    validate_vm_id(&r.vm_id)?;
    let host_tool = mvm_core::protocol::broker::ServiceId::parse(RETIRED_HOST_TOOL_SERVICE)
        .expect("host.tool.v1 is a valid ServiceId");
    anyhow::ensure!(
        !r.services_bindings.contains(&host_tool)
            && !r
                .service_proxies
                .iter()
                .any(|proxy| proxy.service == host_tool),
        "host.tool.v1 is no longer supported"
    );
    if r.service_proxies.len() > mvm_contract::protocol::broker_control::MAX_SERVICE_PROXIES {
        bail!("registration has too many controller-backed services");
    }
    let mut proxy_services = HashSet::new();
    for proxy in &r.service_proxies {
        proxy
            .validate()
            .map_err(|message| anyhow::anyhow!(message))?;
        if !r.services_bindings.contains(&proxy.service) {
            bail!("controller-backed service is absent from signed service admission");
        }
        if !proxy_services.insert(proxy.service.clone()) {
            bail!("registration repeats a controller-backed service");
        }
        for descriptor in &proxy.capabilities {
            if !r.capability_bindings.contains(&descriptor.binding()) {
                bail!("controller-backed capability is absent from signed admission");
            }
        }
    }

    Ok(())
}

/// Open the assurance session the supervisor admitted for this VM.
///
/// This daemon is the process a probe reaches, so it is the only place a
/// session can usefully exist. The registration is host-signed, so what
/// arrives here has already been decided: the binding names a plan the
/// supervisor verified, the authority is post-intersection, and the declared
/// destinations are resolved. Nothing is judged again.
///
/// Both refusals below open nothing rather than opening something partial. A
/// session whose service is not bound and a session with no audit route are
/// each a registration that does not describe a run this daemon should serve,
/// and the probe verb answers `NotBound` or `AuditUnavailable` either way.
pub(crate) fn open_admitted_assurance_session(
    bound: &super::handlers::BoundHandlers,
    r: &RegisterVm,
) {
    let Some(session) = &r.assurance else { return };
    let Some(session_ref) = &session.session else {
        tracing::warn!(vm_id = %r.vm_id, "legacy assurance registration has no provider session identity; refusing to open");
        return;
    };
    let Some(source_digest) = &session.source_digest else {
        tracing::warn!(vm_id = %r.vm_id, "assurance registration has no source digest; refusing to open");
        return;
    };
    let Some(handler) = &bound.assurance else {
        tracing::warn!(
            vm_id = %r.vm_id,
            "an assurance session was registered but host.assurance.v1 is not bound; \
             opening nothing"
        );
        return;
    };
    let Some(path) = &r.audit_signer_uds_path else {
        tracing::warn!(
            vm_id = %r.vm_id,
            "an assurance session was registered with no audit route; its probes could \
             not be recorded, so the session is not opened"
        );
        return;
    };

    let sink = crate::audit::assurance::SignerSink::new(
        super::audit_client::AuditClient::new(path.clone()),
        r.workload_id.clone().unwrap_or_else(|| r.vm_id.clone()),
        r.tenant_id.clone(),
        session.workload_session_id.clone(),
    );
    handler.open_session(super::handlers::host_assurance_v1::AssuranceSessionSpec {
        workload_session_id: session.workload_session_id.clone(),
        binding: session.binding.clone(),
        session: session_ref.clone(),
        source_digest: source_digest.clone(),
        authority: session.authority.clone(),
        trial_id: session.trial_id.clone(),
        policy: session.policy.clone(),
        destinations: session
            .destinations
            .iter()
            .map(
                |edge| super::handlers::host_assurance_v1::DeclaredDestination {
                    label: edge.label.clone(),
                    host: edge.host.clone(),
                    port: edge.port,
                },
            )
            .collect(),
        identity: session.identity.clone(),
        sink: Some(std::sync::Arc::new(sink)),
    });
    tracing::info!(
        vm_id = %r.vm_id,
        workload_session_id = %session.workload_session_id,
        "assurance session opened for the admitted campaign"
    );
}

impl HostAgentDaemon {
    /// New daemon for `tenant_id`, verifying control messages against
    /// `verifying_key` (the host signer's public key). `max_frame_bytes` caps
    /// the per-VM guest dispatch frames.
    pub fn new(
        tenant_id: impl Into<String>,
        verifying_key: VerifyingKey,
        max_frame_bytes: usize,
    ) -> Self {
        let connection_slots = Arc::new(tokio::sync::Semaphore::new(256));
        let custody = Arc::new(MutationCell::new(connection_slots.clone()));
        Self {
            tenant_id: tenant_id.into(),
            verifying_key,
            signer_helper_uds_path: None,
            registration_journal: None,
            max_frame_bytes,
            lifecycle_admission: None,
            work: Arc::new(AcceptedWorkOwner {
                state: std::sync::Mutex::new(AcceptedWorkState {
                    next: 0,
                    closed: false,
                    rows: HashMap::new(),
                }),
                unresolved: std::sync::atomic::AtomicBool::new(false),
                changed: tokio::sync::watch::channel(()).0,
            }),
            resources: None,
            mutation_lane: Arc::new(tokio::sync::Semaphore::new(1)),
            // One per-tenant concurrent ingress budget, shared by every VM.
            // It is distinct from mutation, worker and pending-launch limits.
            connection_slots,
            custody,
            registrations: HashMap::new(),
            mailbox_workers: None,
        }
    }

    /// Install original coordination metadata before serving; this does not
    /// publish Active or grant a signed control operation.
    pub fn with_lifecycle_coordination(
        mut self,
        home: &Path,
        generation: mvm_core::tenant_lifecycle::LifecycleGeneration,
    ) -> Result<Self> {
        let gate = mvm_core::tenant_lifecycle::TenantLifecycleGate::new(home, &self.tenant_id)?;
        {
            let mut state = self
                .work
                .state
                .try_lock()
                .map_err(|_| anyhow::anyhow!("original accepted-work state unavailable"))?;
            anyhow::ensure!(
                state.rows.is_empty(),
                "cannot replace a live admission context"
            );
            anyhow::ensure!(
                !self
                    .work
                    .unresolved
                    .load(std::sync::atomic::Ordering::Acquire),
                "original accepted work unresolved"
            );
            state.closed = true;
        }
        self.lifecycle_admission = Some(DaemonLifecycleAdmission { gate, generation });
        Ok(self)
    }

    pub fn custody_owner(&self) -> DaemonCustodyOwner {
        DaemonCustodyOwner {
            cell: self.custody.clone(),
        }
    }

    pub(crate) fn registration_snapshot(
        &self,
        registration: &RegisterVm,
    ) -> Result<RegistrationSnapshot> {
        validate_registration(&self.tenant_id, registration)?;
        Ok(RegistrationSnapshot {
            registration: registration.clone(),
            tenant: self.tenant_id.clone(),
            helper: self.signer_helper_uds_path.clone(),
            max_frame_bytes: self.max_frame_bytes,
            connection_slots: self.connection_slots.clone(),
        })
    }

    /// One original ordered mutation lane. Acquiring its permit must happen
    /// outside lifecycle/daemon locks; the permit grants no control authority.
    pub fn mutation_lane(&self) -> Arc<tokio::sync::Semaphore> {
        self.mutation_lane.clone()
    }

    /// Called under the original Active file-gate turn after real readiness.
    pub fn open_local_admission(
        &mut self,
        expected: &mvm_core::tenant_lifecycle::LifecycleGeneration,
    ) -> Result<()> {
        let admission = self
            .lifecycle_admission
            .as_ref()
            .context("lifecycle coordination absent")?;
        anyhow::ensure!(
            &admission.generation == expected,
            "daemon generation mismatch"
        );
        anyhow::ensure!(
            !self
                .work
                .unresolved
                .load(std::sync::atomic::Ordering::Acquire),
            "daemon accepted work unresolved"
        );
        let mut state = self
            .work
            .state
            .try_lock()
            .map_err(|_| anyhow::anyhow!("daemon accepted-work state unavailable"))?;
        state.closed = false;
        Ok(())
    }

    /// Publish the local fence only after global Draining was durably written.
    pub fn close_local_admission(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.lifecycle_admission.is_some(),
            "lifecycle coordination absent"
        );
        let mut state = self
            .work
            .state
            .try_lock()
            .map_err(|_| anyhow::anyhow!("daemon accepted-work state unavailable"))?;
        state.closed = true;
        Ok(())
    }

    pub(crate) fn coordination_binding(
        &self,
    ) -> Result<(
        mvm_core::tenant_lifecycle::TenantLifecycleGate,
        mvm_core::tenant_lifecycle::LifecycleGeneration,
    )> {
        let admission = self
            .lifecycle_admission
            .as_ref()
            .context("lifecycle coordination absent")?;
        Ok((admission.gate.clone(), admission.generation.clone()))
    }

    /// Reserve before effects while holding Active gate then daemon try_lock.
    pub(crate) fn reserve_accepted_work(
        &self,
        expected: &mvm_core::tenant_lifecycle::LifecycleGeneration,
    ) -> Result<AcceptedDaemonWork> {
        self.reserve_original_work(expected, false)
    }

    /// Canonical authenticated cleanup may continue during Draining. This
    /// accounts only that original turn; callers must not use it for activation.
    pub(crate) fn reserve_cleanup_work(
        &self,
        expected: &mvm_core::tenant_lifecycle::LifecycleGeneration,
    ) -> Result<AcceptedDaemonWork> {
        self.reserve_original_work(expected, true)
    }

    fn reserve_original_work(
        &self,
        expected: &mvm_core::tenant_lifecycle::LifecycleGeneration,
        cleanup: bool,
    ) -> Result<AcceptedDaemonWork> {
        let admission = self
            .lifecycle_admission
            .as_ref()
            .context("lifecycle coordination absent")?;
        anyhow::ensure!(
            &admission.generation == expected,
            "daemon generation mismatch"
        );
        self.reserve_verified_work(cleanup)
    }

    /// Used only after original canonical control verification (or by the
    /// original owned daemon's already-verified internal operation).
    fn reserve_verified_work(&self, cleanup: bool) -> Result<AcceptedDaemonWork> {
        anyhow::ensure!(
            cleanup
                || !self
                    .work
                    .unresolved
                    .load(std::sync::atomic::Ordering::Acquire),
            "daemon accepted work unresolved"
        );
        let mut state = self
            .work
            .state
            .try_lock()
            .map_err(|_| anyhow::anyhow!("daemon accepted-work state unavailable"))?;
        anyhow::ensure!(
            (cleanup || !state.closed) && state.rows.len() < 256,
            "daemon admission fenced or saturated"
        );
        let id = state
            .next
            .checked_add(1)
            .context("daemon admission sequence exhausted")?;
        state.next = id;
        state.rows.try_reserve(1)?;
        state.rows.insert(id, None);
        Ok(AcceptedDaemonWork {
            owner: self.work.clone(),
            id,
            settled: false,
        })
    }

    /// Conservative original-owner observation, not child-collection proof.
    pub fn has_accepted_work(&self) -> Result<bool> {
        anyhow::ensure!(
            !self
                .work
                .unresolved
                .load(std::sync::atomic::Ordering::Acquire),
            "daemon accepted work unresolved"
        );
        let state = self
            .work
            .state
            .try_lock()
            .map_err(|_| anyhow::anyhow!("daemon accepted-work state unavailable"))?;
        Ok(!state.rows.is_empty())
    }

    /// Capture the original ledger; no new quota or generation is minted.
    pub fn accepted_work_drain(&self) -> Result<AcceptedWorkDrain> {
        Ok(AcceptedWorkDrain {
            owner: self.work.clone(),
        })
    }

    /// Original retained owner supplies this binding before serving. The
    /// binding labels resource custody only; it is never signed permission.
    pub fn with_resource_binding(
        mut self,
        binding: Arc<mvm_vmm::host::installed_owner::InstallationBinding>,
    ) -> Self {
        self.resources = Some(binding);
        self
    }

    /// This component has no injected mailbox child owner by default. An
    /// injected owner needs its actual drain receipt before whole-worker exit;
    /// usage or registration counters cannot stand in for collection.
    pub fn require_no_injected_mailbox_owner(&self) -> Result<()> {
        anyhow::ensure!(
            self.mailbox_workers.is_none(),
            "injected mailbox worker owner requires its original collection receipt"
        );
        Ok(())
    }

    /// Wire the daemon to a supervised resident signer helper. Registered VMs
    /// route `host.audit.v1` appends through this helper instead of a per-VM
    /// audit-signer process.
    pub fn with_signer_helper(mut self, signer_helper_uds_path: impl Into<PathBuf>) -> Self {
        self.signer_helper_uds_path = Some(signer_helper_uds_path.into());
        self
    }

    /// Explicit original-owner injection only. Ordinary daemon startup leaves
    /// worker control disabled; this does not install a production helper.
    pub fn with_mailbox_workers(
        mut self,
        workers: Arc<super::mailbox_workers::MailboxWorkers>,
    ) -> Result<Self> {
        anyhow::ensure!(
            workers.tenant() == self.tenant_id,
            "foreign mailbox worker owner"
        );
        self.mailbox_workers = Some(workers);
        Ok(self)
    }

    /// Persist the live registration set to `path` after every successful
    /// register/deregister and use it for daemon restart recovery.
    pub fn with_registration_journal(mut self, path: impl Into<PathBuf>) -> Self {
        self.registration_journal = Some(RegistrationJournal::new(path));
        self
    }

    /// Whether `vm_id` is currently registered (bound + serving).
    pub fn is_registered(&self, vm_id: &str) -> Result<bool> {
        self.custody.try_contains_vm(vm_id)
    }

    /// Checked original-owner observation, never a Child collection receipt.
    pub fn checked_registration_count(&self) -> Result<usize> {
        anyhow::ensure!(
            !self.custody.has_inflight_mutation()?,
            "original registration mutation unresolved"
        );
        let mut original = self.custody.map_loan()?;
        let map = original.value_mut();
        anyhow::ensure!(
            map.phase != VmMapPhase::Retiring,
            "original service map is retiring"
        );
        let workers = self
            .mailbox_workers
            .as_ref()
            .map(|workers| workers.registration_count())
            .transpose()?
            .unwrap_or(0);
        map.vms
            .len()
            .checked_add(workers)
            .context("original daemon registration count overflow")
    }

    /// Advisory count. Unknown remains conservatively non-idle.
    pub fn registration_count(&self) -> usize {
        self.checked_registration_count().unwrap_or(usize::MAX)
    }

    /// Drop registrations whose VM state no longer has a live supervisor.
    ///
    /// A crashed CLI can miss the signed deregistration request. Without this
    /// backstop, the persisted registration keeps the resident daemon and its
    /// signer helper alive forever. Registrations from older clients without
    /// an ownership marker fail open while their state directory still exists.
    pub async fn reap_dead_registrations(&mut self) -> Result<usize> {
        let dead: Vec<_> = self
            .registrations
            .values()
            .filter(|registration| registration_owner_is_dead(registration))
            .map(|registration| registration.vm_id.clone())
            .collect();
        for vm_id in &dead {
            self.apply(&ControlRequest::Deregister(broker_control::DeregisterVm {
                vm_id: vm_id.clone(),
            }))
            .await?;
        }
        Ok(dead.len())
    }

    /// Probe the existing canonical ownership marker outside the daemon lock.
    /// Mutation rechecks the original signed/current context separately.
    pub async fn reap_dead_registrations_shared(daemon: Arc<Mutex<Self>>) -> Result<usize> {
        let snapshot: Vec<_> = {
            let original = daemon.lock().await;
            original.registrations.values().cloned().collect()
        };
        let dead: Vec<_> = snapshot
            .into_iter()
            .filter(registration_owner_is_dead)
            .collect();
        let mut reaped = 0;
        for original in dead {
            execute_mutation(
                DaemonAccess::Shared(daemon.clone()),
                ControlRequest::Deregister(broker_control::DeregisterVm {
                    vm_id: original.vm_id.clone(),
                }),
                None,
                Some(original),
            )
            .await?;
            reaped += 1;
        }
        Ok(reaped)
    }

    /// Snapshot of the currently-registered VM ids (bound + serving). The
    /// health watcher reads this each pass to decide which guests to probe.
    pub fn registered_vm_ids(&self) -> Result<Vec<String>> {
        anyhow::ensure!(
            !self.custody.has_inflight_mutation()?,
            "original registration mutation unresolved"
        );
        let mut original = self.custody.map_loan()?;
        let map = original.value_mut();
        anyhow::ensure!(
            map.phase == VmMapPhase::Live,
            "original service map unavailable"
        );
        Ok(map.vms.keys().cloned().collect())
    }

    /// Snapshot the state a [`HealthAuditSink`] needs to append chain-signed
    /// health entries for the currently-registered VMs, without holding the
    /// daemon lock across the (blocking) helper round-trip. The health watcher
    /// takes this alongside [`registered_vm_ids`](Self::registered_vm_ids) while
    /// briefly locked, then moves it into its blocking probe pass — so a health
    /// append never serialises against broker request handling.
    pub fn health_audit_sink(&self) -> HealthAuditSink {
        let workload_ids = self
            .registrations
            .iter()
            .map(|(vm, reg)| {
                let wl = reg.workload_id.clone().unwrap_or_else(|| reg.vm_id.clone());
                (vm.clone(), wl)
            })
            .collect();
        HealthAuditSink {
            helper_uds: self.signer_helper_uds_path.clone(),
            tenant_id: self.tenant_id.clone(),
            max_frame_bytes: self.max_frame_bytes,
            workload_ids,
        }
    }

    /// Apply an already-verified original control turn on an exclusively owned
    /// daemon. Shared production callers use `apply_signed_shared`, which never
    /// holds the daemon mutex across preparation, retirement, or helper I/O.
    pub async fn apply(&mut self, request: &ControlRequest) -> Result<()> {
        execute_mutation(DaemonAccess::Owned(self), request.clone(), None, None).await
    }

    /// Verify and retain the canonical signed request across the original
    /// operation, including the final same-generation publication turn.
    pub async fn apply_signed_shared(
        daemon: Arc<Mutex<Self>>,
        signed: SignedControl,
    ) -> Result<()> {
        let request = {
            let original = daemon.lock().await;
            broker_control::verify(&signed, &original.verifying_key)?.clone()
        };
        execute_mutation(DaemonAccess::Shared(daemon), request, Some(signed), None).await
    }

    /// A checked canonical legacy observation, never new authority or a Child
    /// receipt. Unknown, redirected, oversized or duplicate records refuse.
    pub fn checked_journal_registration_count(&self) -> Result<usize> {
        let Some(journal) = &self.registration_journal else {
            return Ok(0);
        };
        let records = journal.load()?;
        let mut identities = HashSet::new();
        for record in &records {
            validate_registration(&self.tenant_id, record)?;
            anyhow::ensure!(
                identities.insert(&record.vm_id),
                "registration journal repeats original VM identity"
            );
        }
        Ok(records.len())
    }

    /// Replay the persisted live registration set after the daemon itself
    /// restarts. Each replay goes through the normal `register` path, so tenant
    /// checks, vm-id validation, socket bind, and signer-helper rebind all
    /// remain fail-closed.
    pub async fn restore_journaled_registrations(&mut self) -> Result<usize> {
        let Some(journal) = &self.registration_journal else {
            return Ok(0);
        };
        let registrations = journal.load()?;
        let mut restored = 0usize;
        for registration in registrations {
            self.apply(&ControlRequest::Register(Box::new(registration.clone())))
                .await
                .with_context(|| format!("restore VM registration {}", registration.vm_id))?;
            restored += 1;
        }
        Ok(restored)
    }

    /// Original checked journal replay with no outer daemon lock across waits.
    pub async fn restore_journaled_registrations_shared(daemon: Arc<Mutex<Self>>) -> Result<usize> {
        let journal = { daemon.lock().await.registration_journal.clone() };
        let Some(journal) = journal else {
            return Ok(0);
        };
        let registrations = journal.load()?;
        let mut restored = 0;
        for registration in registrations {
            execute_mutation(
                DaemonAccess::Shared(daemon.clone()),
                ControlRequest::Register(Box::new(registration)),
                None,
                None,
            )
            .await?;
            restored += 1;
        }
        Ok(restored)
    }

    /// Re-register every live VM with a freshly restarted signer helper.
    ///
    /// The host-agent keeps the live registration set in memory while it owns
    /// the broker sockets. If the key-holding helper restarts under the same
    /// UDS path, replaying these registrations reopens each per-VM chain from
    /// disk and restores helper routing without rebinding guest-facing sockets.
    pub fn rebind_signer_helper_registrations(&self) -> Result<usize> {
        self.signer_registration_replay().execute()
    }

    /// Capture only immutable original data while locked. Helper socket I/O
    /// and its finite blocking task are retained by the caller outside locks.
    pub fn signer_registration_replay(&self) -> SignerRegistrationReplay {
        SignerRegistrationReplay {
            helper: self.signer_helper_uds_path.clone(),
            registrations: self.registrations.values().cloned().collect(),
        }
    }

    /// Bind the per-tenant control UDS (mode 0700, host-only) and process
    /// host-signed Register/Deregister messages until the listener errors.
    pub async fn run(self, control_socket: &Path) -> Result<()> {
        Self::run_shared(Arc::new(Mutex::new(self)), control_socket).await
    }

    /// Shared-state control loop used when another supervisor task needs to
    /// replay helper registrations after a helper restart.
    pub async fn run_shared(daemon: Arc<Mutex<Self>>, control_socket: &Path) -> Result<()> {
        let listener = bind_host_agent_listener(control_socket, 0o700)?;
        Self::run_shared_on_listener(daemon, listener).await
    }

    /// Consume an already-bound original listener only when its coordinator
    /// starts acceptance. Owning a bound listener is distinct from admitting a
    /// control request; startup can stage readiness before calling this loop.
    pub async fn run_shared_on_listener(
        daemon: Arc<Mutex<Self>>,
        listener: UnixListener,
    ) -> Result<()> {
        let (_keepalive, stopped) = tokio::sync::watch::channel(false);
        Self::run_shared_on_listener_until(daemon, listener, stopped).await
    }

    /// Stop cancels only unverified ingress. Once an original mutation is
    /// accepted it is retained; sticky uncertainty keeps this SAME listener
    /// available for canonical cleanup/query instead of inventing completion.
    pub async fn run_shared_on_listener_until(
        daemon: Arc<Mutex<Self>>,
        listener: UnixListener,
        mut stopped: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut accepted_changes = {
            let daemon = daemon.lock().await;
            Some(daemon.work.changed.subscribe())
        };
        loop {
            let stop_requested = *stopped.borrow() || stopped.has_changed().is_err();
            if stop_requested {
                let daemon = daemon.lock().await;
                let known_settled = daemon.mailbox_workers.is_none()
                    && matches!(daemon.has_accepted_work(), Ok(false));
                if known_settled {
                    return Ok(());
                }
            }
            let accepted = tokio::select! {
                biased;
                _ = async {
                    if stop_requested {
                        if let Some(changed) = accepted_changes.as_mut() {
                            if changed.changed().await.is_err() {
                                std::future::pending::<()>().await;
                            }
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } else {
                        let _ = stopped.changed().await;
                    }
                } => continue,
                accepted = listener.accept() => accepted,
            };
            let (mut stream, _addr) = accepted.context("host-agent control accept failed")?;
            let workers = { daemon.lock().await.mailbox_workers.clone() };
            if let Some(workers) = workers {
                // Reservation bounds pending connections, frames and blocking
                // jobs. Never queue an unbounded task before admission.
                let Ok(permit) = workers.reserve_control() else {
                    continue;
                };
                let daemon = daemon.clone();
                let control_stop = stopped.clone();
                tokio::spawn(async move {
                    let frame = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        read_frame::<SignedControl>(&mut stream, CONTROL_MAX_FRAME_BYTES),
                    )
                    .await;
                    let Ok(Ok(signed)) = frame else {
                        return;
                    };
                    let key = { daemon.lock().await.verifying_key };
                    let closing = *control_stop.borrow() || control_stop.has_changed().is_err();
                    if matches!(signed.request, ControlRequest::MailboxWorkerV1(_)) {
                        let verified = workers.now_unix_ms().ok().and_then(|now| {
                            mvm_core::protocol::mailbox_worker_control::verify_request(
                                &signed, &key, now,
                            )
                            .ok()
                            .filter(|request| !closing || matches!(request.operation,
                                mvm_core::protocol::mailbox_worker_control::MailboxWorkerOperation::Query { .. }
                                    | mvm_core::protocol::mailbox_worker_control::MailboxWorkerOperation::Stop { .. }))
                            .cloned()
                        });
                        let Ok(mut stream) = stream.into_std() else {
                            return;
                        };
                        let _ = tokio::task::spawn_blocking(move || {
                            // A canceled async waiter cannot release workspace
                            // credit while this blocking operation still runs.
                            let _permit = permit;
                            let Some(request) = verified else {
                                let _ = super::mailbox_workers::write_error(
                                    &mut stream,
                                    "mailbox worker authorization refused",
                                );
                                return;
                            };
                            let deadline = workers
                                .now_unix_ms()
                                .ok()
                                .and_then(|now| request.deadline_unix_ms.checked_sub(now))
                                .map(|ms| {
                                    std::time::Instant::now() + std::time::Duration::from_millis(ms)
                                });
                            let Some(deadline) = deadline else {
                                return;
                            };
                            match workers.handle(&request) {
                                Ok((result, fd)) => {
                                    if mvm_vmm::host::mailbox_worker_transport::send_response(
                                        &mut stream,
                                        &result,
                                        fd,
                                        deadline,
                                    )
                                    .is_err()
                                    {
                                        let _ = workers.handoff_uncertain(&request);
                                    }
                                }
                                Err(error) => {
                                    let _ = super::mailbox_workers::write_error(
                                        &mut stream,
                                        &error.to_string(),
                                    );
                                }
                            }
                        })
                        .await;
                    } else {
                        let _permit = permit;
                        let response = match broker_control::verify(&signed, &key) {
                            Ok(request)
                                if closing && !matches!(request, ControlRequest::Deregister(_)) =>
                            {
                                ControlResponse::Err {
                                    message: "host-agent activation is draining".into(),
                                }
                            }
                            Ok(_request) => {
                                match Self::apply_signed_shared(daemon.clone(), signed).await {
                                    Ok(()) => ControlResponse::Ok,
                                    Err(error) => ControlResponse::Err {
                                        message: error.to_string(),
                                    },
                                }
                            }
                            Err(_) => ControlResponse::Err {
                                message: "control signature rejected".into(),
                            },
                        };
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            write_frame(&mut stream, &response),
                        )
                        .await;
                    }
                });
                continue;
            }
            let verifying_key = {
                let daemon = daemon.lock().await;
                daemon.verifying_key
            };
            let frame = tokio::select! {
                biased;
                _ = async {
                    if stop_requested {
                        if let Some(changed) = accepted_changes.as_mut() {
                            if changed.changed().await.is_err() {
                                std::future::pending::<()>().await;
                            }
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } else {
                        let _ = stopped.changed().await;
                    }
                } => continue,
                frame = tokio::time::timeout(std::time::Duration::from_secs(5),
                    read_frame::<SignedControl>(&mut stream, CONTROL_MAX_FRAME_BYTES)) => frame,
            };
            let resp = match frame {
                Ok(Ok(signed)) => match broker_control::verify(&signed, &verifying_key) {
                    Ok(req) => {
                        let closing = *stopped.borrow() || stopped.has_changed().is_err();
                        let req = req.clone();
                        if closing && !matches!(req, ControlRequest::Deregister(_)) {
                            let response = ControlResponse::Err {
                                message: "host-agent activation is draining".into(),
                            };
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                write_frame(&mut stream, &response),
                            )
                            .await;
                            continue;
                        }
                        match Self::apply_signed_shared(daemon.clone(), signed).await {
                            Ok(()) => ControlResponse::Ok,
                            Err(e) => ControlResponse::Err {
                                message: e.to_string(),
                            },
                        }
                    }
                    Err(e) => ControlResponse::Err {
                        message: format!("control signature rejected: {e}"),
                    },
                },
                Ok(Err(e)) => {
                    warn!(error = %e, "host-agent control frame read failed");
                    continue;
                }
                Err(_) => continue,
            };
            if !matches!(
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    write_frame(&mut stream, &resp)
                )
                .await,
                Ok(Ok(()))
            ) {
                warn!("host-agent control reply failed or expired");
            }
        }
    }
}

/// Access is borrowed only for short in-memory turns. Async service/helper
/// waits borrow the stable mutation cell, never an outer daemon mutex guard.
enum DaemonAccess<'a> {
    Owned(&'a mut HostAgentDaemon),
    Shared(Arc<Mutex<HostAgentDaemon>>),
}

impl DaemonAccess<'_> {
    async fn memory<T>(
        &mut self,
        action: impl FnOnce(&mut HostAgentDaemon) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Owned(daemon) => action(daemon),
            Self::Shared(daemon) => action(&mut *daemon.lock().await),
        }
    }

    fn try_memory<T>(
        &mut self,
        action: impl FnOnce(&mut HostAgentDaemon) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Owned(daemon) => action(daemon),
            Self::Shared(daemon) => {
                let mut original = daemon
                    .try_lock()
                    .map_err(|_| anyhow::anyhow!("original daemon turn is busy"))?;
                action(&mut original)
            }
        }
    }
}

struct MutationContext {
    tenant: String,
    key: VerifyingKey,
    helper: Option<PathBuf>,
    journal: Option<RegistrationJournal>,
    lifecycle: Option<DaemonLifecycleAdmission>,
    resources: Option<Arc<mvm_vmm::host::installed_owner::InstallationBinding>>,
    custody: Arc<MutationCell>,
    registration: Option<RegistrationSnapshot>,
    vm_id: String,
    original: Vec<RegisterVm>,
    candidate: Vec<RegisterVm>,
}

impl MutationContext {
    fn recheck(
        &self,
        daemon: &HostAgentDaemon,
        signed: Option<&SignedControl>,
        cleanup: bool,
    ) -> Result<()> {
        anyhow::ensure!(
            daemon.tenant_id == self.tenant
                && daemon.verifying_key == self.key
                && Arc::ptr_eq(&daemon.custody, &self.custody),
            "original daemon context changed"
        );
        anyhow::ensure!(
            match (&daemon.resources, &self.resources) {
                (None, None) => true,
                (Some(current), Some(original)) => Arc::ptr_eq(current, original),
                _ => false,
            },
            "original resource context changed"
        );
        match (&daemon.lifecycle_admission, &self.lifecycle) {
            (None, None) => {}
            (Some(current), Some(original)) => anyhow::ensure!(
                current.generation == original.generation,
                "original daemon generation changed"
            ),
            _ => bail!("original lifecycle context changed"),
        }
        if let Some(signed) = signed {
            broker_control::verify(signed, &daemon.verifying_key)?;
        }
        anyhow::ensure!(
            cleanup || !self.custody.stop_requested(),
            "original service admission stopped"
        );
        if let Some(workers) = &daemon.mailbox_workers {
            anyhow::ensure!(
                !workers.try_contains(&self.vm_id)?,
                "original mailbox worker retains this VM identity"
            );
        }
        Ok(())
    }
}

async fn execute_mutation(
    mut access: DaemonAccess<'_>,
    request: ControlRequest,
    signed: Option<SignedControl>,
    expected_registration: Option<RegisterVm>,
) -> Result<()> {
    let (vm_id, cleanup) = match &request {
        ControlRequest::Register(registration) => (registration.vm_id.clone(), false),
        ControlRequest::Deregister(deregistration) => (deregistration.vm_id.clone(), true),
        ControlRequest::MailboxWorkerV1(_) => bail!("mailbox worker ownership is not implemented"),
        ControlRequest::HvfInstanceV1(_) => {
            bail!("HVF instance control requires the instance supervisor")
        }
    };
    let lane = access.memory(|daemon| Ok(daemon.mutation_lane())).await?;
    // Unresolved original work owns this permit. Refuse another mutation rather
    // than enqueue an unbounded waiter or mint a replacement owner.
    let mut permit = Some(
        lane.try_acquire_owned()
            .context("original daemon mutation remains busy")?,
    );
    let context = access
        .memory(|daemon| {
            validate_vm_id(&vm_id)?;
            if let Some(expected) = &expected_registration {
                anyhow::ensure!(
                    daemon.registrations.get(&vm_id) == Some(expected),
                    "canonical ownership probe no longer names this registration"
                );
            }
            let registration = match &request {
                ControlRequest::Register(registration) => {
                    Some(daemon.registration_snapshot(registration)?)
                }
                _ => None,
            };
            let original: Vec<_> = daemon.registrations.values().cloned().collect();
            let mut candidate: Vec<_> = original
                .iter()
                .filter(|record| record.vm_id != vm_id)
                .cloned()
                .collect();
            if let ControlRequest::Register(registration) = &request {
                candidate.push(registration.as_ref().clone());
            }
            let context = MutationContext {
                tenant: daemon.tenant_id.clone(),
                key: daemon.verifying_key,
                helper: daemon.signer_helper_uds_path.clone(),
                journal: daemon.registration_journal.clone(),
                lifecycle: daemon.lifecycle_admission.clone(),
                resources: daemon.resources.clone(),
                custody: daemon.custody.clone(),
                registration,
                vm_id: vm_id.clone(),
                original,
                candidate,
            };
            context.recheck(daemon, signed.as_ref(), cleanup)?;
            // Reserve bounded map capacity before the final short publication turn.
            daemon.registrations.try_reserve(1)?;
            context.custody.map_loan()?.value_mut().vms.try_reserve(1)?;
            Ok(context)
        })
        .await?;
    anyhow::ensure!(
        serde_json::to_vec_pretty(&context.candidate)?.len() < CONTROL_MAX_FRAME_BYTES,
        "candidate registration journal exceeds canonical inventory bound"
    );
    if context.lifecycle.is_some() {
        anyhow::ensure!(
            context.resources.is_some(),
            "original lifecycle resource binding missing"
        );
    }
    let cell = context.custody.clone();
    let mut reserve = || {
        access.try_memory(|daemon| {
            context.recheck(daemon, signed.as_ref(), cleanup)?;
            let reserve_accepted = || {
                if let Some(admission) = &context.lifecycle {
                    if cleanup {
                        daemon.reserve_cleanup_work(&admission.generation)
                    } else {
                        daemon.reserve_accepted_work(&admission.generation)
                    }
                } else {
                    daemon.reserve_verified_work(cleanup)
                }
            };
            let loan = cell.reserve_mutation(&mut permit, reserve_accepted)?;
            // The original cell retains both originals before releasing this gate.
            drop(loan);
            Ok(())
        })
    };
    if let Some(admission) = &context.lifecycle
        && !cleanup
    {
        admission.gate.with_active(
            &admission.generation,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            reserve,
        )?;
    } else {
        reserve()?;
    }
    let mut mutation = cell.mutation_loan()?;
    let original = mutation.value_mut();
    original.capture_journal(JournalSnapshots {
        original: context.original.clone(),
        candidate: context.candidate.clone(),
    })?;
    if let Some(binding) = &context.resources {
        let lease = mvm_vmm::host::installed_owner::HolderLease::acquire(
            &binding.root,
            binding.key,
            binding.generation,
        )?;
        original.attach_resource(lease)?;
    }
    // Move exactly one original service directly between its two retained
    // fields before any await. Queries remain Unknown while it is in flight.
    {
        let mut map = cell.map_loan()?;
        let map = map.value_mut();
        anyhow::ensure!(
            cleanup || map.phase == VmMapPhase::Live,
            "original service map is retiring"
        );
        if let Some(live) = map.vms.remove(&vm_id) {
            original.retiring = Some(live.retire());
        }
    }
    if let Some(retiring) = original.retiring.as_mut() {
        retiring.finish().await?;
    }
    original.retiring = None;
    let helper = context.helper.clone();
    let retired_vm = vm_id.clone();
    original.start_io(MutationIoStage::HelperRetirement, move || {
        if let Some(helper) = helper {
            deregister_helper_vm_at(&helper, &retired_vm)?;
        }
        Ok(())
    })?;
    original
        .finish_io(MutationIoStage::HelperRetirement)
        .await?;
    if let Some(snapshot) = context.registration.as_ref() {
        let registration = snapshot.registration.clone();
        cell.prepare_registration(&mut mutation, snapshot.clone())?;
        let original = mutation.value_mut();
        let helper = context.helper.clone();
        original.start_io(MutationIoStage::HelperRegistration, move || {
            if let Some(helper) = helper {
                register_helper_vm_at(&helper, &registration)?;
            }
            Ok(())
        })?;
        original
            .finish_io(MutationIoStage::HelperRegistration)
            .await?;
    }
    let original = mutation.value_mut();
    let candidate = original.journal_snapshots()?.candidate.clone();
    let journal = context.journal.clone();
    original.start_io(MutationIoStage::JournalPublication, move || {
        if let Some(journal) = journal {
            journal.store(candidate.iter())?;
        }
        Ok(())
    })?;
    original
        .finish_io(MutationIoStage::JournalPublication)
        .await?;
    // FileGate must never be acquired under a borrowed cell loan. Originals
    // remain physically retained in their field while this guard is released.
    drop(mutation);
    let mut commit = || {
        access.try_memory(|daemon| {
            context.recheck(daemon, signed.as_ref(), cleanup)?;
            let mut mutation = cell.mutation_loan()?;
            let original = mutation.value_mut();
            let mut map = cell.map_loan()?;
            let map = map.value_mut();
            anyhow::ensure!(
                cleanup || map.phase == VmMapPhase::Live,
                "original map activation fenced"
            );
            anyhow::ensure!(
                !map.vms.contains_key(&vm_id),
                "another original service occupies this identity"
            );
            if let Some(prepared) = original.prepared.as_mut() {
                let registration = prepared.registration().clone();
                let (live, start) = prepared.take_suspended_parts()?;
                map.vms.insert(vm_id.clone(), live);
                daemon.registrations.insert(vm_id.clone(), registration);
                // Actual original map ownership precedes any dispatch exposure.
                start.release()?;
                anyhow::ensure!(
                    prepared.service_transferred(),
                    "service ownership transfer incomplete"
                );
                original.prepared = None;
            } else {
                daemon.registrations.remove(&vm_id);
            }
            Ok(())
        })
    };
    if let Some(admission) = &context.lifecycle
        && !cleanup
    {
        admission.gate.with_active(
            &admission.generation,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            commit,
        )?;
    } else {
        commit()?;
    }
    // Actual I/O completion + original-map representation precedes settlement.
    cell.complete_mutation(cell.mutation_loan()?)
}

/// Prepare and bind a host-agent control or signer listener, including restarts.
/// Revalidate the short namespace before any stale unlink: it may have been
/// removed or replaced since the launcher created it. Legacy socket parents
/// retain their creation behavior and are not chmodded.
pub fn bind_host_agent_listener(socket: &Path, mode: u32) -> Result<UnixListener> {
    if let Some(parent) = socket.parent() {
        let short_namespace = parent.parent() == Some(Path::new("/tmp"))
            && parent
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b"mvm-sock-"));
        if short_namespace {
            mvm_core::private_fs::create_owned_private_dir(parent)
                .with_context(|| format!("prepare private socket dir {}", parent.display()))?;
        } else {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create socket dir {}", parent.display()))?;
        }
    }
    let _ = std::fs::remove_file(socket);
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind socket {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod socket {}", socket.display()))?;
    Ok(listener)
}

fn registration_owner_is_dead(registration: &RegisterVm) -> bool {
    let Some(head_path) = registration.workload_chain_head_path.as_deref() else {
        return false;
    };
    let Some(state_dir) = Path::new(head_path).parent() else {
        return false;
    };
    if !state_dir.exists() {
        return true;
    }
    let reference = state_dir.join(mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE);
    let Ok(bytes) = std::fs::read(reference) else {
        return false;
    };
    let Ok(pid_path) = serde_json::from_slice::<PathBuf>(&bytes) else {
        return false;
    };
    pid_path.parent() == Some(state_dir)
        && !mvm_vmm::host::process_liveness::pid_file_has_live_process(&pid_path)
}

/// Validate a `vm_id` is safe to embed in a filesystem path: a non-empty DNS-
/// label-shaped token (alphanumeric plus `-`/`_`), no separators, no traversal.
pub(crate) fn validate_vm_id(vm_id: &str) -> Result<()> {
    if vm_id.is_empty() || vm_id.len() > 63 {
        bail!("vm_id must be 1..=63 chars, got {}", vm_id.len());
    }
    if !vm_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("vm_id {:?} has characters outside [A-Za-z0-9_-]", vm_id);
    }
    Ok(())
}

/// A self-contained snapshot that appends chain-signed health entries to
/// registered VMs' per-VM workload chains via the resident signer helper.
///
/// Built by [`HostAgentDaemon::health_audit_sink`] while the daemon is briefly
/// locked, then moved into the health watcher's blocking probe pass — so the
/// blocking helper round-trip never runs under the daemon lock. Health entries
/// land on the same tamper-evident chain that `mvmctl trust audit` verifies and
/// that the guest-facing `host.audit.v1` path appends to; the helper serialises
/// per-chain, so host-asserted health entries interleave safely with a
/// workload's own emissions.
#[derive(Clone)]
pub struct HealthAuditSink {
    helper_uds: Option<PathBuf>,
    tenant_id: String,
    max_frame_bytes: usize,
    /// Server-derived workload id per VM, snapshotted from the registration set.
    /// The helper rejects an append whose `workload_id` doesn't match the VM's
    /// registration, so this must mirror what `register_helper_vm` sent.
    workload_ids: HashMap<String, String>,
}

impl HealthAuditSink {
    /// Append one chain-signed health entry for `vm_id`.
    ///
    /// The entry carries the host-asserted `host` category (distinct from a
    /// workload's own `workload_audit` emissions); the event name and state ride
    /// in `fields`. Best-effort: a VM absent from the snapshot — or a sink with
    /// no helper — is a silent no-op, and a helper refusal is returned for the
    /// caller to log rather than propagated into the probe loop.
    pub fn append(&self, vm_id: &str, fields: serde_json::Value) -> Result<()> {
        let Some(path) = &self.helper_uds else {
            return Ok(());
        };
        let Some(workload_id) = self.workload_ids.get(vm_id) else {
            return Ok(());
        };
        // The timestamp doubles as the per-event disambiguator: successive
        // health events for one VM would otherwise share a request/correlation
        // id, so stamp it into both to keep diagnostics addressable.
        let ts = chrono::Utc::now().to_rfc3339();
        let req = SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
            request_id: format!("health-{vm_id}-{ts}"),
            vm_id: vm_id.to_string(),
            category: HEALTH_AUDIT_CATEGORY.to_string(),
            ts: ts.clone(),
            workload_id: workload_id.clone(),
            tenant_id: self.tenant_id.clone(),
            // The health chain has no per-session identity of its own; a stable
            // per-VM marker keeps entries attributable without inventing one.
            session_id: format!("health-{vm_id}"),
            correlation_id: format!("health-{vm_id}-{ts}"),
            fields,
        });
        match SignerHelperClient::new(path.clone())
            .with_max_frame_bytes(self.max_frame_bytes)
            .send(&req)?
        {
            SignerHelperResponse::Ok { .. } => Ok(()),
            SignerHelperResponse::Err { message, .. } => {
                bail!("signer-helper health append refused: {message}")
            }
            other => bail!("signer-helper returned unexpected append response: {other:?}"),
        }
    }
}

impl crate::health_probe::HealthAudit for HealthAuditSink {
    fn record(&self, vm_id: &str, fields: serde_json::Value) {
        if let Err(e) = self.append(vm_id, fields) {
            warn!(vm_id = %vm_id, error = %e, "health-audit append failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_signer::helper::{
        SignerHelper, serve_on_listener as serve_helper_on_listener,
    };
    use crate::audit_signer::verify::verify_workload_chain;
    use ed25519_dalek::SigningKey;
    use mvm_core::protocol::broker::{ServiceCall, ServiceId, ServiceResponse};
    use mvm_core::protocol::broker_control::DeregisterVm;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UnixStream;
    use tokio::sync::{Mutex, oneshot};

    fn daemon(tenant: &str) -> HostAgentDaemon {
        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        HostAgentDaemon::new(tenant, vk, 64 * 1024)
    }

    #[tokio::test]
    async fn bound_control_listener_waits_for_owned_acceptance_loop() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind_host_agent_listener(&socket, 0o700).unwrap();
        let daemon = Arc::new(Mutex::new(daemon("local")));
        let mut client = tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(&socket))
            .await
            .unwrap()
            .unwrap();
        let signed = broker_control::sign(
            register_control(register(directory.path(), "vm-bound", "local", None)),
            &[5; 32],
        )
        .unwrap();
        write_frame(&mut client, &signed).await.unwrap();
        assert_eq!(daemon.lock().await.registration_count(), 0);

        let serving = tokio::spawn(HostAgentDaemon::run_shared_on_listener(
            daemon.clone(),
            listener,
        ));
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            read_frame::<ControlResponse>(&mut client, CONTROL_MAX_FRAME_BYTES),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(response, ControlResponse::Ok));
        assert_eq!(daemon.lock().await.registration_count(), 1);
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn stopped_control_listener_releases_a_partial_unauthenticated_frame() {
        use tokio::io::AsyncWriteExt;
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind_host_agent_listener(&socket, 0o700).unwrap();
        let daemon = Arc::new(Mutex::new(daemon("local")));
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(HostAgentDaemon::run_shared_on_listener_until(
            daemon.clone(),
            listener,
            stopped,
        ));
        let mut client = UnixStream::connect(&socket).await.unwrap();
        // An incomplete actual length prefix is never a verified mutation.
        client.write_all(&[0]).await.unwrap();
        tokio::task::yield_now().await;
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_millis(500), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(daemon.lock().await.registration_count(), 0);
    }

    #[test]
    fn checked_registration_journal_refuses_oversized_or_redirected_inventory() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("registrations.json");
        let observer = daemon("local").with_registration_journal(&journal);
        assert_eq!(observer.checked_journal_registration_count().unwrap(), 0);
        std::fs::write(&journal, vec![b' '; CONTROL_MAX_FRAME_BYTES + 1]).unwrap();
        assert!(observer.checked_journal_registration_count().is_err());
        std::fs::remove_file(&journal).unwrap();
        let target = directory.path().join("other.json");
        std::fs::write(&target, b"[]").unwrap();
        symlink(&target, &journal).unwrap();
        assert!(observer.checked_journal_registration_count().is_err());
        std::fs::remove_file(&journal).unwrap();
        std::fs::write(&journal, b"[]").unwrap();
        assert_eq!(observer.checked_journal_registration_count().unwrap(), 0);
        let registration = register(directory.path(), "vm-inventory", "local", None);
        std::fs::write(
            &journal,
            serde_json::to_vec(&vec![registration.clone()]).unwrap(),
        )
        .unwrap();
        assert_eq!(observer.checked_journal_registration_count().unwrap(), 1);
        std::fs::write(
            &journal,
            serde_json::to_vec(&vec![registration.clone(), registration]).unwrap(),
        )
        .unwrap();
        assert!(
            observer.checked_journal_registration_count().is_err(),
            "duplicate original VM identity is Unknown"
        );
        let foreign = register(directory.path(), "vm-inventory", "other-tenant", None);
        std::fs::write(&journal, serde_json::to_vec(&vec![foreign]).unwrap()).unwrap();
        assert!(
            observer.checked_journal_registration_count().is_err(),
            "foreign canonical tenant is Unknown"
        );
        std::fs::write(&journal, b"[").unwrap();
        assert!(
            observer.checked_journal_registration_count().is_err(),
            "truncated canonical inventory is Unknown"
        );
    }

    #[tokio::test]
    async fn hvf_instance_control_is_refused_without_registration_side_effects() {
        use mvm_core::protocol::hvf_control::{HvfInstance, HvfInstanceControl};
        let mut daemon = daemon("local");
        let request = ControlRequest::HvfInstanceV1(HvfInstanceControl::StopHvfInstance {
            instance: HvfInstance {
                vm_id: "vm-1".into(),
                boot_nonce: [3; 32],
            },
            connection_nonce: [4; 32],
            issued_at_secs: 100,
        });
        assert!(daemon.apply(&request).await.is_err());
        assert_eq!(daemon.checked_registration_count().unwrap(), 0);
        assert!(daemon.registrations.is_empty());
    }

    #[tokio::test]
    async fn host_agent_listener_restart_recreates_private_short_namespace() {
        for (name, mode) in [("control.sock", 0o700), ("signer-helper.sock", 0o600)] {
            let dir = tempfile::Builder::new()
                .prefix("mvm-sock-")
                .tempdir_in("/tmp")
                .unwrap();
            let socket = dir.path().join(name);
            let listener = bind_host_agent_listener(&socket, mode).unwrap();
            drop(listener);
            std::fs::remove_file(&socket).unwrap();
            std::fs::remove_dir(dir.path()).unwrap();

            let _restarted = bind_host_agent_listener(&socket, mode).unwrap();
            assert_eq!(
                std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }

    #[tokio::test]
    async fn host_agent_listener_restart_refuses_replaced_short_namespace_before_unlink() {
        use std::os::unix::fs::symlink;

        for (name, mode) in [("control.sock", 0o700), ("signer-helper.sock", 0o600)] {
            let dir = tempfile::Builder::new()
                .prefix("mvm-sock-")
                .tempdir_in("/tmp")
                .unwrap();
            let target = tempfile::tempdir().unwrap();
            let sentinel = target.path().join(name);
            std::fs::write(&sentinel, b"must not unlink").unwrap();
            std::fs::remove_dir(dir.path()).unwrap();
            symlink(target.path(), dir.path()).unwrap();
            assert!(bind_host_agent_listener(&dir.path().join(name), mode).is_err());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"must not unlink");
            std::fs::remove_file(dir.path()).unwrap();

            std::fs::write(dir.path(), b"not a directory").unwrap();
            assert!(bind_host_agent_listener(&dir.path().join(name), mode).is_err());
            assert_eq!(std::fs::read(dir.path()).unwrap(), b"not a directory");
            std::fs::remove_file(dir.path()).unwrap();
        }
    }

    #[tokio::test]
    async fn host_agent_listener_preserves_legacy_parent_permissions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let _listener = bind_host_agent_listener(&dir.path().join("control.sock"), 0o700).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    pub(super) fn register(
        dir: &Path,
        vm: &str,
        tenant: &str,
        signer: Option<PathBuf>,
    ) -> RegisterVm {
        RegisterVm {
            vm_id: vm.into(),
            workload_id: Some(format!("wl-{vm}")),
            tenant_id: tenant.into(),
            broker_listen_socket: dir
                .join(format!("{vm}.sock"))
                .to_string_lossy()
                .into_owned(),
            workload_chain_path: dir
                .join(format!("{tenant}.{vm}.workload.jsonl"))
                .to_string_lossy()
                .into_owned(),
            workload_chain_head_path: Some(
                dir.join(format!("{tenant}.{vm}.head"))
                    .to_string_lossy()
                    .into_owned(),
            ),
            audit_signer_uds_path: signer.map(|p| p.to_string_lossy().into_owned()),
            services_bindings: vec![],
            capability_bindings: vec![],
            assurance: None,
            service_proxies: vec![],
        }
    }

    fn register_control(registration: RegisterVm) -> ControlRequest {
        ControlRequest::Register(Box::new(registration))
    }

    async fn start_helper(
        helper_sock: PathBuf,
        tenant_id: &str,
        key_path: PathBuf,
    ) -> tokio::task::JoinHandle<()> {
        let helper_listener = UnixListener::bind(&helper_sock).unwrap();
        let helper = Arc::new(Mutex::new(SignerHelper::new(tenant_id, Some(key_path))));
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn({
            let helper = helper.clone();
            async move {
                let _ = ready_tx.send(());
                let _ = serve_helper_on_listener(helper_listener, helper, 65_536).await;
            }
        });
        ready_rx.await.unwrap();
        task
    }

    /// Rebind the daemon's signer-helper registrations, waiting out a
    /// previous helper that still holds the chain file's exclusive writer
    /// lock.
    ///
    /// Retries only that one refusal: any other error fails immediately, so a
    /// genuine regression still surfaces as a failure rather than as a
    /// timeout. Bounded, so a lock that is never released fails the test
    /// instead of hanging it.
    async fn rebind_when_chain_released(d: &HostAgentDaemon) -> usize {
        const ATTEMPTS: usize = 100;
        for attempt in 0..ATTEMPTS {
            match d.rebind_signer_helper_registrations() {
                Ok(n) => return n,
                Err(e) if format!("{e:#}").contains("already held by another writer") => {
                    assert!(
                        attempt + 1 < ATTEMPTS,
                        "the previous helper never released the chain lock: {e:#}"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => panic!("rebind failed for an unexpected reason: {e:#}"),
            }
        }
        unreachable!("the loop either returns or asserts on its last attempt")
    }

    async fn emit_audit(sock: &Path, vm: &str) -> ServiceResponse {
        let mut client = UnixStream::connect(sock).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.audit.v1").unwrap(),
            verb: "emit".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("guest-picked-id"),
            payload: serde_json::json!({
                "ts": "2026-06-17T00:00:00Z",
                "fields": {"vm": vm}
            }),
            capability: None,
        };
        write_frame(&mut client, &call).await.unwrap();
        read_frame(&mut client, 64 * 1024).await.unwrap()
    }

    #[test]
    fn validate_vm_id_rejects_traversal_and_separators() {
        assert!(validate_vm_id("vm-1").is_ok());
        assert!(validate_vm_id("e53b4probe").is_ok());
        assert!(validate_vm_id("").is_err());
        assert!(validate_vm_id("../escape").is_err());
        assert!(validate_vm_id("a/b").is_err());
        assert!(validate_vm_id("a.b").is_err());
        assert!(validate_vm_id(&"x".repeat(64)).is_err());
    }

    #[tokio::test]
    async fn register_binds_socket_then_deregister_unbinds() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        let reg = register(dir.path(), "vm-1", "local", None);
        let sock = PathBuf::from(&reg.broker_listen_socket);

        d.apply(&register_control(reg)).await.unwrap();
        assert!(d.is_registered("vm-1").unwrap());
        assert!(sock.exists(), "broker socket bound");

        d.apply(&ControlRequest::Deregister(DeregisterVm {
            vm_id: "vm-1".into(),
        }))
        .await
        .unwrap();
        assert!(!d.is_registered("vm-1").unwrap());
        // Drop runs synchronously on remove → socket file gone.
        assert!(!sock.exists(), "broker socket unbound");
    }

    #[tokio::test]
    async fn dead_registration_is_reaped_and_removed_from_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("registrations.json");
        let mut d = daemon("local").with_registration_journal(&journal_path);
        let reg = register(dir.path(), "dead-vm", "local", None);
        let owner_pid_path = dir.path().join("hvf.pid");
        std::fs::write(
            dir.path()
                .join(mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE),
            serde_json::to_vec(&owner_pid_path).unwrap(),
        )
        .unwrap();
        let sock = PathBuf::from(&reg.broker_listen_socket);

        d.apply(&register_control(reg)).await.unwrap();

        assert_eq!(d.reap_dead_registrations().await.unwrap(), 1);
        assert_eq!(d.registration_count(), 0);
        assert!(!sock.exists(), "dead registration must unbind its socket");
        assert!(
            RegistrationJournal::new(journal_path)
                .load()
                .unwrap()
                .is_empty(),
            "dead registration must be removed from the restart journal"
        );
    }

    #[tokio::test]
    async fn live_supervisor_pid_spares_registration() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hvf.pid"), std::process::id().to_string()).unwrap();
        let mut d = daemon("local");
        let reg = register(dir.path(), "live-vm", "local", None);
        let owner_pid_path = dir.path().join("hvf.pid");
        std::fs::write(
            dir.path()
                .join(mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE),
            serde_json::to_vec(&owner_pid_path).unwrap(),
        )
        .unwrap();

        d.apply(&register_control(reg)).await.unwrap();

        assert_eq!(d.reap_dead_registrations().await.unwrap(), 0);
        assert!(d.is_registered("live-vm").unwrap());
    }

    #[tokio::test]
    async fn legacy_registration_without_owner_path_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        let reg = register(dir.path(), "legacy-vm", "local", None);

        d.apply(&register_control(reg)).await.unwrap();

        assert_eq!(d.reap_dead_registrations().await.unwrap(), 0);
        assert!(d.is_registered("legacy-vm").unwrap());
    }

    #[test]
    fn registration_with_missing_state_directory_is_dead() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = register(dir.path(), "missing-vm", "local", None);
        reg.workload_chain_head_path = Some(
            dir.path()
                .join("removed-state")
                .join("audit-signer.head")
                .to_string_lossy()
                .into_owned(),
        );

        assert!(registration_owner_is_dead(&reg));
    }

    #[test]
    fn registration_journal_stores_sorted_snapshot_and_loads_it() {
        let dir = tempfile::tempdir().unwrap();
        let journal = RegistrationJournal::new(dir.path().join("registrations.json"));
        let reg_b = register(dir.path(), "vm-b", "local", None);
        let reg_a = register(dir.path(), "vm-a", "local", None);

        journal.store([&reg_b, &reg_a]).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("registrations.json")).unwrap();
        assert!(
            raw.find("\"vm-a\"").unwrap() < raw.find("\"vm-b\"").unwrap(),
            "journal snapshot should be stable by vm_id"
        );
        assert_eq!(journal.load().unwrap(), vec![reg_a, reg_b]);
    }

    #[tokio::test]
    async fn deregister_updates_registration_journal_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("registrations.json");
        let mut d = daemon("local").with_registration_journal(&journal_path);

        d.apply(&register_control(register(
            dir.path(),
            "vm-1",
            "local",
            None,
        )))
        .await
        .unwrap();
        assert_eq!(
            RegistrationJournal::new(journal_path.clone())
                .load()
                .unwrap()
                .len(),
            1
        );

        d.apply(&ControlRequest::Deregister(DeregisterVm {
            vm_id: "vm-1".into(),
        }))
        .await
        .unwrap();
        assert!(
            RegistrationJournal::new(journal_path.clone())
                .load()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn daemon_restart_restores_journaled_registration() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("registrations.json");
        let reg = register(dir.path(), "vm-1", "local", None);
        let sock = PathBuf::from(&reg.broker_listen_socket);

        {
            let mut first = daemon("local").with_registration_journal(&journal_path);
            first.apply(&register_control(reg)).await.unwrap();
            assert!(first.is_registered("vm-1").unwrap());
            assert!(sock.exists(), "first daemon bound broker socket");
        }
        assert!(!sock.exists(), "dropping daemon unbinds broker socket");

        let mut restarted = daemon("local").with_registration_journal(&journal_path);
        assert_eq!(
            restarted.restore_journaled_registrations().await.unwrap(),
            1
        );
        assert!(restarted.is_registered("vm-1").unwrap());
        assert!(sock.exists(), "restarted daemon rebound broker socket");
    }

    fn legacy_host_agent_config(control_socket: &Path) -> HostAgentConfig {
        serde_json::from_value(serde_json::json!({
            "tenant_id": "local",
            "control_socket": control_socket,
            "host_signer_public_key_path": "/unused/host.pub",
            "signer_helper_uds_path": "/unused/signer.sock",
            "software_chain_key_path": "/unused/host.key",
        }))
        .unwrap()
    }

    #[test]
    fn registration_journal_config_preserves_legacy_path_and_roundtrips() {
        let mut cfg = legacy_host_agent_config(Path::new("/private/state/control.sock"));
        assert_eq!(cfg.registration_journal_path, None);
        assert_eq!(
            cfg.registration_journal_path().unwrap(),
            PathBuf::from("/private/state/registrations.json")
        );
        cfg.registration_journal_path = Some("/persistent/registrations.json".into());
        cfg.control_socket = "/tmp/short/control.sock".into();
        let decoded: HostAgentConfig =
            serde_json::from_slice(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert_eq!(decoded, cfg);
        assert_eq!(
            decoded.registration_journal_path().unwrap(),
            PathBuf::from("/persistent/registrations.json")
        );
    }

    #[tokio::test]
    async fn relocated_control_socket_recovers_original_persistent_journal() {
        let persistent = tempfile::tempdir().unwrap();
        let sockets = tempfile::tempdir().unwrap();
        let state = persistent
            .path()
            .join("deep".repeat(40))
            .join("host-agent/local");
        let legacy = legacy_host_agent_config(&state.join("control.sock"));
        let journal = legacy.registration_journal_path().unwrap();
        let reg = register(sockets.path(), "vm-1", "local", None);
        let broker_socket = PathBuf::from(&reg.broker_listen_socket);
        {
            let mut original = daemon("local").with_registration_journal(&journal);
            original.apply(&register_control(reg)).await.unwrap();
        }
        assert!(journal.exists());
        assert!(!broker_socket.exists());

        let mut relocated = legacy;
        relocated.control_socket = sockets.path().join("control.sock");
        relocated.registration_journal_path = Some(journal.clone());
        let socket_journal = sockets.path().join("registrations.json");
        std::fs::write(&socket_journal, b"not the authoritative journal").unwrap();
        let mut restarted = daemon("local")
            .with_registration_journal(relocated.registration_journal_path().unwrap());
        assert_eq!(
            restarted.restore_journaled_registrations().await.unwrap(),
            1
        );
        assert!(restarted.is_registered("vm-1").unwrap());
        assert!(broker_socket.exists());
        assert_eq!(
            std::fs::read(&socket_journal).unwrap(),
            b"not the authoritative journal"
        );
        assert_eq!(RegistrationJournal::new(journal).load().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn one_tenant_daemon_tracks_many_vm_registrations() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");

        for vm in ["vm-1", "vm-2", "vm-3"] {
            d.apply(&register_control(register(dir.path(), vm, "local", None)))
                .await
                .unwrap();
            assert!(d.is_registered(vm).unwrap(), "{vm} registered");
        }

        assert_eq!(d.registration_count(), 3);
        assert_eq!(d.registrations.len(), 3);

        d.apply(&ControlRequest::Deregister(DeregisterVm {
            vm_id: "vm-2".into(),
        }))
        .await
        .unwrap();

        assert_eq!(d.registration_count(), 2);
        assert_eq!(d.registrations.len(), 2);
        assert!(d.is_registered("vm-1").unwrap());
        assert!(!d.is_registered("vm-2").unwrap());
        assert!(d.is_registered("vm-3").unwrap());
    }

    #[tokio::test]
    async fn register_refuses_other_tenant_and_unsafe_vm_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        assert!(
            d.apply(&register_control(register(
                dir.path(),
                "vm-1",
                "acme",
                None
            )))
            .await
            .is_err(),
            "cross-tenant register refused"
        );
        let mut bad = register(dir.path(), "ok", "local", None);
        bad.vm_id = "../escape".into();
        assert!(
            d.apply(&register_control(bad)).await.is_err(),
            "unsafe vm_id refused"
        );
        assert_eq!(d.registration_count(), 0);
    }

    #[tokio::test]
    async fn register_refuses_controller_capability_absent_from_signed_admission() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon("local");
        let mut registration = register(dir.path(), "vm-1", "local", None);
        let descriptor = mvm_contract::assurance::probe_capability_descriptor();
        registration
            .services_bindings
            .push(descriptor.id.service.clone());
        registration.service_proxies.push(
            mvm_contract::protocol::broker_control::ServiceProxyBinding {
                service: descriptor.id.service.clone(),
                endpoint: dir
                    .path()
                    .join("controller.sock")
                    .to_string_lossy()
                    .into_owned(),
                capabilities: vec![descriptor],
            },
        );

        let error = daemon
            .apply(&register_control(registration))
            .await
            .expect_err("an unsigned controller capability must be refused");

        assert!(
            error
                .to_string()
                .contains("controller-backed capability is absent from signed admission")
        );
        assert_eq!(daemon.registration_count(), 0);
    }

    #[tokio::test]
    async fn legacy_tool_service_binding_cannot_register_a_vm() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon("local");
        let mut registration = register(dir.path(), "vm-legacy-tool", "local", None);
        registration
            .services_bindings
            .push(ServiceId::parse(RETIRED_HOST_TOOL_SERVICE).unwrap());
        let error = daemon
            .apply(&register_control(registration))
            .await
            .expect_err("legacy tool service must be refused");
        assert!(
            error
                .to_string()
                .contains("host.tool.v1 is no longer supported")
        );
        assert_eq!(daemon.registration_count(), 0);
    }

    #[tokio::test]
    async fn registered_vm_dispatches_through_its_own_registry_with_server_correlation() {
        // No audit-signer registered ⇒ `host.audit.v1` is `NotBound`. The point
        // is that the call still *routes through the daemon's per-VM registry*
        // and comes back as a typed response with a server-reassigned
        // correlation id — i.e. bind + dispatch + server-derived identity work,
        // without depending on the audit-signer wire (covered elsewhere).
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        let reg = register(dir.path(), "vm-1", "local", None);
        let sock = PathBuf::from(&reg.broker_listen_socket);
        d.apply(&register_control(reg)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A guest dials the VM's broker socket. Its `correlation_id` is its own
        // choosing — the server must not echo it back.
        let mut client = UnixStream::connect(&sock).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.audit.v1").unwrap(),
            verb: "emit".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("guest-picked-id"),
            payload: serde_json::json!({"ts": "2026-06-16T00:00:00Z", "fields": {"a": 1}}),
            capability: None,
        };
        write_frame(&mut client, &call).await.unwrap();
        let resp: ServiceResponse = read_frame(&mut client, 64 * 1024).await.unwrap();
        let correlation_id = match resp {
            ServiceResponse::Ok { correlation_id, .. }
            | ServiceResponse::Err { correlation_id, .. } => correlation_id,
        };
        // Server-authoritative id (brk-*), never the guest's — even within a
        // shared daemon a guest can't choose its audit-chain correlation id.
        assert!(
            correlation_id.as_str().starts_with("brk-"),
            "server-derived correlation id, got {correlation_id:?}"
        );
        assert_ne!(correlation_id.as_str(), "guest-picked-id");
    }

    #[tokio::test]
    async fn host_time_binding_serves_time_without_widening_to_host_audit() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        let mut reg = register(dir.path(), "vm-time", "local", None);
        reg.services_bindings = vec![ServiceId::parse("host.time.v1").unwrap()];
        let sock = PathBuf::from(&reg.broker_listen_socket);
        d.apply(&register_control(reg)).await.unwrap();

        let mut time_client = UnixStream::connect(&sock).await.unwrap();
        let time_call = ServiceCall {
            service: ServiceId::parse("host.time.v1").unwrap(),
            verb: "now".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("guest-time"),
            payload: serde_json::json!({}),
            capability: None,
        };
        write_frame(&mut time_client, &time_call).await.unwrap();
        let time_response: ServiceResponse = read_frame(&mut time_client, 64 * 1024).await.unwrap();
        assert!(matches!(time_response, ServiceResponse::Ok { .. }));

        let audit_response = emit_audit(&sock, "not-bound").await;
        assert!(matches!(
            audit_response,
            ServiceResponse::Err {
                code: mvm_core::protocol::broker::ServiceErrorCode::NotBound,
                ..
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn helper_backed_registered_vm_can_only_write_its_own_chain() {
        let dir = tempfile::tempdir().unwrap();
        let helper_sock = dir.path().join("signer-helper.sock");
        let key_path = dir.path().join("tenant-key.ed25519");
        std::fs::write(&key_path, [12u8; 32]).unwrap();
        let helper_task = start_helper(helper_sock.clone(), "local", key_path).await;

        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let mut d = HostAgentDaemon::new("local", vk, 64 * 1024).with_signer_helper(&helper_sock);
        let mut reg_a = register(dir.path(), "vm-a", "local", None);
        reg_a.services_bindings = vec![ServiceId::parse("host.audit.v1").unwrap()];
        let sock_a = PathBuf::from(&reg_a.broker_listen_socket);
        let chain_a = PathBuf::from(&reg_a.workload_chain_path);
        let mut reg_b = register(dir.path(), "vm-b", "local", None);
        reg_b.services_bindings = vec![ServiceId::parse("host.audit.v1").unwrap()];
        let chain_b = PathBuf::from(&reg_b.workload_chain_path);

        d.apply(&register_control(reg_a)).await.unwrap();
        d.apply(&register_control(reg_b)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&sock_a).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.audit.v1").unwrap(),
            verb: "emit".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("guest-picked-id"),
            payload: serde_json::json!({
                "ts": "2026-06-17T00:00:00Z",
                "fields": {"vm": "a"}
            }),
            capability: None,
        };
        write_frame(&mut client, &call).await.unwrap();
        let resp: ServiceResponse = read_frame(&mut client, 64 * 1024).await.unwrap();
        assert!(matches!(resp, ServiceResponse::Ok { .. }));

        let a_lines = std::fs::read_to_string(&chain_a).unwrap();
        assert_eq!(a_lines.lines().count(), 1);
        assert!(
            !chain_b.exists() || std::fs::read_to_string(&chain_b).unwrap().is_empty(),
            "vm-a socket must not write vm-b chain"
        );

        helper_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn helper_restart_rebinds_live_registration_and_preserves_chain() {
        let dir = tempfile::tempdir().unwrap();
        let helper_sock = dir.path().join("signer-helper.sock");
        let key_path = dir.path().join("tenant-key.ed25519");
        std::fs::write(&key_path, [12u8; 32]).unwrap();
        let helper_task = start_helper(helper_sock.clone(), "local", key_path.clone()).await;

        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let mut d = HostAgentDaemon::new("local", vk, 64 * 1024).with_signer_helper(&helper_sock);
        let mut reg = register(dir.path(), "vm-a", "local", None);
        reg.services_bindings = vec![ServiceId::parse("host.audit.v1").unwrap()];
        let sock = PathBuf::from(&reg.broker_listen_socket);
        let chain = PathBuf::from(&reg.workload_chain_path);
        d.apply(&register_control(reg)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let before = emit_audit(&sock, "before-restart").await;
        assert!(matches!(before, ServiceResponse::Ok { .. }));

        helper_task.abort();
        let _ = helper_task.await;
        let _ = std::fs::remove_file(&helper_sock);
        let restarted = start_helper(helper_sock.clone(), "local", key_path).await;

        // Aborting the accept loop is not the same as the old helper being
        // gone. `audit_signer::helper::serve` spawns a detached task per
        // connection, each holding its own `SharedSignerHelper` clone, and
        // those are not cancelled with the loop — so the previous helper, and
        // the exclusive chain-file lock its `Chain` holds, can outlive the
        // `await` above. Registering the restarted helper then fails with
        // "chain already held by another writer".
        //
        // Production never hits this: the helper is its own process
        // (`mvm-signer-helper`), so shutdown releases the lock at exit. This
        // test is the only place a helper is torn down by cancelling a task,
        // so it has to wait for the same condition process exit would give it.
        // A fixed sleep would only make the window bigger, not closed.
        assert_eq!(rebind_when_chain_released(&d).await, 1);
        let after = emit_audit(&sock, "after-restart").await;
        assert!(matches!(after, ServiceResponse::Ok { .. }));

        let verifying_key = SigningKey::from_bytes(&[12u8; 32]).verifying_key();
        let count = verify_workload_chain(&chain, &verifying_key).unwrap();
        assert_eq!(count, 2);
        assert_eq!(std::fs::read_to_string(&chain).unwrap().lines().count(), 2);

        restarted.abort();
    }

    #[test]
    fn health_audit_sink_is_noop_without_helper() {
        // A daemon with no signer helper yields a sink whose append is a silent
        // success — health observability degrades cleanly rather than erroring.
        let d = daemon("local");
        let sink = d.health_audit_sink();
        sink.append("vm-a", serde_json::json!({"event": "health.transition"}))
            .unwrap();
    }

    #[test]
    fn health_audit_sink_is_noop_for_unregistered_vm() {
        // With nothing registered, the snapshot carries no workload id for the
        // VM, so append no-ops before it ever connects to the helper (which
        // isn't running here).
        let dir = tempfile::tempdir().unwrap();
        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let d = HostAgentDaemon::new("local", vk, 64 * 1024)
            .with_signer_helper(dir.path().join("helper.sock"));
        let sink = d.health_audit_sink();
        sink.append("ghost", serde_json::json!({"event": "x"}))
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_audit_sink_appends_host_category_entry_to_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let helper_sock = dir.path().join("signer-helper.sock");
        let key_path = dir.path().join("tenant-key.ed25519");
        std::fs::write(&key_path, [12u8; 32]).unwrap();
        let helper_task = start_helper(helper_sock.clone(), "local", key_path).await;

        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let mut d = HostAgentDaemon::new("local", vk, 64 * 1024).with_signer_helper(&helper_sock);
        let reg = register(dir.path(), "vm-a", "local", None);
        let chain = PathBuf::from(&reg.workload_chain_path);
        d.apply(&register_control(reg)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The append does blocking helper I/O, so run it off the reactor.
        let sink = d.health_audit_sink();
        let fields = serde_json::json!({"event": "health.transition", "state": "unhealthy"});
        tokio::task::spawn_blocking(move || sink.append("vm-a", fields))
            .await
            .unwrap()
            .unwrap();

        // The health entry landed on vm-a's per-VM chain, chain-signed under the
        // helper's tenant key, recording the host category (not workload_audit).
        let verifying_key = SigningKey::from_bytes(&[12u8; 32]).verifying_key();
        assert_eq!(verify_workload_chain(&chain, &verifying_key).unwrap(), 1);

        // The entry's fields are stored as base64-encoded JCS bytes in the
        // on-disk `canonical` field; decode it to inspect the recorded category.
        let raw = std::fs::read_to_string(&chain).unwrap();
        let line: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        let canonical = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(line["canonical"].as_str().unwrap())
                .unwrap()
        };
        let entry: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(entry["category"], "host");
        assert_eq!(entry["fields"]["event"], "health.transition");
        assert_eq!(entry["fields"]["state"], "unhealthy");
        assert_ne!(entry["category"], "workload_audit");

        helper_task.abort();
    }
}

#[cfg(test)]
#[path = "daemon/token_tests.rs"]
mod token_tests;

#[cfg(test)]
#[path = "daemon/cooperative_tests.rs"]
mod cooperative_tests;
