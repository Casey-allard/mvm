//! Private installed-parent bootstrap and terminal cleanup on original stdio.
//! The serialized projection is not authority: the parent retains the actual
//! typed handoff and the child adopts its original inherited holder.

use super::*;
use crate::host::{
    host_agent_spawn::{HostAgentServicesParams, OwnedHostAgentRegistrar, OwnedVmRegistration},
    process_exit::{ProcessExitObserver, ProcessExitWait},
};
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
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use zeroize::Zeroizing;

mod audit;
mod bootstrap;
mod producer;
mod records;
pub use audit::InstalledEndpointAudit;
pub use bootstrap::{INSTALLED_BOOTSTRAP_MIN_BYTES, installed_endpoint_bootstrap_requirement};
pub use records::InstalledTelemetryRecords;

const CONFIG_LIMIT: usize = 65_536;
const CONTROL_LIMIT: usize = 1024;
const STARTUP_LIMIT: Duration = Duration::from_secs(10);

/// Borrow the exact original host-agent registration through endpoint startup.
pub struct InstalledHostServices<'a> {
    registrar: &'a OwnedHostAgentRegistrar,
    registration: &'a OwnedVmRegistration,
    params: HostAgentServicesParams<'a>,
}

impl<'a> InstalledHostServices<'a> {
    pub fn new(
        registrar: &'a OwnedHostAgentRegistrar,
        registration: &'a OwnedVmRegistration,
        params: HostAgentServicesParams<'a>,
    ) -> Result<Self> {
        registration.check_current_for(registrar, &params)?;
        Ok(Self {
            registrar,
            registration,
            params,
        })
    }

    pub fn check_endpoint_binding(
        &self,
        vm_name: &str,
        tenant: &str,
        state_dir: &Path,
    ) -> Result<()> {
        if vm_name != self.params.vm_name
            || Some(tenant) != self.params.tenant_id
            || state_dir != self.params.state_dir
        {
            bail!("installed endpoint differs from original host-service registration");
        }
        self.registration
            .check_current_for(self.registrar, &self.params)
    }

    fn check_endpoint(&self, params: &SubstitutionSpawnParams<'_>) -> Result<()> {
        self.check_endpoint_binding(params.vm_name, params.tenant, params.state_dir)
    }

    pub fn check_flowmux_host_anchor(&self, candidate: &[u8; 32]) -> Result<()> {
        self.registration
            .check_flowmux_host_anchor(self.registrar, &self.params, candidate)
    }
}

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
struct Prepare<C = serde_json::Value> {
    version: u8,
    nonce: [u8; 32],
    projection: EndpointPartitionProjection,
    directory: i32,
    holder: i32,
    expected: HostLeaseExpectation,
    config: C,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    telemetry_records: Option<records::RecordsProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit: Option<audit::AuditProjection>,
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
        audit: None,
        telemetry: None,
        input: None,
        output: None,
        nonce: [0; 32],
        drained: false,
    });
    let result = complete_start(&mut endpoint, config, None, None, &params, None, deadline);
    match result {
        Ok(()) => Ok(endpoint),
        Err(reason) => Err(owned::OwnedEndpointSpawnError { reason, endpoint }.into()),
    }
}

fn validate_installed_proxy(proxy: Option<&EgressProxySpawnConfig>) -> Result<()> {
    let proxy =
        proxy.context("installed endpoint requires canonical pre-resolved proxy settings")?;
    let bytes = [&proxy.https, &proxy.http, &proxy.no_proxy]
        .into_iter()
        .flatten()
        .try_fold(0usize, |bytes, value| bytes.checked_add(value.len()))
        .context("installed endpoint proxy length overflow")?;
    if bytes > CONFIG_LIMIT {
        bail!("installed endpoint proxy settings exceed input bound")
    }
    Ok(())
}

/// Spawn only through the existing canonical endpoint binary/config path while
/// retaining the original typed partition and holder through terminal cleanup.
pub fn spawn_network_endpoint_installed_registered(
    mut params: SubstitutionSpawnParams<'_>,
    handoff: PreparedEndpointHandoff,
    original: &InstalledHostServices<'_>,
) -> Result<OwnedEndpoint> {
    let deadline = Instant::now() + STARTUP_LIMIT;
    if !params.telemetry {
        bail!("registered installed endpoint requires retained telemetry");
    }
    owned::require_child_custody()?;
    handoff.check_current()?;
    original.check_endpoint(&params)?;
    let projection = handoff.partition().projection();
    if params.lifetime != EndpointLifetime::Launcher
        || params.vm_name != projection.binding.vm_name
        || projection.profile != 2
        || projection.limits.host_metadata_bytes < INSTALLED_BOOTSTRAP_MIN_BYTES
        || params.state_dir.as_os_str().len() > 4096
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
    if plan.plan_id.0 != projection.admitted_plan_id || policy.payload_mapping().is_none() {
        bail!("installed endpoint differs from original admitted mapping")
    }
    let env_path = mvm_core::config::vm_substitution_env_path(params.vm_name);
    owned::refuse_existing_evidence(&params, &env_path)?;
    // Installed embeddings resolve the canonical operator table/environment
    // under their original retained credit. Never allocate an unbounded
    // ambient variable or operator TOML here, and never invent direct egress.
    let settings = original
        .registration
        .installed_endpoint_settings(original.registrar, &original.params)?;
    let direct = EgressProxySpawnConfig::default();
    let proxy = match settings {
        InstalledEndpointSettings::ResolvedDirect => &direct,
        InstalledEndpointSettings::ResolvedConfigured(proxy) => proxy,
    };
    validate_installed_proxy(Some(proxy))?;
    if params
        .egress_proxy
        .as_ref()
        .is_some_and(|supplied| supplied != proxy)
    {
        bail!("installed endpoint proxy differs from original settings");
    }
    params.egress_proxy = Some(proxy.clone());
    params.session_marker = Some(params.state_dir.join(SUBST_SESSION_FILE));
    let metadata = projection.limits.host_metadata_bytes;
    let telemetry_template = super::collector::TelemetrySection::owned(
        params.tenant,
        params.state_dir,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )?;
    let config = encode_config_with_telemetry_credit(&params, &telemetry_template, metadata)?;
    original.check_endpoint(&params)?;
    // The canonical digest and proxy parser run only after the original
    // partition has passed the bounded config's full instance requirement.
    plan.validate_for(policy, params.tenant, params.vm_name)?;
    if let Some(proxy) = &params.egress_proxy {
        proxy.resolve()?;
    }
    let audit = original
        .registration
        .prepare_endpoint_audit(original.registrar, &original.params)?;
    let mut preparation = producer::Preparation::new(handoff, audit);
    let startup: Result<OwnedEndpoint> = (|| {
        let audit_projection = audit::AuditProjection::from_original(
            preparation
                .custody()
                .audit
                .as_ref()
                .context("original audit custody missing")?,
        )?;
        // The actual key has the same width as the verified placeholder.
        drop(config);
        let keys_dir = telemetry_template.keys_directory()?.to_path_buf();
        let (key, records_projection) =
            preparation.prepare_retained(&params, original, &keys_dir, deadline)?;
        use base64::Engine as _;
        let key =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key.expose_bytes()));
        let telemetry = telemetry_template.with_key(&key)?;
        let config = encode_config_with_telemetry_credit(&params, &telemetry, metadata)?;
        preparation.check_current(original, &params, deadline)?;
        let bin = resolve_network_endpoint_path()?;
        preparation.check_current(original, &params, deadline)?;
        let log = owned::create_evidence(&endpoint_stderr_log_path(params.state_dir))?;
        let mut command = owned::endpoint_command(
            mvm_core::env_hygiene::helper_command(&bin),
            EndpointLifetime::Launcher,
            params.state_dir,
            log,
        );
        command.arg("--installed-partition");
        let mut fds = vec![
            preparation
                .custody()
                .handoff
                .holder()
                .directory()
                .as_raw_fd(),
            preparation.custody().handoff.holder().holder().as_raw_fd(),
        ];
        fds.extend(
            preparation
                .custody()
                .audit
                .as_ref()
                .expect("original audit custody")
                .event_descriptors()
                .map(|fd| fd.as_raw_fd()),
        );
        fds.push(records_projection.descriptor());
        if fds.iter().any(|fd| *fd <= 2)
            || fds
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != fds.len()
        {
            bail!("installed endpoint descriptors differ")
        }
        crate::host::restore_image::inherit_descriptors(&mut command, fds);
        preparation.check_current(original, &params, deadline)?;
        let child = command
            .spawn()
            .context("spawn original installed endpoint")?;
        let mut endpoint = OwnedEndpoint::new(child);
        // Install supporting custody BEFORE any fallible post-spawn operation.
        endpoint.installed = Some(preparation.take());
        let result = complete_start(
            &mut endpoint,
            config,
            Some(audit_projection),
            Some(records_projection),
            &params,
            Some(original),
            deadline,
        );
        match result {
            Ok(()) => Ok(endpoint),
            Err(reason) => Err(owned::OwnedEndpointSpawnError { reason, endpoint }.into()),
        }
    })();
    startup.map_err(|reason| preparation.error(reason))
}

fn complete_start<C: Serialize>(
    endpoint: &mut OwnedEndpoint,
    config: C,
    audit: Option<audit::AuditProjection>,
    telemetry_records: Option<records::RecordsProjection>,
    params: &SubstitutionSpawnParams<'_>,
    original: Option<&InstalledHostServices<'_>>,
    deadline: Instant,
) -> Result<()> {
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
    if let Some(original) = original {
        installed
            .audit
            .as_ref()
            .context("original audit custody missing")?
            .check_current()?;
        original.check_endpoint(params)?;
    }
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
            telemetry_records,
            audit,
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
    if let Some(original) = original {
        installed
            .audit
            .as_ref()
            .context("original audit custody missing")?
            .check_current()?;
        original.check_endpoint(params)?;
    }
    endpoint.ensure_running()?;
    owned::create_evidence(&params.state_dir.join(SUBST_PID_FILE))?
        .write_all(EndpointPid::of_child(endpoint.id()).render().as_bytes())?;
    let env = Zeroizing::new(serde_json::to_vec(&ready.handshake.env)?);
    owned::create_evidence(&mvm_core::config::vm_substitution_env_path(params.vm_name))?
        .write_all(&env)?;
    record_secret_fingerprints(params.vm_name, ready.handshake.input_fingerprints);
    Ok(())
}

#[derive(Debug)]
pub(super) struct InstalledCustody {
    pub(super) handoff: PreparedEndpointHandoff,
    pub(super) audit: Option<crate::host::host_agent_spawn::PreparedEndpointAudit>,
    telemetry: Option<producer::RetainedFiles>,
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
struct ChildAuthority {
    input: File,
    holder: PreparedHostLifetimeLease,
    parent: ProcessExitObserver,
    projection: EndpointPartitionProjection,
    fenced: AtomicBool,
    cleanup_failed: AtomicBool,
    pool_claimed: AtomicBool,
    audit: Option<audit::ChildAudit>,
    guest: Mutex<GuestTransport>,
}

#[derive(Default)]
struct GuestTransport {
    claimed: bool,
    original: Option<std::os::unix::net::UnixStream>,
}

/// Original child authority retained by its one local pool and bounded workers.
/// Cloning this lease shares its single claim; it never creates a new quota.
#[derive(Clone)]
pub struct InstalledEndpointLease {
    authority: Arc<ChildAuthority>,
}
impl std::fmt::Debug for InstalledEndpointLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstalledEndpointLease")
            .field("projection", &self.authority.projection)
            .finish_non_exhaustive()
    }
}
impl InstalledEndpointLease {
    pub fn projection(&self) -> &EndpointPartitionProjection {
        &self.authority.projection
    }
    pub fn audit(&self) -> Result<InstalledEndpointAudit> {
        InstalledEndpointAudit::require(self)
    }
    /// Retain one cancellation clone before the original guest authentication.
    /// This monotonic slot grants no network or audit authority.
    pub fn bind_guest_transport(&self, stream: &std::os::unix::net::UnixStream) -> Result<()> {
        self.check_current()?;
        let original = stream.try_clone()?;
        let mut guest = match self.authority.guest.lock() {
            Ok(guest) => guest,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                self.fence();
                bail!("installed guest cancellation slot poisoned")
            }
        };
        if self.authority.fenced.load(Ordering::Acquire) || guest.claimed {
            bail!("installed guest cancellation slot unavailable")
        }
        guest.claimed = true;
        guest.original = Some(original);
        drop(guest);
        self.check_current()
    }
    /// Monotonic admission fence and original transport wake, with socket I/O
    /// outside the publication mutex. It provides no exit or drain receipt.
    pub fn fence(&self) {
        self.authority.fenced.store(true, Ordering::Release);
        let original = {
            let mut guest = self
                .authority
                .guest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guest.original.take()
        };
        if let Some(original) = original {
            let _ = original.shutdown(std::net::Shutdown::Both);
        }
    }
    fn fail_cleanup(&self) {
        self.authority.cleanup_failed.store(true, Ordering::Release);
        self.fence();
    }
    pub(super) fn same_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
    }
    /// One monotonic claim, including any later authorization failure.
    pub fn claim_payload_pool(&self) -> Result<()> {
        if self.authority.pool_claimed.swap(true, Ordering::AcqRel) {
            bail!("installed endpoint local pool already claimed")
        }
        self.check_current()
    }
    pub fn check_current(&self) -> Result<()> {
        if self.authority.fenced.load(Ordering::Acquire) {
            bail!("installed endpoint authority fenced")
        }
        let result = (|| {
            self.authority.holder.verify_current()?;
            if self.authority.parent.wait_event(Instant::now())? != ProcessExitWait::TimedOut
                || parent_closed(&self.authority.input)?
            {
                bail!("installed endpoint parent admission closed")
            }
            if let Some(audit) = &self.authority.audit {
                audit.check_current()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.fence();
        }
        result
    }
}

pub struct InstalledEndpointChild {
    lease: InstalledEndpointLease,
    output: File,
    config: Option<Box<serde_json::value::RawValue>>,
    records: Option<Option<InstalledTelemetryRecords>>,
    nonce: [u8; 32],
    phase: u8,
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
        let mut input = duplicate_descriptor(libc::STDIN_FILENO)?;
        let mut output = duplicate_descriptor(libc::STDOUT_FILENO)?;
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
        let prepared: Prepare<Box<serde_json::value::RawValue>> = read_frame(&mut input, CONFIG_LIMIT, deadline)?;
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
            parent
                .event_fd()
                .context("installed original parent event missing")?
                .as_raw_fd(),
        ];
        let records_descriptor = prepared
            .telemetry_records
            .as_ref()
            .map(records::RecordsProjection::descriptor);
        let audit_descriptors = prepared
            .audit
            .as_ref()
            .map(audit::AuditProjection::descriptors);
        let mut raw_namespace = std::collections::BTreeSet::new();
        let mut object_namespace = std::collections::BTreeSet::new();
        for fd in descriptors
            .into_iter()
            .chain(records_descriptor)
            .chain(audit_descriptors.into_iter().flatten())
        {
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            // Linux process descriptors are checked by live kernel PID below,
            // even when the host represents them with a shared anonymous inode.
            let process_event = cfg!(target_os = "linux")
                && audit_descriptors
                    .is_some_and(|audit| audit.contains(&fd) || fd == descriptors[4]);
            // SAFETY: raw metadata query only, before any inherited fd is adopted.
            if fd <= 2
                || !raw_namespace.insert(fd)
                || unsafe { libc::fstat(fd, &mut metadata) } != 0
                || (!process_event && !object_namespace.insert((metadata.st_dev, metadata.st_ino)))
                || (fd == prepared.directory && metadata.st_mode & libc::S_IFMT != libc::S_IFDIR)
                || (fd == prepared.holder && metadata.st_mode & libc::S_IFMT != libc::S_IFREG)
            {
                bail!("installed endpoint complete descriptor namespace differs")
            }
        }
        let mut audit_excluded = descriptors.to_vec();
        audit_excluded.extend(records_descriptor);
        if prepared.telemetry_records.is_some() || prepared.audit.is_some() {
            // Verify the original holder on temporary duplicates before any
            // audit event or records writer can be adopted.
            let verified = PreparedHostLifetimeLease::bind(
                duplicate_descriptor(prepared.directory)?,
                duplicate_descriptor(prepared.holder)?,
                prepared.expected.clone(),
            )?;
            verified.verify_current()?;
        }
        if let Some(records) = &prepared.telemetry_records {
            let mut excluded = descriptors.to_vec();
            excluded.extend(audit_descriptors.into_iter().flatten());
            records.preflight(&excluded)?;
        }
        if let Some(audit) = &prepared.audit {
            #[derive(Deserialize)]
            struct Tenant<'a> {
                tenant_id: &'a str,
            }
            let tenant: Tenant<'_> = serde_json::from_str(prepared.config.get())?;
            if tenant.tenant_id != audit.tenant() {
                bail!("installed audit tenant differs from endpoint config");
            }
            audit.preflight(&audit_excluded, &prepared.projection.binding.vm_name)?;
            #[cfg(target_os = "linux")]
            audit.check_linux_processes(pid)?;
        }
        let audit = prepared
            .audit
            .map(|audit| {
                audit::ChildAudit::adopt(
                    audit,
                    &audit_excluded,
                    &prepared.projection.binding.vm_name,
                )
            })
            .transpose()?;
        // SAFETY: the complete preflight established distinct original inherited
        // files, and each number is adopted exactly once by this private startup.
        let directory = unsafe { File::from_raw_fd(prepared.directory) };
        // SAFETY: same exclusive inherited-file contract as directory above.
        let holder = unsafe { File::from_raw_fd(prepared.holder) };
        let holder = PreparedHostLifetimeLease::bind(directory, holder, prepared.expected)?;
        holder.verify_current()?;
        let lease = InstalledEndpointLease {
            authority: Arc::new(ChildAuthority {
                input,
                holder,
                parent,
                projection: prepared.projection,
                fenced: AtomicBool::new(false),
                cleanup_failed: AtomicBool::new(false),
                pool_claimed: AtomicBool::new(false),
                audit,
                guest: Mutex::new(GuestTransport::default()),
            }),
        };
        let records = prepared
            .telemetry_records
            .map(|projection| {
                // SAFETY: complete borrowed preflight validated a distinct
                // inherited writer whose ownership is transferred here once.
                let file = unsafe { File::from_raw_fd(projection.descriptor()) };
                projection.adopt(file, lease.clone())
            })
            .transpose()?;
        Ok(Self {
            lease,
            output,
            config: Some(prepared.config),
            records: Some(records),
            nonce,
            phase: 0,
            startup_deadline: deadline,
        })
    }
    pub fn lease(&self) -> InstalledEndpointLease {
        self.lease.clone()
    }
    /// Claim the original records writer once, including an absent mapping.
    pub fn take_telemetry_records(&mut self) -> Result<Option<InstalledTelemetryRecords>> {
        self.check_parent()?;
        let records = self
            .records
            .take()
            .context("installed records already consumed")?;
        self.check_parent()?;
        Ok(records)
    }
    pub fn projection(&self) -> &EndpointPartitionProjection {
        self.lease.projection()
    }
    /// Move the original bounded configuration text without constructing a
    /// generic JSON tree. Typed consumers hold their workspace before decoding.
    pub fn take_raw_config(&mut self) -> Result<Box<serde_json::value::RawValue>> {
        self.config
            .take()
            .context("installed endpoint config already consumed")
    }
    /// Legacy compatibility conversion. Installed shipping consumers use
    /// `take_raw_config` and decode directly into their bounded typed schema.
    pub fn take_config(&mut self) -> Result<serde_json::Value> {
        let config = self.take_raw_config()?;
        serde_json::from_str(config.get())
            .map_err(|_| anyhow!("invalid installed endpoint configuration"))
    }
    /// Deadline retained from the original installed startup exchange.
    pub fn startup_deadline(&self) -> Instant {
        self.startup_deadline
    }
    pub fn control_fd(&self) -> i32 {
        self.lease.authority.input.as_raw_fd()
    }
    pub fn check_parent(&self) -> Result<()> {
        self.lease.check_current()
    }
    /// Borrow only the verified readonly state file through the sole controller.
    pub fn with_verification_state<T>(
        &mut self,
        operation: impl FnOnce(&File) -> Result<T>,
    ) -> Result<T> {
        let result = (|| {
            self.check_parent()?;
            let value = self
                .lease
                .authority
                .holder
                .with_verification_state(operation)?;
            self.check_parent()?;
            Ok(value)
        })();
        if result.is_err() {
            self.lease.fence();
        }
        result
    }
    pub fn parent_closed(&self) -> Result<bool> {
        parent_closed(&self.lease.authority.input)
    }
    pub fn send_ready(&mut self, handshake: EndpointHandshake, deadline: Instant) -> Result<()> {
        let deadline = deadline.min(self.startup_deadline);
        if self.phase != 0 || self.config.is_some() {
            bail!("installed endpoint readiness phase differs")
        }
        self.check_parent()?;
        let session = self.projection().session;
        let serial = self.projection().partition_serial;
        write_frame(
            &mut self.output,
            &Ready {
                version: 1,
                nonce: self.nonce,
                session,
                serial,
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
        if self.lease.authority.cleanup_failed.load(Ordering::Acquire) {
            bail!("installed endpoint cleanup is unverified")
        }
        self.lease.authority.fenced.store(true, Ordering::Release);
        let session = self.projection().session;
        let serial = self.projection().partition_serial;
        write_frame(
            &mut self.output,
            &Drained {
                version: 1,
                nonce: self.nonce,
                session,
                serial,
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
fn duplicate_descriptor(raw: i32) -> Result<File> {
    // SAFETY: fcntl duplicates a descriptor and returns a new CLOEXEC owner.
    let fd = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicate installed descriptor");
    }
    // SAFETY: fcntl returned this new owned descriptor, used without buffering.
    Ok(unsafe { File::from_raw_fd(fd) })
}

struct BoundedBytes {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
fn encode_config_projection(
    params: &SubstitutionSpawnParams<'_>,
    telemetry: Option<&super::collector::TelemetrySection<'_>>,
) -> Result<Box<serde_json::value::RawValue>> {
    if params.telemetry != telemetry.is_some() || params.state_dir.as_os_str().len() > 4096 {
        bail!("installed endpoint configuration shape unsupported")
    }
    let mut bounded = BoundedBytes {
        bytes: Zeroizing::new(Vec::with_capacity(CONFIG_LIMIT)),
        limit: CONFIG_LIMIT,
    };
    serde_json::to_writer(&mut bounded, &EndpointConfigProjection(params, telemetry))
        .map_err(|_| anyhow!("installed endpoint configuration exceeds bound"))?;
    let text = String::from_utf8(std::mem::take(&mut bounded.bytes))
        .map_err(|_| anyhow!("invalid installed endpoint configuration"))?;
    serde_json::value::RawValue::from_string(text)
        .map_err(|_| anyhow!("invalid installed endpoint configuration"))
}

pub(super) fn encode_config_with_telemetry_credit(
    params: &SubstitutionSpawnParams<'_>,
    telemetry: &super::collector::TelemetrySection<'_>,
    metadata: u64,
) -> Result<Box<serde_json::value::RawValue>> {
    if metadata < INSTALLED_BOOTSTRAP_MIN_BYTES {
        bail!("installed endpoint bootstrap credit missing")
    }
    let config = encode_config_projection(params, Some(telemetry))?;
    if installed_endpoint_bootstrap_requirement(config.get())? > metadata {
        bail!("installed endpoint typed configuration credit missing")
    }
    Ok(config)
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
