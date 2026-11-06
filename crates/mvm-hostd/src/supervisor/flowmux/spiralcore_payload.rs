//! Canonical post-admission mapping onto the single shared object core.
mod installed;

use super::{AdmittedTcpPayload, AuthenticatedTcpPayloadFactory, AuthenticatedTcpPayloadIo};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use mvm_contract::policy::network_policy::PayloadMappingProfile;
use spiralcore_mvm_flowmux::{
    Duplex, MappedStream, ObjectChannel, Role,
    scope::{ScopeAuthority, ScopeFacts},
    tls::{PinnedIdentity, TlsCarrier},
};
use spiralcore_transfer::v1::{Capabilities, NegotiatedProfile, ObjectEndpoint, ObjectSender};
use std::{
    fmt,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_string())
}
fn remaining(until: Instant) -> io::Result<Duration> {
    let remaining = until.saturating_duration_since(Instant::now());
    if remaining.is_zero() || remaining > Duration::from_secs(30) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "payload original setup deadline",
        ));
    }
    Ok(remaining)
}
fn digest<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    hex::decode(value)
        .map_err(invalid)?
        .try_into()
        .map_err(|_| invalid("admitted digest length"))
}
fn capabilities(selected: PayloadMappingProfile) -> Capabilities {
    match selected {
        PayloadMappingProfile::SpiralCoreObjectStreamSmallV1 => Capabilities::small_v1(),
        PayloadMappingProfile::SpiralCoreObjectStreamV1 => {
            let mut capabilities = Capabilities::full();
            capabilities.max_object_bytes = 65536;
            capabilities
        }
    }
}

/// Trusted local controller; received facts or TLS alone never grant a scope.
pub trait PayloadScopeController: Send + Sync + fmt::Debug {
    fn requires_owned_tcp_relays(&self) -> bool {
        false
    }
    fn check_owned_tcp_relays(
        &self,
        _: &super::OwnedTcpRelays,
        _: &mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan,
        _: &str,
        _: [u8; 32],
        _: [u8; 32],
    ) -> io::Result<()> {
        Err(invalid("controller has no original installed partition"))
    }
    fn check_before_carrier(&self, _: &AdmittedTcpPayload) -> io::Result<()> {
        Ok(())
    }
    fn prepare(
        &self,
        request: &AdmittedTcpPayload,
        facts: &ScopeFacts,
        profile: NegotiatedProfile,
        deadline: Instant,
    ) -> io::Result<PreparedPayloadSession>;
}
/// Constructed only after explicit local enrollment, with bounded core storage.
pub struct PreparedPayloadSession {
    artifacts: Vec<PayloadArtifact>,
    authority: ScopeAuthority,
    sender: ObjectSender,
    endpoint: ObjectEndpoint<ScopeAuthority>,
    resources: PayloadResourcePermit,
    reader_resources: Option<Arc<crate::installed_endpoint::InstalledEndpointComponentPermit>>,
    relay_witness: Option<super::owned_relays::RelayWitness>,
}
pub enum PayloadArtifact {
    Schema,
    Checkpoint,
    Base(Vec<u8>),
}
impl PreparedPayloadSession {
    pub fn with_artifacts(mut self, artifacts: Vec<PayloadArtifact>) -> io::Result<Self> {
        if artifacts.len() > 3 {
            return Err(invalid("too many setup artifacts"));
        }
        let mut seen = [false; 3];
        for artifact in &artifacts {
            let tag = match artifact {
                PayloadArtifact::Schema => 0,
                PayloadArtifact::Checkpoint => 1,
                PayloadArtifact::Base(bytes) => {
                    if bytes.is_empty() || bytes.len() > 65536 {
                        return Err(invalid("base artifact limit"));
                    }
                    2
                }
            };
            if seen[tag] {
                return Err(invalid("duplicate setup artifact"));
            }
            seen[tag] = true;
        }
        self.artifacts = artifacts;
        Ok(self)
    }
    pub fn new(
        authority: ScopeAuthority,
        sender: ObjectSender,
        endpoint: ObjectEndpoint<ScopeAuthority>,
        resources: PayloadResourcePermit,
    ) -> io::Result<Self> {
        Self::check_parts(&authority, &sender, &endpoint, &resources)?;
        Ok(Self {
            artifacts: Vec::new(),
            authority,
            sender,
            endpoint,
            resources,
            reader_resources: None,
            relay_witness: None,
        })
    }
    fn check_parts(
        authority: &ScopeAuthority,
        sender: &ObjectSender,
        endpoint: &ObjectEndpoint<ScopeAuthority>,
        resources: &PayloadResourcePermit,
    ) -> io::Result<()> {
        resources.check_current()?;
        authority.check().map_err(invalid)?;
        let profile = sender.profile();
        if profile != endpoint.profile()
            || profile.capabilities().profile != authority.object_profile()
            || resources.profile.map(|resource| match resource {
                spiralcore_transfer::resource_profile::ResourceProfile::SmallV1 => 2,
                spiralcore_transfer::resource_profile::ResourceProfile::General => 1,
            }) != Some(authority.object_profile())
        {
            return Err(invalid(
                "resource reservation, enrolled scope and core profile differ",
            ));
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct SpiralCorePayloadFactory {
    identity: PinnedIdentity,
    controller: Controller,
}
#[derive(Debug)]
enum Controller {
    Enrolled(Arc<dyn PayloadScopeController>),
    Installed(Box<installed::InstalledScopeController>),
}
enum PendingScope<'a> {
    Enrolled(&'a dyn PayloadScopeController),
    Installed(
        &'a installed::InstalledScopeController,
        Option<PayloadResourcePermit>,
    ),
}
impl SpiralCorePayloadFactory {
    pub fn from_host_key(
        key: &SigningKey,
        controller: Arc<dyn PayloadScopeController>,
    ) -> io::Result<Self> {
        let identity = pinned_identity(key)?;
        Ok(Self {
            identity,
            controller: Controller::Enrolled(controller),
        })
    }
}
fn pinned_identity(key: &SigningKey) -> io::Result<PinnedIdentity> {
    let encoded = key.to_pkcs8_der().map_err(invalid)?;
    PinnedIdentity::from_pkcs8(encoded.as_bytes().to_vec())
}
impl AuthenticatedTcpPayloadFactory for SpiralCorePayloadFactory {
    fn requires_owned_tcp_relays(&self) -> bool {
        match &self.controller {
            Controller::Enrolled(controller) => controller.requires_owned_tcp_relays(),
            Controller::Installed(_) => true,
        }
    }
    fn check_owned_tcp_relays(
        &self,
        group: &super::OwnedTcpRelays,
        plan: &mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan,
        session: &str,
        host: [u8; 32],
        guest: [u8; 32],
    ) -> io::Result<()> {
        match &self.controller {
            Controller::Enrolled(controller) => {
                controller.check_owned_tcp_relays(group, plan, session, host, guest)
            }
            Controller::Installed(controller) => {
                controller.check_owned_tcp_relays(group, plan, session, host, guest)
            }
        }
    }
    fn map(
        &self,
        socket: TcpStream,
        request: AdmittedTcpPayload,
    ) -> io::Result<Box<dyn AuthenticatedTcpPayloadIo>> {
        let deadline = request.deadline();
        remaining(deadline)?;
        let pending = match &self.controller {
            Controller::Enrolled(controller) => {
                controller.check_before_carrier(&request)?;
                PendingScope::Enrolled(controller.as_ref())
            }
            Controller::Installed(controller) => {
                PendingScope::Installed(controller, Some(controller.reserve(&request)?))
            }
        };
        // Tuple fields drop in order. An error or unwind while validating
        // actual TLS facts destroys the carrier before returning its credit.
        let mut carrier = (
            TlsCarrier::connect(
                socket,
                &self.identity,
                request.selected().spki_sha256,
                &request.selected().server_name,
                deadline,
            )?,
            pending,
        );
        let plan = request.plan();
        let caps = capabilities(request.selected().profile);
        let facts = ScopeFacts {
            object_profile: caps.profile,
            policy_sha256: digest(&plan.policy_sha256)?,
            plan_id: plan.plan_id.0.clone(),
            plan_version: plan.plan_version,
            plan_nonce: digest(plan.plan_nonce.as_hex())?,
            bundle_sha256: digest(&plan.bundle_sha256)?,
            tenant: plan.tenant_id.clone(),
            instance: plan.instance_id.clone(),
            session: request.session_id().into(),
            guest_key: request.guest_key(),
            stream_id: request.stream_id(),
            requested_host: request.requested_host().into(),
            requested_port: request.requested_port(),
            actual_peer: request.actual_peer(),
            route: request.route().into(),
            initiator_spki: carrier.0.local_spki_sha256(),
            acceptor_spki: carrier.0.peer_spki_sha256(),
            tls_exporter: carrier.0.exporter(),
        };
        facts.canonical_bytes().map_err(invalid)?;
        remaining(deadline)?;
        let profile = caps.negotiate(&caps).map_err(invalid)?;
        let prepared = match &mut carrier.1 {
            PendingScope::Enrolled(controller) => {
                controller.prepare(&request, &facts, profile, deadline)?
            }
            PendingScope::Installed(controller, permit) => {
                controller.prepare(&request, &facts, profile, deadline, permit)?
            }
        };
        let ready = (carrier.0, prepared);
        if ready.1.authority.binding().map_err(invalid)? != facts.binding().map_err(invalid)? {
            return Err(invalid("prepared scope differs from actual admitted facts"));
        }
        let mapped = assemble(ready, Role::Initiator, deadline)?;
        Ok(Box::new(mapped))
    }
}
/// The cooperating application endpoint must already have exact enrollment.
pub fn accept_enrolled_payload(
    tls: TlsCarrier,
    prepared: PreparedPayloadSession,
    deadline: Instant,
) -> io::Result<EnrolledPayloadStream> {
    assemble((tls, prepared), Role::Acceptor, deadline)
}
fn assemble(
    ready: (TlsCarrier, PreparedPayloadSession),
    role: Role,
    deadline: Instant,
) -> io::Result<EnrolledPayloadStream> {
    let prepared = &ready.1;
    prepared.resources.check_current()?;
    check_reader(
        prepared.reader_resources.as_ref(),
        prepared.relay_witness.as_ref(),
    )?;
    prepared.authority.check().map_err(invalid)?;
    let caps = prepared.sender.profile().capabilities();
    let context = prepared.authority.context().clone();
    let time = remaining(deadline)?;
    let channel =
        ObjectChannel::from_authenticated(ready.0, &prepared.authority, time, role, caps, caps)
            .map_err(invalid)?;
    let prepared = ready.1;
    let duplex = Duplex::spawn(channel, prepared.sender, prepared.endpoint, context, role)
        .map_err(invalid)?;
    let artifacts = prepared.artifacts;
    let mapped = EnrolledPayloadStream {
        inner: Arc::new(OwnedMappedPayload {
            stream: MappedStream::from_duplex(duplex),
            resources: prepared.resources,
            reader_resources: prepared.reader_resources,
            relay_witness: prepared.relay_witness,
        }),
    };
    if let Some(witness) = &mapped.inner.relay_witness {
        witness.retain_prepared(mapped.clone())?;
    }
    for artifact in artifacts {
        remaining(deadline)?;
        mapped.check_current()?;
        let publication = match artifact {
            PayloadArtifact::Schema => mapped.inner.stream.seed_schema_until(deadline),
            PayloadArtifact::Checkpoint => mapped.inner.stream.seed_checkpoint_until(deadline),
            PayloadArtifact::Base(bytes) => mapped.inner.stream.seed_base_until(bytes, deadline),
        };
        if let Err(error) = publication {
            let _ = mapped.shutdown(Shutdown::Both);
            return Err(invalid(error));
        }
    }
    if let Err(error) = remaining(deadline) {
        let _ = mapped.shutdown(Shutdown::Both);
        return Err(error);
    }
    mapped.check_current()?;
    Ok(mapped)
}
struct OwnedMappedPayload {
    // Declaration order is the cleanup barrier: join the exact owned reader
    // through the last mapped stream before store cleanup/resource release.
    stream: MappedStream,
    resources: PayloadResourcePermit,
    reader_resources: Option<Arc<crate::installed_endpoint::InstalledEndpointComponentPermit>>,
    relay_witness: Option<super::owned_relays::RelayWitness>,
}

fn check_reader(
    reader: Option<&Arc<crate::installed_endpoint::InstalledEndpointComponentPermit>>,
    relay: Option<&super::owned_relays::RelayWitness>,
) -> io::Result<()> {
    match (reader, relay) {
        (Some(reader), Some(relay)) => relay.check(reader),
        (None, None) => Ok(()),
        _ => Err(invalid("installed reader original relay witness missing")),
    }
}
#[derive(Clone)]
pub struct EnrolledPayloadStream {
    inner: Arc<OwnedMappedPayload>,
}
impl EnrolledPayloadStream {
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.stream.shutdown(how)
    }
    fn check_current(&self) -> io::Result<()> {
        if let Err(error) = check_reader(
            self.inner.reader_resources.as_ref(),
            self.inner.relay_witness.as_ref(),
        ) {
            let _ = self.inner.stream.shutdown(Shutdown::Both);
            return Err(error);
        }
        if let Err(error) = self.inner.resources.check_current() {
            let _ = self.inner.stream.shutdown(Shutdown::Both);
            return Err(error);
        }
        Ok(())
    }
}
impl fmt::Debug for EnrolledPayloadStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrolledPayloadStream")
            .finish_non_exhaustive()
    }
}
impl Read for EnrolledPayloadStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check_current()?;
        let count = self.inner.stream.clone().read(bytes)?;
        self.check_current()?;
        Ok(count)
    }
}
impl Write for EnrolledPayloadStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check_current()?;
        let count = self.inner.stream.clone().write(bytes)?;
        self.check_current()?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check_current()?;
        self.inner.stream.clone().flush()?;
        self.check_current()
    }
}
impl AuthenticatedTcpPayloadIo for EnrolledPayloadStream {
    fn try_clone(&self) -> io::Result<Box<dyn AuthenticatedTcpPayloadIo>> {
        self.check_current()?;
        Ok(Box::new(self.clone()))
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
    fn close_and_join_until(&self, until: Instant) -> io::Result<()> {
        self.inner
            .stream
            .close_and_join_until(until)
            .map_err(|error| match error {
                spiralcore_mvm_flowmux::Error::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "payload reader completion deadline",
                ),
                other => invalid(other),
            })
    }
}

/// Host-owned reservation extension. A serialized number/flag is not this proof.
pub trait ParentPayloadReservation: Send + Sync + fmt::Debug {
    fn limits(&self) -> PayloadResourceLimits;
    fn authorize(
        &self,
        plan: &mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan,
        session: &str,
    ) -> io::Result<()>;
    fn check_current(&self) -> io::Result<()>;
}
pub use mvm_vmm::host::network_endpoint_spawn::PayloadResourceLimits;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadResourceCharge {
    pub resident_bytes: u64,
    pub disk_bytes: u64,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PayloadPoolSnapshot {
    pub active: u16,
    pub resident_charge: u64,
    pub disk_charge: u64,
    pub quarantined: u16,
}
struct PoolLedger {
    closed: bool,
    used: PayloadPoolSnapshot,
    carrier_used: u64,
    stores: Vec<OwnedPayloadStore>,
}

#[cfg(test)]
#[path = "spiralcore_payload/pool_close_tests.rs"]
mod pool_close_tests;
struct PoolInner {
    limits: PayloadResourceLimits,
    carrier_limit: u64,
    parent: Option<Arc<dyn ParentPayloadReservation>>,
    ledger: std::sync::Mutex<PoolLedger>,
    retained_uncertain: std::sync::atomic::AtomicBool,
    fenced: std::sync::atomic::AtomicBool,
}
#[derive(Clone)]
pub struct PayloadResourcePool {
    inner: Arc<PoolInner>,
}
impl fmt::Debug for PayloadResourcePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadResourcePool")
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}
impl PayloadResourcePool {
    /// Explicit DEV arithmetic qualification, not a production host capacity grant.
    pub fn for_qualification(limits: PayloadResourceLimits) -> io::Result<Self> {
        Self::new(limits, None, 0)
    }
    pub fn from_parent(
        parent: Arc<dyn ParentPayloadReservation>,
        plan: &mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan,
        session: &str,
    ) -> io::Result<Self> {
        Self::from_installed_parent(parent, plan, session, 0)
    }
    pub(crate) fn from_installed_parent(
        parent: Arc<dyn ParentPayloadReservation>,
        plan: &mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan,
        session: &str,
        carrier_limit: u64,
    ) -> io::Result<Self> {
        parent.authorize(plan, session)?;
        parent.check_current()?;
        Self::new(parent.limits(), Some(parent), carrier_limit)
    }
    fn new(
        limits: PayloadResourceLimits,
        parent: Option<Arc<dyn ParentPayloadReservation>>,
        carrier_limit: u64,
    ) -> io::Result<Self> {
        limits.validate().map_err(invalid)?;
        Ok(Self {
            inner: Arc::new(PoolInner {
                limits,
                carrier_limit,
                parent,
                ledger: std::sync::Mutex::new(PoolLedger {
                    closed: false,
                    used: PayloadPoolSnapshot::default(),
                    carrier_used: 0,
                    stores: Vec::new(),
                }),
                retained_uncertain: std::sync::atomic::AtomicBool::new(false),
                fenced: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }
    pub fn snapshot(&self) -> io::Result<PayloadPoolSnapshot> {
        Ok(self
            .inner
            .ledger
            .lock()
            .map_err(|_| invalid("payload pool poisoned"))?
            .used)
    }
    /// Fence new local reservations without preventing existing owned cleanup.
    /// No parent callback or filesystem I/O runs while this ledger is held.
    pub fn close_admission(&self) -> io::Result<()> {
        let mut ledger = self.inner.ledger.lock().map_err(|_| {
            self.inner.retain_uncertain();
            invalid("payload pool poisoned")
        })?;
        ledger.closed = true;
        Ok(())
    }
    /// Local accounting is drained only behind a closed admission barrier.
    /// This does not replace positive worker joins or the parent's disk receipt.
    pub fn drained(&self) -> io::Result<bool> {
        let ledger = self.inner.ledger.lock().map_err(|_| {
            self.inner.retain_uncertain();
            invalid("payload pool poisoned")
        })?;
        Ok(ledger.closed
            && !self.inner.fenced.load(std::sync::atomic::Ordering::Acquire)
            && ledger.used == PayloadPoolSnapshot::default()
            && ledger.carrier_used == 0
            && ledger.stores.is_empty())
    }
    pub fn reserve_profile(
        &self,
        resources: spiralcore_transfer::resource_profile::ResourceProfile,
    ) -> io::Result<PayloadResourcePermit> {
        self.reserve_profile_with_carrier(resources, 0)
    }
    fn reserve_installed_profile(
        &self,
        resources: spiralcore_transfer::resource_profile::ResourceProfile,
    ) -> io::Result<PayloadResourcePermit> {
        // The original configured envelope is split across the existing
        // stream slots. This is credit ownership, not a TLS allocation quote.
        let carrier = self.inner.carrier_limit / u64::from(self.inner.limits.max_active);
        if carrier == 0 {
            return Err(invalid("original payload carrier credit unavailable"));
        }
        self.reserve_profile_with_carrier(resources, carrier)
    }
    fn reserve_profile_with_carrier(
        &self,
        resources: spiralcore_transfer::resource_profile::ResourceProfile,
        carrier_bytes: u64,
    ) -> io::Result<PayloadResourcePermit> {
        let limits = resources.receiver_limits();
        let disk_bytes = limits
            .cache_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(1 << 20))
            .ok_or_else(|| invalid("store charge overflow"))?;
        let mut permit = self.reserve_charge_with_carrier(
            PayloadResourceCharge {
                resident_bytes: resources.operation_charge().map_err(invalid)?,
                disk_bytes,
            },
            carrier_bytes,
        )?;
        permit.profile = Some(resources);
        Ok(permit)
    }
    pub fn reserve_shared_sender(
        &self,
        _mode: spiralcore_transfer::v1::ObjectMode,
    ) -> io::Result<PayloadResourcePermit> {
        self.reserve_profile(spiralcore_transfer::resource_profile::ResourceProfile::General)
    }
    #[cfg(test)]
    fn reserve_charge(&self, charge: PayloadResourceCharge) -> io::Result<PayloadResourcePermit> {
        self.reserve_charge_with_carrier(charge, 0)
    }
    fn reserve_charge_with_carrier(
        &self,
        charge: PayloadResourceCharge,
        carrier_bytes: u64,
    ) -> io::Result<PayloadResourcePermit> {
        if charge.resident_bytes == 0 || charge.disk_bytes == 0 {
            return Err(invalid("zero payload resource charge"));
        }
        self.inner.check_current()?;
        let mut ledger = self
            .inner
            .ledger
            .lock()
            .map_err(|_| invalid("payload pool poisoned"))?;
        if ledger.closed || self.inner.fenced.load(std::sync::atomic::Ordering::Acquire) {
            return Err(invalid("payload pool admission closed or fenced"));
        }
        let active = ledger
            .used
            .active
            .checked_add(1)
            .ok_or_else(|| invalid("active payload overflow"))?;
        let resident = ledger
            .used
            .resident_charge
            .checked_add(charge.resident_bytes)
            .ok_or_else(|| invalid("payload resident overflow"))?;
        let disk = ledger
            .used
            .disk_charge
            .checked_add(charge.disk_bytes)
            .ok_or_else(|| invalid("payload disk overflow"))?;
        let carrier = ledger
            .carrier_used
            .checked_add(carrier_bytes)
            .ok_or_else(|| invalid("payload carrier overflow"))?;
        if active > self.inner.limits.max_active
            || resident > self.inner.limits.resident_bytes
            || disk > self.inner.limits.disk_bytes
            || carrier > self.inner.carrier_limit
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "aggregate payload pool full",
            ));
        }
        ledger.used.active = active;
        ledger.used.resident_charge = resident;
        ledger.used.disk_charge = disk;
        ledger.carrier_used = carrier;
        drop(ledger);
        Ok(PayloadResourcePermit {
            inner: self.inner.clone(),
            charge,
            carrier_bytes,
            store: None,
            uncertain: false,
            profile: None,
        })
    }
}
impl PoolInner {
    fn check_current(&self) -> io::Result<()> {
        if self.fenced.load(std::sync::atomic::Ordering::Acquire) {
            return Err(invalid("payload pool fenced"));
        }
        if let Some(parent) = &self.parent {
            parent.check_current()?;
        }
        Ok(())
    }
    fn retain_uncertain(self: &Arc<Self>) {
        self.fenced
            .store(true, std::sync::atomic::Ordering::Release);
        // A single retained owner keeps the actual parent reservation and all
        // quarantined held identities alive, including after every API clone.
        if !self
            .retained_uncertain
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            std::mem::forget(Arc::clone(self));
        }
    }
}
struct OwnedPayloadStore {
    path: std::path::PathBuf,
    directory: std::fs::File,
    device: u64,
    inode: u64,
}
impl OwnedPayloadStore {
    fn capture(path: std::path::PathBuf) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let before = std::fs::symlink_metadata(&path)?;
        mvm_core::private_fs::require_current_owner(&before)?;
        if !before.is_dir() || before.file_type().is_symlink() || before.mode() & 0o077 != 0 {
            return Err(invalid("payload store is not private directory"));
        }
        let directory = std::fs::File::open(&path)?;
        Self::capture_directory(path, directory)
    }
    fn capture_directory(path: std::path::PathBuf, directory: std::fs::File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let before = std::fs::symlink_metadata(&path)?;
        mvm_core::private_fs::require_current_owner(&before)?;
        if !before.is_dir() || before.file_type().is_symlink() || before.mode() & 0o077 != 0 {
            return Err(invalid("payload store is not private directory"));
        }
        let opened = directory.metadata()?;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(invalid("payload store identity changed"));
        }
        Ok(Self {
            path,
            directory,
            device: opened.dev(),
            inode: opened.ino(),
        })
    }
    fn cleanup(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let held = self.directory.metadata()?;
        let current = std::fs::symlink_metadata(&self.path)?;
        mvm_core::private_fs::require_current_owner(&current)?;
        if !current.is_dir()
            || current.file_type().is_symlink()
            || current.mode() & 0o077 != 0
            || current.dev() != self.device
            || current.ino() != self.inode
            || held.dev() != self.device
            || held.ino() != self.inode
        {
            return Err(invalid("payload store no longer has original identity"));
        }
        std::fs::remove_dir_all(&self.path)?;
        match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(invalid("payload store cleanup not confirmed")),
        }
    }
}
#[must_use]
pub struct PayloadResourcePermit {
    inner: Arc<PoolInner>,
    charge: PayloadResourceCharge,
    carrier_bytes: u64,
    store: Option<OwnedPayloadStore>,
    uncertain: bool,
    profile: Option<spiralcore_transfer::resource_profile::ResourceProfile>,
}
impl PayloadResourcePermit {
    fn attach_owned_directory(
        &mut self,
        path: std::path::PathBuf,
        directory: std::fs::File,
    ) -> io::Result<()> {
        if self.store.is_some() {
            self.uncertain = true;
            return Err(invalid("payload store already attached"));
        }
        match OwnedPayloadStore::capture_directory(path, directory) {
            Ok(store) => {
                self.store = Some(store);
                Ok(())
            }
            Err(error) => {
                self.uncertain = true;
                Err(error)
            }
        }
    }
    pub fn with_owned_store(mut self, path: std::path::PathBuf) -> io::Result<Self> {
        if self.store.is_some() {
            self.uncertain = true;
            return Err(invalid("payload store already attached"));
        }
        // A failed identity capture cannot prove that the newly created path
        // contains no retained storage. Refuse and retain its admitted charge.
        match OwnedPayloadStore::capture(path) {
            Ok(store) => {
                self.store = Some(store);
                Ok(self)
            }
            Err(error) => {
                self.uncertain = true;
                Err(error)
            }
        }
    }
    fn check_current(&self) -> io::Result<()> {
        self.inner.check_current()
    }
}
impl Drop for PayloadResourcePermit {
    fn drop(&mut self) {
        let mut uncertain = self.uncertain
            || self
                .store
                .as_ref()
                .is_some_and(|store| store.cleanup().is_err());
        let mut ledger = match self.inner.ledger.lock() {
            Ok(ledger) => ledger,
            Err(poisoned) => {
                uncertain = true;
                self.inner.retain_uncertain();
                poisoned.into_inner()
            }
        };
        if uncertain {
            if let Some(store) = self.store.take() {
                ledger.stores.push(store);
            }
            ledger.used.quarantined = ledger.used.quarantined.saturating_add(1);
            // Keep one bounded owner, its parent reservation and held directory
            // identities alive. No uncertain cleanup returns resource capacity.
            self.inner.retain_uncertain();
            drop(ledger);
            return;
        }
        let Some(active) = ledger.used.active.checked_sub(1) else {
            self.inner.retain_uncertain();
            return;
        };
        let Some(resident) = ledger
            .used
            .resident_charge
            .checked_sub(self.charge.resident_bytes)
        else {
            self.inner.retain_uncertain();
            return;
        };
        let Some(disk) = ledger.used.disk_charge.checked_sub(self.charge.disk_bytes) else {
            self.inner.retain_uncertain();
            return;
        };
        let Some(carrier) = ledger.carrier_used.checked_sub(self.carrier_bytes) else {
            self.inner.retain_uncertain();
            return;
        };
        ledger.used.active = active;
        ledger.used.resident_charge = resident;
        ledger.used.disk_charge = disk;
        ledger.carrier_used = carrier;
    }
}

#[cfg(test)]
mod resource_pool_tests {
    use super::*;

    #[test]
    fn carrier_refusal_cannot_partially_debit_the_original_payload_pool() {
        let pool = PayloadResourcePool::new(
            PayloadResourceLimits {
                max_active: 2,
                resident_bytes: 20,
                disk_bytes: 20,
            },
            None,
            10,
        )
        .expect("isolated arithmetic ledger");
        let charge = PayloadResourceCharge {
            resident_bytes: 3,
            disk_bytes: 4,
        };
        let original = pool.reserve_charge_with_carrier(charge, 7).unwrap();
        let before = pool.snapshot().unwrap();
        let refusal = pool
            .reserve_charge_with_carrier(charge, 4)
            .err()
            .expect("original carrier capacity must refuse");
        assert_eq!(refusal.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(pool.snapshot().unwrap(), before);
        assert_eq!(pool.inner.ledger.lock().unwrap().carrier_used, 7);
        pool.close_admission().unwrap();
        assert!(!pool.drained().unwrap());
        drop(original);
        assert!(pool.drained().unwrap());
    }

    #[test]
    fn shared_small_profile_charge_is_reserved_once_per_local_engine() {
        let pool = PayloadResourcePool::for_qualification(PayloadResourceLimits {
            max_active: 4,
            resident_bytes: 8 << 20,
            disk_bytes: 32 << 20,
        })
        .expect("explicit DEV ledger");
        let resources = spiralcore_transfer::resource_profile::ResourceProfile::SmallV1;
        let held = pool
            .reserve_profile(resources)
            .expect("qualified Small engine");
        assert_eq!(
            pool.snapshot().expect("snapshot").resident_charge,
            resources.operation_charge().expect("shared charge")
        );
        assert!(
            pool.reserve_profile(resources).is_err(),
            "8MiB does not admit two local engines"
        );
        drop(held);
        assert_eq!(pool.snapshot().expect("released").active, 0);
        assert!(pool.reserve_profile(resources).is_ok());
    }
    #[test]
    fn failed_store_identity_capture_fences_without_returning_capacity() {
        let root = tempfile::tempdir().expect("owned fixture root");
        let path = root.path().join("not-a-directory");
        std::fs::write(&path, b"must survive uncertain capture").expect("fixture bytes");
        let pool = PayloadResourcePool::for_qualification(PayloadResourceLimits {
            max_active: 2,
            resident_bytes: 8 << 20,
            disk_bytes: 32 << 20,
        })
        .expect("DEV ledger");
        let charge = PayloadResourceCharge {
            resident_bytes: 1 << 20,
            disk_bytes: 8 << 20,
        };
        assert!(
            pool.reserve_charge(charge)
                .expect("reserve")
                .with_owned_store(path.clone())
                .is_err()
        );
        let held = pool.snapshot().expect("snapshot");
        assert_eq!(held.active, 1);
        assert_eq!(held.quarantined, 1);
        assert_eq!(held.resident_charge, charge.resident_bytes);
        assert_eq!(held.disk_charge, charge.disk_bytes);
        assert!(
            pool.reserve_charge(charge).is_err(),
            "uncertain pool must fence later admission"
        );
        assert_eq!(
            std::fs::read(path).expect("retained fixture"),
            b"must survive uncertain capture"
        );
    }
    #[test]
    fn one_pool_bounds_all_callers_and_refuses_existing_codec_charges() {
        let pool = PayloadResourcePool::for_qualification(PayloadResourceLimits {
            max_active: 4,
            resident_bytes: 8 << 20,
            disk_bytes: 32 << 20,
        })
        .expect("explicit DEV ledger");
        for mode in [
            spiralcore_transfer::v1::ObjectMode::Whole,
            spiralcore_transfer::v1::ObjectMode::Warm,
            spiralcore_transfer::v1::ObjectMode::Runtime,
            spiralcore_transfer::v1::ObjectMode::Combined,
        ] {
            assert!(
                pool.reserve_shared_sender(mode).is_err(),
                "existing conservative core charge cannot fit8MiB"
            );
        }
        assert_eq!(pool.snapshot().expect("snapshot").active, 0);
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                pool.reserve_charge(PayloadResourceCharge {
                    resident_bytes: 2 << 20,
                    disk_bytes: 8 << 20,
                })
                .expect("arithmetic-only fixture charge"),
            );
        }
        assert!(
            pool.reserve_charge(PayloadResourceCharge {
                resident_bytes: 1,
                disk_bytes: 1
            })
            .is_err()
        );
        let full = pool.snapshot().expect("snapshot");
        assert_eq!(full.active, 4);
        assert_eq!(full.resident_charge, 8 << 20);
        assert_eq!(full.disk_charge, 32 << 20);
        drop(held.pop());
        assert_eq!(pool.snapshot().expect("snapshot").active, 3);
        drop(held);
        assert_eq!(pool.snapshot().expect("snapshot").active, 0);
    }
    #[test]
    fn store_cleanup_releases_only_exact_owned_identity_and_retains_failed_charge() {
        let root = tempfile::tempdir().expect("root");
        let pool = PayloadResourcePool::for_qualification(PayloadResourceLimits {
            max_active: 2,
            resident_bytes: 8 << 20,
            disk_bytes: 32 << 20,
        })
        .expect("DEV ledger");
        let charge = PayloadResourceCharge {
            resident_bytes: 1 << 20,
            disk_bytes: 8 << 20,
        };
        let clean = root.path().join("clean");
        mvm_core::private_fs::create_owned_private_dir(&clean).expect("private store");
        let permit = pool
            .reserve_charge(charge)
            .expect("reserve")
            .with_owned_store(clean.clone())
            .expect("own store");
        std::fs::write(clean.join("verified-disposable-fixture"), b"exact").expect("write");
        drop(permit);
        assert!(!clean.exists());
        assert_eq!(pool.snapshot().expect("snapshot").active, 0);
        let replaced = root.path().join("replaced");
        mvm_core::private_fs::create_owned_private_dir(&replaced).expect("store");
        let permit = pool
            .reserve_charge(charge)
            .expect("reserve")
            .with_owned_store(replaced.clone())
            .expect("own");
        let retained = root.path().join("retained-original");
        std::fs::rename(&replaced, &retained).expect("rename");
        mvm_core::private_fs::create_owned_private_dir(&replaced).expect("replacement");
        std::fs::write(replaced.join("must-remain"), b"different").expect("replacement bytes");
        drop(permit);
        assert!(retained.exists());
        assert_eq!(
            std::fs::read(replaced.join("must-remain")).expect("read"),
            b"different"
        );
        let held = pool.snapshot().expect("snapshot");
        assert_eq!(held.active, 1);
        assert_eq!(held.quarantined, 1);
        assert_eq!(held.resident_charge, charge.resident_bytes);
        assert_eq!(held.disk_charge, charge.disk_bytes);
    }
}
