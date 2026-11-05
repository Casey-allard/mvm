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
        Ok(Self {
            artifacts: Vec::new(),
            authority,
            sender,
            endpoint,
            resources,
        })
    }
}
#[derive(Debug)]
pub struct SpiralCorePayloadFactory {
    identity: PinnedIdentity,
    controller: Arc<dyn PayloadScopeController>,
}
impl SpiralCorePayloadFactory {
    pub fn from_host_key(
        key: &SigningKey,
        controller: Arc<dyn PayloadScopeController>,
    ) -> io::Result<Self> {
        let identity = pinned_identity(key)?;
        Ok(Self {
            identity,
            controller,
        })
    }
}
fn pinned_identity(key: &SigningKey) -> io::Result<PinnedIdentity> {
    let encoded = key.to_pkcs8_der().map_err(invalid)?;
    PinnedIdentity::from_pkcs8(encoded.as_bytes().to_vec())
}
impl AuthenticatedTcpPayloadFactory for SpiralCorePayloadFactory {
    fn map(
        &self,
        socket: TcpStream,
        request: AdmittedTcpPayload,
    ) -> io::Result<Box<dyn AuthenticatedTcpPayloadIo>> {
        let deadline = request.deadline();
        remaining(deadline)?;
        let tls = TlsCarrier::connect(
            socket,
            &self.identity,
            request.selected().spki_sha256,
            &request.selected().server_name,
            deadline,
        )?;
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
            initiator_spki: tls.local_spki_sha256(),
            acceptor_spki: tls.peer_spki_sha256(),
            tls_exporter: tls.exporter(),
        };
        facts.canonical_bytes().map_err(invalid)?;
        remaining(deadline)?;
        let profile = caps.negotiate(&caps).map_err(invalid)?;
        let prepared = self
            .controller
            .prepare(&request, &facts, profile, deadline)?;
        if prepared.authority.binding().map_err(invalid)? != facts.binding().map_err(invalid)? {
            return Err(invalid("prepared scope differs from actual admitted facts"));
        }
        let mapped = assemble(tls, prepared, Role::Initiator, deadline)?;
        Ok(Box::new(mapped))
    }
}
/// The cooperating application endpoint must already have exact enrollment.
pub fn accept_enrolled_payload(
    tls: TlsCarrier,
    prepared: PreparedPayloadSession,
    deadline: Instant,
) -> io::Result<EnrolledPayloadStream> {
    assemble(tls, prepared, Role::Acceptor, deadline)
}
fn assemble(
    tls: TlsCarrier,
    prepared: PreparedPayloadSession,
    role: Role,
    deadline: Instant,
) -> io::Result<EnrolledPayloadStream> {
    prepared.resources.check_current()?;
    prepared.authority.check().map_err(invalid)?;
    let caps = prepared.sender.profile().capabilities();
    let context = prepared.authority.context().clone();
    let channel = ObjectChannel::from_authenticated(
        tls,
        &prepared.authority,
        remaining(deadline)?,
        role,
        caps,
        caps,
    )
    .map_err(invalid)?;
    let duplex = Duplex::spawn(channel, prepared.sender, prepared.endpoint, context, role)
        .map_err(invalid)?;
    let mapped = MappedStream::from_duplex(duplex);
    for artifact in prepared.artifacts {
        remaining(deadline)?;
        let publication = match artifact {
            PayloadArtifact::Schema => mapped.seed_schema_until(deadline),
            PayloadArtifact::Checkpoint => mapped.seed_checkpoint_until(deadline),
            PayloadArtifact::Base(bytes) => mapped.seed_base_until(bytes, deadline),
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
    prepared.resources.check_current()?;
    Ok(EnrolledPayloadStream {
        inner: Arc::new(OwnedMappedPayload {
            stream: mapped,
            resources: prepared.resources,
        }),
    })
}
struct OwnedMappedPayload {
    // Declaration order is the cleanup barrier: join the exact owned reader
    // through the last mapped stream before store cleanup/resource release.
    stream: MappedStream,
    resources: PayloadResourcePermit,
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
    stores: Vec<OwnedPayloadStore>,
}

#[cfg(test)]
#[path = "spiralcore_payload/pool_close_tests.rs"]
mod pool_close_tests;
struct PoolInner {
    limits: PayloadResourceLimits,
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
        Self::new(limits, None)
    }
    pub fn from_parent(
        parent: Arc<dyn ParentPayloadReservation>,
        plan: &mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan,
        session: &str,
    ) -> io::Result<Self> {
        parent.authorize(plan, session)?;
        parent.check_current()?;
        Self::new(parent.limits(), Some(parent))
    }
    fn new(
        limits: PayloadResourceLimits,
        parent: Option<Arc<dyn ParentPayloadReservation>>,
    ) -> io::Result<Self> {
        limits.validate().map_err(invalid)?;
        Ok(Self {
            inner: Arc::new(PoolInner {
                limits,
                parent,
                ledger: std::sync::Mutex::new(PoolLedger {
                    closed: false,
                    used: PayloadPoolSnapshot::default(),
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
            && ledger.stores.is_empty())
    }
    pub fn reserve_profile(
        &self,
        resources: spiralcore_transfer::resource_profile::ResourceProfile,
    ) -> io::Result<PayloadResourcePermit> {
        let limits = resources.receiver_limits();
        let disk_bytes = limits
            .cache_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(1 << 20))
            .ok_or_else(|| invalid("store charge overflow"))?;
        let mut permit = self.reserve_charge(PayloadResourceCharge {
            resident_bytes: resources.operation_charge().map_err(invalid)?,
            disk_bytes,
        })?;
        permit.profile = Some(resources);
        Ok(permit)
    }
    pub fn reserve_shared_sender(
        &self,
        _mode: spiralcore_transfer::v1::ObjectMode,
    ) -> io::Result<PayloadResourcePermit> {
        self.reserve_profile(spiralcore_transfer::resource_profile::ResourceProfile::General)
    }
    fn reserve_charge(&self, charge: PayloadResourceCharge) -> io::Result<PayloadResourcePermit> {
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
        if active > self.inner.limits.max_active
            || resident > self.inner.limits.resident_bytes
            || disk > self.inner.limits.disk_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "aggregate payload pool full",
            ));
        }
        ledger.used.active = active;
        ledger.used.resident_charge = resident;
        ledger.used.disk_charge = disk;
        drop(ledger);
        Ok(PayloadResourcePermit {
            inner: self.inner.clone(),
            charge,
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
    store: Option<OwnedPayloadStore>,
    uncertain: bool,
    profile: Option<spiralcore_transfer::resource_profile::ResourceProfile>,
}
impl PayloadResourcePermit {
    fn with_owned_directory(
        mut self,
        path: std::path::PathBuf,
        directory: std::fs::File,
    ) -> io::Result<Self> {
        if self.store.is_some() {
            self.uncertain = true;
            return Err(invalid("payload store already attached"));
        }
        match OwnedPayloadStore::capture_directory(path, directory) {
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
        ledger.used.active = active;
        ledger.used.resident_charge = resident;
        ledger.used.disk_charge = disk;
    }
}

#[cfg(test)]
mod resource_pool_tests {
    use super::*;
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
