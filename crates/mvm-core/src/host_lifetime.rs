//! Original installation resources retained through one canonical native launch.
//! File exclusion and retained objects are not signed-plan or parent-grant authority.

use crate::{
    plan::{ExecutionPlan, Nonce, PlanArtifact, PlanId},
    vm_backend::{BackendKind, VmStartConfig},
};
use anyhow::{Context, Result, ensure};
use rustix::{
    fs::{AtFlags, FlockOperation, Mode, OFlags},
    io::FdFlags,
};
use sha2::{Digest, Sha256};
use std::{
    any::Any,
    fmt,
    fs::File,
    io::Read,
    num::NonZeroU64,
    os::unix::fs::MetadataExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

mod endpoint;
pub use endpoint::{
    EndpointPartitionGuard, EndpointPartitionLimits, EndpointPartitionProjection,
    EndpointStoreLocator, PreparedEndpointHandoff, PreparedEndpointPartition,
};

/// A refusal index only. Neither its contents nor its absence proves VM exit.
pub const INSTALLED_NATIVE_CUSTODY_MARKER: &str = ".installed-native-custody";

/// Compatibility name-based lifecycle paths cannot act on installed custody.
/// Only the original native owner can establish a positive retirement barrier.
pub fn require_no_installed_native(vm_name: &str) -> Result<()> {
    crate::naming::validate_vm_name(vm_name)?;
    match std::fs::symlink_metadata(
        crate::config::vm_state_dir(vm_name).join(INSTALLED_NATIVE_CUSTODY_MARKER),
    ) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect installed native refusal marker"),
        Ok(_) => anyhow::bail!(
            "original installed native owner required; no name-based lifecycle fallback"
        ),
    }
}

/// Bounded continuity expectation from the original installation owner.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLeaseExpectation {
    pub state_name: String,
    pub state_bytes: u16,
    pub state_sha256: [u8; 32],
    pub absent_names: [String; 2],
}

/// Original shared holder descriptions. Drop never explicitly unlocks a duplicate.
#[derive(Debug)]
pub struct PreparedHostLifetimeLease {
    directory: File,
    holder: File,
    expected: HostLeaseExpectation,
    directory_id: (u64, u64),
    holder_id: (u64, u64),
    uid: u32,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

impl PreparedHostLifetimeLease {
    pub fn bind(directory: File, holder: File, expected: HostLeaseExpectation) -> Result<Self> {
        ensure!(
            valid_name(&expected.state_name)
                && expected
                    .absent_names
                    .iter()
                    .all(|name| valid_name(name) && name != &expected.state_name)
                && expected.absent_names[0] != expected.absent_names[1]
                && (1..=4096).contains(&expected.state_bytes),
            "invalid host lifetime expectation"
        );
        let directory_meta = directory
            .metadata()
            .context("host lifetime directory metadata")?;
        let holder_meta = holder.metadata().context("host lifetime holder metadata")?;
        let uid = rustix::process::geteuid().as_raw();
        ensure!(
            directory_meta.is_dir()
                && directory_meta.uid() == uid
                && directory_meta.mode() & 0o7777 == 0o700
                && holder_meta.is_file()
                && holder_meta.uid() == uid
                && holder_meta.mode() & 0o7777 == 0o600
                && holder_meta.nlink() == 1,
            "host lifetime requires private original directory and regular holder"
        );
        for file in [&directory, &holder] {
            let flags = rustix::io::fcntl_getfd(file)?;
            rustix::io::fcntl_setfd(file, flags | FdFlags::CLOEXEC)?;
        }
        rustix::fs::flock(&holder, FlockOperation::NonBlockingLockShared)
            .context("host lifetime shared holder refused")?;
        Ok(Self {
            directory,
            holder,
            expected,
            uid,
            directory_id: (directory_meta.dev(), directory_meta.ino()),
            holder_id: (holder_meta.dev(), holder_meta.ino()),
        })
    }

    pub fn directory(&self) -> &File {
        &self.directory
    }
    pub fn holder(&self) -> &File {
        &self.holder
    }
    pub fn expectation(&self) -> &HostLeaseExpectation {
        &self.expected
    }
    pub fn directory_object_id(&self) -> (u64, u64) {
        self.directory_id
    }
    pub fn holder_object_id(&self) -> (u64, u64) {
        self.holder_id
    }
    pub fn owner_uid(&self) -> u32 {
        self.uid
    }

    /// Read only the retained directory, with bounded no-follow state and marker checks.
    pub fn verify_current(&self) -> Result<()> {
        self.with_verification_state(|_| Ok(()))
    }

    /// Borrow the readonly state file only after the same original-state checks.
    /// No holder or directory descriptor is supplied to the callback.
    pub fn with_verification_state<T>(
        &self,
        operation: impl FnOnce(&File) -> Result<T>,
    ) -> Result<T> {
        let directory = self.directory.metadata()?;
        let holder = self.holder.metadata()?;
        ensure!(
            (directory.dev(), directory.ino()) == self.directory_id
                && directory.is_dir()
                && directory.uid() == self.uid
                && directory.mode() & 0o7777 == 0o700
                && (holder.dev(), holder.ino()) == self.holder_id
                && holder.is_file()
                && holder.uid() == self.uid
                && holder.mode() & 0o7777 == 0o600
                && holder.nlink() == 1,
            "host lifetime descriptor identity changed"
        );
        for name in &self.expected.absent_names {
            match rustix::fs::statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                Ok(_) => anyhow::bail!("host lifetime publication is unresolved"),
                Err(error) => return Err(error).context("inspect host lifetime marker"),
            }
        }
        let mut file = File::from(rustix::fs::openat(
            &self.directory,
            self.expected.state_name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == self.uid
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.len() == u64::from(self.expected.state_bytes),
            "host lifetime state metadata differs"
        );
        let mut bytes = [0; 4097];
        let limit = usize::from(self.expected.state_bytes);
        file.read_exact(&mut bytes[..limit])?;
        ensure!(
            file.read(&mut bytes[limit..limit + 1])? == 0
                && <[u8; 32]>::from(Sha256::digest(&bytes[..limit])) == self.expected.state_sha256,
            "host lifetime original state differs"
        );
        operation(&file)
    }

    /// Duplicate the SAME open descriptions for an explicit native handoff.
    pub fn duplicate(&self) -> Result<Self> {
        self.verify_current()?;
        Ok(Self {
            directory: self.directory.try_clone()?,
            holder: self.holder.try_clone()?,
            expected: self.expected.clone(),
            directory_id: self.directory_id,
            holder_id: self.holder_id,
            uid: self.uid,
        })
    }
}

/// Local continuity facts. These do not construct admission or a budget grant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLaunchBinding {
    pub installation: [u8; 32],
    pub profile: [u8; 32],
    pub generation: u64,
    pub grant_serial: u64,
    pub vm_name: String,
    pub backend: BackendKind,
    pub cpus: u32,
    pub memory_mib: u32,
}

pub struct HostLifetimeInputs {
    pub directory: File,
    pub holder: File,
    pub expected: HostLeaseExpectation,
    pub binding: HostLaunchBinding,
}

/// Trusted current parent resource admission, supplied only by installed DI.
/// Implementations retain the actual original reservation, not a quota DTO.
pub trait CoreCurrentParentPermit: Send + Sync {
    fn check_current(&self, binding: &HostLaunchBinding) -> Result<()>;

    /// Enter the already reserved portable verification and snapshot workspace.
    /// The callback only changes accounting state. The original parent retains
    /// responsibility for its reservation on refusal, panic, or abandoned startup.
    fn begin_startup_workspace(&self, _binding: &HostLaunchBinding) -> Result<()> {
        anyhow::bail!("original parent startup workspace unavailable")
    }

    /// Complete this phase on the same reservation, after its last use.
    fn complete_startup_workspace(&self, _binding: &HostLaunchBinding) -> Result<()> {
        anyhow::bail!("original parent startup workspace completion unavailable")
    }

    fn prepare_endpoint_partition(
        &self,
        _binding: &HostLaunchBinding,
    ) -> Result<PreparedEndpointPartition> {
        anyhow::bail!("original parent endpoint partition provider unavailable")
    }
}

pub struct PreparedHostLifetime {
    lease: PreparedHostLifetimeLease,
    binding: HostLaunchBinding,
    parent_owner: Box<dyn Any + Send + Sync>,
    portable_archive: Option<(PlanArtifact, NonZeroU64)>,
}

impl PreparedHostLifetime {
    pub fn binding(&self) -> &HostLaunchBinding {
        &self.binding
    }

    /// Cleanup identity only: equal metadata or a different erasure is not the
    /// same original Arc. This exports neither ownership nor launch permission.
    pub fn retains_parent_owner<T: Send + Sync + 'static>(&self, original: &Arc<T>) -> bool {
        self.parent_owner
            .downcast_ref::<Arc<T>>()
            .is_some_and(|held| Arc::ptr_eq(held, original))
    }

    /// Retain a real parent owner; the erased value alone proves no accounting.
    pub fn bind(
        inputs: HostLifetimeInputs,
        parent_owner: impl Send + Sync + 'static,
    ) -> Result<Self> {
        crate::naming::validate_vm_name(&inputs.binding.vm_name)?;
        ensure!(
            inputs.binding.generation > 0
                && inputs.binding.grant_serial > 0
                && inputs.binding.cpus > 0
                && inputs.binding.memory_mib > 0,
            "invalid host lifetime binding"
        );
        let lease =
            PreparedHostLifetimeLease::bind(inputs.directory, inputs.holder, inputs.expected)?;
        lease.verify_current()?;
        Ok(Self {
            lease,
            binding: inputs.binding,
            parent_owner: Box::new(parent_owner),
            portable_archive: None,
        })
    }

    /// Record the exact archive covered by the original parent's reservation.
    /// The installed parent still checks that reservation against this owner.
    pub fn with_portable_archive(mut self, pin: PlanArtifact, bytes: NonZeroU64) -> Result<Self> {
        ensure!(
            self.portable_archive.is_none(),
            "original portable archive already selected"
        );
        self.portable_archive = Some((pin, bytes));
        Ok(self)
    }

    pub fn into_anchor(self) -> Arc<HostLifetimeAnchor> {
        Arc::new(HostLifetimeAnchor {
            lease: self.lease,
            binding: self.binding,
            _parent_owner: self.parent_owner,
            portable_archive: self.portable_archive,
            admitted: Mutex::new(None),
            current_parent: Mutex::new(None),
            native_claimed: AtomicBool::new(false),
            endpoint_claimed: AtomicBool::new(false),
            startup_claimed: AtomicBool::new(false),
            startup_complete: AtomicBool::new(false),
        })
    }
}

#[derive(PartialEq)]
struct AdmissionBinding {
    plan_id: PlanId,
    nonce: Nonce,
    body_sha256: [u8; 32],
    direct: Option<DirectNetworkBinding>,
    legacy_portable: bool,
}

#[derive(PartialEq)]
struct DirectNetworkBinding {
    plan: crate::policy::direct_plan::AdmittedNetworkPlan,
    limits: crate::plan::NetworkLimits,
    redaction: crate::policy::RedactionPolicy,
}

impl DirectNetworkBinding {
    fn from_plan(config: &VmStartConfig, plan: &ExecutionPlan) -> Result<Option<Self>> {
        if config.network_policy.payload_mapping().is_none() {
            return Ok(None);
        }
        ensure!(plan.ingress.is_empty() && plan.secrets.is_empty(),
            "selected direct endpoint does not serve requested ingress or secrets");
        Ok(Some(Self {
            plan: crate::policy::direct_plan::AdmittedNetworkPlan::from_plan(plan, &config.name, &config.network_policy)?,
            limits: plan.effective_network_limits()?,
            redaction: plan.redaction.clone(),
        }))
    }
}

/// Shared one-shot owner, never a serializable permission or exit receipt.
pub struct HostLifetimeAnchor {
    lease: PreparedHostLifetimeLease,
    binding: HostLaunchBinding,
    _parent_owner: Box<dyn Any + Send + Sync>,
    portable_archive: Option<(PlanArtifact, NonZeroU64)>,
    admitted: Mutex<Option<AdmissionBinding>>,
    current_parent: Mutex<Option<Arc<dyn CoreCurrentParentPermit>>>,
    native_claimed: AtomicBool,
    endpoint_claimed: AtomicBool,
    startup_claimed: AtomicBool,
    startup_complete: AtomicBool,
}

/// Linear custody of the original startup workspace. Dropping it leaves the
/// original parent responsible for cleanup and does not acknowledge completion.
#[must_use]
pub struct RuntimeStartupWorkspace {
    owner: Arc<HostLifetimeAnchor>,
    permit: Arc<dyn CoreCurrentParentPermit>,
}

impl RuntimeStartupWorkspace {
    pub fn complete(self) -> Result<()> {
        self.owner.verify_current()?;
        self.permit.check_current(&self.owner.binding)?;
        self.permit
            .complete_startup_workspace(&self.owner.binding)?;
        self.owner.startup_complete.store(true, Ordering::Release);
        Ok(())
    }
}

impl fmt::Debug for HostLifetimeAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostLifetimeAnchor")
            .field("binding", &self.binding)
            .field(
                "native_claimed",
                &self.native_claimed.load(Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl HostLifetimeAnchor {
    /// Match retained native disposal evidence after the grant has closed.
    /// Freshness is a launch/dispatch check. Disposal compares held objects.
    pub fn check_original_lease(&self, lease: &PreparedHostLifetimeLease) -> Result<()> {
        ensure!(self.lease.directory_object_id() == lease.directory_object_id()
            && self.lease.holder_object_id() == lease.holder_object_id()
            && self.lease.owner_uid() == lease.owner_uid()
            && self.lease.expectation() == lease.expectation(), "native disposal belongs to a different original holder");
        Ok(())
    }

    /// The archive length fixed by the original preparation for this pin.
    pub fn portable_archive_bytes(&self, pin: &PlanArtifact) -> Result<NonZeroU64> {
        let (original, bytes) = self
            .portable_archive
            .as_ref()
            .context("original portable archive length missing")?;
        ensure!(
            original == pin,
            "portable archive differs from the original quote"
        );
        Ok(*bytes)
    }

    /// Reserve from the same actual parent, then duplicate the original SH
    /// description. Returned projections never supply a replacement authority.
    pub fn prepare_endpoint_handoff(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<PreparedEndpointHandoff> {
        self.check_parent_current(config, backend)?;
        ensure!(
            !self.endpoint_claimed.load(Ordering::Acquire),
            "original endpoint partition already handed off"
        );
        let parent = self
            .current_parent
            .lock()
            .map_err(|_| anyhow::anyhow!("host parent binding poisoned"))?
            .as_ref()
            .cloned()
            .context("original parent resource permit missing")?;
        let partition = parent.prepare_endpoint_partition(&self.binding)?;
        let admitted_plan_id = self
            .admitted
            .lock()
            .map_err(|_| anyhow::anyhow!("host lifetime admission poisoned"))?
            .as_ref()
            .context("original admission missing")?
            .plan_id
            .0
            .clone();
        ensure!(
            partition.projection().binding == self.binding
                && partition.projection().admitted_plan_id == admitted_plan_id,
            "endpoint partition differs from original admission"
        );
        partition.check_current()?;
        let holder = self.lease.duplicate()?;
        self.check_parent_current(config, backend)?;
        partition.check_current()?;
        self.endpoint_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("original endpoint partition already handed off"))?;
        Ok(PreparedEndpointHandoff {
            partition,
            holder,
            anchor: Arc::clone(self),
        })
    }

    pub fn binding(&self) -> &HostLaunchBinding {
        &self.binding
    }
    pub fn verify_current(&self) -> Result<()> {
        self.lease.verify_current()
    }

    pub fn bind_to_config(self: &Arc<Self>, config: &mut VmStartConfig) -> Result<()> {
        ensure!(
            config
                .host_lifetime
                .as_ref()
                .is_none_or(|owner| Arc::ptr_eq(owner, self)),
            "host lifetime owner substituted"
        );
        ensure!(
            !self.native_claimed.load(Ordering::Acquire),
            "host lifetime already claimed"
        );
        self.verify_shape(config, self.binding.backend)?;
        self.verify_current()?;
        config.host_lifetime = Some(Arc::clone(self));
        Ok(())
    }

    fn verify_shape(&self, config: &VmStartConfig, backend: BackendKind) -> Result<()> {
        ensure!(
            config.name == self.binding.vm_name
                && backend == self.binding.backend
                && config.cpus > 0
                && config.cpus <= self.binding.cpus
                && config.memory_mib > 0
                && config.memory_mib <= self.binding.memory_mib
                && config.warm_pool_size == 0,
            "host lifetime launch shape differs"
        );
        Ok(())
    }

    pub fn verify_config(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<()> {
        ensure!(
            config
                .host_lifetime
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, self)),
            "original host lifetime owner missing"
        );
        self.verify_shape(config, backend)?;
        self.verify_current()
    }

    /// Continuity check at the canonical opaque-admission boundary, not re-admission.
    pub fn bind_admitted(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
        plan: &ExecutionPlan,
    ) -> Result<()> {
        self.verify_config(config, backend)?;
        ensure!(
            plan.resources.cpus == config.cpus
                && plan.resources.mem_mib == u64::from(config.memory_mib),
            "host lifetime differs from original admitted resources"
        );
        let wanted = AdmissionBinding {
            plan_id: plan.plan_id.clone(),
            nonce: plan.nonce.clone(),
            body_sha256: Sha256::digest(serde_jcs::to_vec(plan)?).into(),
            direct: DirectNetworkBinding::from_plan(config, plan)?,
            legacy_portable: config.legacy_portable_runtime.is_some(),
        };
        ensure!(
            self.projected_admission(config)? == wanted,
            "launch projection differs from original admitted plan"
        );
        let mut admitted = self
            .admitted
            .lock()
            .map_err(|_| anyhow::anyhow!("host lifetime admission poisoned"))?;
        ensure!(
            !self.native_claimed.load(Ordering::Acquire),
            "host lifetime already claimed"
        );
        ensure!(
            admitted.as_ref().is_none_or(|prior| prior == &wanted),
            "host lifetime admission substituted"
        );
        *admitted = Some(wanted);
        Ok(())
    }

    fn projected_admission(&self, config: &VmStartConfig) -> Result<AdmissionBinding> {
        let encoded = config
            .plan_json
            .as_deref()
            .context("host lifetime signed plan missing")?;
        let plan = crate::plan::plan_from_admitted_json(encoded)
            .context("host lifetime original plan projection invalid")?;
        if let Some(proof) = &config.legacy_portable_runtime {
            ensure!(
                plan.bundle.as_ref() == Some(&proof.pin),
                "portable runtime differs from the signed bundle"
            );
            self.portable_archive_bytes(&proof.pin)?;
        }
        Ok(AdmissionBinding {
            plan_id: plan.plan_id.clone(),
            nonce: plan.nonce.clone(),
            body_sha256: Sha256::digest(serde_jcs::to_vec(&plan)?).into(),
            direct: DirectNetworkBinding::from_plan(config, &plan)?,
            legacy_portable: config.legacy_portable_runtime.is_some(),
        })
    }

    /// Compare the original erased owner before a current-parent permit exists.
    /// This exports no owner, descriptor, reservation or admission authority.
    pub fn retains_parent_owner<T: Send + Sync + 'static>(&self, original: &Arc<T>) -> bool {
        self._parent_owner
            .downcast_ref::<Arc<T>>()
            .is_some_and(|held| Arc::ptr_eq(held, original))
    }

    /// Compare the installed original parent object without exporting it.
    /// This is cleanup identity, not a fresh launch authorization check: a
    /// closed/revoked parent may still need to acknowledge positive retirement.
    pub fn retains_parent_permit(&self, permit: &Arc<dyn CoreCurrentParentPermit>) -> bool {
        self.current_parent.lock().ok().is_some_and(|parent| {
            parent
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, permit))
        })
    }

    /// Install one original parent after canonical opaque admission. It cannot
    /// be replaced to refresh authority or resource lifetime.
    pub fn bind_parent_permit(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
        permit: Arc<dyn CoreCurrentParentPermit>,
    ) -> Result<()> {
        self.verify_config(config, backend)?;
        self.verify_admitted_config(config)?;
        ensure!(
            !self.native_claimed.load(Ordering::Acquire),
            "native lifetime already claimed"
        );
        permit.check_current(&self.binding)?;
        let mut parent = self
            .current_parent
            .lock()
            .map_err(|_| anyhow::anyhow!("host parent binding poisoned"))?;
        ensure!(
            parent.is_none(),
            "original host parent permit already installed"
        );
        *parent = Some(permit);
        Ok(())
    }

    fn verify_admitted_config(&self, config: &VmStartConfig) -> Result<()> {
        let wanted = self.projected_admission(config)?;
        let admitted = self
            .admitted
            .lock()
            .map_err(|_| anyhow::anyhow!("host lifetime admission poisoned"))?;
        ensure!(
            admitted.as_ref() == Some(&wanted),
            "host lifetime original admission missing or changed"
        );
        Ok(())
    }

    /// Fresh current-parent check before native claim and before activation.
    /// No callback or filesystem I/O runs while the parent/admission mutex is held.
    pub fn check_parent_current(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<()> {
        self.current_parent_permit(config, backend)?
            .check_current(&self.binding)
    }

    fn current_parent_permit(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<Arc<dyn CoreCurrentParentPermit>> {
        self.verify_config(config, backend)?;
        self.verify_admitted_config(config)?;
        self.current_parent
            .lock()
            .map_err(|_| anyhow::anyhow!("host parent binding poisoned"))?
            .as_ref()
            .cloned()
            .context("original parent resource permit missing")
    }

    /// Start the original parent's one-shot workspace after opaque admission.
    /// A failed callback still consumes the attempt because it may have acted.
    pub fn begin_startup_workspace(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<RuntimeStartupWorkspace> {
        ensure!(
            config.legacy_portable_runtime.is_some(),
            "original launch has no portable runtime selection"
        );
        let permit = self.current_parent_permit(config, backend)?;
        permit.check_current(&self.binding)?;
        ensure!(
            !self.native_claimed.load(Ordering::Acquire),
            "native lifetime already claimed"
        );
        self.startup_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("original startup workspace already claimed"))?;
        permit.begin_startup_workspace(&self.binding)?;
        Ok(RuntimeStartupWorkspace {
            owner: Arc::clone(self),
            permit,
        })
    }

    /// Exactly one backend handoff after the original admission was bound.
    pub fn claim_for_native(
        self: &Arc<Self>,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<PreparedHostLifetimeLease> {
        self.check_parent_current(config, backend)?;
        ensure!(
            config.legacy_portable_runtime.is_none()
                || self.startup_complete.load(Ordering::Acquire),
            "original startup workspace did not complete"
        );
        let lease = self.lease.duplicate()?;
        ensure!(
            self.native_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "host lifetime already claimed"
        );
        Ok(lease)
    }
}

mod native_stack;
pub use native_stack::{NativeThreadStackTerms, native_thread_stack_terms};
