//! Actual child-context subdivision of an already retained parent partition.
//! Projected limits or config DTOs alone cannot construct this resource owner.

use crate::supervisor::{
    flowmux::{ParentPayloadReservation, PayloadResourceLimits, PayloadResourcePool},
    network_endpoint::{EgressMode, EndpointConfig},
};
use crate::telemetry_collector::TelemetryOnlyConfig;
use anyhow::{Context, Result, ensure};
use mvm_contract::policy::network_policy::PayloadMappingProfile;
use mvm_core::host_lifetime::EndpointStoreLocator;
use mvm_vmm::host::network_endpoint_spawn::{
    AdmittedNetworkPlan, InstalledEndpointChild, InstalledEndpointLease, InstalledTelemetryRecords,
};
pub use mvm_vmm::host::network_endpoint_spawn::{
    INSTALLED_BOOTSTRAP_MIN_BYTES, installed_endpoint_bootstrap_requirement,
};
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

mod audit;
pub(crate) use audit::InstalledAuditOrigin;
mod session_control;
pub(crate) use session_control::InstalledSessionControl;
mod auxiliary;
mod controller;
pub use controller::{
    OwnedEndpointRuntimeRequirements, OwnedNetworkRuntimeRequirements,
    owned_endpoint_runtime_requirements, owned_network_runtime_requirements,
    run_installed_endpoint,
};
#[cfg(test)]
#[path = "installed_endpoint/auxiliary_tests.rs"]
mod auxiliary_tests;
mod typed_model;
pub(crate) use auxiliary::InstalledEndpointComponentPermit;
use auxiliary::{AuxiliaryLedger, Component};

pub enum InstalledEndpointProgram {
    Network(Box<EndpointConfig>),
    TelemetryOnly(Box<TelemetryOnlyConfig>),
}

/// One prepared child. Cloning its pool shares the same ledger and authority.
pub struct InstalledEndpointResources {
    startup_deadline: Instant,
    program: InstalledEndpointProgram,
    lease: InstalledEndpointLease,
    pool: Option<PayloadResourcePool>,
    store: Option<Arc<HeldStore>>,
    auxiliary: Arc<AuxiliaryLedger>,
    records: Mutex<Option<InstalledTelemetryRecords>>,
    #[cfg(target_os = "linux")]
    verification_state: File,
}
impl InstalledEndpointResources {
    pub fn from_child(child: &mut InstalledEndpointChild) -> Result<Self> {
        let lease = child.lease();
        lease.check_current()?;
        typed_model::require_supported_model()?;
        let projection = lease.projection();
        ensure!(
            projection.limits.host_metadata_bytes
                >= mvm_vmm::host::network_endpoint_spawn::INSTALLED_BOOTSTRAP_MIN_BYTES,
            "installed endpoint bootstrap credit missing"
        );
        #[cfg(target_os = "linux")]
        let verification_state = child.with_verification_state(|state| Ok(state.try_clone()?))?;
        let config = child.take_raw_config()?;
        let bootstrap =
            mvm_vmm::host::network_endpoint_spawn::installed_endpoint_bootstrap_requirement(
                config.get(),
            )
            .map_err(|_| anyhow::anyhow!("invalid installed network configuration"))?;
        lease.check_current()?;
        let auxiliary = Arc::new(AuxiliaryLedger::new_with_bootstrap(
            projection.limits.host_stack_bytes,
            projection.limits.host_metadata_bytes,
            bootstrap,
        )?);
        if projection.profile == 1 {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct CollectorConfig {
                telemetry_only: TelemetryOnlyConfig,
            }
            let config = serde_json::from_str::<CollectorConfig>(config.get())
                .map_err(|_| anyhow::anyhow!("invalid installed collector configuration"))?
                .telemetry_only;
            ensure!(
                config.instance_id == projection.binding.vm_name && projection.store.is_none(),
                "installed collector binding differs"
            );
            let records = take_original_records(child, &lease, Some(&config.telemetry))?;
            lease.check_current()?;
            return Ok(Self {
                startup_deadline: child.startup_deadline(),
                program: InstalledEndpointProgram::TelemetryOnly(Box::new(config)),
                lease,
                pool: None,
                store: None,
                auxiliary,
                records: Mutex::new(records),
                #[cfg(target_os = "linux")]
                verification_state,
            });
        }
        ensure!(
            projection.profile == 2,
            "installed endpoint program unsupported"
        );
        let config: EndpointConfig = serde_json::from_str(config.get())
            .map_err(|_| anyhow::anyhow!("invalid installed network configuration"))?;
        let records = take_original_records(child, &lease, config.telemetry.as_ref())?;
        ensure!(
            config.egress_mode == EgressMode::FlowMux,
            "installed codec requires FlowMux"
        );
        ensure!(
            config.instance_id == projection.binding.vm_name,
            "installed endpoint VM differs"
        );
        let policy = config
            .network_policy
            .as_ref()
            .context("installed network policy missing")?;
        let mapping = policy
            .payload_mapping()
            .context("installed codec mapping missing")?;
        ensure!(
            mapping
                .peers()
                .iter()
                .all(|peer| peer.profile == PayloadMappingProfile::SpiralCoreObjectStreamSmallV1),
            "installed codec profile unsupported"
        );
        let plan = config
            .admitted_network_plan
            .as_ref()
            .context("installed admitted network facts missing")?;
        plan.validate_for(policy, &config.tenant_id, &config.instance_id)?;
        let session = config
            .flowmux_identity
            .as_ref()
            .context("installed guest identity missing")?
            .session_id
            .clone();
        let (retained_records, retained_sidecars) = if let Some(telemetry) = &config.telemetry {
            let reserved = mvm_vmm::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP;
            ensure!(
                telemetry.records_byte_cap <= reserved,
                "installed telemetry cap exceeds retained reservation"
            );
            // The versioned parent profile reserves fixed R independently of
            // a smaller sink cap. Config data cannot return that debt to codecs.
            (
                reserved,
                mvm_core::runtime_state_protection::INSTALLED_TELEMETRY_SIDECAR_BYTES,
            )
        } else {
            (0, 0)
        };
        let limits = PayloadResourceLimits {
            max_active: projection.limits.max_streams,
            resident_bytes: projection.limits.host_codec_bytes,
            disk_bytes: projection
                .limits
                .cache_disk_bytes
                // The SAME cache quota includes retained telemetry. Those
                // bytes never become disposable-codec credit or Drained refund.
                .checked_sub(retained_records)
                .and_then(|bytes| bytes.checked_sub(retained_sidecars))
                .context("installed retained telemetry disk credit missing")?
                .checked_add(projection.limits.staging_disk_bytes)
                .context("installed payload disk limit overflow")?,
        }
        .validate()?;
        let locator = projection
            .store
            .as_ref()
            .context("installed codec original store missing")?;
        let store = Arc::new(HeldStore::capture(locator.clone())?);
        let parent = Arc::new(ChildPoolParent {
            lease: lease.clone(),
            plan: plan.clone(),
            session: session.clone(),
            limits,
            store: store.clone(),
        });
        let pool = PayloadResourcePool::from_installed_parent(
            parent, plan, &session, projection.limits.host_carrier_bytes,
        )?;
        Ok(Self {
            startup_deadline: child.startup_deadline(),
            program: InstalledEndpointProgram::Network(Box::new(config)),
            lease,
            pool: Some(pool),
            store: Some(store),
            auxiliary,
            records: Mutex::new(records),
            #[cfg(target_os = "linux")]
            verification_state,
        })
    }
    /// Apply the canonical confinement with only the original state's file and
    /// this child's captured store added. Any error requires process exit.
    #[cfg(target_os = "linux")]
    pub fn confine(&self, spec: &crate::jailer::ConfinementSpec) -> Result<()> {
        self.confine_with_runtime_state(spec, None)
    }

    pub(crate) fn open_original_state_directory(&self) -> Result<File> {
        match self.records.lock() {
            Ok(records) => records
                .as_ref()
                .context("installed original records writer unavailable")?
                .open_original_state_directory(),
            Err(_) => {
                self.lease.fence();
                anyhow::bail!("installed original records writer poisoned")
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn confine_with_runtime_state(
        &self,
        spec: &crate::jailer::ConfinementSpec,
        runtime_state: Option<&File>,
    ) -> Result<()> {
        self.lease.check_current()?;
        if let Some(store) = &self.store {
            store.check_current()?;
        }
        // Only the actual inherited opaque writer selects its read-only ACL
        // query shape. This private filter selection is not an FD/DTO grant.
        let records = self
            .records
            .lock()
            .map_err(|_| {
                self.lease.fence();
                anyhow::anyhow!("installed records ownership poisoned")
            })?
            .is_some();
        crate::jailer::confine_self_with_owned_files(
            spec,
            &self.verification_state,
            self.store.as_ref().map(|store| &store.directory),
            runtime_state,
            records,
        )?;
        self.lease.check_current()?;
        if let Some(store) = &self.store {
            store.check_current()?;
        }
        Ok(())
    }
    /// Captured location data only; the pool retains the actual current checker.
    pub fn store_locator(&self) -> Option<&EndpointStoreLocator> {
        self.store.as_ref().map(|store| &store.locator)
    }
    pub(crate) fn network_config(&self) -> Option<&EndpointConfig> {
        match &self.program {
            InstalledEndpointProgram::Network(config) => Some(config),
            InstalledEndpointProgram::TelemetryOnly(_) => None,
        }
    }
    pub(crate) fn payload_pool(&self) -> Option<&PayloadResourcePool> {
        self.pool.as_ref()
    }
    pub(crate) fn lease(&self) -> &InstalledEndpointLease {
        &self.lease
    }
    /// Start only the collector selected by this original authenticated child.
    /// All allocations/threads follow the same one-shot auxiliary subdivision.
    pub(crate) fn start_owned_collector(
        &self,
        deadline: Instant,
        anchor: File,
        state_directory: Arc<File>,
    ) -> Result<Option<crate::telemetry_collector::OwnedEmbeddedCollector>> {
        use crate::telemetry_collector::{
            OwnedCollectorStart, owned_collector_requirements, owned_scanner_requested_bytes,
            start_owned,
        };
        let deadline = deadline.min(self.startup_deadline);
        ensure!(
            Instant::now() < deadline,
            "installed collector startup expired"
        );
        self.lease.check_current()?;
        let (vm, config, redaction) = match &self.program {
            InstalledEndpointProgram::TelemetryOnly(config) => (
                config.instance_id.as_str(),
                &config.telemetry,
                &config.redaction,
            ),
            InstalledEndpointProgram::Network(config) => {
                let Some(telemetry) = &config.telemetry else {
                    return Ok(None);
                };
                (config.instance_id.as_str(), telemetry, &config.redaction)
            }
        };
        ensure!(
            self.lease.projection().limits.cache_disk_bytes >= config.records_byte_cap,
            "installed retained telemetry disk credit missing"
        );
        let facts = owned_collector_requirements()?;
        let metadata = facts
            .known_metadata_bytes
            .checked_add(owned_scanner_requested_bytes(redaction)?)
            .context("installed collector requested workspace overflow")?;
        let permit =
            self.claim_component(Component::Collector, facts.known_rust_stack_bytes, metadata)?;
        let records = match self.records.lock() {
            Ok(mut records) => records
                .take()
                .context("installed original records writer unavailable")?,
            Err(_) => {
                self.lease.fence();
                anyhow::bail!("installed original records writer poisoned")
            }
        };
        records.check_for(&self.lease, &config.state_dir)?;
        ensure!(
            Instant::now() < deadline,
            "installed collector startup expired"
        );
        let fingerprints = match &self.program {
            InstalledEndpointProgram::Network(config) => {
                crate::supervisor::network_endpoint::fingerprint_bound_secrets(config)?
            }
            InstalledEndpointProgram::TelemetryOnly(_) => Vec::new(),
        };
        Ok(Some(start_owned(OwnedCollectorStart {
            vm,
            config,
            redaction,
            fingerprints,
            permit,
            records,
            anchor,
            state_directory,
            audit: self.lease.audit()?,
            deadline,
        })?))
    }
    pub(crate) fn claim_relay_group(
        &self,
        stack: u64,
        metadata: u64,
    ) -> io::Result<InstalledEndpointComponentPermit> {
        self.claim_component(Component::Relay, stack, metadata)
    }
    pub(crate) fn claim_codec_readers(
        &self,
        stack: u64,
        metadata: u64,
    ) -> io::Result<InstalledEndpointComponentPermit> {
        self.claim_component(Component::CodecReaders, stack, metadata)
    }
    fn claim_component(
        &self,
        component: Component,
        stack: u64,
        metadata: u64,
    ) -> io::Result<InstalledEndpointComponentPermit> {
        self.auxiliary.reserve(component, stack, metadata, || {
            self.lease.check_current().map_err(invalid)?;
            if !matches!(&self.program, InstalledEndpointProgram::Network(_))
                && !matches!(component, Component::Collector | Component::Controller)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "collector has no TCP component",
                ));
            }
            Ok(())
        })?;
        Ok(InstalledEndpointComponentPermit::new(
            self.lease.clone(),
            self.auxiliary.clone(),
        ))
    }
    pub fn into_parts(
        self,
    ) -> (
        InstalledEndpointProgram,
        InstalledEndpointLease,
        Option<PayloadResourcePool>,
    ) {
        (self.program, self.lease, self.pool)
    }
}

/// Publish one bounded installed status file in the held state directory.
pub(crate) fn publish_runtime_sidecar(
    directory: &File,
    name: &'static str,
    scratch: &'static str,
    bytes: &[u8],
) -> io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};
    use std::io::Write as _;

    let descriptor = openat(
        directory,
        scratch,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    let mut file = File::from(descriptor);
    let result = file.write_all(bytes).and_then(|()| {
        renameat(directory, scratch, directory, name).map_err(Into::into)
    });
    if result.is_err() {
        let _ = unlinkat(directory, scratch, AtFlags::empty());
    }
    result
}

fn take_original_records(
    child: &mut InstalledEndpointChild,
    lease: &InstalledEndpointLease,
    telemetry: Option<&crate::telemetry_collector::TelemetryEmbedConfig>,
) -> Result<Option<InstalledTelemetryRecords>> {
    if telemetry.is_none() {
        return Ok(None);
    }
    let records = child.take_telemetry_records()?;
    match (telemetry, records) {
        (None, None) => Ok(None),
        (Some(config), Some(records)) => {
            let retained = mvm_vmm::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP;
            ensure!(
                config.records_byte_cap <= retained,
                "installed retained record cap unsupported"
            );
            ensure!(
                lease
                    .projection()
                    .limits
                    .cache_disk_bytes
                    .checked_sub(retained)
                    .and_then(|bytes| bytes.checked_sub(
                        mvm_core::runtime_state_protection::INSTALLED_TELEMETRY_SIDECAR_BYTES
                    ))
                    .is_some(),
                "installed retained telemetry disk credit missing"
            );
            records.check_for(lease, &config.state_dir)?;
            Ok(Some(records))
        }
        _ => anyhow::bail!("installed original records writer selection differs"),
    }
}

#[derive(Debug)]
struct HeldStore {
    locator: EndpointStoreLocator,
    directory: File,
    fenced: AtomicBool,
}
impl HeldStore {
    fn capture(locator: EndpointStoreLocator) -> Result<Self> {
        let directory = mvm_vmm::host::restore_image::open_trusted_dir(&locator.path)
            .context("open original installed codec store")?;
        let held = Self {
            locator,
            directory,
            fenced: AtomicBool::new(false),
        };
        held.check_current()?;
        Ok(held)
    }
    fn check_current(&self) -> io::Result<()> {
        if self.fenced.load(Ordering::Acquire) {
            return Err(invalid("installed codec store authority fenced"));
        }
        let result = self.check_identity();
        if result.is_err() {
            self.fenced.store(true, Ordering::Release);
        }
        result
    }
    fn check_identity(&self) -> io::Result<()> {
        let held = self.directory.metadata()?;
        let current = std::fs::symlink_metadata(&self.locator.path)?;
        mvm_core::private_fs::require_current_owner(&current)?;
        if !current.is_dir()
            || current.file_type().is_symlink()
            || current.mode() & 0o7777 != 0o700
            || (held.dev(), held.ino()) != (self.locator.device, self.locator.inode)
            || (current.dev(), current.ino()) != (held.dev(), held.ino())
        {
            return Err(invalid("installed codec store identity differs"));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ChildPoolParent {
    lease: InstalledEndpointLease,
    plan: AdmittedNetworkPlan,
    session: String,
    limits: PayloadResourceLimits,
    store: Arc<HeldStore>,
}
impl ParentPayloadReservation for ChildPoolParent {
    fn limits(&self) -> PayloadResourceLimits {
        self.limits
    }
    fn authorize(&self, plan: &AdmittedNetworkPlan, session: &str) -> io::Result<()> {
        self.lease.claim_payload_pool().map_err(invalid)?;
        let projection = self.lease.projection();
        if plan != &self.plan
            || session != self.session
            || session != hex::encode(projection.session)
            || plan.plan_id.0 != projection.admitted_plan_id
            || plan.instance_id != projection.binding.vm_name
            || self.store.locator.session != projection.session
        {
            return Err(invalid("installed payload original scope differs"));
        }
        self.check_current()
    }
    fn check_current(&self) -> io::Result<()> {
        self.lease.check_current().map_err(invalid)?;
        self.store.check_current()
    }
}
fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error.to_string())
}
