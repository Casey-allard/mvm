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
    AdmittedNetworkPlan, InstalledEndpointChild, InstalledEndpointLease,
};
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub enum InstalledEndpointProgram {
    Network(EndpointConfig),
    TelemetryOnly(TelemetryOnlyConfig),
}

/// One prepared child. Cloning its pool shares the same ledger and authority.
pub struct InstalledEndpointResources {
    program: InstalledEndpointProgram,
    lease: InstalledEndpointLease,
    pool: Option<PayloadResourcePool>,
    store: Option<Arc<HeldStore>>,
    #[cfg(target_os = "linux")]
    verification_state: File,
}
impl InstalledEndpointResources {
    pub fn from_child(child: &mut InstalledEndpointChild) -> Result<Self> {
        let lease = child.lease();
        lease.check_current()?;
        #[cfg(target_os = "linux")]
        let verification_state = child.with_verification_state(|state| Ok(state.try_clone()?))?;
        let config = child.take_config()?;
        let projection = lease.projection();
        if projection.profile == 1 {
            let serde_json::Value::Object(mut wrapper) = config else {
                anyhow::bail!("installed collector config is not an object")
            };
            ensure!(wrapper.len() == 1, "installed collector wrapper differs");
            let config: TelemetryOnlyConfig = serde_json::from_value(
                wrapper
                    .remove("telemetry_only")
                    .context("installed collector config missing")?,
            )?;
            ensure!(
                config.instance_id == projection.binding.vm_name && projection.store.is_none(),
                "installed collector binding differs"
            );
            lease.check_current()?;
            return Ok(Self {
                program: InstalledEndpointProgram::TelemetryOnly(config),
                lease,
                pool: None,
                store: None,
                #[cfg(target_os = "linux")]
                verification_state,
            });
        }
        ensure!(
            projection.profile == 2,
            "installed endpoint program unsupported"
        );
        let config: EndpointConfig = serde_json::from_value(config)?;
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
        let limits = PayloadResourceLimits {
            max_active: projection.limits.max_streams,
            resident_bytes: projection.limits.host_codec_bytes,
            disk_bytes: projection
                .limits
                .cache_disk_bytes
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
            parent,
            plan,
            &session,
            projection.limits.host_carrier_bytes,
        )?;
        Ok(Self {
            program: InstalledEndpointProgram::Network(config),
            lease,
            pool: Some(pool),
            store: Some(store),
            #[cfg(target_os = "linux")]
            verification_state,
        })
    }
    /// Apply the canonical confinement with only the original state's file and
    /// this child's captured store added. Any error requires process exit.
    #[cfg(target_os = "linux")]
    pub fn confine(&self, spec: &crate::jailer::ConfinementSpec) -> Result<()> {
        self.lease.check_current()?;
        if let Some(store) = &self.store {
            store.check_current()?;
        }
        crate::jailer::confine_self_with_owned_files(
            spec,
            &self.verification_state,
            self.store.as_ref().map(|store| &store.directory),
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
