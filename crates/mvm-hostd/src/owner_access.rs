//! Installed owner-access composition. Connectivity and a request's owner label
//! are not authority; the host supplies the admitted plan and authenticated peer.
use crate::plan_admission::AdmittedPlan;
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_agentd::vsock::{GuestRequest, GuestResponse};
use mvm_core::{
    net::session::{Session, SessionRole},
    plan::ExecutionPlan,
    vm_backend::{BackendKind, VmId, VmStartConfig, VmStatus},
};
use mvm_vmm::host::telemetry_registration::{
    ExpectedTelemetryPeer, resolve_expected_telemetry_peer,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
pub type FactoryResult<T> = Result<T>;

/// Operator-installed mapping, never deserialized from a request. The peer must
/// prove this key through the canonical session before its label is usable.
pub struct OwnerPin {
    pub owner: String,
    pub tenant: String,
    pub key: VerifyingKey,
}
pub struct AuthenticatedOwner {
    owner: String,
    tenant: String,
    key: VerifyingKey,
}
impl AuthenticatedOwner {
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Fresh boot/key expectation and the exact admitted policy. The registration
/// supplies identity only; it contributes no telemetry or access permission.
#[derive(Clone)]
pub struct CurrentAccessBoot {
    instance: String,
    plan: ExecutionPlan,
    backend: BackendKind,
    peer: ExpectedTelemetryPeer,
    revoked: Arc<AtomicBool>,
    grant: mvm_contract::plan::VerbGrant,
    host: VerifyingKey,
}
impl CurrentAccessBoot {
    pub fn instance(&self) -> &str {
        &self.instance
    }
    pub fn peer(&self) -> &VerifyingKey {
        &self.peer.key
    }
    pub fn grant(&self) -> &mvm_contract::plan::VerbGrant {
        &self.grant
    }
    pub fn host(&self) -> &VerifyingKey {
        &self.host
    }
    pub fn connect_before(
        &self,
        deadline: std::time::Instant,
    ) -> Result<std::os::unix::net::UnixStream> {
        self.check()?;
        let stream = mvm_runtime::vsock_transport::connect_for_vm_before(
            &self.instance,
            mvm_agentd::vsock::GUEST_AGENT_PORT,
            deadline,
        )?;
        self.check()?;
        Ok(stream)
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.revoked.load(Ordering::Acquire),
            "owner access revoked"
        );
        let current = crate::audit::plan_persist::read_plan(&self.instance)?;
        ensure!(
            current.plan_id == self.plan.plan_id
                && current.nonce == self.plan.nonce
                && mvm_core::plan::compute_plan_id(&current) == self.plan.plan_id,
            "owner access admitted plan changed"
        );
        let directory = mvm_core::config::vm_state_dir(&self.instance);
        ensure!(
            resolve_expected_telemetry_peer(&directory, &self.instance)? == self.peer,
            "owner access boot changed"
        );
        mvm_runtime::AnyBackend::require_hypervisor_selectable(self.backend.as_str())?;
        let backend = mvm_runtime::AnyBackend::from_hypervisor(self.backend.as_str());
        ensure!(
            backend.kind() == self.backend,
            "owner access runtime backend changed"
        );
        ensure!(
            backend.status(&VmId(self.instance.clone()))? == VmStatus::Running,
            "owner access runtime is not running"
        );
        let envelope = mvm_runtime::microvm::read_verb_grant_envelope(&self.instance)?
            .context("owner access grant disappeared")?;
        ensure!(
            envelope.grant.signing_bytes() == self.grant.signing_bytes()
                && envelope.grant.sig == self.grant.sig,
            "owner access grant changed"
        );
        self.grant
            .verify(
                &self.host,
                &self.instance,
                &self.plan.nonce,
                chrono::Utc::now(),
            )
            .context("owner access grant expired or invalid")?;
        Ok(())
    }
}

/// The embedding owns the actual guest connector, shared budgets, clock,
/// scanner and durable audit. It must check `boot` before every forward.
pub trait OwnerAccessEndpoint: Send + Sync {
    fn dispatch(
        &self,
        owner: &AuthenticatedOwner,
        request: GuestRequest,
        boot: &CurrentAccessBoot,
    ) -> Result<Vec<GuestResponse>>;
    fn revoke(&self);
}
pub trait OwnerAccessFactory: Send + Sync {
    fn preflight(&self, admitted: &AdmittedPlan, config: &VmStartConfig) -> Result<()>;
    fn activate(
        &self,
        admitted: &AdmittedPlan,
        config: &VmStartConfig,
        boot: CurrentAccessBoot,
    ) -> Result<Arc<dyn OwnerAccessEndpoint>>;
    fn owner_pins(&self) -> &[OwnerPin];
}
struct Registered {
    endpoint: Arc<dyn OwnerAccessEndpoint>,
    boot: CurrentAccessBoot,
}
struct Slot {
    revoked: Arc<AtomicBool>,
    entry: Option<Registered>,
}
pub struct OwnerAccessRegistry {
    capacity: usize,
    factory: Option<Arc<dyn OwnerAccessFactory>>,
    require_dev: bool,
    entries: Mutex<BTreeMap<String, Slot>>,
}
impl OwnerAccessRegistry {
    pub fn new(
        capacity: usize,
        factory: Option<Arc<dyn OwnerAccessFactory>>,
        require_dev: bool,
    ) -> Result<Self> {
        ensure!(
            (1..=64).contains(&capacity),
            "owner access registry capacity invalid"
        );
        if let Some(factory) = &factory {
            let pins = factory.owner_pins();
            ensure!(
                !pins.is_empty() && pins.len() <= 32,
                "owner access pins invalid"
            );
            for (index, pin) in pins.iter().enumerate() {
                ensure!(
                    !pin.owner.is_empty()
                        && pin.owner.len() <= 128
                        && !pin.tenant.is_empty()
                        && pin.tenant.len() <= 128,
                    "owner access pin invalid"
                );
                ensure!(
                    !pins[..index].iter().any(|old| old.key == pin.key
                        || old.owner == pin.owner && old.tenant == pin.tenant),
                    "owner access duplicate pin"
                );
            }
        }
        Ok(Self {
            capacity,
            factory,
            require_dev,
            entries: Mutex::new(BTreeMap::new()),
        })
    }
    fn selected(&self, plan: &ExecutionPlan) -> bool {
        plan.grants
            .as_ref()
            .is_some_and(|grants| grants.owner_access.is_some())
            || self.require_dev
    }
    pub fn require(&self, plan: &ExecutionPlan) -> Result<()> {
        ensure!(
            !self.selected(plan) || self.factory.is_some(),
            "selected owner access profile has no installed factory"
        );
        Ok(())
    }
    /// Authenticate only an existing canonical host-facing session. Callers
    /// cannot provide an owner label, tenant, key or claimed proof here.
    pub fn authenticated_owner(&self, session: &Session) -> Result<AuthenticatedOwner> {
        ensure!(
            session.role() == SessionRole::Guest && !session.is_poisoned(),
            "owner session not authenticated"
        );
        let factory = self
            .factory
            .as_ref()
            .context("owner access factory absent")?;
        let pin = factory
            .owner_pins()
            .iter()
            .find(|pin| &pin.key == session.peer_verifying_key())
            .context("owner key not admitted")?;
        Ok(AuthenticatedOwner {
            owner: pin.owner.clone(),
            tenant: pin.tenant.clone(),
            key: pin.key,
        })
    }
    pub fn preflight(&self, admitted: &AdmittedPlan, config: &VmStartConfig) -> Result<()> {
        mvm_core::naming::validate_vm_name(&config.name)?;
        self.require(admitted.plan())?;
        if self.selected(admitted.plan()) {
            self.factory
                .as_ref()
                .context("owner factory absent")?
                .preflight(admitted, config)?;
        }
        Ok(())
    }
    pub fn activate(
        &self,
        admitted: &AdmittedPlan,
        config: &VmStartConfig,
        backend: BackendKind,
    ) -> Result<()> {
        if !self.selected(admitted.plan()) {
            return Ok(());
        }
        self.require(admitted.plan())?;
        let factory = self.factory.as_ref().context("owner factory absent")?;
        let revoked = Arc::new(AtomicBool::new(false));
        {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| anyhow::anyhow!("owner registry poisoned"))?;
            ensure!(
                !entries.contains_key(&config.name) && entries.len() < self.capacity,
                "owner access registry full or instance already active"
            );
            entries.insert(
                config.name.clone(),
                Slot {
                    revoked: revoked.clone(),
                    entry: None,
                },
            );
        }
        let result = (|| {
            let directory = mvm_core::config::vm_state_dir(&config.name);
            let envelope = mvm_runtime::microvm::read_verb_grant_envelope(&config.name)?
                .context("owner access grant missing after boot")?;
            let signer = crate::audit::host_keypair::load_or_init()?;
            envelope.grant.verify(
                &signer.verifying,
                &config.name,
                &admitted.plan().nonce,
                chrono::Utc::now(),
            )?;
            let boot = CurrentAccessBoot {
                instance: config.name.clone(),
                plan: admitted.plan().clone(),
                backend,
                peer: resolve_expected_telemetry_peer(&directory, &config.name)?,
                revoked: revoked.clone(),
                grant: envelope.grant,
                host: signer.verifying,
            };
            boot.check()?;
            let endpoint = factory.activate(admitted, config, boot.clone())?;
            if let Err(error) = boot.check() {
                endpoint.revoke();
                return Err(error);
            }
            Ok(Registered { endpoint, boot })
        })();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("owner registry poisoned"))?;
        match result {
            Ok(entry) => {
                let current = entries.get_mut(&config.name).filter(|slot| {
                    Arc::ptr_eq(&slot.revoked, &revoked) && !revoked.load(Ordering::Acquire)
                });
                let Some(current) = current else {
                    entry.boot.revoked.store(true, Ordering::Release);
                    entry.endpoint.revoke();
                    bail!("owner access activation revoked");
                };
                current.entry = Some(entry);
                Ok(())
            }
            Err(error) => {
                if entries
                    .get(&config.name)
                    .is_some_and(|slot| Arc::ptr_eq(&slot.revoked, &revoked))
                {
                    entries.remove(&config.name);
                }
                Err(error)
            }
        }
    }
    pub fn dispatch(
        &self,
        instance: &str,
        owner: &AuthenticatedOwner,
        request: GuestRequest,
    ) -> Result<Vec<GuestResponse>> {
        let factory = self.factory.as_ref().context("owner factory absent")?;
        ensure!(
            factory.owner_pins().iter().any(|pin| pin.key == owner.key
                && pin.owner == owner.owner
                && pin.tenant == owner.tenant),
            "owner proof is not enrolled in this registry"
        );
        let (endpoint, boot) = {
            let entries = self
                .entries
                .lock()
                .map_err(|_| anyhow::anyhow!("owner registry poisoned"))?;
            let registered = entries
                .get(instance)
                .and_then(|slot| slot.entry.as_ref())
                .context("owner access instance not active")?;
            (registered.endpoint.clone(), registered.boot.clone())
        };
        ensure!(
            owner.tenant == boot.plan.tenant.0,
            "owner tenant differs from admitted instance"
        );
        boot.check()?;
        let reply = endpoint.dispatch(owner, request, &boot)?;
        boot.check()?;
        ensure!(reply.len() <= 16, "owner access reply frame limit");
        Ok(reply)
    }
    /// Called before stop, restore or replacement. Missing cleanup is still
    /// refused by the fresh plan, boot and running-runtime checks on dispatch.
    pub fn revoke(&self, instance: &str) -> Result<()> {
        let entry = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("owner registry poisoned"))?
            .remove(instance);
        if let Some(slot) = entry {
            slot.revoked.store(true, Ordering::Release);
            if let Some(entry) = slot.entry {
                entry.endpoint.revoke();
            }
        }
        Ok(())
    }
}
impl Drop for OwnerAccessRegistry {
    fn drop(&mut self) {
        let entries = self
            .entries
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, slot) in std::mem::take(entries) {
            slot.revoked.store(true, Ordering::Release);
            if let Some(entry) = slot.entry {
                entry.endpoint.revoke();
            }
        }
    }
}
static INSTALLED: OnceLock<Arc<OwnerAccessRegistry>> = OnceLock::new();
pub fn install(registry: Arc<OwnerAccessRegistry>) -> Result<()> {
    INSTALLED
        .set(registry)
        .map_err(|_| anyhow::anyhow!("owner access factory already installed"))
}
pub fn installed() -> Option<&'static Arc<OwnerAccessRegistry>> {
    INSTALLED.get()
}
pub(crate) fn require_selected(plan: &ExecutionPlan) -> Result<()> {
    if let Some(registry) = installed() {
        registry.require(plan)
    } else if plan
        .grants
        .as_ref()
        .is_some_and(|grants| grants.owner_access.is_some())
    {
        bail!("selected owner access profile has no installed factory")
    } else {
        Ok(())
    }
}
