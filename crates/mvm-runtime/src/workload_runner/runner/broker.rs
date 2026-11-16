use anyhow::{Context, Result, bail};
use std::path::Path;
#[cfg(unix)]
use std::sync::Arc;

use mvm_core::protocol::broker::ServiceId;

/// The production broker registrar delegates to the resident host agent or
/// the per-VM broker fork, preserving the admitted capability boundary.
pub struct RealBrokerRegistrar;

impl BrokerRegistrar for RealBrokerRegistrar {
    #[cfg(unix)]
    fn register_installed(
        &self,
        req: &BrokerRegisterRequest<'_>,
        original: &mvm_vmm::host::host_agent_spawn::OwnedHostAgentRegistrar,
    ) -> Result<BrokerGuard> {
        let registration = original.register(req.host_agent_params()?)?;
        Ok(BrokerGuard::from_owned_registration(registration))
    }

    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        if req.services.is_empty() {
            return Ok(BrokerGuard::defused());
        }
        let (Some(tenant), Some(broker_listen_socket)) = (req.tenant, req.broker_listen_socket)
        else {
            return Ok(BrokerGuard::defused());
        };

        let guard = if mvm_vmm::host::host_agent_spawn::host_agent_daemon_enabled() {
            mvm_vmm::host::host_agent_spawn::register_host_agent_services_if_admitted(
                mvm_vmm::host::host_agent_spawn::HostAgentServicesParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                    services: req.services,
                    capability_bindings: req.capability_bindings,
                    service_proxies: req.service_proxies,
                },
            )
            .map(mvm_vmm::host::host_agent_spawn::ServicesGuard::Agent)?
        } else {
            if !req.service_proxies.is_empty() {
                bail!("controller-backed typed services require the resident host-agent path");
            }
            mvm_vmm::host::broker_services_spawn::spawn_broker_services_if_admitted(
                mvm_vmm::host::broker_services_spawn::BrokerServicesSpawnParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                    services: req.services,
                    capability_bindings: req.capability_bindings,
                },
            )
            .map(mvm_vmm::host::host_agent_spawn::ServicesGuard::Fork)?
        };
        Ok(BrokerGuard::from_services_guard(guard))
    }
}

/// What the runner needs to register the per-VM host-services broker after boot.
pub struct BrokerRegisterRequest<'a> {
    /// VM name — the registration's `vm_id`, workload id, and per-VM chain key.
    pub vm_name: &'a str,
    /// Per-VM state dir (audit-signer pid/sock + the daemon tenant-ref marker).
    pub state_dir: &'a Path,
    /// Tenant from the admitted plan. `None` ⇒ unadmitted ⇒ a defused no-op:
    /// no broker services and no BROKER_PORT in the spec, so a stray guest dial
    /// stays `ECONNREFUSED` (fail-closed).
    pub tenant: Option<&'a str>,
    /// The `BROKER_PORT` socket the broker/daemon binds — the same path the spec
    /// wires the guest's `BROKER_PORT` relay to. `None` on the unadmitted path.
    pub broker_listen_socket: Option<&'a Path>,
    /// Host services from the admitted plan. Empty means no broker process is
    /// needed and every broker call remains fail-closed.
    pub services: &'a [ServiceId],
    /// Exact typed capabilities carried by admitted extension bindings.
    pub capability_bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
    /// Controller-backed typed services prepared by the admitting process.
    pub service_proxies: &'a [mvm_contract::protocol::broker_control::ServiceProxyBinding],
}

#[cfg(unix)]
impl<'a> BrokerRegisterRequest<'a> {
    pub(super) fn host_agent_params(
        &self,
    ) -> Result<mvm_vmm::host::host_agent_spawn::HostAgentServicesParams<'a>> {
        Ok(mvm_vmm::host::host_agent_spawn::HostAgentServicesParams {
            workload_id: self.vm_name,
            tenant_id: Some(self.tenant.context("installed tenant missing")?),
            vm_name: self.vm_name,
            state_dir: self.state_dir,
            broker_listen_socket: self
                .broker_listen_socket
                .context("installed broker socket missing")?,
            services: self.services,
            capability_bindings: self.capability_bindings,
            service_proxies: self.service_proxies,
        })
    }
}

/// Register/spawn the per-VM host-services broker for an admitted workload,
/// returning a guard whose Drop reaps until defused. The claims-12/13 seam:
/// Admitted host services reach the guest over `BROKER_PORT`. Behind a trait so
/// the runner is unit-testable with no real broker subprocess.
pub trait BrokerRegistrar: Send + Sync {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard>;
    /// Installed launches must use the original resident helper. Unsupported
    /// implementations never fall back to legacy registration or discovery.
    #[cfg(unix)]
    fn register_installed(
        &self,
        _req: &BrokerRegisterRequest<'_>,
        _original: &mvm_vmm::host::host_agent_spawn::OwnedHostAgentRegistrar,
    ) -> Result<BrokerGuard> {
        anyhow::bail!("installed broker registration unsupported")
    }
}

/// RAII guard around the registered broker services: Drop reaps them until the
/// VM is confirmed up and `defuse`d (the `stop` path then owns teardown). Wraps
/// the existing `ServicesGuard` so no reaping logic is duplicated.
pub struct BrokerGuard(pub(super) BrokerCustody);

pub(super) enum BrokerCustody {
    Legacy(mvm_vmm::host::host_agent_spawn::ServicesGuard),
    #[cfg(unix)]
    Installed(Arc<mvm_vmm::host::host_agent_spawn::OwnedVmRegistration>),
}

impl BrokerGuard {
    pub(crate) fn from_services_guard(
        guard: mvm_vmm::host::host_agent_spawn::ServicesGuard,
    ) -> Self {
        Self(BrokerCustody::Legacy(guard))
    }

    /// A guard that reaps nothing on drop — the unadmitted / spawn-failed path.
    pub(super) fn defused() -> Self {
        Self::from_services_guard(mvm_vmm::host::host_agent_spawn::ServicesGuard::None)
    }

    #[cfg(unix)]
    pub(super) fn from_owned_registration(
        guard: mvm_vmm::host::host_agent_spawn::OwnedVmRegistration,
    ) -> Self {
        Self(BrokerCustody::Installed(Arc::new(guard)))
    }

    /// Legacy disarm only. Installed registration always retains its original
    /// signed cleanup owner, including if a compatibility caller invokes this.
    pub fn defuse(&mut self) {
        match &mut self.0 {
            BrokerCustody::Legacy(guard) => guard.defuse(),
            #[cfg(unix)]
            BrokerCustody::Installed(_) => {}
        }
    }

    pub(super) fn shutdown_owned(&mut self) -> Result<()> {
        match &mut self.0 {
            BrokerCustody::Legacy(mvm_vmm::host::host_agent_spawn::ServicesGuard::None) => Ok(()),
            #[cfg(unix)]
            BrokerCustody::Installed(guard) => Arc::get_mut(guard)
                .context("original broker observation in progress; registration retained")?
                .shutdown(),
            _ => anyhow::bail!(
                "original broker cleanup confirmation unavailable; installed owner retained"
            ),
        }
    }

    /// Whether the launch came up with the host services it asked for.
    ///
    /// The guard alone cannot answer this. It records only whether anything was
    /// registered, which is the same `false` for a workload that bound no
    /// service as for one whose registration was skipped — `requested` is what
    /// separates them. Judging on the guard alone marks every workload that
    /// binds no host service as degraded, and a degraded launch is refused as a
    /// sample of a healthy one.
    #[must_use]
    pub fn services_healthy(&self, requested: &[ServiceId]) -> bool {
        requested.is_empty()
            || match &self.0 {
                BrokerCustody::Legacy(guard) => guard.is_registered(),
                #[cfg(unix)]
                BrokerCustody::Installed(_) => true,
            }
    }
}

pub(super) fn admitted_broker_bindings(
    plan_json: Option<&str>,
) -> Result<(
    Vec<ServiceId>,
    Vec<mvm_contract::protocol::agent_capability::CapabilityBinding>,
)> {
    plan_json
        .map(mvm_core::plan::plan_from_admitted_json)
        .transpose()
        .context("parse admitted plan host services")
        .map(|plan| {
            plan.map_or_else(
                || (Vec::new(), Vec::new()),
                |plan| {
                    let capabilities = plan
                        .extensions
                        .iter()
                        .flat_map(|extension| extension.capabilities.iter().cloned())
                        .collect();
                    (plan.services, capabilities)
                },
            )
        })
}
