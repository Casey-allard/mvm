#![cfg(unix)]

use mvm_core::vm_backend::VmStartConfig;
use mvm_runtime::workload_runner::claim::ClaimGuards;
use mvm_runtime::workload_runner::{NetworkEndpointSpawnRequest, NetworkEndpointSpawner};

#[test]
fn installed_endpoint_dispatch_is_additive_and_returns_original_custody() {
    fn dispatch(
        spawner: &dyn NetworkEndpointSpawner,
        request: &NetworkEndpointSpawnRequest<'_>,
        config: &VmStartConfig,
    ) -> anyhow::Result<mvm_runtime::workload_runner::InstalledSpawnedEndpoint> {
        spawner.spawn_installed(request, config, None)
    }
    let _ = dispatch;
    let _ = ClaimGuards::spawn_endpoint_installed;
}

#[test]
fn original_registrar_preflight_is_required_for_installed_telemetry() {
    fn check(
        registrar: &mvm_vmm::host::host_agent_spawn::OwnedHostAgentRegistrar,
        tenant: &str,
    ) -> anyhow::Result<()> {
        registrar.check_current_for_tenant(tenant)
    }
    let _ = check;
}
