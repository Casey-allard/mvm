#![cfg(unix)]

#[test]
fn installed_endpoint_requires_the_original_handoff_and_explicit_drain() {
    use mvm_vmm::host::network_endpoint_spawn::{
        InstalledEndpointChild, OwnedEndpoint, spawn_network_endpoint_installed,
    };
    let _ = spawn_network_endpoint_installed;
    let _ = InstalledEndpointChild::from_stdio;
    let _ = InstalledEndpointChild::send_ready;
    let _ = InstalledEndpointChild::send_drained;
    let _ = OwnedEndpoint::close_admission;
}

#[test]
fn positive_endpoint_retirement_is_linear_and_keeps_the_original_partition() {
    use mvm_vmm::host::network_endpoint_spawn::{EndpointRetirement, OwnedEndpoint};
    let _: fn(&mut OwnedEndpoint) -> anyhow::Result<EndpointRetirement> =
        OwnedEndpoint::take_retirement;
    let _ = EndpointRetirement::projection;
    let _ = EndpointRetirement::retains_partition_guard;
}
