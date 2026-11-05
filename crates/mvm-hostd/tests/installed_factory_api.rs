#![cfg(unix)]

#[test]
fn installed_factory_requires_original_prepared_resources() {
    use mvm_hostd::{
        installed_endpoint::InstalledEndpointResources,
        supervisor::flowmux::SpiralCorePayloadFactory,
    };
    let _: fn(&InstalledEndpointResources) -> std::io::Result<Option<SpiralCorePayloadFactory>> =
        SpiralCorePayloadFactory::from_installed_resources;
}
