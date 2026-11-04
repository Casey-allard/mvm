#![cfg(target_os = "linux")]

#[test]
fn native_guardian_has_an_owned_controller_and_opaque_exit() {
    let _ = mvm_vmm::host::fc_lifetime::run_guardian;
    let _ = mvm_vmm::host::fc_lifetime::OwnedFcLauncher::start;
    let _ = mvm_vmm::host::fc_lifetime::OwnedFcLauncher::stop;
}
