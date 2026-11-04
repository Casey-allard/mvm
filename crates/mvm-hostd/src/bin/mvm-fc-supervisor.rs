//! Foreground per-VM Firecracker child owner, selected only by native custody.

fn main() -> std::process::ExitCode {
    mvm_vmm::host::helper_contract::exit_with_probe_answer_if_requested("mvm-fc-supervisor");
    #[cfg(target_os = "linux")]
    {
        mvm_hostd::panic_hook::install("fc-supervisor");
        match mvm_vmm::host::fc_lifetime::run_guardian() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(_) => {
                eprintln!("owned Firecracker guardian failed; native custody remains unresolved");
                std::process::ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("mvm-fc-supervisor requires the native Linux Firecracker profile");
        std::process::ExitCode::FAILURE
    }
}
