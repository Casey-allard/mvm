//! Foreground original-child lifecycle. Legacy endpoint startup is separate.

use super::{InstalledEndpointProgram, InstalledEndpointResources};
use anyhow::{Result, ensure};
use mvm_vmm::host::network_endpoint_spawn::InstalledEndpointChild;

mod collector;
mod network;
pub use network::{OwnedNetworkRuntimeRequirements, owned_network_runtime_requirements};

/// Requested controller storage; bootstrap, collector, relays and readers have
/// separate same-partition charges. This is not process RSS/native heap proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedEndpointRuntimeRequirements {
    pub main_stack_envelope_bytes: u64,
    pub controller_metadata_bytes: u64,
    pub additional_threads: u8,
}

pub fn owned_endpoint_runtime_requirements() -> Result<OwnedEndpointRuntimeRequirements> {
    const MAIN_STACK: u64 = 8 * 1024 * 1024;
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    ensure!(
        // SAFETY: limit points to writable, aligned storage for one rlimit; getrlimit fills it on success.
        unsafe { libc::getrlimit(libc::RLIMIT_STACK, limit.as_mut_ptr()) } == 0,
        "installed main stack query refused"
    );
    // SAFETY: successful getrlimit initialized this value.
    let limit = unsafe { limit.assume_init() };
    ensure!(
        limit.rlim_cur != libc::RLIM_INFINITY
            && limit.rlim_cur > 0
            && limit.rlim_cur <= MAIN_STACK as libc::rlim_t,
        "installed main stack envelope unsupported"
    );
    let supplement = mvm_core::host_lifetime::native_thread_stack_terms(MAIN_STACK)?;
    Ok(OwnedEndpointRuntimeRequirements {
        // Conservatively retain the full declared main envelope and the same
        // Rust signal-stack mapping term, independent of observed resident pages.
        main_stack_envelope_bytes: supplement.known_rust_bytes,
        // Fixed poll descriptors, original control/owner references and terminal
        // bookkeeping. Raw/typed config is charged by the bootstrap query.
        controller_metadata_bytes: 65_536,
        additional_threads: 0,
    })
}

/// Called by the canonical binary BEFORE orphan watchers or runtime threads.
/// The original private-stdio handshake alone creates its child/resource owners.
pub fn run_installed_endpoint() -> Result<()> {
    let mut child = InstalledEndpointChild::from_stdio()
        .map_err(|_| anyhow::anyhow!("installed endpoint handshake failed"))?;
    let resources = InstalledEndpointResources::from_child(&mut child)
        .map_err(|_| anyhow::anyhow!("installed endpoint resource adoption failed"))?;
    if matches!(
        &resources.program,
        InstalledEndpointProgram::TelemetryOnly(_)
    ) {
        return collector::run(child, resources);
    }
    if let InstalledEndpointProgram::Network(config) = &resources.program
        && config.telemetry.is_some()
    {
        ensure!(
            cfg!(target_os = "linux"),
            "installed endpoint controller confinement unavailable on this platform"
        );
        return network::run(child, resources);
    }
    anyhow::bail!("installed endpoint controller unavailable")
}
