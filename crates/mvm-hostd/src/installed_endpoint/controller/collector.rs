//! Foreground collector-only controller under the original installed partition.
use super::*;
use crate::installed_endpoint::Component;
use anyhow::Context as _;
use std::{
    fs::OpenOptions,
    io,
    os::unix::fs::OpenOptionsExt,
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) fn run(
    mut child: InstalledEndpointChild,
    resources: InstalledEndpointResources,
) -> Result<()> {
    let InstalledEndpointProgram::TelemetryOnly(config) = &resources.program else {
        anyhow::bail!("installed collector program differs")
    };
    ensure!(
        cfg!(target_os = "linux"),
        "installed collector confinement unavailable"
    );
    let telemetry = &config.telemetry;
    let audit = resources.lease.audit()?;
    ensure!(
        audit.vm() == config.instance_id
            && audit.socket() == telemetry.signer_sock
            && telemetry.state_dir.is_absolute()
            && telemetry.telemetry_sock
                == mvm_core::config::vm_hvf_vsock_port_socket_at(
                    &telemetry.state_dir,
                    mvm_core::protocol::telemetry::TELEMETRY_PORT
                )
            && telemetry.signer_sock
                == mvm_core::config::host_agent_signer_helper_socket(audit.tenant())
            && telemetry.host_anchor_path
                == mvm_core::config::mvm_keys_dir()
                    .join(mvm_vmm::host::broker_services_spawn::HOST_SIGNER_PUB),
        "installed collector original service paths differ"
    );
    let quote = owned_endpoint_runtime_requirements()?;
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{Resource, getrlimit};
        let funded = child.projection().limits.host_resident_bytes()?;
        let limit = getrlimit(Resource::As);
        ensure!(
            limit
                .current
                .zip(limit.maximum)
                .is_some_and(|(soft, hard)| soft <= hard && hard <= funded),
            "installed collector original process limit missing"
        );
    }
    let controller = resources.claim_component(
        Component::Controller,
        quote.main_stack_envelope_bytes,
        quote.controller_metadata_bytes,
    )?;
    let anchor = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&telemetry.host_anchor_path)
        .context("open original collector anchor")?;
    let (state, _socket) = resources.open_original_directories()?;
    let state = Arc::new(state);
    #[cfg(target_os = "linux")]
    {
        let mut spec = crate::jailer::ConfinementSpec::telemetry_collector(
            &telemetry.state_dir,
            telemetry.telemetry_sock.parent(),
            mvm_core::config::mvm_keys_dir(),
        );
        // The original records and state descriptors supply the only write
        // grants. The public anchor is already open; no host key-directory grant.
        spec.readable_paths.clear();
        spec.read_write_paths.clear();
        resources.confine_with_runtime_state(&spec, Some(&state))?;
    }
    let mut collector = resources
        .start_owned_collector(child.startup_deadline(), anchor, state)?
        .context("original installed collector missing")?;
    // Keep startup failure inside the same close/join transaction as serving.
    let serving = (|| -> Result<()> {
        child.send_ready(Default::default(), child.startup_deadline())?;
        loop {
            if child.parent_closed()? {
                return Ok(());
            }
            child.check_parent()?;
            controller.check_current()?;
            audit.check_current()?;
            let mut fd = libc::pollfd {
                fd: child.control_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: the original child owns this live control descriptor for the entire poll.
            if unsafe { libc::poll(&mut fd, 1, 25) } < 0
                && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                anyhow::bail!("installed collector control poll failed")
            }
        }
    })();
    let cleanup = Instant::now() + Duration::from_secs(2);
    collector.close_and_join(cleanup)?;
    serving?;
    child.send_drained(cleanup)
}
