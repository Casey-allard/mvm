//! `mvm-signer-helper` — resident per-tenant key-holding signer helper.
//!
//! The host-agent daemon supervises this child. The helper holds the tenant's
//! signing key material, opens per-VM workload chains on `RegisterVm`, routes
//! appends by server-derived `vm_id`, and closes chains on `DeregisterVm`.

use std::io::Read as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tracing::{error, info};

use mvm_hostd::audit_signer::config::{SignerHelperConfig, parse_signer_helper as parse_config};
use mvm_hostd::audit_signer::helper::{SignerHelper, serve_on_listener, serve_owned_on_listener};

fn main() -> Result<()> {
    // First statement in the process: a panic before this line would
    // print its payload unredacted.
    mvm_hostd::panic_hook::install("signer-helper");
    let owned = std::env::args_os().any(|arg| arg == "--installed-owned");
    #[cfg(target_os = "macos")]
    if owned {
        mvm_vmm::host::owned_liveness::prepare_stdout_writer()
            .context("prepare original signer liveness writer")?;
    }

    if owned {
        mvm_hostd::parent_death::bound_owned_main_stack()
            .context("bound owned signer main stack")?;
    }
    // A signer-helper whose host-agent parent is gone holds key material no one
    // can reach — exit rather than leak as an orphan.
    if owned {
        mvm_hostd::parent_death::exit_when_orphaned_with_stack(2 * 1024 * 1024)
            .context("arm owned signer parent protection")?;
    } else {
        mvm_hostd::parent_death::exit_when_orphaned();
    }

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let raw = if owned {
        let mut bytes = Vec::with_capacity(65537);
        std::io::stdin()
            .lock()
            .take(65537)
            .read_to_end(&mut bytes)?;
        mvm_hostd::owned_resources::validate_shape(&bytes)?;
        bytes
    } else {
        mvm_hostd::read_launch_config("mvm-signer-helper")?
    };
    let (cfg, chain_bytes): (SignerHelperConfig, _) = if owned {
        let setup: mvm_hostd::audit_signer::config::OwnedSignerSetup = serde_json::from_slice(&raw)
            .context("decoding original signer setup")?;
        (setup.config, setup.audit_chain_bytes)
    } else { (parse_config(&raw).context("mvm-signer-helper config parse failed")?, None) };
    if owned {
        mvm_core::naming::validate_vm_name(&cfg.tenant_id)?;
    }
    info!(
        tenant_id = %cfg.tenant_id,
        uds_path = %cfg.uds_path.display(),
        software_chain_key_path = ?cfg.software_chain_key_path,
        max_frame_bytes = cfg.max_frame_bytes,
        "mvm-signer-helper config loaded"
    );

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-signer-helper");
    if owned {
        builder.worker_threads(mvm_vmm::host::host_agent_spawn::OWNED_ASYNC_WORKERS_PER_PROCESS);
        builder
            .thread_stack_size(2 * 1024 * 1024)
            .max_io_events_per_tick(16)
            .max_blocking_threads(mvm_vmm::host::host_agent_spawn::OWNED_BLOCKING_WORKERS_PER_PROCESS);
    }
    let runtime = builder
        .build()
        .context("mvm-signer-helper tokio runtime build failed")?;

    runtime.block_on(async move {
        let helper = SignerHelper::new(cfg.tenant_id, cfg.software_chain_key_path);
        let helper = Arc::new(Mutex::new(if owned {
            helper.with_owned_resource_limits().with_audit_chain_bytes(chain_bytes)
        } else {
            helper
        }));
        let serving = if owned {
            let admission =
                Arc::new(mvm_hostd::owned_resources::registered::RegistrationAdmission::new());
            let listener =
                mvm_hostd::broker::daemon::bind_owned_signer_listener(&cfg.uds_path, &admission)?;
            serve_owned_on_listener(listener, helper, cfg.max_frame_bytes, admission).await
        } else {
            let listener =
                mvm_hostd::broker::daemon::bind_host_agent_listener(&cfg.uds_path, 0o600)?;
            serve_on_listener(listener, helper, cfg.max_frame_bytes).await
        };
        if let Err(e) = serving {
            error!(error = %e, "mvm-signer-helper serve loop exited with error");
            return Err::<(), _>(e);
        }
        Ok(())
    })?;

    Ok(())
}
