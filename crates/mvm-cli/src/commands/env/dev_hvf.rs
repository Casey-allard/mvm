//! `DevBackend::Hvf` — the interactive dev VM on the in-house HVF VMM.
//!
//! Unlike the Vz path (which rides the `VzPersistentBuilderVm`
//! snapshot/park/residency apparatus), the in-house dev VM is a long-lived
//! *workload*: it boots the dev rootfs through
//! [`AnyBackend::from_hypervisor("hvf")`](mvm_backend::backend::AnyBackend::from_hypervisor)
//! with an interactive PTY-over-vsock console (`dev_console = true`), a `/work`
//! virtio-fs share, and vsock-only egress under a trusted build policy. Its
//! lifecycle verbs reuse the generic in-house VM marker via
//! [`AnyBackend::for_started_vm`](mvm_backend::backend::AnyBackend::for_started_vm)
//! — exactly as `machine down` / `machine ps` resolve the owning VMM — so there
//! is no Hvf-specific stop/status machinery to keep in sync.
//!
//! Opt-in via `MVM_DEV_BACKEND=hvf` until it is the proven default; Vz remains
//! the macOS-26 default meanwhile.

use anyhow::Result;

use mvm_backend::backend::AnyBackend;
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{VmId, VmStartConfig, VmStatus, VmVolume, VmVolumeKind};

use super::super::vm::console::console_interactive;
use super::dev_vz::{DEV_VM_NAME, ensure_dev_image};
use crate::ui;

/// Is the in-house dev VM up? True when the `hvf` VM marker resolves an owning
/// backend and it reports `Running`. Mirrors `is_vz_dev_running`'s contract for
/// the dispatch's idempotency checks.
pub(in crate::commands) fn is_hvf_dev_running() -> bool {
    match AnyBackend::for_started_vm(DEV_VM_NAME) {
        Some(backend) => matches!(
            backend.status(&VmId::from(DEV_VM_NAME)),
            Ok(VmStatus::Running)
        ),
        None => false,
    }
}

/// The `/work` virtio-fs share: the invoking directory, mounted read-write in
/// the guest at `/work`. The in-house virtio-fs device (Plan 222 Phase 2)
/// carries it; `spec_map::workload_dir_shares` tags it `work` from the mount.
fn work_share_volume() -> VmVolume {
    let host = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .to_string_lossy()
        .into_owned();
    VmVolume {
        host,
        guest: "/work".into(),
        size: String::new(),
        read_only: false,
        kind: VmVolumeKind::DirShare,
        encrypted: false,
    }
}

/// Boot the interactive dev VM on the in-house HVF VMM. Idempotent: a
/// second `dev up` on an already-running VM just (optionally) opens a shell.
#[cfg(feature = "builder-vm")]
pub(super) fn cmd_dev_hvf(cpus: u32, memory_gib: u32, open_shell: bool) -> Result<&'static str> {
    ui::progress("Starting dev environment via the in-house HVF VMM...");

    if is_hvf_dev_running() {
        if open_shell {
            ui::progress("Dev VM already running. Opening shell...");
            console_interactive(DEV_VM_NAME)?;
        } else {
            ui::progress("Dev VM already running.");
        }
        return Ok("already-running");
    }

    // Lock ~/.mvm and ~/.cache/mvm to 0700 on every `dev up`. Idempotent.
    mvm_core::config::ensure_data_dir()
        .map_err(|e| anyhow::anyhow!("locking down data dir to mode 0700: {e}"))?;
    mvm_core::config::ensure_cache_dir()
        .map_err(|e| anyhow::anyhow!("locking down cache dir to mode 0700: {e}"))?;

    let (kernel, rootfs) = ensure_dev_image()?;

    ui::info(&format!(
        "Booting dev VM ({cpus} vCPUs, {memory_gib} GiB memory)..."
    ));
    let memory_mib = memory_gib.saturating_mul(1024);

    let start_config = VmStartConfig {
        name: DEV_VM_NAME.to_string(),
        rootfs_path: rootfs,
        kernel_path: Some(kernel),
        revision_hash: "dev".to_string(),
        flake_ref: "dev:hvf".to_string(),
        profile: Some("dev".to_string()),
        cpus,
        memory_mib,
        volumes: vec![work_share_volume()],
        // The dev VM is trusted build infrastructure: it gets the gated egress
        // endpoint with an open (trusted) policy, not the default-deny a
        // workload receives. Egress still rides vsock-only through the host
        // gate — never a NIC. See claim-10 / Plan 223.
        network_policy: NetworkPolicy::trusted_build_egress(),
        // Interactive PTY-over-vsock console (dev-only; claim 15). Pre-opens the
        // console data ports so `dev shell` can attach.
        dev_console: true,
        ..Default::default()
    };

    let backend = AnyBackend::from_hypervisor("hvf");
    backend
        .start(&start_config)
        .map_err(|e| anyhow::anyhow!("Failed to start dev VM: {e}"))?;

    ui::success("Dev VM ready.");
    ui::info("  Shell:      mvmctl dev shell");
    ui::info("  Stop VM:    mvmctl dev down");

    if open_shell {
        ui::info("");
        let _ = console_interactive(DEV_VM_NAME);
    }

    Ok("started")
}

#[cfg(not(feature = "builder-vm"))]
pub(super) fn cmd_dev_hvf(_cpus: u32, _memory_gib: u32, _open_shell: bool) -> Result<&'static str> {
    anyhow::bail!(
        "the dev VM is built locally via the builder VM, but this mvmctl was \
         compiled without the `builder-vm` feature."
    )
}

/// Stop the in-house dev VM, dispatched to its owning VMM via the VM marker.
pub(in crate::commands) fn cmd_dev_hvf_down(json: bool) -> Result<bool> {
    let Some(backend) = AnyBackend::for_started_vm(DEV_VM_NAME) else {
        if json {
            println!("{}", serde_json::json!({ "stopped": false }));
        } else {
            ui::info("Dev VM is not running.");
        }
        return Ok(false);
    };
    backend
        .stop(&VmId::from(DEV_VM_NAME))
        .map_err(|e| anyhow::anyhow!("Failed to stop dev VM: {e}"))?;
    if json {
        println!("{}", serde_json::json!({ "stopped": true }));
    } else {
        ui::success("Dev VM stopped.");
    }
    Ok(true)
}

/// Report the in-house dev VM's status.
pub(super) fn cmd_dev_hvf_status(json: bool) -> Result<()> {
    let running = is_hvf_dev_running();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "backend": "hvf",
                "vm_name": DEV_VM_NAME,
                "running": running,
            })
        );
    } else {
        ui::info("Dev backend: in-house HVF VMM");
        ui::info(&format!("Dev VM:   {DEV_VM_NAME}"));
        ui::info(&format!(
            "Status:   {}",
            if running { "running" } else { "stopped" }
        ));
    }
    Ok(())
}
