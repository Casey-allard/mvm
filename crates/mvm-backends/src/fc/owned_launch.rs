//! Foreground installed Firecracker launch using the canonical scope and sudo.

use anyhow::{Context, Result, ensure};
use mvm_core::{
    host_lifetime::{HostLaunchBinding, PreparedHostLifetimeLease},
    spawn_scope::SpawnBounds,
};
use mvm_vmm::{
    driver::prepared_disks::SudoWritableHandoff,
    host::{
        fc_lifetime::{FcGuardianConfig, LaunchFailure, OutputFile, OwnedFcLauncher},
        shell::shell_quote,
    },
};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};

pub(crate) struct OwnedStart<'a> {
    pub state_dir: &'a Path,
    pub socket: &'a str,
    pub vm: &'a str,
    pub bounds: &'a SpawnBounds,
    pub disks: Option<&'a SudoWritableHandoff>,
    pub lease: &'a PreparedHostLifetimeLease,
    pub binding: &'a HostLaunchBinding,
}

fn evidence(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("create original owned Firecracker output")
}
fn output(file: &File) -> Result<OutputFile> {
    let metadata = file.metadata()?;
    Ok(OutputFile {
        parent_pid: std::process::id(),
        fd: file.as_raw_fd(),
        object: (metadata.dev(), metadata.ino()),
        uid: metadata.uid(),
    })
}

/// Pending is filled before any subsequent fallible native preparation.
pub(crate) fn start(input: OwnedStart<'_>, pending: &mut Option<OwnedFcLauncher>) -> Result<()> {
    ensure!(
        pending.is_none(),
        "original Firecracker owner already occupied"
    );
    ensure!(
        input.vm == input.binding.vm_name,
        "Firecracker binding differs"
    );
    super::daemon::validate_required_scope(input.vm, input.bounds)?;
    super::daemon::ensure_api_socket_fits(input.socket)?;
    super::daemon::secure_socket_dir(&input.state_dir.to_string_lossy())?;
    input.lease.verify_current()?;
    mvm_vmm::host::process_exit::require_owned_child_custody()?;
    let guardian = mvm_vmm::host::aux_bin::resolve_verified(&mvm_vmm::host::aux_bin::AuxBin::new(
        "mvm-fc-supervisor",
        "MVM_FC_SUPERVISOR_PATH",
        "mvm-hostd",
    ))?;
    let program = which::which("firecracker")
        .context("canonical Firecracker executable unavailable")?
        .canonicalize()?;
    let console = evidence(&input.state_dir.join("console.log"))?;
    let stderr = evidence(&input.state_dir.join("firecracker.log"))?;
    let config = FcGuardianConfig {
        binding: input.binding.clone(),
        program,
        api_socket: input.socket.into(),
        state_dir: input.state_dir.into(),
        holder_object: input.lease.holder_object_id(),
        holder_uid: input.lease.owner_uid(),
        console: output(&console)?,
        stderr: output(&stderr)?,
    };
    let disk_prefix = match input.disks {
        Some(disks) => {
            super::daemon::descriptor_reopen_prefix(std::process::id(), disks.first(), disks.last())
        }
        None => String::new(),
    };
    let preflight = crate::driver::fc::host_lease_preflight(input.lease);
    let inner = format!(
        "{disk_prefix}{preflight}exec {} --holder-fd \"$mvm_host_holder\"\n",
        shell_quote(&guardian.display().to_string())
    );
    // Both layers reopen original disks before allocating dynamic lease FDs.
    let sudo = super::daemon::sudo_prefix_for_euid(input.lease.owner_uid());
    let script = format!(
        "set -euo pipefail\n{disk_prefix}{preflight}exec {sudo}/bin/bash -c {}\n",
        shell_quote(&inner)
    );
    let mut command = mvm_core::env_hygiene::helper_command("/bin/bash");
    command.args(["-c", &script]);
    let mut bound =
        mvm_core::spawn_scope::bind_spawn(command, input.vm, input.state_dir, input.bounds);
    bound
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = None;
    if let Err(error) = bound.spawn_custodied(&mut child) {
        if let Some(child) = child.take() {
            *pending = Some(OwnedFcLauncher::hold_unprepared(
                child,
                input.binding.clone(),
            ));
        }
        return Err(error);
    }
    let child = child.context("original Firecracker scope child missing")?;
    match OwnedFcLauncher::start(child, config, Instant::now() + Duration::from_secs(3)) {
        Ok(owner) => *pending = Some(owner),
        Err(error) => match error.downcast::<LaunchFailure>() {
            Ok(failure) => {
                let (reason, owner) = failure.into_parts();
                *pending = Some(owner);
                return Err(reason);
            }
            Err(error) => return Err(error),
        },
    }
    let pid = pending
        .as_ref()
        .and_then(OwnedFcLauncher::native_pid)
        .context("owned Firecracker child missing")?;
    // Observation only. No installed lifecycle reads this marker as authority.
    let marker = evidence(&input.state_dir.join("fc.pid"))?;
    use std::io::Write;
    (&marker).write_all(pid.to_string().as_bytes())?;
    super::daemon::wait_for_api_socket(Path::new(input.socket), Duration::from_secs(3))?;
    super::daemon::adopt_api_socket(input.socket)?;
    Ok(())
}
