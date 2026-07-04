//! In-house VMM host-process helpers: the per-VM `mvm-hvf-supervisor` PID-file
//! lifecycle and supervisor-binary resolution, plus the HVF availability probe.
//!
//! These are shared by the [`InHouseDriver`](crate::driver::InHouseDriver) (which
//! spawns and tracks the supervisor) and the builder runner. The in-house VMM's
//! `VmBackend`/`WorkloadBackend` behaviour lives on the driver-generic
//! [`WorkloadRunner`](crate::workload_runner::WorkloadRunner); this module carries
//! only the process mechanics they both need.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

/// PID file the supervisor writes inside `vm_state_dir`. Distinct from the other
/// backends' markers so in-house VMs coexist under the same `~/.mvm/vms/` root.
pub(crate) const PID_FILE_NAME: &str = "hvf.pid";
/// How long boot waits for the supervisor to confirm boot (PID file). Shared by
/// the in-house driver, which spawns the supervisor binary.
pub(crate) const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub(crate) fn pid_alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 probes existence/permission without delivering a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// SIGTERM a recorded pid, then SIGKILL if it lingers past a short grace. The
/// supervisor installs no SIGTERM handler, so the default action terminates it
/// and the in-house VM dies with it.
pub(crate) fn terminate_pid(pid: libc::pid_t) {
    // SAFETY: signalling a pid we recorded from our own supervisor.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while pid_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if pid_alive(pid) {
        // SAFETY: same pid.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

/// Locate the per-VM supervisor binary: `$MVM_HVF_SUPERVISOR_PATH`, else
/// alongside the current executable (release + `cargo` layouts both put it there).
pub(crate) fn resolve_supervisor_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("MVM_HVF_SUPERVISOR_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "MVM_HVF_SUPERVISOR_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-hvf-supervisor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "mvm-hvf-supervisor binary not found (looked at $MVM_HVF_SUPERVISOR_PATH \
         and alongside the current exe)"
    )
}

/// Probe whether HVF can actually run here. The in-house VMM's lifecycle is
/// platform-agnostic (spawns a binary + tracks PID files), so it compiles
/// everywhere; only this probe is macOS/Apple-silicon-specific.
pub(crate) fn hvf_probe() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        crate::hvf::probe_available()
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_path_env_must_point_at_a_file() {
        // SAFETY: single-threaded test mutation of a process env var.
        unsafe { std::env::set_var("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor") };
        let r = resolve_supervisor_path();
        unsafe { std::env::remove_var("MVM_HVF_SUPERVISOR_PATH") };
        assert!(r.is_err());
    }
}
