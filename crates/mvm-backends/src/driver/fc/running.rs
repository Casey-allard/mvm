//! Live Firecracker handle and the selected original-process lifecycle.
use super::stop::prepare_guest_filesystems_for_stop;
use super::*;

impl FcDriver {
    #[cfg(target_os = "linux")]
    pub(super) fn original_exit_report(
        &self,
    ) -> Result<Option<super::owned_capture::CaptureReport>> {
        self.owned
            .as_ref()
            .map(|original| {
                Ok(original
                    .lock()
                    .map_err(|_| anyhow!("original Firecracker custody poisoned"))?
                    .exit_capture
                    .as_ref()
                    .context("original Firecracker exit worker absent")?
                    .report())
            })
            .transpose()
    }
    pub(super) fn has_original_lifetime(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.owned.is_some();
        #[cfg(not(target_os = "linux"))]
        false
    }

    pub(super) fn check_original_lifetime(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            original
                .lock()
                .map_err(|_| anyhow!("original Firecracker custody poisoned"))?
                .check_current()?;
        }
        Ok(())
    }

    pub(super) fn boot_process_id(&self, state_dir: &str) -> Result<u32> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            return Ok(original
                .lock()
                .map_err(|_| anyhow!("original Firecracker custody poisoned"))?
                .process()?
                .pid());
        }
        read_firecracker_pid(state_dir)
    }

    pub(super) fn authenticate_original_channel(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            let original = original
                .lock()
                .map_err(|_| anyhow!("original Firecracker custody poisoned"))?;
            original.check_current()?;
            original.process()?.authenticate_config(stream)?;
            original.check_current()?;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = stream;
        Ok(())
    }
}

/// A live Firecracker VM: the detached `firecracker` daemon tracked by its PID
/// file, with the workload's exit code persisted under its state dir and the
/// vsock mux UDS for host→guest dials.
pub(super) struct FcRunningVm {
    #[cfg(target_os = "linux")]
    pub(super) owned: Option<std::sync::Arc<std::sync::Mutex<owned::OwnedFcState>>>,
    #[cfg(target_os = "linux")]
    pub(super) original_report: Option<super::owned_capture::CaptureReport>,
    pub(super) id: VmId,
    pub(super) state_dir: PathBuf,
    pub(super) pid_file: PathBuf,
    /// Process identity captured while attaching, before any sidecar teardown
    /// can remove the recovery marker. `None` represents an already-stopped VM.
    pub(super) pid: Option<u32>,
    /// The single host-side vsock mux UDS (`<state_dir>/runtime/v.sock`); the
    /// host dials guest ports through the CONNECT handshake on this socket.
    pub(super) vsock_uds: String,
    /// Whether stopping asks the guest agent to flush filesystems first. False
    /// for a guest booted without an agent port (a builder or Stage 0 guest),
    /// which has no agent to ask and flushes its own disks before halting.
    pub(super) flush_via_agent: bool,
}

impl RunningVm for FcRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn host_process_id(&self) -> Option<u32> {
        self.pid
    }

    fn wait(&self) -> Result<VmExitStatus> {
        self.wait_with_deadline(
            Instant::now() + mvm_vmm::host::workload_wait::WORKLOAD_WAIT_TIMEOUT,
        )
    }

    fn wait_with_deadline(&self, until: Instant) -> Result<VmExitStatus> {
        #[cfg(target_os = "linux")]
        if self.owned.is_some() {
            let report = self
                .original_report
                .as_ref()
                .context("original Firecracker exit report absent")?;
            return report.wait(until);
        }
        Ok(mvm_vmm::host::workload_wait::wait_for_workload_exit_within(
            &self.state_dir,
            until.saturating_duration_since(Instant::now()),
        ))
    }

    fn original_workload_report(
        &self,
    ) -> Option<std::sync::Arc<dyn mvm_vmm::driver::OriginalWorkloadReport>> {
        #[cfg(target_os = "linux")]
        if self.owned.is_some() {
            return self.original_report.as_ref().map(|report| {
                std::sync::Arc::new(report.clone())
                    as std::sync::Arc<dyn mvm_vmm::driver::OriginalWorkloadReport>
            });
        }
        None
    }

    fn prepare_stop(&self) -> Result<()> {
        if !self.flush_via_agent {
            return Ok(());
        }
        let Some(pid) = self.pid else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            let original = original
                .lock()
                .map_err(|_| anyhow!("original Firecracker custody poisoned"))?;
            if original.process()?.wait_exit(Instant::now())?
                == mvm_vmm::host::process_exit::ProcessExitWait::Exited
            {
                return Ok(());
            }
            return super::stop::prepare_guest_filesystems_for_stop_with(
                &self.vsock_uds,
                |stream| original.process()?.authenticate_config(stream),
            );
        }
        if !crate::fc::is_firecracker_pid_running(pid)? {
            return Ok(());
        }
        let started = Instant::now();
        let result = prepare_guest_filesystems_for_stop(&self.vsock_uds);
        tracing::debug!(
            ms = started.elapsed().as_secs_f64() * 1000.0,
            ok = result.is_ok(),
            "fc stop: guest filesystem flush"
        );
        result
    }

    fn kill(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            return original
                .lock()
                .map_err(|_| anyhow!("original Firecracker custody poisoned"))?
                .stop_original(
                    Instant::now()
                        + crate::driver::libkrun_process::STOP_TIMEOUT
                        + Duration::from_millis(500),
                );
        }
        // Firecracker runs as the invoking user, so the signal is a plain
        // kill; liveness is probed via /proc/<pid>/comm so a recycled pid is
        // not mistaken for the VMM. The escalation is SIGTERM → grace →
        // SIGKILL, mirroring the raw stop path.
        let Some(pid) = self.pid else {
            return Ok(());
        };
        if !crate::fc::is_firecracker_pid_running(pid)? {
            remove_pid_marker_if_matches(&self.pid_file, pid);
            return Ok(());
        }
        terminate_firecracker_pid(&self.id.0, pid, &self.pid_file)
    }

    #[cfg(target_os = "linux")]
    fn terminate_with_kernel_exit(&self) -> Result<mvm_vmm::driver::traits::KernelStopOutcome> {
        let fc_exit = match &self.owned {
            Some(original) => Some(
                original
                    .lock()
                    .map_err(|_| anyhow!("original Firecracker custody poisoned"))?
                    .collect_original(
                        Instant::now()
                            + crate::driver::libkrun_process::STOP_TIMEOUT
                            + Duration::from_millis(500),
                    )?,
            ),
            None => {
                self.kill()?;
                None
            }
        };
        Ok(mvm_vmm::driver::traits::KernelStopOutcome {
            timing: None,
            hvf_exit: None,
            fc_exit,
        })
    }

    fn process_identity(&self) -> Result<Option<mvm_vmm::host::process_identity::ProcessIdentity>> {
        #[cfg(target_os = "linux")]
        if self.owned.is_some() {
            return Ok(None);
        }
        let Some(pid) = self.pid else {
            return Ok(None);
        };
        let socket = crate::fc::fc_api_socket_path(&self.state_dir.to_string_lossy());
        bind_process_to_socket(
            &self.id.0,
            pid,
            |pid| crate::fc::is_firecracker_for_socket(pid, Path::new(&socket)),
            mvm_vmm::host::process_identity::ProcessIdentity::capture,
        )
    }

    #[cfg(target_os = "linux")]
    fn check_original_firecracker_kernel(
        &self,
        anchor: &mvm_core::host_lifetime::HostLifetimeAnchor,
    ) -> Result<()> {
        let original = self
            .owned
            .as_ref()
            .context("original Firecracker owner unavailable")?
            .lock()
            .map_err(|_| anyhow!("original Firecracker custody poisoned"))?;
        original.check_kernel_anchor(anchor)
    }

    #[cfg(target_os = "linux")]
    fn open_owned_entrypoint(
        &self,
        anchor: std::sync::Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
        identity: mvm_vmm::driver::OriginalEntrypointIdentity,
        until: Instant,
    ) -> Result<Box<dyn mvm_vmm::driver::OriginalEntrypointChannel>> {
        super::entrypoint::open(
            std::sync::Arc::clone(
                self.owned
                    .as_ref()
                    .context("original Firecracker owner unavailable")?,
            ),
            anchor,
            identity,
            Path::new(&self.vsock_uds),
            until,
        )
    }

    fn pause(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            return owned::set_vm_state(original, &self.state_dir, "Paused");
        }
        // Firecracker exposes vCPU pause via the control API; reuse the existing
        // FC control helper (PATCH /vm InstanceState) keyed by the VM name.
        crate::fc::pause_vm(&self.id.0)
    }

    fn resume(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            return owned::set_vm_state(original, &self.state_dir, "Resumed");
        }
        crate::fc::resume_vm(&self.id.0)
    }

    fn status(&self) -> Result<VmStatus> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.owned {
            let original = original
                .lock()
                .map_err(|_| anyhow!("original Firecracker custody poisoned"))?;
            if original.retired
                || original.process()?.wait_exit(Instant::now())?
                    == mvm_vmm::host::process_exit::ProcessExitWait::Exited
            {
                return Ok(VmStatus::Stopped);
            }
            original.check_current()?;
            return Ok(VmStatus::Running);
        }
        // Probe via /proc/<pid>/comm, reusing FC's own liveness helper, so a
        // recycled pid is not mistaken for the VMM.
        firecracker_status_with(self.pid, crate::fc::is_firecracker_pid_running)
    }

    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        // Firecracker multiplexes every host→guest connection over the single
        // vsock UDS, selecting the destination port via the `CONNECT <port>\n`
        // handshake. Restricted to agent, telemetry and dev-only console data
        // ports (a sealed prod boot registers no console listeners), mirroring
        // the other drivers' allow-list.
        if !super::super::host_dialable_port(guest_port) {
            bail!(
                "Firecracker driver vsock_connect supports only the agent port \
                 ({GUEST_AGENT_PORT}), telemetry and dev console data ports ({}..={}); got {guest_port}",
                CONSOLE_PORT_BASE + 1,
                CONSOLE_PORT_BASE + 128,
            );
        }
        #[cfg(target_os = "linux")]
        let held = match &self.owned {
            Some(original) => {
                let held = original
                    .lock()
                    .map_err(|_| anyhow!("original Firecracker custody poisoned"))?;
                held.check_current()?;
                Some(held)
            }
            None => None,
        };
        let stream = connect_to_port(&self.vsock_uds, guest_port, VSOCK_CONNECT_TIMEOUT_SECS)
            .with_context(|| {
                format!(
                    "connect to Firecracker vsock port {guest_port} via {}",
                    self.vsock_uds
                )
            })?;
        #[cfg(target_os = "linux")]
        if let Some(held) = held {
            held.process()?.authenticate_config(&stream)?;
            held.check_current()?;
        }
        Ok(Box::new(stream))
    }
}
