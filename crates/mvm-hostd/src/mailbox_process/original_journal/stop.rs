//! Stop authority for an already held paired mailbox original.
use super::{OriginalJournalDestination, OriginalMarker, relay::OriginalJournalSourceHost};
use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::vm_backend::{BackendKind, VmId};
use mvm_core::{mailbox::reader::MailboxReaderBootBinding, plan::ExecutionPlan};
use mvm_runtime::AnyBackend;
use mvm_vmm::host::{
    network_endpoint_spawn::EndpointPid,
    process_exit::{ProcessExitObserver, ProcessExitWait},
};
use std::{
    fs::File,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    process::{Child, ExitStatus},
    sync::Arc,
    time::{Duration, Instant},
};

struct InstalledStopOwner<'a> {
    backend: &'a AnyBackend,
    anchor: &'a Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
}

impl InstalledStopOwner<'_> {
    fn check_name(&self, name: &str) -> Result<()> {
        ensure!(
            self.anchor.binding().vm_name == name
                && self.anchor.binding().backend == self.backend.kind(),
            "original installed journal stop binding differs"
        );
        ensure!(
            cfg!(target_os = "linux") && self.backend.kind() == BackendKind::Firecracker,
            "original installed journal stop backend unavailable"
        );
        Ok(())
    }
}

#[cfg(test)]
mod owned_stop_tests;

pub(super) struct StopCustody {
    state: File,
    split_socket: Option<(std::path::PathBuf, File)>,
    kind: BackendKind,
    // Component-only helper fixtures need no VMM. A real typed stop always
    // requires the originally observed kernel identity before touching a VMM.
    vmm: Option<(EndpointPid, ProcessExitObserver)>,
    #[cfg(target_os = "macos")]
    pub(super) hvf: Option<crate::plan_admission::object_hvf::OriginalHvf>,
    sdk_abort_confirmed: bool,
    vm_stopped: bool,
    kernel_exit_observed: bool,
    assisted: bool,
    sdk_cleanup: Option<ExitStatus>,
}

impl StopCustody {
    pub(super) fn capture(
        config: &crate::mailbox_process::MailboxProcessConfig,
        backend: &AnyBackend,
        name: &str,
    ) -> Result<Self> {
        let pid = backend
            .host_process_id(&VmId(name.into()))?
            .context("no installed VMM process to observe")?;
        let original = EndpointPid::of_child(pid);
        ensure!(original.is_live_and_ours(), "no live original VMM identity");
        let observer = ProcessExitObserver::arm(original.pid)?;
        ensure!(
            original.is_live_and_ours(),
            "original VMM changed while arming observer"
        );
        Self::capture_state(
            &config.vm_state_dir,
            backend.kind(),
            Some((original, observer)),
        )
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn capture_object(
        state_dir: &std::path::Path,
        original: crate::mailbox_launch::object_pair::bootstrap::OriginalVmmId,
    ) -> Result<Self> {
        let id = EndpointPid {
            pid: original.pid.try_into()?,
            started: Some(original.birth),
        };
        ensure!(
            id.is_live_and_ours(),
            "original object VMM generation changed"
        );
        let observer = ProcessExitObserver::arm(id.pid)?;
        ensure!(
            id.is_live_and_ours(),
            "original object VMM generation changed during observation"
        );
        #[cfg(target_os = "linux")]
        let kind = BackendKind::Firecracker;
        #[cfg(target_os = "macos")]
        let kind = BackendKind::Hvf;
        Self::capture_state(state_dir, kind, Some((id, observer)))
    }
    fn capture_state(
        state_dir: &std::path::Path,
        kind: BackendKind,
        vmm: Option<(EndpointPid, ProcessExitObserver)>,
    ) -> Result<Self> {
        let state = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(state_dir)?;
        let socket_dir = mvm_core::config::vm_socket_dir_at(state_dir);
        let split_socket = if socket_dir != state_dir {
            let fd = File::options()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(&socket_dir)?;
            Some((socket_dir, fd))
        } else {
            None
        };
        Ok(Self {
            state,
            split_socket,
            kind,
            vmm,
            #[cfg(target_os = "macos")]
            hvf: None,
            sdk_abort_confirmed: false,
            vm_stopped: false,
            kernel_exit_observed: false,
            assisted: false,
            sdk_cleanup: None,
        })
    }
    pub(super) fn live_for_reconnect(
        &mut self,
        state: &std::path::Path,
    ) -> Result<super::super::lifetime::OriginalVmm> {
        ensure!(
            !self.vm_stopped
                && !self.sdk_abort_confirmed
                && !self.kernel_exit_observed
                && self.sdk_cleanup.is_none(),
            "original VM is retiring"
        );
        let check = |fd: &File, path: &std::path::Path| -> Result<()> {
            require_directory(fd, path)?;
            let m = fd.metadata()?;
            ensure!(
                m.mode() & 0o022 == 0 && m.uid() == rustix::process::geteuid().as_raw(),
                "unsafe original runtime or socket directory"
            );
            Ok(())
        };
        check(&self.state, state)?;
        if let Some((path, fd)) = &self.split_socket {
            check(fd, path)?;
        }
        let (identity, observer) = self.vmm.as_ref().context("original VMM observer absent")?;
        ensure!(identity.is_live_and_ours(), "original VM has exited");
        if observer.wait_event(Instant::now())? == ProcessExitWait::Exited {
            // On Darwin this observation consumes the original exit event.
            // Preserve it for the later SDK stop/collection owner.
            self.kernel_exit_observed = true;
            anyhow::bail!("original VM has exited");
        }
        ensure!(identity.is_live_and_ours(), "original VM has exited");
        Ok(super::super::lifetime::OriginalVmm::from_held(*identity)?)
    }
    pub(super) fn socket_parent(&self) -> &File {
        self.split_socket.as_ref().map_or(&self.state, |(_, fd)| fd)
    }
    pub(super) fn spawn_helper(
        &self,
        config: &crate::mailbox_process::MailboxProcessConfig,
        owner_dir: &std::path::Path,
    ) -> Result<(
        Child,
        OriginalMarker,
        Option<String>,
        super::reconnect::RestartInput,
    )> {
        let command = super::super::serving_command()?;
        let mut restart =
            super::reconnect::RestartInput::capture(config, command.get_program(), owner_dir)?;
        let mut command = restart.command()?;
        let original = self
            .vmm
            .as_ref()
            .map(|(id, _)| super::super::lifetime::OriginalVmm::from_held(*id))
            .transpose()?;
        if original.is_some() {
            command.arg(super::super::ORIGINAL_JOURNAL_V1);
        }
        let (mut child, marker) = super::spawn_claimed(owner_dir, command)?;
        let until = Instant::now() + super::super::READY_TIMEOUT;
        let readiness = match original {
            Some(original_vmm_v1) => super::super::configure_serving(
                &super::super::OriginalJournalStartup {
                    config,
                    original_vmm_v1,
                    required_reader_sha256: None,
                },
                &mut child,
            ),
            None => super::super::configure_serving(config, &mut child),
        };
        let readiness = readiness
            .and_then(|()| restart.capture_socket(&mut child, self.socket_parent(), until));
        Ok((
            child,
            marker,
            readiness.err().map(|e| e.to_string()),
            restart,
        ))
    }
    pub(super) fn observe_helper(
        &self,
        marker: &mut OriginalMarker,
        child: &mut Child,
    ) -> std::io::Result<Option<ExitStatus>> {
        if self.vmm.is_some() {
            return child.try_wait(); // Durable original claim survives through typed SDK cleanup.
        }
        #[cfg(test)]
        {
            marker.collect(child)
        }
        #[cfg(not(test))]
        {
            let _ = marker;
            Err(std::io::Error::other("missing installed VMM custody"))
        }
    }
}

pub enum JournalOwner<'a> {
    Source(&'a mut OriginalJournalSourceHost),
    Destination(&'a mut OriginalJournalDestination),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Object(&'a mut super::object_workers::OriginalObjectWorker),
}

#[derive(Debug)]
pub struct JournalStopOutcome {
    pub helper_status: ExitStatus,
    pub assisted: bool,
}

impl JournalOwner<'_> {
    fn parts(
        &mut self,
    ) -> (
        &str,
        &MailboxReaderBootBinding,
        &super::LaunchClaim,
        &mut StopCustody,
        &mut OriginalMarker,
        &mut Child,
    ) {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Object(w) => (
                &w.name,
                &w.boot,
                &w.claim,
                &mut w.stop,
                &mut w.marker,
                &mut w.child,
            ),
            Self::Source(a) => (
                &a.plan.image.name,
                &a.boot,
                &a._guard,
                &mut a.stop,
                &mut a.marker,
                &mut a.source,
            ),
            Self::Destination(b) => (
                &b.name,
                &b.boot,
                &b._original,
                &mut b.stop,
                &mut b.marker,
                &mut b.child,
            ),
        }
    }

    /// Abort a failed launch through its own original backend. Only a positive
    /// backend return creates this abort record. Collection separately checks
    /// the kernel observer that was armed while this generation was live.
    pub fn abort_original_launch(
        &mut self,
        plan: &ExecutionPlan,
        backend: &AnyBackend,
        id: &VmId,
    ) -> Result<()> {
        #[cfg(target_os = "macos")]
        let is_object = matches!(self, Self::Object(_));
        let (name, boot, _, state, _, _) = self.parts();
        ensure!(
            name == plan.image.name && name == id.0,
            "abort belongs to another VM"
        );
        boot.check_plan(plan)?;
        let (original, _) = state.vmm.as_ref().context("original VMM observer absent")?;
        #[cfg(target_os = "macos")]
        if is_object {
            let hvf = state
                .hvf
                .as_ref()
                .context("original HVF worker has no retained native stop authority")?;
            ensure!(
                backend.kind() == BackendKind::Hvf,
                "different original backend"
            );
            hvf.stop()?;
            state.sdk_abort_confirmed = true;
            return Ok(());
        }
        ensure!(
            backend.kind() == state.kind
                && original.is_live_and_ours()
                && backend.host_process_id(id)? == Some(original.pid as u32),
            "original VMM changed before abort"
        );
        backend.abort_start(id)?;
        state.sdk_abort_confirmed = true;
        Ok(())
    }

    /// Record rollback only after the actual installed backend confirms stop.
    pub fn abort_original_launch_owned(
        &mut self,
        plan: &ExecutionPlan,
        backend: &AnyBackend,
        id: &VmId,
        anchor: &Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
    ) -> Result<()> {
        InstalledStopOwner { backend, anchor }.check_name(&id.0)?;
        let (name, boot, guard, state, marker, _) = self.parts();
        ensure!(
            name == plan.image.name && name == id.0,
            "abort belongs to another VM"
        );
        boot.check_plan(plan)?;
        let dir = mvm_core::config::vm_state_dir(name);
        let owner =
            mvm_core::config::vm_mailbox_original_owner_at(&mvm_core::config::mvm_keys_dir(), name);
        ensure!(owner == guard.owner_dir, "different original installation");
        require_directory(&state.state, &dir)?;
        ensure!(
            &MailboxReaderBootBinding::load(&dir)? == boot && backend.kind() == state.kind,
            "original installed boot changed before abort"
        );
        marker.require_original()?;
        if state.sdk_abort_confirmed || state.vm_stopped {
            return Ok(());
        }
        let (original, _) = state.vmm.as_ref().context("original VMM observer absent")?;
        ensure!(
            original.is_live_and_ours()
                && backend.host_process_id(id)? == Some(original.pid as u32),
            "original installed VMM changed before abort"
        );
        backend.stop_owned(id, anchor)?;
        state.sdk_abort_confirmed = true;
        Ok(())
    }

    /// Stop only the original VM, collect its mailbox, then perform the caller's
    /// SDK accounting while the original name exclusion and launcher still hold.
    pub fn stop_and_collect(
        &mut self,
        name: &str,
        until: Instant,
        finish: impl FnOnce(&ExecutionPlan, bool) -> Result<()>,
    ) -> Result<JournalStopOutcome> {
        self.stop_and_collect_with_owner(name, until, None, finish)
    }

    /// Collect the same original mailbox after its installed native owner stops.
    pub fn stop_and_collect_owned(
        &mut self,
        name: &str,
        until: Instant,
        backend: &AnyBackend,
        anchor: &Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
        finish: impl FnOnce(&ExecutionPlan, bool) -> Result<()>,
    ) -> Result<JournalStopOutcome> {
        let installed = InstalledStopOwner { backend, anchor };
        installed.check_name(name)?;
        self.stop_and_collect_with_owner(name, until, Some(installed), finish)
    }

    fn stop_and_collect_with_owner(
        &mut self,
        name: &str,
        until: Instant,
        installed: Option<InstalledStopOwner<'_>>,
        finish: impl FnOnce(&ExecutionPlan, bool) -> Result<()>,
    ) -> Result<JournalStopOutcome> {
        #[cfg(target_os = "macos")]
        let is_object = matches!(self, Self::Object(_));
        let (original_name, boot, guard, state, marker, child) = self.parts();
        ensure!(original_name == name, "different original machine name");
        let dir = mvm_core::config::vm_state_dir(name);
        let owner =
            mvm_core::config::vm_mailbox_original_owner_at(&mvm_core::config::mvm_keys_dir(), name);
        ensure!(owner == guard.owner_dir, "different original installation");
        let _boot = super::PairedBootReservation::for_original_lifecycle(name)?;
        if let Some(status) = state.sdk_cleanup {
            // The SDK already disposed only the original directories. A retry
            // may finish the original marker's directory sync, but must not
            // reopen a VM or run cleanup against a later path.
            marker.clear_original()?;
            return Ok(JournalStopOutcome {
                helper_status: status,
                assisted: state.assisted,
            });
        }
        let same_state = || -> Result<()> {
            require_directory(&state.state, &dir)?;
            if let Some((path, fd)) = &state.split_socket {
                require_directory(fd, path)?;
            }
            Ok(())
        };
        same_state()?;
        let plan = crate::audit::plan_persist::read_plan(name)?;
        boot.check_plan(&plan)?;
        ensure!(
            &MailboxReaderBootBinding::load(&dir)? == boot,
            "VM boot changed since original launch"
        );
        ensure!(Instant::now() < until, "original stop deadline elapsed");
        if !marker.unlinked {
            marker.require_original()?;
        } else {
            ensure!(
                matches!(std::fs::symlink_metadata(&marker.path),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "replacement mailbox marker"
            );
        }
        ensure!(
            matches!(std::fs::symlink_metadata(dir.join(super::super::MAILBOX_PID_FILE)),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
            "unexpected ordinary mailbox PID record for paired original"
        );
        let (original, observer) = state
            .vmm
            .as_ref()
            .context("no original kernel process identity")?;
        if !state.vm_stopped && !state.sdk_abort_confirmed {
            let stop_registered = || -> Result<()> {
                if let Some(InstalledStopOwner { backend, anchor }) = &installed {
                    let vm = VmId(name.to_owned());
                    ensure!(
                        backend.kind() == state.kind
                            && original.is_live_and_ours()
                            && backend.host_process_id(&vm)? == Some(original.pid as u32),
                        "original installed VMM identity changed"
                    );
                    return backend.stop_owned(&vm, anchor);
                }
                let backend = AnyBackend::for_started_vm(name)
                    .context("original VMM backend is unavailable")?;
                let vm = VmId(name.to_owned());
                ensure!(
                    backend.kind() == state.kind
                        && original.is_live_and_ours()
                        && backend.host_process_id(&vm)? == Some(original.pid as u32),
                    "original VMM identity changed"
                );
                // The normal backend confirms kernel stop and handles all other
                // admitted services. The paired mailbox has no numeric PID record.
                backend.stop(&vm)?;
                Ok(())
            };
            #[cfg(target_os = "macos")]
            if is_object {
                state
                    .hvf
                    .as_ref()
                    .context("missing original HVF worker stop authority")?
                    .stop()?;
            } else {
                stop_registered()?;
            }
            #[cfg(not(target_os = "macos"))]
            stop_registered()?;
            state.vm_stopped = true;
        }
        let status = collect_after_vm(
            observer,
            &mut state.kernel_exit_observed,
            child,
            &mut state.assisted,
            until,
        )?;
        same_state()?;
        super::super::shred_epoch_secret(&dir)?;
        finish(&plan, state.sdk_abort_confirmed)?;
        state.sdk_cleanup = Some(status);
        marker.clear_original()?;
        Ok(JournalStopOutcome {
            helper_status: status,
            assisted: state.assisted,
        })
    }
}

fn require_directory(original: &File, path: &std::path::Path) -> Result<()> {
    let held = original.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    ensure!(
        current.is_dir() && (held.dev(), held.ino()) == (current.dev(), current.ino()),
        "VM runtime or socket directory changed since original launch"
    );
    Ok(())
}

fn collect_after_vm(
    observer: &ProcessExitObserver,
    kernel_exit_observed: &mut bool,
    child: &mut Child,
    assisted: &mut bool,
    until: Instant,
) -> Result<ExitStatus> {
    if !*kernel_exit_observed {
        ensure!(
            observer.wait_event(until)? == ProcessExitWait::Exited,
            "original VMM exit still unconfirmed"
        );
        *kernel_exit_observed = true;
    }
    // Allow one admitted in-flight exchange to unwind. An idle helper wakes
    // on kernel exit during backoff or at its next first-byte poll. Reserve a
    // short collection interval inside the caller's existing total deadline.
    let now = Instant::now();
    let remaining = until.saturating_duration_since(now);
    let reserve = Duration::from_millis(250).min(remaining / 4);
    let natural =
        now + (remaining - reserve).min(crate::mailbox_service::durable::GUEST_EXCHANGE_TIMEOUT);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let now = Instant::now();
        ensure!(now < until, "original mailbox collection deadline elapsed");
        if !*assisted && now >= natural {
            child.kill()?;
            *assisted = true;
        }
        std::thread::sleep(Duration::from_millis(10).min(until - now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    #[test]
    fn observed_helper_exit_keeps_the_original_claim_while_its_vm_lives() {
        let directory = tempfile::tempdir().unwrap();
        let mut marker = OriginalMarker::claim(directory.path()).unwrap();
        let mut vm = Command::new("sleep").arg("15").spawn().unwrap();
        let pid = EndpointPid::of_child(vm.id());
        let original = StopCustody {
            state: File::open(directory.path()).unwrap(),
            split_socket: None,
            kind: BackendKind::Firecracker,
            vmm: Some((pid, ProcessExitObserver::arm(pid.pid).unwrap())),
            #[cfg(target_os = "macos")]
            hvf: None,
            sdk_abort_confirmed: false,
            vm_stopped: false,
            kernel_exit_observed: false,
            assisted: false,
            sdk_cleanup: None,
        };
        let mut helper = Command::new("true").spawn().unwrap();
        helper.wait().unwrap();
        assert!(
            original
                .observe_helper(&mut marker, &mut helper)
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(marker.path.exists());
        assert!(vm.try_wait().unwrap().is_none());
        vm.kill().unwrap();
        vm.wait().unwrap();
    }

    #[test]
    fn reconnect_requires_the_still_running_original_and_its_protected_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("original");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut vm = Command::new("sleep").arg("20").spawn().unwrap();
        let id = EndpointPid::of_child(vm.id());
        let observer = ProcessExitObserver::arm(id.pid).unwrap();
        let mut owner =
            StopCustody::capture_state(&state, BackendKind::Firecracker, Some((id, observer)))
                .unwrap();
        assert!(owner.live_for_reconnect(&state).is_ok());
        owner.sdk_abort_confirmed = true;
        assert!(owner.live_for_reconnect(&state).is_err());
        owner.sdk_abort_confirmed = false;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(owner.live_for_reconnect(&state).is_err());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let replaced = dir.path().join("moved");
        std::fs::rename(&state, &replaced).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(owner.live_for_reconnect(&state).is_err());
        std::fs::remove_dir(&state).unwrap();
        std::fs::rename(&replaced, &state).unwrap();
        vm.kill().unwrap();
        vm.wait().unwrap();
        assert!(owner.live_for_reconnect(&state).is_err());
        assert!(owner.live_for_reconnect(&state).is_err());
    }

    #[test]
    fn replaced_socket_directory_cannot_be_cleaned_as_the_original() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        std::fs::create_dir(&path).unwrap();
        let original = File::open(&path).unwrap();
        require_directory(&original, &path).unwrap();
        std::fs::rename(&path, root.path().join("old")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("keep"), b"replacement").unwrap();
        assert!(require_directory(&original, &path).is_err());
        assert_eq!(std::fs::read(path.join("keep")).unwrap(), b"replacement");
    }

    #[test]
    fn unresolved_vmm_keeps_actual_helper_until_original_kernel_exit() {
        let directory = tempfile::tempdir().unwrap();
        let mut marker = OriginalMarker::claim(directory.path()).unwrap();
        let mut vm = Command::new("sleep").arg("15").spawn().unwrap();
        let observer = ProcessExitObserver::arm(vm.id() as i32).unwrap();
        let mut helper = Command::new("sleep").arg("15").spawn().unwrap();
        let mut observed = false;
        let mut assisted = false;
        let early = collect_after_vm(
            &observer,
            &mut observed,
            &mut helper,
            &mut assisted,
            Instant::now() + Duration::from_millis(20),
        );
        assert!(early.is_err() && !observed && !assisted);
        assert!(helper.try_wait().unwrap().is_none() && marker.path.is_file());
        vm.kill().unwrap();
        vm.wait().unwrap();
        let status = collect_after_vm(
            &observer,
            &mut observed,
            &mut helper,
            &mut assisted,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(!status.success() && observed && assisted && marker.path.exists());
        assert!(marker.collect(&mut helper).unwrap().is_some());
    }
}
