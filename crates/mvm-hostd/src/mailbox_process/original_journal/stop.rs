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
    time::{Duration, Instant},
};

pub(super) struct StopCustody {
    state: File,
    split_socket: Option<(std::path::PathBuf, File)>,
    kind: BackendKind,
    // Component-only helper fixtures need no VMM. A real typed stop always
    // requires the originally observed kernel identity before touching a VMM.
    vmm: Option<(EndpointPid, ProcessExitObserver)>,
    sdk_abort_confirmed: bool,
    vm_stopped: bool,
    kernel_exit_observed: bool,
    assisted: bool,
    sdk_cleanup: Option<ExitStatus>,
    pub(super) stop_started: bool,
}

impl StopCustody {
    pub(super) fn capture(
        config: &crate::mailbox_process::MailboxProcessConfig,
        backend: &AnyBackend,
        name: &str,
    ) -> Result<Self> {
        let state = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&config.vm_state_dir)?;
        let socket_dir = mvm_core::config::vm_socket_dir_at(&config.vm_state_dir);
        let split_socket = if socket_dir != config.vm_state_dir {
            let fd = File::options()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(&socket_dir)?;
            Some((socket_dir, fd))
        } else {
            None
        };
        let vmm = backend
            .host_process_id(&VmId(name.into()))
            .ok()
            .flatten()
            .map(EndpointPid::of_child)
            .filter(EndpointPid::is_live_and_ours)
            .and_then(|original| {
                let observer = ProcessExitObserver::arm(original.pid).ok()?;
                original.is_live_and_ours().then_some((original, observer))
            });
        Ok(Self {
            state,
            split_socket,
            kind: backend.kind(),
            vmm,
            sdk_abort_confirmed: false,
            vm_stopped: false,
            kernel_exit_observed: false,
            assisted: false,
            sdk_cleanup: None,
            stop_started: false,
        })
    }
}

pub enum JournalOwner<'a> {
    Source(&'a mut OriginalJournalSourceHost),
    Destination(&'a mut OriginalJournalDestination),
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
        let (name, boot, _, state, _, _) = self.parts();
        ensure!(
            name == plan.image.name && name == id.0,
            "abort belongs to another VM"
        );
        boot.check_plan(plan)?;
        let (original, _) = state.vmm.as_ref().context("original VMM observer absent")?;
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

    /// Stop only the original VM, collect its mailbox, then perform the caller's
    /// SDK accounting while the original name exclusion and launcher still hold.
    pub fn stop_and_collect(
        &mut self,
        name: &str,
        until: Instant,
        finish: impl FnOnce(&ExecutionPlan, bool) -> Result<()>,
    ) -> Result<JournalStopOutcome> {
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
        state.stop_started = true;
        if !state.vm_stopped && !state.sdk_abort_confirmed {
            let backend =
                AnyBackend::for_started_vm(name).context("original VMM backend is unavailable")?;
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
    let natural = Instant::now() + Duration::from_millis(250);
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
