//! Original SDK custody of the selected Linux object mailbox workers.
use super::{LaunchClaim, OriginalMarker, stop::StopCustody};
use crate::mailbox_launch::object_pair::{InstalledObjectPair, bootstrap::ObjectWorkerBootstrapV1};
use anyhow::{Result, ensure};
use mvm_core::mailbox::{
    object_pair::role::ObjectParticipantRole as Role, reader::MailboxReaderBootBinding,
};
use mvm_runtime::AnyBackend;
use std::{
    io::Read,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Stdio},
    sync::Arc,
    time::Instant,
};

pub struct OriginalObjectWorker {
    pub(super) name: String,
    pub(super) boot: MailboxReaderBootBinding,
    pub(super) claim: Arc<LaunchClaim>,
    pub(super) stop: StopCustody,
    pub(super) marker: OriginalMarker,
    pub(super) child: Child,
    control: UnixStream,
}
impl OriginalObjectWorker {
    pub fn owner(&mut self) -> super::JournalOwner<'_> {
        super::JournalOwner::Object(self)
    }
    fn spawn(config: &ObjectWorkerBootstrapV1, claim: Arc<LaunchClaim>) -> Result<Self> {
        let a = config.validate_current()?;
        let name = a.local_plan.image.name;
        let boot = config.role.role.local().clone();
        let original = match config.role.role.role {
            Role::Caller => config.caller_vmm,
            Role::Callee => config.callee_vmm,
        };
        let stop = StopCustody::capture_object(&a.local_state, original)?;
        let (control, peer) = UnixStream::pair()?;
        let mut cmd = super::super::serving_command()?;
        cmd.arg("--original-object-endpoint-v1")
            .stdin(Stdio::from(OwnedFd::from(peer)))
            .stdout(Stdio::null());
        let (child, marker) = super::spawn_claimed(&claim.owner_dir, cmd)?;
        Ok(Self {
            name,
            boot,
            claim,
            stop,
            marker,
            child,
            control,
        })
    }
    fn wait_ready(&mut self, until: Instant) -> Result<()> {
        let mut reader =
            crate::mailbox_service::durable::GuestDeadline::new(self.control.try_clone()?, until)?;
        let mut marker = [0; 6];
        reader.read_exact(&mut marker)?;
        ensure!(
            &marker == b"READY\n" && self.child.try_wait()?.is_none(),
            "object endpoint did not become ready"
        );
        Ok(())
    }
}

/// Slots are filled immediately after each successful exec. An error after
/// exec returns through the same slots, so the SDK can stop each original.
#[derive(Default)]
pub struct OriginalObjectWorkers {
    pub caller: Option<OriginalObjectWorker>,
    pub callee: Option<OriginalObjectWorker>,
}

impl InstalledObjectPair<'_> {
    pub fn start_original_workers(
        &self,
        caller: &AnyBackend,
        callee: &AnyBackend,
        owners: &mut OriginalObjectWorkers,
        until: Instant,
    ) -> Result<()> {
        use crate::mailbox_process::object_worker::send_launch;
        ensure!(
            owners.caller.is_none() && owners.callee.is_none(),
            "an original object worker is still owned"
        );
        let (a, afds) = self.original_worker_bootstrap(Role::Caller, caller)?;
        let (b, bfds) = self.original_worker_bootstrap(Role::Callee, callee)?;
        let ca = self.registration.original_claim(Role::Caller)?;
        let cb = self.registration.original_claim(Role::Callee)?;
        let (a_out, b_in) = UnixStream::pair()?;
        let (b_out, a_in) = UnixStream::pair()?;
        mvm_vmm::host::process_exit::require_owned_child_custody()?;
        ensure!(Instant::now() < until, "original launch deadline elapsed");
        let a_worker = owners.caller.insert(OriginalObjectWorker::spawn(&a, ca)?);
        send_launch(&a_worker.control, &a, afds, [&a_out, &a_in], until)?;
        self.registration.require_originals()?;
        ensure!(Instant::now() < until, "original launch deadline elapsed");
        let b_worker = owners.callee.insert(OriginalObjectWorker::spawn(&b, cb)?);
        send_launch(&b_worker.control, &b, bfds, [&b_out, &b_in], until)?;
        drop((a_out, a_in, b_out, b_in));
        a_worker.wait_ready(until)?;
        b_worker.wait_ready(until)?;
        self.registration.require_originals()?;
        a.validate_current()?;
        b.validate_current()?;
        ensure!(
            a_worker.child.try_wait()?.is_none() && b_worker.child.try_wait()?.is_none(),
            "original object helper exited during bilateral readiness"
        );
        Ok(())
    }
}

mod join;
pub use join::{OriginalLaunchGuard, OriginalObjectLaunch};
