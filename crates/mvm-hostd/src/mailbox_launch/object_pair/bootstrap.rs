//! Private, original owner to per-VM process configuration. Only the public
//! role and enrollment are exposed by the guest reader. The two Linux pidfds
//! travel separately on the original child's anonymous Unix control channel.
use super::*;
use mvm_core::mailbox::journal::{HistoryKeyCustody, HistoryKeyRef};
use mvm_core::mailbox::object_pair::role::{ObjectParticipantRole, SignedObjectRoleV1};
use mvm_core::vm_backend::{BackendKind, HostDialRoute};
use mvm_runtime::AnyBackend;
use serde::{Deserialize, Serialize};
use std::os::fd::BorrowedFd;
use std::path::PathBuf;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalVmmId {
    pub(crate) pid: u32,
    pub(crate) birth: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjectWorkerBootstrapV1 {
    pub(crate) role: SignedObjectRoleV1,
    pub(crate) caller_plan: SignedExecutionPlan,
    pub(crate) callee_plan: SignedExecutionPlan,
    pub(crate) plan_verifier: [u8; 32],
    pub(crate) caller_receive: SignedMailboxCapability,
    pub(crate) callee_receive: SignedMailboxCapability,
    pub(crate) reader_enrollment: SignedMailboxGuestReaderEnrollment,
    pub(crate) caller_vmm: OriginalVmmId,
    pub(crate) callee_vmm: OriginalVmmId,
    pub(crate) home: PathBuf,
    pub(crate) route: HostDialRoute,
    pub(crate) routing: MailboxRoutingFrame,
    pub(crate) local_journal: PathBuf,
    pub(crate) local_anchor: PathBuf,
    pub(crate) local_intents: PathBuf,
    pub(crate) history_ref: HistoryKeyRef,
    pub(crate) secrets: ObjectWorkerSecrets,
}

// No Debug or Clone: never format the private handoff; decoded buffers clear
// their own secret material. The peer's signer and host signing key are absent.
#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjectWorkerSecrets {
    pub(crate) local_sender: [u8; 32],
    pub(crate) local_authority: [u8; 32],
    pub(crate) inbound: [u8; 32],
    pub(crate) outbound: [u8; 32],
    pub(crate) history: [u8; 32],
    pub(crate) anchor: [u8; 32],
}

impl InstalledParticipant<'_> {
    fn worker_pidfd(&self) -> Result<(OriginalVmmId, BorrowedFd<'_>)> {
        let OriginalNative::Firecracker(native) = self.original else {
            anyhow::bail!("object worker pidfd handoff requires original Linux Firecracker");
        };
        let (pid, fd) = native.original_peer()?;
        let generation = mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(pid);
        let birth = generation
            .started
            .context("original VMM birth unavailable")?;
        ensure!(
            generation.is_live_and_ours(),
            "original VMM changed during capture"
        );
        native.require_live()?;
        Ok((OriginalVmmId { pid, birth }, fd))
    }
}

impl InstalledObjectPair<'_> {
    pub(crate) fn original_worker_bootstrap(
        &self,
        local_role: ObjectParticipantRole,
        backend: &AnyBackend,
    ) -> Result<(ObjectWorkerBootstrapV1, [BorrowedFd<'_>; 2])> {
        self.check_current()?;
        ensure!(
            backend.kind() == BackendKind::Firecracker,
            "wrong mailbox backend"
        );
        let (a, afd) = self.caller.worker_pidfd()?;
        let (b, bfd) = self.callee.worker_pidfd()?;
        ensure!(a.pid != b.pid, "two object endpoints selected the same VMM");
        let (source, local) = match local_role {
            ObjectParticipantRole::Caller => (&self.caller, &self.material.caller),
            ObjectParticipantRole::Callee => (&self.callee, &self.material.callee),
        };
        let keys = mvm_core::config::mvm_keys_dir();
        let paths = local.custody.storage_paths(&keys)?;
        let local_keys = super::super::derived_keys(
            &keys,
            &local.reader.grant.mailbox,
            local.reader.grant.epoch,
        )?;
        ensure!(
            local_keys.authority.verifying_key().to_bytes() == local.reader.grant.authority_key
                && local_keys.sender.verifying_key() == local.sender.verifying_key(),
            "local worker signer changed"
        );
        let state = mvm_core::config::vm_state_dir(&source.admitted.plan().image.name);
        let route = backend
            .host_dial_route(&state, MAILBOX_PORT)
            .context("no admitted guest mailbox route")?;
        let history_ref = local.custody.history_reference();
        let history = local.custody.load_existing(&history_ref)?;
        let config = ObjectWorkerBootstrapV1 {
            role: local.public_role.clone(),
            caller_plan: self.caller.admitted.signed().clone(),
            callee_plan: self.callee.admitted.signed().clone(),
            plan_verifier: self.material.plan_verifier.to_bytes(),
            caller_receive: self.prepared.credentials.receive_at_caller.clone(),
            callee_receive: self.prepared.credentials.receive_at_callee.clone(),
            reader_enrollment: local.reader.enrollment.clone(),
            caller_vmm: a,
            callee_vmm: b,
            home: mvm_core::config::mvm_home_strict()?,
            route,
            routing: local.routing.clone(),
            local_journal: paths.journal,
            local_anchor: paths.anchor,
            local_intents: paths.source_intents,
            history_ref,
            secrets: ObjectWorkerSecrets {
                local_sender: local.sender.to_bytes(),
                local_authority: local_keys.authority.to_bytes(),
                inbound: *local.inbound_key.expose_bytes(),
                outbound: *local.outbound_key.expose_bytes(),
                history: *history.expose_bytes(),
                anchor: local.custody.anchor_key(),
            },
        };
        self.check_current()?;
        Ok((config, [afd, bfd]))
    }
}
