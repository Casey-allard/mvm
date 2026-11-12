//! Same-host endpoint mapping from two original installed leases. A mapping
//! is an observation; it cannot enable ReliableV1 or issue a routing grant.
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::{
    mailbox::{MAILBOX_PORT, PrincipalId, local::LocalGreeting},
    mailbox_worker::{MailboxWorkerBackend, MailboxWorkerOwner, MailboxWorkerState},
};
use mvm_core::{mailbox::frame::cast::CastChannel, vm_backend::HostDialRoute};
use mvm_runtime::backend::AnyBackend;
use std::time::Instant;

use super::{derived_keys, now_unix_ms, template_for};
use crate::{mailbox_process::owned_client::InstalledMailboxClient, plan_admission::AdmittedPlan};

/// Each client must still authenticate its connected peer as the original
/// installed worker. Merely parsing an independently signed plan is insufficient.
pub struct InstalledCastParticipant<'a> {
    pub plan: &'a AdmittedPlan,
    pub worker: &'a InstalledMailboxClient,
}

impl InstalledCastParticipant<'_> {
    fn serving_owner(
        &self,
        expected_backend: MailboxWorkerBackend,
        deadline: Instant,
    ) -> Result<&MailboxWorkerOwner> {
        use mvm_core::protocol::mailbox_worker_control::context_commitment;
        let a = self.worker.acquire_request();
        let signed = self.plan.plan();
        let owner = self
            .worker
            .owner()
            .context("missing original acquired mailbox owner")?;
        ensure!(
            a.backend == expected_backend
                && a.tenant == signed.tenant.0
                && a.workload_id == signed.workload.0
                && a.vm_id == signed.workload.0
                && signed.mailbox == Some(a.mailbox_grant)
                && self.plan.plan_id().0 == format!("sha256:{}", hex::encode(a.plan_commitment))
                && context_commitment(a)? == owner.context_commitment,
            "installed Cast participant differs from the admitted plan"
        );
        ensure!(
            self.worker.query(deadline)? == MailboxWorkerState::Serving,
            "original Cast participant is not serving"
        );
        Ok(owner)
    }
}

/// The original backend's port-5257 route and the locally authenticated channel
/// it would serve. A router cannot construct the channel from its frame headers.
/// A caller must still hold the *destination role owner's* live route, keyset,
/// shared reservation and matching session greeting when calling dispatch_on.
/// Candidate discovery alone consequently has no I/O or durable receipt effect.
pub struct InstalledCastMapping {
    pub channel: CastChannel,
    pub destination_route: HostDialRoute,
}

pub fn map_installed_cast_pair(
    source: InstalledCastParticipant<'_>,
    destination: InstalledCastParticipant<'_>,
    backend: &AnyBackend,
    trusted_plan_signers: &[(&str, &VerifyingKey)],
    destination_greeting: LocalGreeting,
    deadline: Instant,
) -> Result<InstalledCastMapping> {
    use mvm_runtime::catalog::BackendKind;
    let kind = match backend.kind() {
        BackendKind::Firecracker => MailboxWorkerBackend::Firecracker,
        BackendKind::Hvf => MailboxWorkerBackend::Hvf,
        _ => anyhow::bail!("backend has no installed mailbox pair binding"),
    };
    let left = source.serving_owner(kind, deadline)?;
    let right = destination.serving_owner(kind, deadline)?;
    ensure!(
        left.daemon_boot_nonce == right.daemon_boot_nonce
            && left.lease != right.lease
            && left.context_commitment != right.context_commitment,
        "pair requires distinct leases of the same live coordinator"
    );
    let src = &source.worker.acquire_request().mailbox_grant;
    let dst = &destination.worker.acquire_request().mailbox_grant;
    let keys = mvm_core::config::mvm_keys_dir();
    let origin = derived_keys(&keys, &src.mailbox, src.epoch)?;
    let target = derived_keys(&keys, &dst.mailbox, dst.epoch)?;
    ensure!(
        origin.authority.verifying_key().to_bytes() == src.authority_key
            && target.authority.verifying_key().to_bytes() == dst.authority_key,
        "installed root differs from admitted mailbox authority"
    );
    let now = now_unix_ms();
    let template = template_for(&keys, &target, dst, now)?;
    let channel = CastChannel::from_signed_pair(
        source.plan.signed(),
        destination.plan.signed(),
        trusted_plan_signers,
        (source.plan.plan_id(), destination.plan.plan_id()),
        destination_greeting,
        PrincipalId::from_bytes(origin.sender.verifying_key().to_bytes()),
        template.header.recipient,
        now,
    )?;
    let state = mvm_core::config::vm_state_dir(&destination.worker.acquire_request().vm_id);
    let destination_route = backend
        .host_dial_route(&state, MAILBOX_PORT)
        .context("installed backend has no mailbox route")?;
    Ok(InstalledCastMapping {
        channel,
        destination_route,
    })
}
