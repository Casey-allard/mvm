//! Same-host endpoint mapping from two original installed leases. A mapping
//! is an observation; it cannot enable ReliableV1 or issue a routing grant.
pub mod development;
pub(crate) mod source_pull;

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
        self.owner_in_state(expected_backend, deadline, MailboxWorkerState::Serving)
    }
    fn owner_in_state(
        &self,
        expected_backend: MailboxWorkerBackend,
        deadline: Instant,
        state: MailboxWorkerState,
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
            self.worker.query(deadline)? == state,
            "original Cast participant state changed"
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

/// A routing handle only the original live coordinator's checked provisioning
/// path can construct. A passive diagnostic map cannot route an envelope.
pub struct ServingCastMapping {
    channel: CastChannel,
    destination_route: HostDialRoute,
    destination_socket: std::path::PathBuf,
    source_socket: std::path::PathBuf,
    source_vm: String,
    destination_vm: String,
    source_owner: MailboxWorkerOwner,
    destination_owner: MailboxWorkerOwner,
    destination_sender: PrincipalId,
    destination_epoch: mvm_contract::protocol::mailbox::ExecutionEpoch,
    destination_greeting: LocalGreeting,
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

use crate::broker::mailbox_workers::{
    MailboxWorkers,
    cast_credit::{CAST_BODY_LIMIT, CastCredit},
};
use mvm_contract::protocol::mailbox::MailboxEnvelope;
use mvm_core::mailbox::{OpenContext, frame::cast::route::AddressedCastGrants};

/// Public identities read from the ORIGINAL two worker bindings, once, when
/// their configurations are admitted. The principal keys never leave either
/// endpoint. This entrypoint intentionally takes no template path or key file.
pub struct ServingCastParticipant<'a> {
    pub plan: &'a AdmittedPlan,
    pub owner: &'a MailboxWorkerOwner,
    pub current: &'a OpenContext,
}

/// Coordinator-native alternative to remote SDK Query. Look up both original
/// Serving slots from the one coordinator, bind their admitted plan digests,
/// and intersect their actual grants with the submitted address credentials.
/// Runtime callers must take the public policies from the original installed
/// endpoint owners. A caller cannot replace grant signatures with these fields.
pub fn map_serving_cast_pair(
    workers: &MailboxWorkers,
    source: ServingCastParticipant<'_>,
    destination: ServingCastParticipant<'_>,
    backend: &AnyBackend,
    trusted_plan_signers: &[(&str, &VerifyingKey)],
    destination_greeting: LocalGreeting,
    grants: AddressedCastGrants<'_>,
) -> Result<ServingCastMapping> {
    use mvm_core::protocol::mailbox_worker_control::context_commitment;
    use mvm_runtime::catalog::BackendKind;
    let kind = match backend.kind() {
        BackendKind::Firecracker => MailboxWorkerBackend::Firecracker,
        BackendKind::Hvf => MailboxWorkerBackend::Hvf,
        _ => anyhow::bail!("unsupported installed Cast backend"),
    };
    let (a, b) = (
        &source.plan.plan().workload.0,
        &destination.plan.plan().workload.0,
    );
    let requests = workers.original_cast_pair((a, source.owner), (b, destination.owner))?;
    for (request, participant) in requests.iter().zip([&source, &destination]) {
        let plan = participant.plan.plan();
        ensure!(
            request.backend == kind
                && request.tenant == plan.tenant.0
                && request.vm_id == plan.workload.0
                && request.workload_id == plan.workload.0
                && plan.mailbox == Some(request.mailbox_grant)
                && participant.plan.plan_id().0
                    == format!("sha256:{}", hex::encode(request.plan_commitment))
                && context_commitment(request)? == participant.owner.context_commitment,
            "original Cast worker differs from the signed plan"
        );
        ensure!(
            participant.current.expected_mailbox == request.mailbox_grant.mailbox
                && participant.current.current_execution_epoch == request.mailbox_grant.epoch,
            "changed original endpoint mailbox policy"
        );
    }
    let now = i64::try_from(workers.now_unix_ms()?)?;
    let mut channel = CastChannel::from_signed_pair(
        source.plan.signed(),
        destination.plan.signed(),
        trusted_plan_signers,
        (source.plan.plan_id(), destination.plan.plan_id()),
        destination_greeting,
        source.current.expected_sender,
        destination.current.expected_recipient,
        now,
    )?;
    channel.restrict_frame_budget(CAST_BODY_LIMIT as u32)?;
    let state = mvm_core::config::vm_state_dir(b);
    let route = backend
        .host_dial_route(&state, MAILBOX_PORT)
        .context("missing installed mailbox route")?;
    let mapping = ServingCastMapping {
        channel,
        destination_route: route,
        destination_socket: mvm_core::config::vm_mailbox_socket_at(&state),
        source_socket: mvm_core::config::vm_mailbox_socket_at(&mvm_core::config::vm_state_dir(a)),
        source_vm: a.to_owned(),
        destination_vm: b.to_owned(),
        source_owner: source.owner.clone(),
        destination_owner: destination.owner.clone(),
        destination_sender: destination.current.expected_sender,
        destination_epoch: requests[1].mailbox_grant.epoch,
        destination_greeting,
    };
    grants.check_compact_policy(source.current, destination.current)?;
    let (a, b) = mapping.current_policies(workers, source.current, destination.current)?;
    mapping.channel.authorize_addressed(grants, &a, &b)?;
    Ok(mapping)
}

/// One bounded ciphertext admitted to the existing tenant worker's ledger.
/// Neither participant's private key is part of this routing operation.
pub struct RoutedCast<'a> {
    canonical: Vec<u8>,
    envelope: MailboxEnvelope,
    grants: AddressedCastGrants<'a>,
    mapping: &'a ServingCastMapping,
    credit: CastCredit<'a>,
}

impl ServingCastMapping {
    pub fn destination_route(&self) -> &HostDialRoute {
        &self.destination_route
    }

    fn current_policies(
        &self,
        workers: &MailboxWorkers,
        source: &OpenContext,
        destination: &OpenContext,
    ) -> Result<(OpenContext, OpenContext)> {
        ensure!(
            destination.current_execution_epoch == self.destination_epoch
                && destination.expected_sender == self.destination_sender,
            "destination policy does not belong to its original mailbox epoch and sender"
        );
        // Preserve the original receiver's address/issuer/domain/revocations.
        // The canonical Send is exercised by A and its execution epoch.
        let now = i64::try_from(workers.now_unix_ms()?)?;
        let mut a = source.clone();
        a.now_unix_ms = now;
        let mut b = destination.clone();
        b.now_unix_ms = now;
        b.expected_sender = a.expected_sender;
        b.acting_principal = a.acting_principal;
        b.current_execution_epoch = a.current_execution_epoch;
        b.required_operation = mvm_contract::protocol::mailbox::MailboxOperation::Send;
        Ok((a, b))
    }

    /// Both contexts are the participants' original policy owners. The caller
    /// must sample their current revocations/epochs in a common admission turn.
    /// Unlike a destination capability, the source's own-address right only
    /// witnesses membership in its signed domain.
    pub fn route_opaque<'a>(
        &'a self,
        workers: &'a MailboxWorkers,
        envelope: MailboxEnvelope,
        grants: AddressedCastGrants<'a>,
        source_policy: &OpenContext,
        destination_policy: &OpenContext,
    ) -> Result<RoutedCast<'a>> {
        let credit = workers.reserve_cast(
            (&self.source_vm, &self.source_owner),
            (&self.destination_vm, &self.destination_owner),
        )?;
        self.route_reserved(credit, envelope, grants, source_policy, destination_policy)
    }

    fn route_reserved<'a>(
        &'a self,
        credit: CastCredit<'a>,
        envelope: MailboxEnvelope,
        grants: AddressedCastGrants<'a>,
        source_policy: &OpenContext,
        destination_policy: &OpenContext,
    ) -> Result<RoutedCast<'a>> {
        let workers = credit.workers();
        ensure!(
            self.channel.admits_workspace(
                crate::broker::mailbox_workers::cast_credit::CAST_WORK_BYTES as u64
            ),
            "routed workspace exceeds original signed limits"
        );
        envelope.validate_bounds()?;
        ensure!(
            envelope.ciphertext.len() <= CAST_BODY_LIMIT
                && envelope.ciphertext.capacity() <= CAST_BODY_LIMIT,
            "ciphertext outside installed workspace"
        );
        grants.check_compact_policy(source_policy, destination_policy)?;
        let (a, b) = self.current_policies(workers, source_policy, destination_policy)?;
        self.channel.authorize_addressed(grants, &a, &b)?;
        // Count the canonical complete JCS record, including encrypted-frame
        // metadata. Reuse the exact encoding at the protected handoff.
        let canonical = mvm_core::mailbox::encode_envelope(&envelope)?;
        ensure!(
            canonical.len() <= CAST_BODY_LIMIT
                && grants.admits_encoded_contribution(canonical.len()),
            "canonical envelope exceeds addressed queue or frame bound"
        );
        credit.admitted()?;
        Ok(RoutedCast {
            canonical,
            envelope,
            grants,
            mapping: self,
            credit,
        })
    }
}

pub struct AuthorizedOpaqueCast<'a> {
    pub envelope: &'a MailboxEnvelope,
    pub canonical_bytes: &'a [u8],
    pub grants: AddressedCastGrants<'a>,
}
impl RoutedCast<'_> {
    /// Forward to the original helper's preselected local data socket. Its
    /// immediate peer verdict is an ingress result, never a journal receipt
    /// or evidence of guest workload delivery. Source and destination policy
    /// must be resampled after connecting, immediately before transmission.
    pub fn forward_to_original_helper<S: std::borrow::Borrow<OpenContext>, D: std::borrow::Borrow<OpenContext>>(
        self,
        direction: &development::DevelopmentDirection,
        deadline: Instant,
        current: impl FnOnce() -> Result<(S, D)>,
    ) -> Result<Result<(), mvm_core::mailbox::frame::Refusal>> {
        self.exchange_at_destination(direction, deadline, current)
    }

    fn exchange_at_destination<S: std::borrow::Borrow<OpenContext>, D: std::borrow::Borrow<OpenContext>>(
        &self,
        direction: &development::DevelopmentDirection,
        deadline: Instant,
        current: impl FnOnce() -> Result<(S, D)>,
    ) -> Result<Result<(), mvm_core::mailbox::frame::Refusal>> {
        let deadline = deadline.min(Instant::now() + std::time::Duration::from_secs(5));
        let mut socket = mvm_agentd::vsock::connect_unix_before(&self.mapping.destination_socket, deadline)?;
        let (source, destination) = current()?;
        self.check_direction(direction, source.borrow(), destination.borrow())?;
        let body = mvm_core::mailbox::frame::encode_frame_from_canonical(self.grants.send, &self.canonical)?;
        self.credit.exchange_with_original(&mut socket, &body, direction.commitment(), deadline)
    }

    pub(crate) fn channel(&self) -> &CastChannel {
        &self.mapping.channel
    }
    pub(crate) fn policies(
        &self,
        source: &OpenContext,
        destination: &OpenContext,
    ) -> Result<(OpenContext, OpenContext)> {
        self.grants.check_compact_policy(source, destination)?;
        self.mapping
            .current_policies(self.credit.workers(), source, destination)
    }

    /// Hand the original sealed object and its three existing credentials to
    /// the authorized destination ingress. This router has no decryption key,
    /// plaintext output, caller-selected socket, or destination receipt. The
    /// admission remains charged while the returned borrows are in use.
    pub fn for_original_destination(
        &self,
        receiver: &MailboxWorkerOwner,
        source_policy: &OpenContext,
        destination_policy: &OpenContext,
    ) -> Result<AuthorizedOpaqueCast<'_>> {
        ensure!(
            receiver == &self.mapping.destination_owner,
            "wrong original Cast receiver"
        );
        self.credit.live()?;
        self.grants
            .check_compact_policy(source_policy, destination_policy)?;
        let (a, b) = self.mapping.current_policies(
            self.credit.workers(),
            source_policy,
            destination_policy,
        )?;
        self.mapping
            .channel
            .authorize_addressed(self.grants, &a, &b)?;
        Ok(AuthorizedOpaqueCast {
            envelope: &self.envelope,
            canonical_bytes: &self.canonical,
            grants: self.grants,
        })
    }
}

impl super::DerivedMailboxKeys {
    pub(crate) fn open_original_cast(
        &self,
        channel: &CastChannel,
        envelope: MailboxEnvelope,
        grants: AddressedCastGrants<'_>,
        key: &development::InstalledDirection,
        source: &OpenContext,
        destination: &OpenContext,
        replay: &mut impl mvm_core::mailbox::ReplayProtector,
        sequence: std::num::NonZeroU64,
    ) -> std::io::Result<mvm_core::mailbox::frame::cast::route::AddressedVerifiedCast> {
        let original = &self.template.header;
        if destination.expected_mailbox != original.mailbox
            || destination.expected_recipient != original.recipient
            || destination.expected_authorization_domain
                != key.scope().grant.address.authorization_domain
            || destination.expected_tenant != key.scope().grant.address.tenant
            || destination.expected_capability_issuer != self.template.capability.issuer
            || &envelope.encryption != key.context()
            || !key.admits_routing(&envelope.routing)
            || destination.current_policy_epoch != original.policy_epoch
            || envelope.ciphertext.capacity() > CAST_BODY_LIMIT
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "address outside original destination scope",
            ));
        }
        grants
            .check_compact_policy(source, destination)
            .map_err(std::io::Error::other)?;
        let now = now_unix_ms();
        let mut source = source.clone();
        source.now_unix_ms = now;
        let mut destination = destination.clone();
        destination.now_unix_ms = now;
        channel
            .open_addressed_if(
                envelope,
                grants,
                &source,
                &destination,
                key.key(),
                replay,
                sequence,
                |h| h.sender_boot == key.sender_boot(),
            )
            .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
    #[test]
    fn installed_default_mailbox_domains_differ_between_named_guests() {
        let home = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(home.path()).unwrap();
        let template = |id| {
            let mailbox = MailboxId::from_bytes([id; 32]);
            let epoch = ExecutionEpoch::new(1).unwrap();
            let d = derived_keys(home.path(), &mailbox, epoch).unwrap();
            let grant = MailboxGrant {
                mailbox,
                epoch,
                authority_key: d.authority.verifying_key().to_bytes(),
                local_service: None,
            };
            let t = template_for(home.path(), &d, &grant, 1_000).unwrap();
            let sig = mvm_core::mailbox::sign_capability(t.capability, &d.authority).unwrap();
            mvm_core::mailbox::verify_capability_signature(&sig, &d.authority.verifying_key())
                .unwrap();
            sig.grant.address
        };
        let a = template(1);
        let b = template(2);
        assert_ne!(a.tenant, b.tenant);
        assert_ne!(a.authorization_domain, b.authorization_domain);
        assert_ne!(a.mailbox, b.mailbox);
    }
}
