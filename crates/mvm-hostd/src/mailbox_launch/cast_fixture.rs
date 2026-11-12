//! Development fixture issuer, built only by the two-guest qualification
//! controller. Uses the original disposable installation and the signed epoch
//! authority of each named mailbox; no serialized private key leaves this call.
use super::{
    cast_enrollment::{OriginalCastBoot, PreparedOriginalCastBoot},
    cast_pair::{
        InstalledCastParticipant,
        development::{self, DirectionDelivery, Participant, PreparedRole},
    },
    derived_keys, now_unix_ms, template_for,
};
use crate::{audit::host_keypair, host_signer::keystore::Keystore};
use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::{
    mailbox::*,
    mailbox_worker::{MailboxWorkerBackend, MailboxWorkerState},
};
use mvm_core::{
    crypto::aead::Key,
    mailbox::{OpenContext, frame::cast::route::AddressedCastGrants, sign_capability},
    vm_backend::VmStartConfig,
};
use std::{path::Path, time::Instant};

/// Explicit grant requested by this fixture before the plan is signed.
pub fn local_service() -> local_service::MailboxLocalServiceGrant {
    let mut service = local_service::MailboxLocalServiceGrant::reliable_v1();
    service.limits.payload_bytes = 1024;
    service.limits.max_frame_bytes = 4096;
    service.limits.spooled_requests = 1;
    service.limits.queued_messages = 1;
    service.limits.active_calls = 1;
    service.limits.retained_guest_bytes = 8192;
    service.limits.retained_host_bytes = 16 * 1024;
    service
}
pub struct ReservedFixture<'a> {
    pub original: InstalledCastParticipant<'a>,
    pub config: &'a VmStartConfig,
}
pub struct SignedFixtureDirection {
    pub delivery: DirectionDelivery,
    pub source_scope: SignedMailboxCapability,
    pub send: SignedMailboxCapability,
    pub receive: SignedMailboxCapability,
    pub source_policy: OpenContext,
    pub destination_policy: OpenContext,
}
impl SignedFixtureDirection {
    pub fn grants(&self) -> AddressedCastGrants<'_> {
        AddressedCastGrants {
            source_scope: &self.source_scope,
            send: &self.send,
            receive: &self.receive,
        }
    }
}
pub struct PairedFixture {
    pub source: (PreparedOriginalCastBoot, PreparedRole),
    pub destination: (PreparedOriginalCastBoot, PreparedRole),
    pub retained: SignedFixtureDirection,
}
fn bounded(
    mut c: MailboxCapabilityGrant,
    subject: PrincipalId,
    op: MailboxOperation,
    epoch: ExecutionEpoch,
    window: (i64, i64),
) -> MailboxCapabilityGrant {
    c.operations = CapabilityOperations::from_operations(&[op]);
    c.subject = subject;
    c.message_kinds = vec![MailboxMessageKind::Cast];
    c.max_payload_bytes = c.max_payload_bytes.min(1024);
    c.max_queue_contribution_bytes = c.max_queue_contribution_bytes.min(8192);
    c.max_messages_per_minute = 1;
    c.max_outstanding_calls = 1;
    c.minimum_execution_epoch = epoch;
    c.maximum_execution_epoch = epoch;
    c.delegation_depth = 0;
    c.not_before_unix_ms = c.not_before_unix_ms.max(window.0);
    c.expires_at_unix_ms = c.expires_at_unix_ms.min(window.1);
    c.capability_id = CapabilityId::from_bytes(*Key::random().expose_bytes());
    c.revocation_id = RevocationId::from_bytes(*Key::random().expose_bytes());
    c
}
/// Caller owns the two exact SDK reservations and explicitly requests this
/// synthetic route in a fresh, private MVM_HOME. Every emitted credential ends
/// with the earlier of the plans' validity, original admissions, and 3 minutes.
pub fn prepare(
    home: &Path,
    claim: &std::fs::File,
    a: ReservedFixture<'_>,
    b: ReservedFixture<'_>,
    deadline: Instant,
) -> Result<PairedFixture> {
    let keys = mvm_core::config::mvm_keys_dir();
    ensure!(
        home == mvm_core::config::mvm_home_strict()?
            && keys == home.join("keys")
            && a.config.name.starts_with("spiralcore-")
            && b.config.name.starts_with("spiralcore-")
            && a.config.name != b.config.name,
        "fixture requires original named pair in its isolated home"
    );
    let file = std::fs::symlink_metadata(home)?;
    mvm_core::private_fs::require_current_owner(&file)?;
    ensure!(
        file.is_dir() && mvm_core::private_fs::mode_bits(home, &file)? == 0o700,
        "private fixture home required"
    );
    use std::os::unix::fs::MetadataExt;
    let marker = home.join(".spiralcore-canonical-witness-owner");
    let entry = std::fs::symlink_metadata(&marker)?;
    let held = claim.metadata()?;
    mvm_core::private_fs::require_current_owner(&entry)?;
    ensure!(
        entry.is_file()
            && entry.nlink() == 1
            && mvm_core::private_fs::mode_bits(&marker, &entry)? == 0o600
            && (entry.dev(), entry.ino()) == (held.dev(), held.ino()),
        "original isolated witness claim unavailable"
    );
    let ra = a.original.worker.acquire_request();
    let rb = b.original.worker.acquire_request();
    ensure!(
        ra.tenant == rb.tenant
            && ra.tenant == "local"
            && ra.vm_id == a.config.name
            && rb.vm_id == b.config.name
            && ra.backend == MailboxWorkerBackend::Firecracker
            && rb.backend == ra.backend
            && ra.mailbox_grant.mailbox != rb.mailbox_grant.mailbox,
        "different fixture reservations required"
    );
    for p in [&a, &b] {
        let r = p.original.worker.acquire_request();
        let owner = p
            .original
            .worker
            .owner()
            .context("missing original fixture holder")?;
        ensure!(
            p.original.worker.query(deadline)? == MailboxWorkerState::Reserved
                && p.config
                    .installed_mailbox_owner
                    .as_ref()
                    .is_some_and(|x| x.owner == *owner && x.plan_commitment == r.plan_commitment)
                && p.original.plan.plan().mailbox == Some(r.mailbox_grant)
                && p.original.plan.plan().workload.0 == r.vm_id,
            "fixture must own original reservation"
        );
        ensure!(
            r.mailbox_grant.local_service == Some(local_service()),
            "actual signed local mailbox service absent"
        );
    }
    let ak = derived_keys(&keys, &ra.mailbox_grant.mailbox, ra.mailbox_grant.epoch)?;
    let bk = derived_keys(&keys, &rb.mailbox_grant.mailbox, rb.mailbox_grant.epoch)?;
    ensure!(
        ra.mailbox_grant.authority_key == ak.authority.verifying_key().to_bytes()
            && rb.mailbox_grant.authority_key == bk.authority.verifying_key().to_bytes()
            && ra.mailbox_grant.authority_key != rb.mailbox_grant.authority_key,
        "original fixture signer mismatch"
    );
    let now = now_unix_ms();
    let at = template_for(&keys, &ak, &ra.mailbox_grant, now)?;
    let bt = template_for(&keys, &bk, &rb.mailbox_grant, now)?;
    let end = now
        .checked_add(180_000)
        .context("fixture clock overflow")?
        .min(a.original.plan.plan().valid_until.timestamp_millis())
        .min(b.original.plan.plan().valid_until.timestamp_millis())
        .min(i64::try_from(ra.admission_expires_at_unix_ms)?)
        .min(i64::try_from(rb.admission_expires_at_unix_ms)?);
    ensure!(now < end, "fixture window expired");
    let mut pa = at.launch_context();
    let mut pb = bt.launch_context();
    // B's own authority explicitly admits A's original domain as the
    // destination's development scope. Do not change either default template.
    pb.expected_tenant = pa.expected_tenant;
    pb.expected_authorization_domain = pa.expected_authorization_domain;
    let content = at.header.content_type.clone();
    ensure!(
        content == bt.header.content_type,
        "incompatible content type"
    );
    pa.accepted_content_types = vec![content.clone()];
    pb.accepted_content_types = vec![content.clone()];
    let mut ascope = bounded(
        at.capability,
        pa.expected_sender,
        MailboxOperation::Send,
        ra.mailbox_grant.epoch,
        (now, end),
    );
    let mut recv = bounded(
        bt.capability.clone(),
        pb.expected_recipient,
        MailboxOperation::Receive,
        rb.mailbox_grant.epoch,
        (now, end),
    );
    let mut send = bounded(
        bt.capability,
        pa.expected_sender,
        MailboxOperation::Send,
        ra.mailbox_grant.epoch,
        (now, end),
    );
    for c in [&mut ascope, &mut recv, &mut send] {
        c.address.tenant = pa.expected_tenant;
        c.address.authorization_domain = pa.expected_authorization_domain;
        c.content_types = vec![content.clone()];
    }
    let source_scope = sign_capability(ascope, &ak.authority)?;
    let receive = sign_capability(recv, &bk.authority)?;
    let send = sign_capability(send, &bk.authority)?;
    let grants = AddressedCastGrants {
        source_scope: &source_scope,
        send: &send,
        receive: &receive,
    };
    let host = host_keypair::load_or_init_at(&keys)?;
    let who = host_keypair::host_signer_id();
    let signers = [(who.as_str(), &host.verifying)];
    ensure!(
        a.original.plan.signer_id() == who && b.original.plan.signer_id() == who,
        "test controller expects its own host-signed plans"
    );
    fn part<'a>(r: &ReservedFixture<'a>) -> InstalledCastParticipant<'a> {
        InstalledCastParticipant {
            plan: r.original.plan,
            worker: r.original.worker,
        }
    }
    let prepared = development::prepare_immutable_generation(
        Participant {
            installed: part(&a),
            current: &pa,
        },
        Participant {
            installed: part(&b),
            current: &pb,
        },
        ra.backend,
        &signers,
        grants,
        deadline,
    )?;
    let mut routed = pb.clone();
    routed.expected_sender = pa.expected_sender;
    routed.acting_principal = pa.acting_principal;
    routed.current_execution_epoch = pa.current_execution_epoch;
    routed.required_operation = MailboxOperation::Send;
    let boot = OriginalCastBoot {
        source: part(&a),
        destination: part(&b),
        source_policy: &pa,
        destination_policy: &routed,
        grants,
        trusted_plan_signers: &signers,
        direction: &prepared.delivery.direction,
    };
    let signer = Keystore::load_from_file(&host.secret_path)?;
    let original = |p: &ReservedFixture<'_>| {
        mvm_runtime::microvm::read_verb_grant_envelope(&p.config.name)?
            .context("original workload needs signed entrypoint verbs")
    };
    let first = boot.prepare_submit(&signer, &original(&a)?, a.config, deadline, &content)?;
    let second = boot.prepare(&signer, &original(&b)?, b.config, deadline)?;
    Ok(PairedFixture {
        source: (first, prepared.source),
        destination: (second, prepared.destination),
        retained: SignedFixtureDirection {
            delivery: prepared.delivery,
            source_scope,
            send,
            receive,
            source_policy: pa,
            destination_policy: pb,
        },
    })
}
