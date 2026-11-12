//! Original principals and signed capabilities for a proposed journal direction.
//! Validation does not sign a plan or enable a helper on its own.
use super::OriginalJournalDestination;
use crate::mailbox_launch::{MailboxTemplate, journal_scope_before_launch};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    MailboxAddress, MailboxEnvelopeHeader, MailboxJournalDirectionV1, MailboxMessageKind,
    MailboxOperation, PrincipalId, SignedMailboxCapability,
};
use mvm_core::mailbox::{
    OpenContext, authorize_receive, authorize_send,
    outbound::{check_projection, journal_capability_digest},
    reader::MailboxReaderBootBinding,
};
use mvm_core::plan::{ExecutionPlan, Nonce};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// All three must be separately supplied, already signed original grants.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCredentials {
    pub source_scope: SignedMailboxCapability,
    pub destination_send: SignedMailboxCapability,
    pub destination_receive: SignedMailboxCapability,
}

pub(crate) fn now_ms() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

pub(crate) fn require_destination(
    d: &MailboxJournalDirectionV1,
    boot: &MailboxReaderBootBinding,
    address: MailboxAddress,
    policy_epoch: u64,
) -> Result<()> {
    ensure!(
        boot.plan_id.0 == format!("sha256:{}", hex::encode(d.destination_plan_sha256))
            && boot.plan_nonce == Nonce::from_bytes(d.destination_plan_nonce)
            && boot.boot == d.destination_boot
            && boot.mailbox == d.address.mailbox
            && boot.authority_key == d.receipt_key
            && boot.execution_epoch == d.execution_epoch
            && address == d.address
            && policy_epoch == d.policy_epoch,
        "journal destination differs from the original admitted boot"
    );
    Ok(())
}

pub(crate) fn check_credentials(
    source: &MailboxTemplate,
    d: &MailboxJournalDirectionV1,
    grants: &JournalCredentials,
    source_context: &OpenContext,
    destination_context: &OpenContext,
    now: i64,
    length: u32,
) -> Result<()> {
    ensure!(
        (d.not_before_unix_ms..d.expires_at_unix_ms).contains(&now)
            && length > 0
            && length <= d.max_payload_bytes,
        "outside original direction limits"
    );
    ensure!(
        d.source == source.header.sender
            && d.source == source_context.expected_sender
            && source_context.expected_capability_issuer == source.capability.issuer
            && destination_context.expected_sender == d.source
            && destination_context.expected_capability_issuer.as_bytes() == &d.receipt_key
            && destination_context.current_execution_epoch == d.execution_epoch
            && destination_context.current_policy_epoch == d.policy_epoch,
        "original permission context changed"
    );
    ensure!(
        journal_capability_digest(&grants.source_scope)? == d.source_scope_grant_sha256
            && journal_capability_digest(&grants.destination_send)? == d.send_grant_sha256
            && journal_capability_digest(&grants.destination_receive)? == d.receive_grant_sha256,
        "signed journal credential changed"
    );
    ensure!(
        source_context.expected_tenant == destination_context.expected_tenant
            && source_context.expected_authorization_domain
                == destination_context.expected_authorization_domain,
        "journal direction crosses the admitted tenant or authorization domain"
    );
    for credential in [
        &grants.source_scope,
        &grants.destination_send,
        &grants.destination_receive,
    ] {
        let cap = &credential.grant;
        ensure!(
            cap.not_before_unix_ms <= d.not_before_unix_ms
                && cap.expires_at_unix_ms >= d.expires_at_unix_ms
                && cap.max_payload_bytes >= d.max_payload_bytes
                && cap.max_queue_contribution_bytes >= u64::from(d.max_payload_bytes),
            "direction exceeds an original signed capability limit"
        );
    }
    let mut local = source.header.clone();
    local.kind = MailboxMessageKind::Cast;
    local.reply_to = None;
    local.capability_id = grants.source_scope.grant.capability_id;
    local.plaintext_len = length;
    local.issued_at_unix_ms = d.not_before_unix_ms;
    local.expires_at_unix_ms = d.expires_at_unix_ms;
    let key_a = VerifyingKey::from_bytes(source.capability.issuer.as_bytes())?;
    let key_b = VerifyingKey::from_bytes(&d.receipt_key)?;
    let context = |base: &OpenContext, actor, op| {
        let mut v = base.clone();
        v.acting_principal = actor;
        v.required_operation = op;
        v.now_unix_ms = now;
        v
    };
    authorize_send(
        &local,
        &grants.source_scope,
        &context(source_context, d.source, MailboxOperation::Send),
        &key_a,
    )?;
    let remote = destination_header(local, d, &grants.destination_send);
    authorize_send(
        &remote,
        &grants.destination_send,
        &context(destination_context, d.source, MailboxOperation::Send),
        &key_b,
    )?;
    authorize_receive(
        &remote,
        &grants.destination_receive,
        &context(
            destination_context,
            d.address.recipient,
            MailboxOperation::Receive,
        ),
        &key_b,
    )?;
    Ok(())
}

pub(crate) fn destination_header(
    mut header: MailboxEnvelopeHeader,
    d: &MailboxJournalDirectionV1,
    send: &SignedMailboxCapability,
) -> MailboxEnvelopeHeader {
    header.tenant = d.address.tenant;
    header.authorization_domain = d.address.authorization_domain;
    header.mailbox = d.address.mailbox;
    header.recipient = d.address.recipient;
    header.kind = MailboxMessageKind::Cast;
    header.reply_to = None;
    header.capability_id = send.grant.capability_id;
    header.execution_epoch = d.execution_epoch;
    header.policy_epoch = d.policy_epoch;
    header.issued_at_unix_ms = d.not_before_unix_ms;
    header.expires_at_unix_ms = d.expires_at_unix_ms;
    header
}

impl OriginalJournalDestination {
    /// Verify the actual destination child, its admitted inbound policy, the
    /// prospective A plan, and the three exact signatures. A conventional
    /// destination helper expecting its own sender is ineligible.
    pub fn check_proposal(
        &mut self,
        plan: &ExecutionPlan,
        grants: &JournalCredentials,
        deadline: Instant,
    ) -> Result<()> {
        self.connect_for_proposal(plan, grants, deadline).map(drop)
    }

    pub(super) fn connect_for_proposal(
        &mut self,
        plan: &ExecutionPlan,
        grants: &JournalCredentials,
        deadline: Instant,
    ) -> Result<std::os::unix::net::UnixStream> {
        self.check_current_credentials(plan, grants)?;
        self.connect(deadline)
    }

    pub(super) fn check_current_credentials(
        &self,
        plan: &ExecutionPlan,
        grants: &JournalCredentials,
    ) -> Result<()> {
        let grant = plan.mailbox.as_ref().context("source has no mailbox")?;
        let d = grant
            .outbound_journal_v1
            .as_ref()
            .context("source has no enrolled direction")?;
        ensure!(
            plan.plan_id == mvm_core::plan::compute_plan_id(plan),
            "unbound source plan"
        );
        check_projection(grant, d)?;
        require_destination(d, &self.boot, self.address, self.policy_epoch)?;
        ensure!(
            self.incoming.as_ref().is_some_and(|i| i.agrees(grants)),
            "B did not admit these original sender and reader credentials"
        );
        let now = now_ms()?;
        let source = journal_scope_before_launch(&self.keys_dir, grant, now)?;
        mvm_core::naming::validate_vm_name(&plan.image.name)?;
        let read_revocations = |path: &std::path::Path| {
            crate::mailbox_service::durable::reader_revocations(path)
                .map_err(|e| anyhow::anyhow!("original mailbox revocation state: {e:?}"))
        };
        let source_state = self.peer_state(&plan.image.name)?;
        let mut inbound = self.inbound.clone();
        inbound.revoked_capabilities = read_revocations(&self.revocations_path)?;
        let h = &source.header;
        let local = OpenContext {
            expected_tenant: h.tenant,
            expected_authorization_domain: h.authorization_domain,
            expected_mailbox: grant.mailbox,
            expected_sender: h.sender,
            expected_recipient: h.recipient,
            acting_principal: h.sender,
            expected_capability_issuer: PrincipalId::from_bytes(grant.authority_key),
            current_execution_epoch: grant.epoch,
            current_policy_epoch: h.policy_epoch,
            required_operation: MailboxOperation::Send,
            now_unix_ms: now,
            accepted_content_types: vec![h.content_type.clone()],
            revoked_capabilities: read_revocations(&super::super::reader::revocations_path(
                &source_state,
            ))?,
        };
        ensure!(
            self.sender_key.to_bytes() == *d.source.as_bytes(),
            "destination has no enrolled original A verifier"
        );
        check_credentials(
            &source,
            d,
            grants,
            &local,
            &inbound,
            now,
            d.max_payload_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{
        BootId, CapabilityOperations, ExecutionEpoch, MailboxGrant, MailboxId, RevocationId,
    };
    use mvm_core::crypto::aead::Key;
    use mvm_core::mailbox::sign_capability;

    #[test]
    fn signatures_original_shared_scope_and_current_revocations_gate_the_proposal() {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let make = |id: u8| {
            let mailbox = MailboxId::from_bytes([id; 32]);
            let epoch = ExecutionEpoch::new(2).unwrap();
            let grant = MailboxGrant {
                mailbox,
                epoch,
                authority_key: crate::mailbox_launch::authority_key_for(
                    dir.path(),
                    &mailbox,
                    epoch,
                )
                .unwrap()
                .to_bytes(),
                report: None,
                retention: None,
                durable_object_pair_sha256_v1: None,
                incoming_journal_policy_sha256_v1: None,
                outbound_journal_v1: None,
            };
            crate::mailbox_launch::derive_launch_keys(dir.path(), &grant, &Key::random())
                .unwrap()
                .trust()
        };
        let (a_policy, a) = make(11);
        let (b_policy, b) = make(12);
        let source = MailboxTemplate {
            header: a.header.clone(),
            routing: a.routing.clone(),
            capability: a.capability.clone(),
        };
        let mut a_scope = a.capability.clone();
        a_scope.message_kinds = vec![MailboxMessageKind::Cast];
        let scope = sign_capability(a_scope, &a.authority_key).unwrap();
        let mut b_send = b.capability.clone();
        b_send.address.tenant = a.header.tenant;
        b_send.address.authorization_domain = a.header.authorization_domain;
        b_send.subject = a.header.sender;
        b_send.message_kinds = vec![MailboxMessageKind::Cast];
        let mut b_recv = b_send.clone();
        b_recv.revocation_id = RevocationId::from_bytes([32; 32]);
        b_recv.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
        b_recv.subject = b_send.address.recipient;
        let address = b_send.address;
        let send = sign_capability(b_send, &b.authority_key).unwrap();
        let receive = sign_capability(b_recv, &b.authority_key).unwrap();
        let start = scope
            .grant
            .not_before_unix_ms
            .max(send.grant.not_before_unix_ms);
        let end = scope
            .grant
            .expires_at_unix_ms
            .min(send.grant.expires_at_unix_ms);
        let d = MailboxJournalDirectionV1 {
            sender_settlement: None,
            source: a.header.sender,
            destination_plan_sha256: [4; 32],
            destination_plan_nonce: [3; 16],
            destination_boot: BootId::from_bytes([5; 32]),
            address,
            execution_epoch: b.header.execution_epoch,
            policy_epoch: b.header.policy_epoch,
            receipt_key: b.authority_key.verifying_key().to_bytes(),
            source_scope_grant_sha256: journal_capability_digest(&scope).unwrap(),
            send_grant_sha256: journal_capability_digest(&send).unwrap(),
            receive_grant_sha256: journal_capability_digest(&receive).unwrap(),
            not_before_unix_ms: start,
            expires_at_unix_ms: end,
            max_payload_bytes: 313,
        };
        let grants = JournalCredentials {
            source_scope: scope,
            destination_send: send,
            destination_receive: receive,
        };
        let mut inbound = b_policy.context.clone();
        inbound.expected_tenant = address.tenant;
        inbound.expected_authorization_domain = address.authorization_domain;
        inbound.expected_sender = a.header.sender;
        let now = start + 1;
        let check = |a: &OpenContext,
                     b: &OpenContext,
                     g: &JournalCredentials,
                     d: &MailboxJournalDirectionV1| {
            check_credentials(&source, d, g, a, b, now, 313)
        };
        assert!(check(&a_policy.context, &inbound, &grants, &d).is_ok());
        assert!(check(&a_policy.context, &b_policy.context, &grants, &d).is_err());
        let mut a_revoked = a_policy.context.clone();
        a_revoked
            .revoked_capabilities
            .push(grants.source_scope.grant.revocation_id);
        assert!(check(&a_revoked, &inbound, &grants, &d).is_err());
        for id in [
            grants.destination_send.grant.revocation_id,
            grants.destination_receive.grant.revocation_id,
        ] {
            let mut revoked = inbound.clone();
            revoked.revoked_capabilities.push(id);
            assert!(check(&a_policy.context, &revoked, &grants, &d).is_err());
        }
        let mut stale = inbound.clone();
        stale.current_policy_epoch += 1;
        assert!(check(&a_policy.context, &stale, &grants, &d).is_err());
        let mut foreign = d;
        foreign.send_grant_sha256 = [0; 32];
        assert!(check(&a_policy.context, &inbound, &grants, &foreign).is_err());
        let mut excess = d;
        excess.max_payload_bytes = grants.destination_send.grant.max_payload_bytes + 1;
        assert!(check(&a_policy.context, &inbound, &grants, &excess).is_err());
    }
}

/// Borrowed only during the pre-sign / pre-dispatch decision. The underlying
/// original process cannot be replaced or reconstructed from a public ID.
pub struct PairedJournalAdmission {
    pub(super) original: std::sync::Arc<std::sync::Mutex<OriginalJournalDestination>>,
    pub(super) grants: std::sync::Arc<JournalCredentials>,
    pub(super) deadline: Instant,
}

impl std::fmt::Debug for PairedJournalAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairedJournalAdmission")
    }
}

impl PairedJournalAdmission {
    pub fn new(
        original: std::sync::Arc<std::sync::Mutex<OriginalJournalDestination>>,
        grants: std::sync::Arc<JournalCredentials>,
        deadline: Instant,
    ) -> Self {
        Self {
            original,
            grants,
            deadline,
        }
    }

    pub(crate) fn verify(&self, plan: &ExecutionPlan) -> Result<()> {
        self.original
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original destination is busy"))?
            .check_proposal(plan, &self.grants, self.deadline)
    }
}
