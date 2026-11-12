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
        let now = now_ms()?;
        let source = journal_scope_before_launch(&self.keys_dir, grant, now)?;
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
            revoked_capabilities: Vec::new(),
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
            &self.inbound,
            now,
            d.max_payload_bytes,
        )?;
        drop(self.connect(deadline)?);
        Ok(())
    }
}
