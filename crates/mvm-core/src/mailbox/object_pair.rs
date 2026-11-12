//! Pure contract checks for the durable object Call/Reply profile. The caller
//! supplies the two original boots from live local custody, not peer headers.
//! This module cannot launch a helper, admit a journal entry, release a key,
//! disclose cache membership, settle a reader lease or consume a reply.
pub mod role;

use super::{
    outbound::journal_capability_digest, reader::MailboxReaderBootBinding,
    verify_capability_signature,
};
use crate::plan::{Nonce, SignedExecutionPlan, validity::check_window, verify_plan};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::*;
use sha2::{Digest, Sha256};

/// Public, independently issued credentials. A receive/reader grant is still
/// required at each destination before any application payload can be released.
#[derive(Clone, Copy)]
pub struct ObjectPairGrants<'a> {
    pub call: &'a SignedMailboxCapability,
    pub reply: &'a SignedMailboxCapability,
}

impl ObjectPairGrants<'_> {
    /// Compute after selecting both original nonces, before signing either
    /// plan. Neither final plan hash nor a future boot ID is self-referential.
    pub fn commitment(&self, caller_nonce: &Nonce, callee_nonce: &Nonce) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"mvm.mailbox.durable-object-pair.v1\0");
        hash.update(caller_nonce.as_hex().as_bytes());
        hash.update(callee_nonce.as_hex().as_bytes());
        for grant in [self.call, self.reply] {
            grant.grant.validate_bounds()?;
            hash.update(journal_capability_digest(grant)?);
        }
        Ok(hash.finalize().into())
    }
}

/// Original inputs held by each trusted local controller. Plan verification
/// keys are from the installation; boot data is from the original VM owner.
pub struct OriginalObjectEndpoint<'a> {
    pub plan: &'a SignedExecutionPlan,
    pub trusted_signers: &'a [(&'a str, &'a VerifyingKey)],
    pub boot: &'a MailboxReaderBootBinding,
}

/// A structural preflight of the selected profile, never reusable permission.
/// Message checks require a fresh time and both authorities' current revocations.
pub struct ObjectPairV1<'a> {
    grants: ObjectPairGrants<'a>,
    commitment: [u8; 32],
    caller_binding: MailboxReaderBootBinding,
    callee_binding: MailboxReaderBootBinding,
    start: i64,
    end: i64,
}

impl<'a> ObjectPairV1<'a> {
    pub fn check_originals(
        caller: &OriginalObjectEndpoint<'_>,
        callee: &OriginalObjectEndpoint<'_>,
        grants: ObjectPairGrants<'a>,
        now_ms: i64,
        state: PairAuthorityState<'_>,
    ) -> Result<Self> {
        let now =
            chrono::DateTime::from_timestamp_millis(now_ms).context("invalid original time")?;
        let a = verify_plan(caller.plan, caller.trusted_signers)?;
        let b = verify_plan(callee.plan, callee.trusted_signers)?;
        ensure!(
            a.nonce != b.nonce && a.workload != b.workload && a.tenant == b.tenant,
            "expected two distinct original workloads in one tenant"
        );
        ensure!(
            caller.boot.boot != callee.boot.boot,
            "duplicate original boot"
        );
        let digest = grants.commitment(&a.nonce, &b.nonce)?;
        let call = &grants.call.grant;
        let reply = &grants.reply.grant;
        ensure!(
            call.address.mailbox != reply.address.mailbox
                && call.issuer != reply.issuer
                && call.subject != reply.subject
                && call.subject == reply.address.recipient
                && reply.subject == call.address.recipient
                && call.address.tenant == reply.address.tenant
                && call.address.authorization_domain == reply.address.authorization_domain,
            "credentials are not an exact reciprocal pair"
        );
        let content = ContentType::parse("application/spiralcore-object", 1)?;
        for (plan, boot, signed, op, kind) in [
            (
                &a,
                caller.boot,
                grants.reply,
                MailboxOperation::Reply,
                MailboxMessageKind::Reply,
            ),
            (
                &b,
                callee.boot,
                grants.call,
                MailboxOperation::Send,
                MailboxMessageKind::Call,
            ),
        ] {
            check_window(plan, now)?;
            boot.check_plan(plan)?;
            let local = plan.mailbox.context("original plan lacks mailbox")?;
            let grant = &signed.grant;
            ensure!(
                local.durable_object_pair_sha256_v1 == Some(digest)
                    && local.retention.is_some()
                    && local.report.is_none()
                    && local.incoming_journal_policy_sha256_v1.is_none()
                    && local.outbound_journal_v1.is_none(),
                "original plan did not select this exclusive retained profile"
            );
            ensure!(
                local.mailbox == grant.address.mailbox
                    && local.authority_key == *grant.issuer.as_bytes()
                    && local.epoch.get() == plan.execution_epoch
                    && grant.minimum_execution_epoch == local.epoch
                    && grant.maximum_execution_epoch == local.epoch
                    && grant.operations == CapabilityOperations::from_operations(&[op])
                    && grant.message_kinds == [kind]
                    && grant.content_types.as_slice() == std::slice::from_ref(&content)
                    && u64::from(grant.max_payload_bytes) <= grant.max_queue_contribution_bytes,
                "operation exceeds original participant scope"
            );
            verify_capability_signature(signed, &VerifyingKey::from_bytes(&local.authority_key)?)?;
        }
        let pair = Self {
            grants,
            commitment: digest,
            caller_binding: caller.boot.clone(),
            callee_binding: callee.boot.clone(),
            start: a
                .valid_from
                .timestamp_millis()
                .max(b.valid_from.timestamp_millis())
                .max(call.not_before_unix_ms)
                .max(reply.not_before_unix_ms),
            end: a
                .valid_until
                .timestamp_millis()
                .min(b.valid_until.timestamp_millis())
                .min(call.expires_at_unix_ms)
                .min(reply.expires_at_unix_ms),
        };
        pair.current(now_ms, state)?;
        Ok(pair)
    }

    fn current(&self, now: i64, state: PairAuthorityState<'_>) -> Result<()> {
        ensure!(
            (self.start..self.end).contains(&now)
                && state.caller_boot == self.caller_binding.boot
                && state.callee_boot == self.callee_binding.boot
                && state.caller_epoch == self.grants.reply.grant.minimum_execution_epoch
                && state.callee_epoch == self.grants.call.grant.minimum_execution_epoch
                && state.caller_policy == self.grants.reply.grant.policy_epoch
                && state.callee_policy == self.grants.call.grant.policy_epoch
                && !state
                    .at_caller
                    .contains(&self.grants.reply.grant.revocation_id)
                && !state
                    .at_callee
                    .contains(&self.grants.call.grant.revocation_id),
            "expired or revoked original pair"
        );
        Ok(())
    }

    /// Verify an original sealed envelope using the enrolled grant and signer.
    /// The caller supplies its locally retained directional key and the canonical
    /// scope. Public callers commit replay only after profile correlation.
    fn open_turn(
        &self,
        envelope: &MailboxEnvelope,
        signed: &SignedMailboxCapability,
        operation: MailboxOperation,
        now: i64,
        key: &crate::crypto::aead::Key,
    ) -> Result<super::OpenedMailboxEnvelope> {
        let g = &signed.grant;
        let context = super::OpenContext {
            expected_tenant: g.address.tenant,
            expected_authorization_domain: g.address.authorization_domain,
            expected_mailbox: g.address.mailbox,
            expected_sender: g.subject,
            expected_recipient: g.address.recipient,
            acting_principal: g.subject,
            expected_capability_issuer: g.issuer,
            current_execution_epoch: g.minimum_execution_epoch,
            current_policy_epoch: g.policy_epoch,
            required_operation: operation,
            now_unix_ms: now,
            accepted_content_types: g.content_types.clone(),
            revoked_capabilities: Vec::new(),
        };
        Ok(super::decrypt_authorized_envelope(
            envelope,
            signed,
            &context,
            key,
            &VerifyingKey::from_bytes(g.subject.as_bytes())?,
            &VerifyingKey::from_bytes(g.issuer.as_bytes())?,
        )?)
    }

    /// Capture the exact authenticated Call header without retaining or exposing the plaintext.
    /// This correlation input expires with the original participants and Return credential.
    pub fn pending_call(
        &self,
        envelope: MailboxEnvelope,
        now: i64,
        state: PairAuthorityState<'_>,
        key: &crate::crypto::aead::Key,
        replay: &mut impl super::ReplayProtector,
    ) -> Result<PendingObjectCall> {
        self.current(now, state)?;
        let opened = self.open_turn(
            &envelope,
            self.grants.call,
            MailboxOperation::Send,
            now,
            key,
        )?;
        let h = opened.header();
        self.check_call_header(h)?;
        ensure!(
            replay.check_and_record(super::ReplayIdentity::from_header(h)),
            "Call replay"
        );
        Ok(PendingObjectCall {
            message: h.message_id,
            correlation: h.correlation_id,
            issued: h.issued_at_unix_ms,
            expires: h.expires_at_unix_ms,
            commitment: self.commitment,
            caller_boot: self.caller_binding.boot,
            callee_boot: self.callee_binding.boot,
        })
    }

    /// Check a separately authenticated Reply against the original pending Call.
    /// Success confirms correlation only. Durable acceptance and reader possession
    /// still depend on the canonical journal and separately authorized receiver.
    pub fn check_reply(
        &self,
        pending: &PendingObjectCall,
        envelope: MailboxEnvelope,
        now: i64,
        state: PairAuthorityState<'_>,
        key: &crate::crypto::aead::Key,
        replay: &mut impl super::ReplayProtector,
    ) -> Result<()> {
        self.current(now, state)?;
        self.check_pending(pending, now)?;
        let opened = self.open_turn(
            &envelope,
            self.grants.reply,
            MailboxOperation::Reply,
            now,
            key,
        )?;
        let h = opened.header();
        self.check_reply_header(pending, h)?;
        ensure!(
            replay.check_and_record(super::ReplayIdentity::from_header(h)),
            "Reply replay"
        );
        Ok(())
    }
    fn check_call_header(&self, h: &MailboxEnvelopeHeader) -> Result<()> {
        let r = &self.grants.reply.grant;
        ensure!(
            h.sender_boot == self.caller_binding.boot
                && h.kind == MailboxMessageKind::Call
                && h.reply_to
                    == Some(ReplyRoute {
                        address: r.address,
                        capability_id: r.capability_id
                    })
                && h.issued_at_unix_ms >= self.start
                && h.expires_at_unix_ms <= self.end,
            "Call outside original pair or return route"
        );
        Ok(())
    }
    fn check_pending(&self, pending: &PendingObjectCall, now: i64) -> Result<()> {
        ensure!(
            pending.commitment == self.commitment
                && pending.caller_boot == self.caller_binding.boot
                && pending.callee_boot == self.callee_binding.boot
                && (pending.issued..pending.expires).contains(&now),
            "stale original Call"
        );
        Ok(())
    }
    fn check_reply_header(
        &self,
        pending: &PendingObjectCall,
        h: &MailboxEnvelopeHeader,
    ) -> Result<()> {
        ensure!(
            h.sender_boot == self.callee_binding.boot
                && h.kind == MailboxMessageKind::Reply
                && h.reply_to.is_none()
                && h.message_id != pending.message
                && h.correlation_id == pending.correlation
                && h.causation_id.as_bytes() == pending.message.as_bytes()
                && h.issued_at_unix_ms >= pending.issued
                && h.expires_at_unix_ms <= pending.expires,
            "Reply does not match original Call"
        );
        Ok(())
    }

    pub(super) fn retained_capability(
        &self,
        pending: Option<&PendingObjectCall>,
    ) -> &SignedMailboxCapability {
        if pending.is_some() {
            self.grants.reply
        } else {
            self.grants.call
        }
    }

    /// For the canonical journal's already accepted retained row only, after
    /// independent current Receive authorization and before lease mutation.
    /// No new replay entry or receipt. No side effect or plaintext return.
    pub(crate) fn check_retained_envelope(
        &self,
        destination: &MailboxReaderBootBinding,
        envelope: &MailboxEnvelope,
        now: i64,
        state: PairAuthorityState<'_>,
        key: &crate::crypto::aead::Key,
        pending: Option<&PendingObjectCall>,
    ) -> Result<()> {
        self.current(now, state)?;
        if let Some(pending) = pending {
            ensure!(
                destination == &self.caller_binding,
                "Reply lease requires original caller binding"
            );
            self.check_pending(pending, now)?;
            let opened = self.open_turn(
                envelope,
                self.grants.reply,
                MailboxOperation::Reply,
                now,
                key,
            )?;
            self.check_reply_header(pending, opened.header())
        } else {
            ensure!(
                destination == &self.callee_binding,
                "Call lease requires original callee binding"
            );
            let opened =
                self.open_turn(envelope, self.grants.call, MailboxOperation::Send, now, key)?;
            self.check_call_header(opened.header())
        }
    }
}

/// Live boots, current epochs and revocations supplied by the two trusted original owners on this turn.
#[derive(Clone, Copy)]
pub struct PairAuthorityState<'a> {
    pub caller_boot: BootId,
    pub callee_boot: BootId,
    pub caller_epoch: ExecutionEpoch,
    pub callee_epoch: ExecutionEpoch,
    pub caller_policy: u64,
    pub callee_policy: u64,
    pub at_caller: &'a [RevocationId],
    pub at_callee: &'a [RevocationId],
}

/// Fixed-size, live-generation-only correlation metadata from a verified Call.
pub struct PendingObjectCall {
    message: MessageId,
    correlation: CorrelationId,
    issued: i64,
    expires: i64,
    commitment: [u8; 32],
    caller_boot: BootId,
    callee_boot: BootId,
}

#[cfg(test)]
mod tests;
