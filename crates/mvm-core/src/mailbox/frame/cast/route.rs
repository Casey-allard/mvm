//! Addressed Cast admission. Original scope credentials are supplied by the
//! installed participants; sharing a tenant name or host never issues a right.
use super::{CastChannel, VerifiedCast, deny};
use crate::mailbox::{MailboxError, OpenContext, ReplayProtector, frame::Refusal};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    MailboxEnvelope, MailboxMessageKind, MailboxOperation, SignedMailboxCapability,
};
use std::num::NonZeroU64;

#[derive(Clone, Copy)]
pub struct AddressedCastGrants<'a> {
    /// A's existing own-mailbox capability identifies its admitted domain.
    pub source_scope: &'a SignedMailboxCapability,
    /// B's authority permits A to send a Cast to the concrete B address.
    pub send: &'a SignedMailboxCapability,
    /// B's authority separately permits B to receive that Cast.
    pub receive: &'a SignedMailboxCapability,
}

impl AddressedCastGrants<'_> {
    /// Refuse large policy material before cloning or serializing signed
    /// values inside the compact worker workspace. Larger policy sets need a
    /// separately provisioned index; refusal does not discard revocations.
    pub fn check_compact_policy(
        &self,
        source: &OpenContext,
        destination: &OpenContext,
    ) -> Result<(), Refusal> {
        if [source, destination]
            .iter()
            .any(|p| p.revoked_capabilities.len() > 32 || p.accepted_content_types.len() > 4)
            || [self.source_scope, self.send, self.receive]
                .iter()
                .any(|cap| {
                    cap.grant.content_types.len() > 4
                        || cap.grant.message_kinds.len() > 3
                        || cap.signature.len() != 64
                })
        {
            return Err(deny());
        }
        Ok(())
    }
    pub fn admits_encoded_contribution(&self, bytes: usize) -> bool {
        u64::try_from(bytes).is_ok_and(|n| {
            n <= self
                .send
                .grant
                .max_queue_contribution_bytes
                .min(self.receive.grant.max_queue_contribution_bytes)
        })
    }
}

impl CastChannel {
    pub fn admits_workspace(&self, bytes: u64) -> bool {
        self.source
            .local_service
            .is_some_and(|p| p.limits.retained_host_bytes >= bytes)
            && self
                .grant
                .local_service
                .is_some_and(|p| p.limits.retained_host_bytes >= bytes)
    }
    pub fn is_bounded_destination(
        &self,
        grant: &mvm_contract::protocol::mailbox::MailboxGrant,
        frame_limit: usize,
    ) -> bool {
        &self.grant == grant && self.limits.max_frame_bytes as usize <= frame_limit
    }

    /// Validate the three signed scopes without decrypting or recording a replay.
    /// `source_current` is the original source worker policy; destination policy
    /// evaluates the cross-address Send on behalf of the same source principal.
    pub fn authorize_addressed(
        &self,
        grants: AddressedCastGrants<'_>,
        source_current: &OpenContext,
        current: &OpenContext,
    ) -> Result<(), Refusal> {
        grants.check_compact_policy(source_current, current)?;
        let source_key =
            VerifyingKey::from_bytes(&self.source.authority_key).map_err(|_| deny())?;
        let destination_key =
            VerifyingKey::from_bytes(&self.grant.authority_key).map_err(|_| deny())?;
        let src = &grants.source_scope.grant;
        let send = &grants.send.grant;
        let recv = &grants.receive.grant;
        if current.now_unix_ms != source_current.now_unix_ms
            || current.now_unix_ms < self.valid_from
            || current.now_unix_ms >= self.valid_until
            || source_current.expected_sender != self.sender
            || source_current.acting_principal != self.sender
            || current.expected_sender != self.sender
            || current.acting_principal != self.sender
            || source_current.required_operation != MailboxOperation::Send
            || current.required_operation != MailboxOperation::Send
            || source_current.current_execution_epoch != self.source.epoch
            || current.current_execution_epoch != self.source.epoch
            || source_current.expected_mailbox != self.source.mailbox
            || current.expected_mailbox != self.grant.mailbox
            || current.expected_recipient != self.recipient
            || src.address.recipient != source_current.expected_recipient
            || src.address.tenant != source_current.expected_tenant
            || src.address.authorization_domain != source_current.expected_authorization_domain
            || src.address.tenant != current.expected_tenant
            || src.address.authorization_domain != current.expected_authorization_domain
            || send.address != recv.address
            || send.address.tenant != src.address.tenant
            || send.address.authorization_domain != src.address.authorization_domain
            || src.address.mailbox != self.source.mailbox
            || send.address.mailbox != self.grant.mailbox
            || send.address.recipient != self.recipient
            || send.message_kinds.as_slice() != [MailboxMessageKind::Cast]
            || !recv.message_kinds.contains(&MailboxMessageKind::Cast)
            || grants.send.grant.capability_id == grants.receive.grant.capability_id
        {
            return Err(deny());
        }
        for (signed, key, policy, principal, epoch, operation) in [
            (
                grants.source_scope,
                &source_key,
                source_current,
                self.sender,
                self.source.epoch,
                MailboxOperation::Send,
            ),
            (
                grants.send,
                &destination_key,
                current,
                self.sender,
                self.source.epoch,
                MailboxOperation::Send,
            ),
            (
                grants.receive,
                &destination_key,
                current,
                self.recipient,
                self.grant.epoch,
                MailboxOperation::Receive,
            ),
        ] {
            let grant = &signed.grant;
            crate::mailbox::verify_capability_signature(signed, key).map_err(|_| deny())?;
            if grant.subject != principal
                || grant.issuer != policy.expected_capability_issuer
                || !grant.operations.allows(operation)
                || grant.policy_epoch != policy.current_policy_epoch
                || epoch < grant.minimum_execution_epoch
                || epoch > grant.maximum_execution_epoch
                || policy.now_unix_ms < grant.not_before_unix_ms
                || policy.now_unix_ms >= grant.expires_at_unix_ms
                || policy.revoked_capabilities.contains(&grant.revocation_id)
            {
                return Err(deny());
            }
        }
        Ok(())
    }

    /// Intersect installed and signed limits before allocation. The existing
    /// codec requires 1 KiB room for bounded local headers beside the payload.
    pub fn restrict_frame_budget(&mut self, body_limit: u32) -> Result<(), Refusal> {
        let mut limits = self.limits;
        limits.max_frame_bytes = limits.max_frame_bytes.min(body_limit);
        limits.payload_bytes = limits
            .payload_bytes
            .min(limits.max_frame_bytes.checked_sub(1024).ok_or_else(deny)?);
        limits.validate().map_err(|_| deny())?;
        self.limits = limits;
        Ok(())
    }

    /// The receiver calls this with its own key and replay owner, after charging
    /// the ciphertext and workspace. No relay decrypts this object; no receipt
    /// is created. Any failed additional scope check precedes replay mutation.
    pub fn open_addressed(
        &self,
        envelope: MailboxEnvelope,
        grants: AddressedCastGrants<'_>,
        source_current: &OpenContext,
        current: &OpenContext,
        key: &crate::crypto::aead::Key,
        replay: &mut impl ReplayProtector,
        sequence: NonZeroU64,
    ) -> Result<AddressedVerifiedCast, Refusal> {
        self.open_addressed_if(
            envelope,
            grants,
            source_current,
            current,
            key,
            replay,
            sequence,
            |_| true,
        )
    }

    /// Apply an original endpoint's additional bound predicate to the signed,
    /// decrypted header before consuming its replay identity. A predicate can
    /// only narrow canonical admission.
    pub fn open_addressed_if(
        &self,
        envelope: MailboxEnvelope,
        grants: AddressedCastGrants<'_>,
        source_current: &OpenContext,
        current: &OpenContext,
        key: &crate::crypto::aead::Key,
        replay: &mut impl ReplayProtector,
        sequence: NonZeroU64,
        accepts: impl FnOnce(&mvm_contract::protocol::mailbox::MailboxEnvelopeHeader) -> bool,
    ) -> Result<AddressedVerifiedCast, Refusal> {
        self.authorize_addressed(grants, source_current, current)?;
        if envelope.ciphertext.len() > self.limits.max_frame_bytes as usize {
            return Err(deny());
        }
        let sender = VerifyingKey::from_bytes(self.sender.as_bytes()).map_err(|_| deny())?;
        let authority = VerifyingKey::from_bytes(&self.grant.authority_key).map_err(|_| deny())?;
        let recv = &grants.receive.grant;
        let admission = crate::mailbox::open_verified_admission_if(
            envelope,
            grants.send,
            current,
            key,
            &sender,
            &authority,
            replay,
            |header| {
                if !accepts(header)
                    || header.kind != MailboxMessageKind::Cast
                    || header.reply_to.is_some()
                    || !recv.content_types.contains(&header.content_type)
                    || header.plaintext_len > recv.max_payload_bytes
                    || header.plaintext_len > self.limits.payload_bytes
                    || u64::from(header.plaintext_len)
                        > recv
                            .max_queue_contribution_bytes
                            .min(grants.send.grant.max_queue_contribution_bytes)
                {
                    return Err(MailboxError::OperationNotAuthorized);
                }
                Ok(())
            },
        )
        .map_err(|_| deny())?;
        Ok(AddressedVerifiedCast {
            original: VerifiedCast {
                admission,
                original_send: grants.send.clone(),
                sequence,
                destination: self.grant,
                greeting: self.greeting,
            },
            source: self.source,
            source_scope: grants.source_scope.clone(),
            receive: grants.receive.clone(),
        })
    }
}

/// A distinct non-convertible proof. Dispatch must reauthorize all three
/// unchanged credentials after the greeting on EVERY attempt; even a retained
/// successful open cannot be passed to the older, unscoped Cast dispatcher.
pub struct AddressedVerifiedCast {
    original: VerifiedCast,
    source: mvm_contract::protocol::mailbox::MailboxGrant,
    source_scope: SignedMailboxCapability,
    receive: SignedMailboxCapability,
}
impl AddressedVerifiedCast {
    /// Start with an already authenticated host-to-guest Deliver stream and
    /// current policy owners. The destination retains its original proof across
    /// Full, expiry, revoked credentials, partial writes and a missing ACK.
    pub fn dispatch_on<'a>(
        &'a self,
        channel: &CastChannel,
        stream: &mut (impl std::io::Read + std::io::Write),
        current: impl FnOnce() -> std::io::Result<(&'a OpenContext, &'a OpenContext)>,
    ) -> std::io::Result<mvm_contract::protocol::mailbox::local::LocalDeliveryAck> {
        if channel.source != self.source
            || channel.grant != self.original.destination
            || channel.greeting != self.original.greeting
        {
            return Err(std::io::Error::other(
                "wrong original addressed Cast channel",
            ));
        }
        channel.dispatch_on(stream, || {
            let (source, destination) = current()?;
            let grants = AddressedCastGrants {
                source_scope: &self.source_scope,
                send: &self.original.original_send,
                receive: &self.receive,
            };
            channel
                .authorize_addressed(grants, source, destination)
                .map_err(std::io::Error::other)?;
            Ok(super::CastAdmission {
                verified: &self.original,
                current: destination,
                receive: &self.receive,
                sequence: self.original.sequence.get(),
            })
        })
    }
}
