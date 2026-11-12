//! Borrow the original worker's signer and sequence for an enrolled direction.
use super::{GuestSealer, Refusal};
use mvm_contract::protocol::mailbox::{BootId, EncryptionContext, MailboxRoutingFrame};
use mvm_core::{
    crypto::aead::Key,
    mailbox::frame::cast::{
        CastChannel,
        route::AddressedCastGrants,
        source::{CastSource, SourceCastEnrollment, SourceCastSlot},
    },
};

/// Built by the worker's private configuration owner after authenticating
/// the paired enrollment and unwrapping its direction-specific data key.
pub(crate) struct OriginalSourceRole<'a> {
    pub(crate) source_binding: [u8; 32],
    pub(crate) enrollment_commitment: [u8; 32],
    pub(crate) sender_boot: BootId,
    pub(crate) encryption: EncryptionContext,
    pub(crate) data_key: &'a Key,
    pub(crate) routing: MailboxRoutingFrame,
}

impl GuestSealer {
    pub(crate) fn addressed_source<'a, C>(
        &'a mut self,
        channel: &'a CastChannel,
        grants: AddressedCastGrants<'a>,
        role: OriginalSourceRole<'a>,
        slot: &'a mut SourceCastSlot<C>,
    ) -> Result<CastSource<'a, C>, Refusal> {
        let h = &self.header;
        let scope = &grants.source_scope.grant;
        if !channel.matches_original_source(
            h.mailbox,
            h.execution_epoch,
            self.authority_key.verifying_key().as_bytes(),
        ) || scope.address.mailbox != h.mailbox
            || scope.address.recipient != h.recipient
            || scope.subject != h.sender
            || h.sender.as_bytes() != self.sender_key.verifying_key().as_bytes()
            || scope.issuer.as_bytes() != self.authority_key.verifying_key().as_bytes()
        {
            return Err(Refusal::Mailbox("original source worker mismatch".into()));
        }
        CastSource::new(
            channel,
            grants,
            SourceCastEnrollment {
                source_binding: role.source_binding,
                enrollment_commitment: role.enrollment_commitment,
                sender_boot: role.sender_boot,
                signer: &self.sender_key,
                encryption: role.encryption,
                data_key: role.data_key,
                ordering_scope: h.ordering_scope.clone(),
                routing: role.routing,
            },
            &mut self.sent,
            slot,
        )
    }
}
