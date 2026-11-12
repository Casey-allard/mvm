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
            || scope.address.tenant != h.tenant
            || scope.address.authorization_domain != h.authorization_domain
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, ExecutionEpoch, MailboxGrant, MailboxId, TenantId,
    };
    use mvm_core::mailbox::{sign_capability, verify_capability_signature};

    #[test]
    fn original_scope_refuses_validly_signed_foreign_tenant_or_domain() {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let mailbox = MailboxId::from_bytes([5; 32]);
        let epoch = ExecutionEpoch::new(1).unwrap();
        let grant = MailboxGrant {
            local_service: None,
            mailbox,
            epoch,
            authority_key: crate::mailbox_launch::authority_key_for(dir.path(), &mailbox, epoch)
                .unwrap()
                .to_bytes(),
        };
        let (_, mut sealer) =
            crate::mailbox_launch::host_trust(dir.path(), &grant, &Key::from_bytes([5; 32]))
                .unwrap();
        use mvm_contract::protocol::mailbox::{
            CapabilityOperations, MailboxOperation, PrincipalId,
            local::{LocalGreeting, LocalRole},
            local_service::MailboxLocalServiceGrant,
        };
        use mvm_core::plan::{
            signing::{sign_plan, verify_plan},
            test_support::PlanFixture,
        };
        let from = chrono::DateTime::from_timestamp_millis(1000).unwrap();
        let until = chrono::DateTime::from_timestamp_millis(2500).unwrap();
        let mut a = PlanFixture::new()
            .workload("source")
            .validity(from, until)
            .build();
        let mut b = PlanFixture::new()
            .workload("destination")
            .validity(from, until)
            .build();
        let profile = Some(MailboxLocalServiceGrant::reliable_v1());
        let destination = MailboxId::from_bytes([6; 32]);
        let dest_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let recipient = PrincipalId::from_bytes([34; 32]);
        a.mailbox = Some(MailboxGrant {
            local_service: profile,
            ..grant
        });
        b.mailbox = Some(MailboxGrant {
            local_service: profile,
            mailbox: destination,
            authority_key: dest_key.verifying_key().to_bytes(),
            ..grant
        });
        let pkey = ed25519_dalek::SigningKey::from_bytes(&[30; 32]);
        let pvk = pkey.verifying_key();
        let trust = [("fixture", &pvk)];
        let a = sign_plan(&a, &pkey, "fixture");
        let b = sign_plan(&b, &pkey, "fixture");
        let aid = verify_plan(&a, &trust).unwrap().plan_id;
        let bid = verify_plan(&b, &trust).unwrap().plan_id;
        let mut channel = CastChannel::from_signed_pair(
            &a,
            &b,
            &trust,
            (&aid, &bid),
            LocalGreeting {
                binding: [14; 32],
                generation: 1,
                role: LocalRole::Deliver,
            },
            sealer.header.sender,
            recipient,
            1500,
        )
        .unwrap();
        channel.restrict_frame_budget(4096).unwrap();
        let data_key = Key::from_bytes([44; 32]);
        let mut peer = sealer.capability.clone();
        peer.address.mailbox = destination;
        peer.address.recipient = recipient;
        peer.issuer = PrincipalId::from_bytes(dest_key.verifying_key().to_bytes());
        let send = sign_capability(peer.clone(), &dest_key).unwrap();
        peer.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
        peer.subject = recipient;
        let receive = sign_capability(peer, &dest_key).unwrap();
        for (change_tenant, change_domain) in [(false, false), (true, false), (false, true)] {
            let mut member = sealer.capability.clone();
            if change_tenant {
                let mut id = *member.address.tenant.as_bytes();
                id[0] ^= 1;
                member.address.tenant = TenantId::from_bytes(id);
            }
            if change_domain {
                let mut id = *member.address.authorization_domain.as_bytes();
                id[0] ^= 1;
                member.address.authorization_domain = AuthorizationDomainId::from_bytes(id);
            }
            let signed = sign_capability(member, &sealer.authority_key).unwrap();
            verify_capability_signature(&signed, &sealer.authority_key.verifying_key()).unwrap();
            let role = OriginalSourceRole {
                source_binding: [51; 32],
                enrollment_commitment: [52; 32],
                sender_boot: sealer.header.sender_boot,
                encryption: sealer.header.encryption.clone(),
                routing: sealer.routing.clone(),
                data_key: &data_key,
            };
            let mut slot = SourceCastSlot::new((), 32768);
            let result = sealer.addressed_source(
                &channel,
                AddressedCastGrants {
                    source_scope: &signed,
                    send: &send,
                    receive: &receive,
                },
                role,
                &mut slot,
            );
            assert_eq!(result.is_ok(), !change_tenant && !change_domain);
        }
    }
}
