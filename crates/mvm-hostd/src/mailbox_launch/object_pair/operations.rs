//! Operations on the retained original host authority. Persist each sealed turn
//! in the existing outbound-intent transaction before transmitting or retrying.
use super::*;
use mvm_core::mailbox::{
    SealRequest,
    object_pair::role::{ObjectParticipantRole, SignedObjectRoleV1},
    reader::verify_object_delivery_projection,
    seal_envelope,
};

pub struct SealedObjectTurn {
    pub header: MailboxEnvelopeHeader,
    pub envelope: MailboxEnvelope,
    pub capability: SignedMailboxCapability,
}
/// The retained original Call and the canonical current lease from B's own
/// journal. The application submission cannot supply substitute Call bytes.
pub struct OriginalObjectCallLease<'a> {
    pub original: &'a MailboxEnvelope,
    pub original_header: &'a MailboxEnvelopeHeader,
    pub original_body: &'a [u8],
    pub lease: &'a SignedMailboxDeliveryLease,
}

impl InstalledObjectPair<'_> {
    pub(super) fn check_current(&self) -> Result<i64> {
        check_original_native(&self.caller)?;
        check_original_native(&self.callee)?;
        let k = mvm_core::config::mvm_keys_dir();
        let now = super::super::now_unix_ms();
        for (p, g, dir, recv) in [
            (
                &self.caller,
                &self.prepared.caller,
                &self.prepared.credentials.reply,
                &self.prepared.credentials.receive_at_caller,
            ),
            (
                &self.callee,
                &self.prepared.callee,
                &self.prepared.credentials.call,
                &self.prepared.credentials.receive_at_callee,
            ),
        ] {
            let name = &p.admitted.plan().image.name;
            let state = mvm_core::config::vm_state_dir(name);
            ensure!(
                MailboxReaderBootBinding::load(&state)? == *p.boot
                    && mvm_core::plan::synthesis::current_local_epoch(name)? == g.epoch.get(),
                "current original mailbox generation changed"
            );
            let d = super::super::derived_keys(&k, &g.mailbox, g.epoch)?;
            ensure!(
                d.authority.verifying_key().to_bytes() == g.authority_key,
                "original local authority changed"
            );
            let t = super::super::template_for(&k, &d, g, now)?;
            ensure!(
                t.header.policy_epoch == dir.grant.policy_epoch
                    && t.capability.policy_epoch == dir.grant.policy_epoch,
                "local policy epoch changed"
            );
            let revoked = reader_revocations(&revocations_path(&state))
                .map_err(|_| anyhow::anyhow!("current revocations unavailable"))?;
            ensure!(
                !revoked.contains(&dir.grant.revocation_id)
                    && !revoked.contains(&recv.grant.revocation_id),
                "original capability revoked"
            );
        }
        self.material
            .caller
            .public_role
            .verify(self.caller.boot, now)?;
        self.material
            .callee
            .public_role
            .verify(self.callee.boot, now)?;
        Ok(now)
    }

    /// Public bootstrap for the original guest selected by the trusted
    /// per-VM listener. The expected pair/boot identify its bounded request.
    pub fn workload_role(
        &self,
        role: ObjectParticipantRole,
        pair: [u8; 32],
        boot: BootId,
    ) -> Result<&SignedObjectRoleV1> {
        self.check_current()?;
        let endpoint = match role {
            ObjectParticipantRole::Caller => &self.material.caller,
            ObjectParticipantRole::Callee => &self.material.callee,
        };
        ensure!(
            pair == self.prepared.stamp && boot == endpoint.reader.boot.boot,
            "unexpected workload bootstrap scope"
        );
        Ok(&endpoint.public_role)
    }

    pub fn seal_call(
        &self,
        message: MessageId,
        sequence: SequenceNumber,
        body: &[u8],
    ) -> Result<SealedObjectTurn> {
        self.material.seal_turn(
            ObjectParticipantRole::Caller,
            message,
            sequence,
            body,
            None,
            self.check_current()?,
        )
    }

    pub fn seal_reply(
        &self,
        message: MessageId,
        sequence: SequenceNumber,
        body: &[u8],
        original: OriginalObjectCallLease<'_>,
    ) -> Result<SealedObjectTurn> {
        self.material.seal_turn(
            ObjectParticipantRole::Callee,
            message,
            sequence,
            body,
            Some(original),
            self.check_current()?,
        )
    }

    /// Verify the actual signed V2 response for the exact retained ciphertext.
    pub fn verify_accepted(
        &self,
        role: ObjectParticipantRole,
        turn: &SealedObjectTurn,
        receipt: &SignedDestinationReceipt,
    ) -> Result<()> {
        self.check_current()?;
        self.material.verify_accepted(role, turn, receipt)
    }
}

impl PairMaterial {
    fn seal_turn(
        &self,
        role: ObjectParticipantRole,
        message: MessageId,
        sequence: SequenceNumber,
        body: &[u8],
        original: Option<OriginalObjectCallLease<'_>>,
        now: i64,
    ) -> Result<SealedObjectTurn> {
        use rand::Rng as _;
        let local = match role {
            ObjectParticipantRole::Caller => &self.caller,
            ObjectParticipantRole::Callee => &self.callee,
        };
        let d = local.public_role.verify(&local.reader.boot, now)?;
        let g = &d.outbound().grant;
        ensure!(
            message.as_bytes() != &[0; 32] && body.len() <= g.max_payload_bytes as usize,
            "invalid original message or frame length"
        );
        let (kind, correlation, causation, reply_to, expires) = match (role, original) {
            (ObjectParticipantRole::Caller, None) => (
                MailboxMessageKind::Call,
                CorrelationId::from_bytes(*message.as_bytes()),
                CausationId::from_bytes([0; 32]),
                Some(ReplyRoute {
                    address: d.reply.grant.address,
                    capability_id: d.reply.grant.capability_id,
                }),
                d.expires_at_unix_ms,
            ),
            (ObjectParticipantRole::Callee, Some(call)) => {
                let lease = &call.lease.lease;
                let h = call.original_header;
                verify_object_delivery_projection(
                    &d.local()
                        .durable_object_pair_sha256_v1
                        .context("missing pair selection")?,
                    h,
                    call.original_body,
                    call.lease,
                    &ed25519_dalek::VerifyingKey::from_bytes(&local.reader.grant.authority_key)?,
                )?;
                ensure!(
                    call.original.ciphertext_commitment == lease.ciphertext_commitment
                        && call.original.routing.delivery_id == lease.delivery_id
                        && lease.consumer == local.reader.capability.grant.subject
                        && lease.receive_capability_id
                            == local.reader.capability.grant.capability_id
                        && lease.consumer_session
                            == local.reader.enrollment.enrollment.consumer_session
                        && lease.policy_epoch == g.policy_epoch
                        && (lease.issued_at_unix_ms..lease.expires_at_unix_ms).contains(&now)
                        && h.kind == MailboxMessageKind::Call
                        && h.sender_boot == d.caller.boot
                        && h.capability_id == d.call.grant.capability_id
                        && h.sender == d.call.grant.subject
                        && h.reply_to
                            == Some(ReplyRoute {
                                address: g.address,
                                capability_id: g.capability_id
                            })
                        && h.message_id != message
                        && (h.issued_at_unix_ms..h.expires_at_unix_ms).contains(&now),
                    "Reply requires the authenticated retained Call and original current lease"
                );
                (
                    MailboxMessageKind::Reply,
                    h.correlation_id,
                    CausationId::from_bytes(*h.message_id.as_bytes()),
                    None,
                    d.expires_at_unix_ms.min(h.expires_at_unix_ms),
                )
            }
            _ => anyhow::bail!("original direction mismatch"),
        };
        let header = MailboxEnvelopeHeader {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            tenant: g.address.tenant,
            authorization_domain: g.address.authorization_domain,
            sender: g.subject,
            recipient: g.address.recipient,
            mailbox: g.address.mailbox,
            sender_boot: local.reader.boot.boot,
            execution_epoch: g.minimum_execution_epoch,
            message_id: message,
            correlation_id: correlation,
            causation_id: causation,
            kind,
            reply_to,
            ordering_scope: OrderingScope::parse("spiralcore-object-v1")?,
            sequence,
            issued_at_unix_ms: now,
            expires_at_unix_ms: expires,
            nonce: ReplayNonce::from_bytes(rand::rng().random()),
            content_type: g.content_types[0].clone(),
            capability_id: g.capability_id,
            policy_epoch: g.policy_epoch,
            encryption: EncryptionContext {
                algorithm: EncryptionAlgorithm::AES_256_GCM,
                key_id: Sha256::digest(local.outbound_key.expose_bytes()).into(),
            },
            plaintext_len: body.len().try_into()?,
        };
        let mut routing = local.routing.clone();
        routing.delivery_id = DeliveryId::from_bytes(rand::rng().random());
        routing.expires_at_unix_ms = expires;
        Ok(SealedObjectTurn {
            envelope: seal_envelope(
                SealRequest {
                    header: header.clone(),
                    routing,
                    plaintext: body,
                },
                &local.outbound_key,
                &local.sender,
            )?,
            header,
            capability: d.outbound().clone(),
        })
    }
    fn verify_accepted(
        &self,
        role: ObjectParticipantRole,
        turn: &SealedObjectTurn,
        signed: &SignedDestinationReceipt,
    ) -> Result<()> {
        let endpoint = match role {
            ObjectParticipantRole::Caller => &self.caller,
            ObjectParticipantRole::Callee => &self.callee,
        };
        let d = &endpoint.public_role.role;
        let g = &d.outbound().grant;
        mvm_core::mailbox::verify_receipt(
            signed,
            &ed25519_dalek::VerifyingKey::from_bytes(&d.peer().authority_key)?,
        )?;
        let r = &signed.receipt;
        let h = &turn.header;
        ensure!(
            turn.capability == *d.outbound()
                && h.sender_boot == endpoint.reader.boot.boot
                && h.capability_id == g.capability_id
                && r.protocol_version == ProtocolVersion::V2
                && r.outcome == DeliveryOutcome::AcceptedLocalDurable
                && r.address == g.address
                && r.execution_epoch == g.minimum_execution_epoch
                && r.message_id == h.message_id
                && r.delivery_id == turn.envelope.routing.delivery_id
                && r.ciphertext_commitment == turn.envelope.ciphertext_commitment,
            "receipt does not accept this exact original turn"
        );
        Ok(())
    }
}
