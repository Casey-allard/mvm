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
    header: MailboxEnvelopeHeader,
    envelope: MailboxEnvelope,
    capability: SignedMailboxCapability,
}
impl SealedObjectTurn {
    pub fn header(&self) -> &MailboxEnvelopeHeader {
        &self.header
    }
    pub fn envelope(&self) -> &MailboxEnvelope {
        &self.envelope
    }
    pub fn capability(&self) -> &SignedMailboxCapability {
        &self.capability
    }
}
pub use mvm_core::mailbox::journal::RetainedObjectCall as OriginalObjectCallLease;
use mvm_core::mailbox::reader_wire::ObjectSubmissionV1;

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
        correlation: CorrelationId,
        sequence: SequenceNumber,
        body: &[u8],
    ) -> Result<SealedObjectTurn> {
        self.material.seal_turn(
            ObjectParticipantRole::Caller,
            message,
            Some(correlation),
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
            None,
            sequence,
            body,
            Some(&original),
            self.check_current()?,
        )
    }
    /// Reopen only an already bound outbound intent. The returned turn keeps
    /// the original ciphertext/nonce/delivery ID rather than generating a retry.
    pub fn reopen_turn(
        &self,
        role: ObjectParticipantRole,
        cap: &SignedMailboxCapability,
        envelope: MailboxEnvelope,
        sequence: SequenceNumber,
        submission: &ObjectSubmissionV1,
        original: Option<&OriginalObjectCallLease<'_>>,
    ) -> Result<SealedObjectTurn> {
        self.material.reopen(
            role,
            cap,
            envelope,
            sequence,
            submission,
            original,
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

impl InstalledObjectPair<'_> {
    /// Called only on the committed callee's original reader connection.
    /// A fresh authority sample precedes the exact journal owner's lease lookup.
    pub fn authorize_object_call(
        &self,
        pair: [u8; 32],
        boot: BootId,
        journal: &mvm_core::mailbox::journal::MailboxJournal,
        lease: &SignedMailboxDeliveryLease,
    ) -> Result<&SignedObjectRoleV1> {
        let now = self.check_current()?;
        let local = &self.material.callee;
        ensure!(
            pair == self.prepared.stamp && boot == local.reader.boot.boot,
            "wrong destination generation"
        );
        let d = local.public_role.verify(&local.reader.boot, now)?;
        let row = journal.original_object_call(lease, now)?;
        verify_active_call(local, d, &row, now)?;
        Ok(&local.public_role)
    }
}

fn verify_active_call(
    local: &EndpointMaterial,
    d: &mvm_core::mailbox::object_pair::role::ObjectRoleV1,
    call: &OriginalObjectCallLease<'_>,
    now: i64,
) -> Result<MailboxEnvelopeHeader> {
    let g = &d.reply.grant;
    ensure!(
        call.capability() == &d.call,
        "retained row has different Call grant"
    );
    let opened = open_original(
        &d.call,
        MailboxOperation::Send,
        call.envelope(),
        &local.inbound_key,
        now,
    )?;
    let h = opened.header();
    let lease = &call.lease().lease;
    verify_object_delivery_projection(
        &d.local()
            .durable_object_pair_sha256_v1
            .context("missing pair selection")?,
        h,
        opened.payload(),
        call.lease(),
        &ed25519_dalek::VerifyingKey::from_bytes(&local.reader.grant.authority_key)?,
    )?;
    ensure!(
        call.envelope().ciphertext_commitment == lease.ciphertext_commitment
            && call.envelope().routing.delivery_id == lease.delivery_id
            && lease.consumer == local.reader.capability.grant.subject
            && lease.receive_capability_id == local.reader.capability.grant.capability_id
            && lease.consumer_session == local.reader.enrollment.enrollment.consumer_session
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
            && (h.issued_at_unix_ms..h.expires_at_unix_ms).contains(&now),
        "Reply requires the authenticated retained Call and original current lease"
    );
    Ok(h.clone())
}

impl PairMaterial {
    pub(super) fn seal_turn(
        &self,
        role: ObjectParticipantRole,
        message: MessageId,
        correlation_id: Option<CorrelationId>,
        sequence: SequenceNumber,
        body: &[u8],
        original: Option<&OriginalObjectCallLease<'_>>,
        now: i64,
    ) -> Result<SealedObjectTurn> {
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
        let (kind, correlation, causation, reply_to, expires) =
            self.original_fields(role, local, d, message, correlation_id, original, now)?;
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
            nonce: ReplayNonce::from_bytes(rand::random()),
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
        routing.delivery_id = DeliveryId::from_bytes(rand::random());
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
    fn original_fields(
        &self,
        role: ObjectParticipantRole,
        local: &EndpointMaterial,
        d: &mvm_core::mailbox::object_pair::role::ObjectRoleV1,
        message: MessageId,
        correlation_id: Option<CorrelationId>,
        original: Option<&OriginalObjectCallLease<'_>>,
        now: i64,
    ) -> Result<(
        MailboxMessageKind,
        CorrelationId,
        CausationId,
        Option<ReplyRoute>,
        i64,
    )> {
        let g = &d.outbound().grant;
        let fields = match (role, original) {
            (ObjectParticipantRole::Caller, None) => (
                MailboxMessageKind::Call,
                correlation_id
                    .filter(|id| id.as_bytes() != &[0; 32])
                    .context("Call needs original correlation")?,
                CausationId::from_bytes([0; 32]),
                Some(ReplyRoute {
                    address: d.reply.grant.address,
                    capability_id: d.reply.grant.capability_id,
                }),
                d.expires_at_unix_ms,
            ),
            (ObjectParticipantRole::Callee, Some(call)) => {
                let h = verify_active_call(local, d, call, now)?;
                ensure!(
                    h.message_id != message,
                    "Reply cannot reuse its Call identity"
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
        Ok(fields)
    }
    pub(super) fn reopen(
        &self,
        role: ObjectParticipantRole,
        cap: &SignedMailboxCapability,
        envelope: MailboxEnvelope,
        sequence: SequenceNumber,
        submission: &ObjectSubmissionV1,
        original: Option<&OriginalObjectCallLease<'_>>,
        now: i64,
    ) -> Result<SealedObjectTurn> {
        let local = match role {
            ObjectParticipantRole::Caller => &self.caller,
            ObjectParticipantRole::Callee => &self.callee,
        };
        let d = local.public_role.verify(&local.reader.boot, now)?;
        ensure!(
            cap == d.outbound(),
            "retained turn has different credential"
        );
        let (message, correlation, op, body) = match (role, submission) {
            (
                ObjectParticipantRole::Caller,
                ObjectSubmissionV1::Call {
                    message_id,
                    correlation_id,
                    payload,
                },
            ) => (
                *message_id,
                Some(*correlation_id),
                MailboxOperation::Send,
                payload,
            ),
            (
                ObjectParticipantRole::Callee,
                ObjectSubmissionV1::Reply {
                    message_id,
                    original_call,
                    payload,
                },
            ) => {
                ensure!(
                    original.is_some_and(|row| row.lease() == original_call.as_ref()),
                    "different current Call lease"
                );
                (*message_id, None, MailboxOperation::Reply, payload)
            }
            _ => anyhow::bail!("wrong original submission role"),
        };
        let opened = open_original(cap, op, &envelope, &local.outbound_key, now)?;
        let h = opened.header();
        let (kind, correlation, cause, route, expires) =
            self.original_fields(role, local, d, message, correlation, original, now)?;
        ensure!(
            message.as_bytes() != &[0; 32]
                && h.message_id == message
                && h.sequence == sequence
                && opened.payload() == body
                && h.correlation_id == correlation
                && h.causation_id == cause
                && h.reply_to == route
                && h.kind == kind
                && h.sender_boot == local.reader.boot.boot
                && h.issued_at_unix_ms >= d.not_before_unix_ms
                && h.expires_at_unix_ms == expires
                && h.encryption.key_id
                    == <[u8; 32]>::from(Sha256::digest(local.outbound_key.expose_bytes())),
            "retained intent differs from original submission"
        );
        Ok(SealedObjectTurn {
            header: h.clone(),
            envelope,
            capability: cap.clone(),
        })
    }

    pub(super) fn verify_accepted(
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
                && h.encryption.key_id
                    == <[u8; 32]>::from(Sha256::digest(endpoint.outbound_key.expose_bytes()))
                && (h.issued_at_unix_ms..h.expires_at_unix_ms).contains(&r.observed_at_unix_ms)
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

/// Verification of a previously retained immutable row. The source intent or
/// active journal lease owns durable replay accounting. This local inspection
/// is never used to admit a new delivery.
fn open_original(
    cap: &SignedMailboxCapability,
    op: MailboxOperation,
    envelope: &MailboxEnvelope,
    key: &Key,
    now: i64,
) -> Result<mvm_core::mailbox::OpenedMailboxEnvelope> {
    use mvm_core::mailbox::{InMemoryReplayProtector, OpenContext, open_verified_envelope};
    let g = &cap.grant;
    let a = g.address;
    let context = OpenContext {
        expected_tenant: a.tenant,
        expected_authorization_domain: a.authorization_domain,
        expected_mailbox: a.mailbox,
        expected_sender: g.subject,
        expected_recipient: a.recipient,
        acting_principal: g.subject,
        expected_capability_issuer: g.issuer,
        current_execution_epoch: g.minimum_execution_epoch,
        current_policy_epoch: g.policy_epoch,
        required_operation: op,
        now_unix_ms: now,
        accepted_content_types: g.content_types.clone(),
        revoked_capabilities: Vec::new(),
    };
    Ok(open_verified_envelope(
        envelope,
        cap,
        &context,
        key,
        &ed25519_dalek::VerifyingKey::from_bytes(g.subject.as_bytes())?,
        &ed25519_dalek::VerifyingKey::from_bytes(g.issuer.as_bytes())?,
        &mut InMemoryReplayProtector::default(),
    )?)
}
