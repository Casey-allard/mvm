//! Prepare one authorized outbound Cast. The original source worker owns the
//! sequence allocator and supplies direction-specific key material from its
//! trusted enrollment. No key is loaded from a route token or from the guest.
use super::{CastChannel, Refusal, deny, route::AddressedCastGrants};
use crate::{
    crypto::aead::Key,
    mailbox::{
        OpenContext, SealRequest, encode_envelope, frame::local::decode_submit_with_digest,
        seal_envelope,
    },
};
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::*;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Local inputs from the original trusted source. This is not a wire DTO.
/// An installation must authenticate both endpoints and the key generation
/// before construction; the public key ID alone cannot establish possession.
pub struct SourceCastEnrollment<'a> {
    pub source_binding: [u8; 32],
    /// Verified public commitment to the original two-owner enrollment.
    pub enrollment_commitment: [u8; 32],
    pub sender_boot: BootId,
    pub signer: &'a SigningKey,
    pub encryption: EncryptionContext,
    pub data_key: &'a Key,
    pub ordering_scope: OrderingScope,
    pub routing: MailboxRoutingFrame,
}

struct PendingCast {
    request: Zeroizing<Vec<u8>>,
    request_id: u64,
    issued_at_ms: i64,
    content_type: ContentType,
    envelope: MailboxEnvelope,
}

/// One object in the original worker. The credit stays held across socket
/// closes, failed publications and reborrows. Only the issuer creates a new
/// slot for a fresh enrollment.
pub struct SourceCastSlot<C> {
    _credit: C,
    reserved_bytes: usize,
    scope: Option<[u8; 32]>,
    pending: Option<PendingCast>,
    retired: u64,
    last_sequence: u64,
}
impl<C> SourceCastSlot<C> {
    /// The installed issuer supplies its actual live reservation and size.
    pub fn new(credit: C, reserved_bytes: usize) -> Self {
        Self {
            _credit: credit,
            reserved_bytes,
            scope: None,
            pending: None,
            retired: 0,
            last_sequence: 0,
        }
    }
}

pub struct CastSource<'a, C> {
    channel: &'a CastChannel,
    grants: AddressedCastGrants<'a>,
    enrollment: SourceCastEnrollment<'a>,
    sequence: &'a mut u64,
    slot: &'a mut SourceCastSlot<C>,
    scope: [u8; 32],
}

impl CastChannel {
    /// Bind the signing worker to the source of the already verified plan pair.
    pub fn matches_original_source(
        &self,
        mailbox: MailboxId,
        epoch: ExecutionEpoch,
        authority_key: &[u8; 32],
    ) -> bool {
        self.source.mailbox == mailbox
            && self.source.epoch == epoch
            && &self.source.authority_key == authority_key
    }
}

impl<'a, C> CastSource<'a, C> {
    /// One original live binding, with exclusive custody of the source worker's
    /// sequence. A restarted worker needs a fresh authenticated binding; this
    /// in-memory slot cannot recover an earlier generation's ciphertext.
    pub fn new(
        channel: &'a CastChannel,
        grants: AddressedCastGrants<'a>,
        enrollment: SourceCastEnrollment<'a>,
        sequence: &'a mut u64,
        slot: &'a mut SourceCastSlot<C>,
    ) -> Result<Self, Refusal> {
        if enrollment.source_binding == [0; 32]
            || enrollment.enrollment_commitment == [0; 32]
            || enrollment.sender_boot.as_bytes() == &[0; 32]
            || enrollment.signer.verifying_key().as_bytes() != channel.sender.as_bytes()
            || enrollment.encryption.key_id == [0; 32]
            || enrollment.encryption.algorithm != EncryptionAlgorithm::AES_256_GCM
            || enrollment.routing.protocol_version != ProtocolVersion::V1
        {
            return Err(deny());
        }
        let frame_bytes = channel.limits.max_frame_bytes as usize;
        let work_bytes = frame_bytes.checked_mul(8).ok_or_else(deny)?;
        if slot.reserved_bytes < work_bytes || !channel.admits_workspace(work_bytes as u64) {
            return Err(deny());
        }
        // The trusted provider never reassigns an enrollment/key ID. Include
        // its transcript and the actual fixed-size signed credentials before
        // lending a slot to a new physical connection.
        let mut digest = Sha256::new();
        digest.update(b"mvm.mailbox.local.cast.slot.v1\0");
        for credential in [grants.source_scope, grants.send, grants.receive] {
            if credential.signature.len() != 64 {
                return Err(deny());
            }
            digest.update(&credential.signature);
        }
        digest.update(enrollment.enrollment_commitment);
        digest.update(enrollment.source_binding);
        digest.update(channel.greeting.binding);
        digest.update(enrollment.sender_boot.as_bytes());
        digest.update(enrollment.encryption.key_id);
        // A socket may reconnect to the same logical binding. A replacement
        // signed plan or tighter admitted frame/payload budget cannot inherit
        // ciphertext prepared under the prior decision.
        let public_context = serde_jcs::to_vec(&(
            &channel.original_plans,
            channel.limits,
            &enrollment.routing,
            &enrollment.ordering_scope,
        ))
        .map_err(|_| deny())?;
        digest.update(public_context);
        let scope: [u8; 32] = digest.finalize().into();
        if *sequence < slot.last_sequence || slot.scope.is_some_and(|original| original != scope) {
            return Err(deny());
        }
        Ok(Self {
            channel,
            grants,
            enrollment,
            sequence,
            slot,
            scope,
        })
    }

    /// Reauthorize even a byte-identical retry. A different request cannot
    /// evict the pending one. No new nonce, signature or sequence is generated
    /// for a retained request.
    pub fn prepare(
        &mut self,
        encoded: &[u8],
        source: &OpenContext,
        destination: &OpenContext,
    ) -> Result<&MailboxEnvelope, Refusal> {
        self.channel
            .authorize_addressed(self.grants, source, destination)?;
        if self.slot.pending.is_none() {
            let pending = self.seal_new(encoded, source, destination)?;
            self.slot.pending = Some(pending);
            self.slot.scope = Some(self.scope);
        }
        let original = self.slot.pending.as_ref().ok_or_else(deny)?;
        if original.request.as_slice() != encoded
            || destination.now_unix_ms < original.issued_at_ms
            || destination.now_unix_ms >= original.envelope.routing.expires_at_unix_ms
            || !destination
                .accepted_content_types
                .contains(&original.content_type)
            || !source
                .accepted_content_types
                .contains(&original.content_type)
        {
            return Err(deny());
        }
        Ok(&original.envelope)
    }

    fn seal_new(
        &mut self,
        encoded: &[u8],
        source: &OpenContext,
        destination: &OpenContext,
    ) -> Result<PendingCast, Refusal> {
        let src_limits = self.channel.source.local_service.ok_or_else(deny)?.limits;
        let limit = self
            .channel
            .limits
            .max_frame_bytes
            .min(src_limits.max_frame_bytes) as usize;
        if encoded.len() > limit + 4 {
            return Err(Refusal::Oversized(limit));
        }
        let (request, _) = decode_submit_with_digest(encoded, &src_limits)?;
        let send = &self.grants.send.grant;
        let receive = &self.grants.receive.grant;
        let max_payload = send
            .max_payload_bytes
            .min(receive.max_payload_bytes)
            .min(self.channel.limits.payload_bytes);
        let expires = request.expires_at_unix_ms;
        if request.kind != MailboxMessageKind::Cast
            || request.request_id <= self.slot.retired
            || request.originating_binding != self.enrollment.source_binding
            || request.recipient != self.channel.recipient
            || request.body.len() > max_payload as usize
            || ![
                &source.accepted_content_types,
                &destination.accepted_content_types,
                &send.content_types,
                &receive.content_types,
            ]
            .iter()
            .all(|types| types.contains(&request.content_type))
            || expires <= source.now_unix_ms
            || expires > self.channel.valid_until
            || expires > self.enrollment.routing.expires_at_unix_ms
            || [
                self.grants.source_scope,
                self.grants.send,
                self.grants.receive,
            ]
            .iter()
            .any(|c| expires > c.grant.expires_at_unix_ms)
        {
            return Err(deny());
        }

        let n = self.sequence.checked_add(1).ok_or_else(deny)?;
        let identity = |label: &[u8]| -> [u8; 32] {
            let mut hash = Sha256::new();
            hash.update(b"mvm.mailbox.local.cast.source.v1\0");
            hash.update(label);
            hash.update(self.channel.sender.as_bytes());
            hash.update(self.enrollment.sender_boot.as_bytes());
            hash.update(self.enrollment.source_binding);
            hash.update(n.to_be_bytes());
            hash.finalize().into()
        };
        let nonce = identity(b"replay");
        let mut replay = [0; 16];
        replay.copy_from_slice(&nonce[..16]);
        let header = MailboxEnvelopeHeader {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            tenant: send.address.tenant,
            authorization_domain: send.address.authorization_domain,
            sender: self.channel.sender,
            recipient: request.recipient,
            mailbox: send.address.mailbox,
            sender_boot: self.enrollment.sender_boot,
            execution_epoch: self.channel.source.epoch,
            message_id: MessageId::from_bytes(identity(b"message")),
            correlation_id: request.correlation,
            causation_id: request.causation,
            kind: request.kind,
            reply_to: None,
            ordering_scope: self.enrollment.ordering_scope.clone(),
            sequence: SequenceNumber::new(n).map_err(|_| deny())?,
            issued_at_unix_ms: source.now_unix_ms,
            expires_at_unix_ms: expires,
            nonce: ReplayNonce::from_bytes(replay),
            content_type: request.content_type.clone(),
            capability_id: send.capability_id,
            policy_epoch: send.policy_epoch,
            encryption: self.enrollment.encryption.clone(),
            plaintext_len: request.body.len() as u32,
        };
        let mut routing = self.enrollment.routing.clone();
        routing.delivery_id = DeliveryId::from_bytes(identity(b"delivery"));
        routing.expires_at_unix_ms = expires;
        let envelope = seal_envelope(
            SealRequest {
                routing,
                header,
                plaintext: &request.body,
            },
            self.enrollment.data_key,
            self.enrollment.signer,
        )
        .map_err(|_| deny())?;
        let size = encode_envelope(&envelope).map_err(|_| deny())?.len();
        if size > limit || !self.grants.admits_encoded_contribution(size) {
            return Err(deny());
        }
        *self.sequence = n;
        self.slot.last_sequence = n;
        Ok(PendingCast {
            request: Zeroizing::new(encoded.to_vec()),
            request_id: request.request_id,
            issued_at_ms: source.now_unix_ms,
            content_type: request.content_type,
            envelope,
        })
    }

    /// Local owner action after its disposition is recorded. This never
    /// acknowledges destination journal admission or workload processing.
    pub fn retire_after(
        &mut self,
        encoded: &[u8],
        record_disposition: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let pending = self
            .slot
            .pending
            .as_ref()
            .ok_or_else(|| std::io::Error::other(deny()))?;
        if pending.request.as_slice() != encoded {
            return Err(std::io::Error::other(deny()));
        }
        record_disposition()?;
        self.slot.retired = pending.request_id;
        self.slot.pending = None;
        Ok(())
    }
}
