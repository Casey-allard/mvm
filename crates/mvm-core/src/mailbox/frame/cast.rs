//! The Deliver-role handoff for one Cast. The destination owner presents the
//! original verified admission and its current policy while holding admission.
//! This path never submits ciphertext to a relay, signs receipts, or activates a guest.
pub mod route;

use super::Refusal;
use super::local::{decode_local_frame, encode_local_frame, encode_local_greeting};
use crate::mailbox::{OpenContext, VerifiedMailboxAdmission};
use mvm_contract::protocol::mailbox::{
    MailboxGrant, MailboxMessageKind, MailboxOperation, PrincipalId, SignedMailboxCapability,
    local::{
        LocalDelivery, LocalDeliveryAck, LocalDirection, LocalFrame, LocalGreeting,
        LocalInboxDisposition, LocalRole,
    },
    local_service::MailboxLocalLimits,
};

fn deny() -> Refusal {
    Refusal::Mailbox("Cast outside admitted local endpoint".into())
}

/// Canonical verification together with the exact authority and destination
/// session where it was opened. Retrying cannot substitute another grant.
pub struct VerifiedCast {
    admission: VerifiedMailboxAdmission,
    original_send: SignedMailboxCapability,
    sequence: std::num::NonZeroU64,
    destination: MailboxGrant,
    greeting: LocalGreeting,
}

impl VerifiedCast {
    pub fn admission(&self) -> &VerifiedMailboxAdmission {
        &self.admission
    }
}

/// Construct at the destination from already admitted configuration, outside the
/// relay. The original owner provides the authenticated port, clock, aggregate
/// reservation, generation lifetime and independently confirmed sender identity.
pub struct CastChannel {
    greeting: LocalGreeting,
    recipient: PrincipalId,
    sender: PrincipalId,
    limits: MailboxLocalLimits,
    grant: MailboxGrant,
    valid_from: i64,
    valid_until: i64,
    source: MailboxGrant,
}

impl CastChannel {
    /// The two plan IDs and greeting come from the original installed service
    /// owner. Verifying portable plans does not acquire either VM, turn on this
    /// mode, or mint the cross-principal Send and Receive grants.
    pub fn from_signed_pair(
        source: &crate::plan::signing::SignedExecutionPlan,
        destination: &crate::plan::signing::SignedExecutionPlan,
        trusted: &[(&str, &ed25519_dalek::VerifyingKey)],
        plan_ids: (&crate::plan::PlanId, &crate::plan::PlanId),
        greeting: LocalGreeting,
        sender: PrincipalId,
        recipient: PrincipalId,
        now_ms: i64,
    ) -> Result<Self, Refusal> {
        let source = crate::plan::signing::verify_plan(source, trusted).map_err(|_| deny())?;
        let target = crate::plan::signing::verify_plan(destination, trusted).map_err(|_| deny())?;
        let start = source
            .valid_from
            .timestamp_millis()
            .max(target.valid_from.timestamp_millis());
        let until = source
            .valid_until
            .timestamp_millis()
            .min(target.valid_until.timestamp_millis());
        if source.plan_id != *plan_ids.0
            || target.plan_id != *plan_ids.1
            || source.tenant != target.tenant
            || source.workload == target.workload
            || now_ms < start
            || now_ms >= until
        {
            return Err(deny());
        }
        let origin = source.mailbox.ok_or_else(deny)?;
        let destination = target.mailbox.ok_or_else(deny)?;
        if origin.mailbox == destination.mailbox {
            return Err(deny());
        }
        origin
            .local_service
            .ok_or_else(deny)?
            .validate()
            .map_err(|_| deny())?;
        let profile = destination.local_service.ok_or_else(deny)?;
        profile.validate().map_err(|_| deny())?;
        encode_local_greeting(&greeting)?;
        if greeting.role != LocalRole::Deliver
            || sender == recipient
            || sender.as_bytes() == &[0; 32]
            || recipient.as_bytes() == &[0; 32]
        {
            return Err(deny());
        }
        let source_limits = origin.local_service.ok_or_else(deny)?.limits;
        let mut limits = profile.limits;
        limits.payload_bytes = limits.payload_bytes.min(source_limits.payload_bytes);
        limits.max_frame_bytes = limits.max_frame_bytes.min(source_limits.max_frame_bytes);
        limits.validate().map_err(|_| deny())?;
        Ok(Self {
            greeting,
            recipient,
            sender,
            limits,
            grant: destination,
            valid_from: start,
            valid_until: until,
            source: origin,
        })
    }

    /// Open at the admitted destination with the exact public sender identity
    /// and the destination grant's authority. Call inside the original owner's
    /// admission transaction; this uses its replay implementation and never
    /// substitutes a permissive replay check. No IO or destination receipt.
    pub fn verify(
        &self,
        envelope: mvm_contract::protocol::mailbox::MailboxEnvelope,
        capability: &SignedMailboxCapability,
        current: &OpenContext,
        destination_key: &crate::crypto::aead::Key,
        replay: &mut impl crate::mailbox::ReplayProtector,
        sequence: std::num::NonZeroU64,
    ) -> Result<VerifiedCast, Refusal> {
        if current.now_unix_ms < self.valid_from
            || current.now_unix_ms >= self.valid_until
            || current.current_execution_epoch != self.source.epoch
            || current.expected_sender != self.sender
            || current.acting_principal != self.sender
            || current.expected_recipient != self.recipient
            || current.expected_mailbox != self.grant.mailbox
            || current.required_operation != MailboxOperation::Send
            || capability.grant.message_kinds.as_slice() != [MailboxMessageKind::Cast]
        {
            return Err(deny());
        }
        let sender =
            ed25519_dalek::VerifyingKey::from_bytes(self.sender.as_bytes()).map_err(|_| deny())?;
        let authority = ed25519_dalek::VerifyingKey::from_bytes(&self.grant.authority_key)
            .map_err(|_| deny())?;
        crate::mailbox::open_verified_admission(
            envelope,
            capability,
            current,
            destination_key,
            &sender,
            &authority,
            replay,
        )
        .map(|admission| VerifiedCast {
            admission,
            original_send: capability.clone(),
            sequence,
            destination: self.grant,
            greeting: self.greeting,
        })
        .map_err(|_| deny())
    }

    /// Prepare only the exact Cast currently authorized at this destination.
    /// The caller retains the admission and its original ciphertext on refusal.
    /// Grant + capability signature verification happened at canonical verified open.
    pub fn encode_delivery(
        &self,
        active: LocalGreeting,
        cast: &VerifiedCast,
        current: &OpenContext,
        receive: &SignedMailboxCapability,
        sequence: u64,
    ) -> Result<Vec<u8>, Refusal> {
        let admission = cast.admission();
        let capability = &cast.original_send;
        let view = admission.journal_view();
        let h = view.header();
        let proof = view.verified_scope();
        if sequence != cast.sequence.get()
            || current.now_unix_ms < self.valid_from
            || current.now_unix_ms >= self.valid_until
            || cast.greeting != active
            || cast.destination != self.grant
            || active != self.greeting
            || h.kind != MailboxMessageKind::Cast
            || h.reply_to.is_some()
            || self.sender != h.sender
            || self.recipient != h.recipient
            || h.mailbox != self.grant.mailbox
            || current.acting_principal != self.sender
            || proof.acting_principal() != self.sender
            || current.required_operation != MailboxOperation::Send
            || proof.required_operation() != MailboxOperation::Send
            || admission.payload().len() > self.limits.payload_bytes as usize
        {
            return Err(deny());
        }
        let authority = ed25519_dalek::VerifyingKey::from_bytes(&self.grant.authority_key)
            .map_err(|_| deny())?;
        crate::mailbox::verify_capability_signature(capability, &authority).map_err(|_| deny())?;
        crate::mailbox::verify_identity_and_time(h, current).map_err(|_| deny())?;
        crate::mailbox::verify_capability_scope(h, capability, current).map_err(|_| deny())?;
        // Receive is a separate destination-issued right. Its identifier and
        // execution epoch belong to the receiver, not the authenticated sender.
        let r = &receive.grant;
        crate::mailbox::verify_capability_signature(receive, &authority).map_err(|_| deny())?;
        if r.subject != self.recipient
            || r.issuer != current.expected_capability_issuer
            || r.address.mailbox != h.mailbox
            || r.address.recipient != h.recipient
            || r.address.tenant != h.tenant
            || r.address.authorization_domain != h.authorization_domain
            || !r.operations.allows(MailboxOperation::Receive)
            || !r.message_kinds.contains(&h.kind)
            || !r.content_types.contains(&h.content_type)
            || h.plaintext_len > r.max_payload_bytes
            || r.policy_epoch != current.current_policy_epoch
            || current.now_unix_ms < r.not_before_unix_ms
            || current.now_unix_ms >= r.expires_at_unix_ms
            || self.grant.epoch < r.minimum_execution_epoch
            || self.grant.epoch > r.maximum_execution_epoch
            || current.revoked_capabilities.contains(&r.revocation_id)
        {
            return Err(deny());
        }
        let frame = LocalFrame::Deliver(Box::new(LocalDelivery {
            delivery_sequence: sequence,
            message_id: h.message_id,
            correlation: h.correlation_id,
            causation: h.causation_id,
            sender: h.sender,
            recipient: h.recipient,
            kind: h.kind,
            content_type: h.content_type.clone(),
            expires_at_unix_ms: h.expires_at_unix_ms,
            reply_token: Vec::new(),
            body: admission.payload().to_vec(),
        }));
        encode_local_frame(
            &frame,
            LocalRole::Deliver,
            LocalDirection::HostToGuest,
            &self.limits,
        )
    }

    /// The original signed pair's intersection. Retained unread plaintext
    /// is never newly offered to a workload beyond this interval.
    pub fn guest_validity(&self) -> std::ops::Range<i64> {
        self.valid_from..self.valid_until
    }

    /// Limit this endpoint to both the verified destination grant and the
    /// original installed reservation. Repeated calls can only narrow limits.
    pub fn narrow_guest_limits(
        &mut self,
        installed: MailboxLocalLimits,
    ) -> Result<MailboxLocalLimits, Refusal> {
        installed.validate().map_err(|_| deny())?;
        let prior = self.limits;
        let limits = MailboxLocalLimits {
            payload_bytes: prior.payload_bytes.min(installed.payload_bytes),
            spooled_requests: prior.spooled_requests.min(installed.spooled_requests),
            retained_guest_bytes: prior
                .retained_guest_bytes
                .min(installed.retained_guest_bytes),
            queued_messages: prior.queued_messages.min(installed.queued_messages),
            active_calls: prior.active_calls.min(installed.active_calls),
            max_frame_bytes: prior.max_frame_bytes.min(installed.max_frame_bytes),
            retained_host_bytes: prior.retained_host_bytes.min(installed.retained_host_bytes),
            max_connections: prior.max_connections.min(installed.max_connections),
        };
        limits.validate().map_err(|_| deny())?;
        self.limits = limits;
        Ok(limits)
    }

    /// One guest inbox for this original role. Retain the last accepted value
    /// across a lost ACK; taking it never enqueues it again.
    pub fn inbox(&self) -> CastInbox {
        CastInbox {
            greeting: self.greeting,
            sender: self.sender,
            recipient: self.recipient,
            retained: None,
            unread: false,
        }
    }

    /// Guest endpoint for one already greeted, host-authenticated Deliver stream.
    /// The inbox owner decides whether to admit under its existing queue and
    /// retry budget. An ACK means precisely that inbox disposition.
    pub fn receive_cast(
        &self,
        active: LocalGreeting,
        bytes: &[u8],
        now_ms: i64,
        inbox: &mut CastInbox,
    ) -> Result<Vec<u8>, Refusal> {
        if active != self.greeting
            || inbox.greeting != self.greeting
            || inbox.sender != self.sender
            || inbox.recipient != self.recipient
        {
            return Err(deny());
        }
        let LocalFrame::Deliver(item) = decode_local_frame(
            bytes,
            LocalRole::Deliver,
            LocalDirection::HostToGuest,
            &self.limits,
        )?
        else {
            return Err(deny());
        };
        if item.kind != MailboxMessageKind::Cast
            || item.sender != self.sender
            || item.recipient != self.recipient
        {
            return Err(deny());
        }
        let delivery_sequence = item.delivery_sequence;
        let message_id = item.message_id;
        let disposition = if now_ms < self.valid_from
            || now_ms >= self.valid_until
            || now_ms >= item.expires_at_unix_ms
        {
            LocalInboxDisposition::Expired
        } else {
            inbox.accept(*item)
        };
        encode_local_frame(
            &LocalFrame::DeliveryAck(LocalDeliveryAck {
                delivery_sequence,
                message_id,
                disposition,
            }),
            LocalRole::Deliver,
            LocalDirection::GuestToHost,
            &self.limits,
        )
    }
}

/// Stop-and-wait guest state. One retained body is charged for the original
/// connection's lifetime. No persisted journal, processing receipt, or retry
/// window after process loss is implied.
pub struct CastInbox {
    greeting: LocalGreeting,
    sender: PrincipalId,
    recipient: PrincipalId,
    retained: Option<std::sync::Arc<LocalDelivery>>,
    unread: bool,
}
impl CastInbox {
    pub fn take(&mut self) -> Option<std::sync::Arc<LocalDelivery>> {
        if !std::mem::take(&mut self.unread) {
            return None;
        }
        self.retained.clone()
    }
    /// Clear the original unread mark only after a successful workload
    /// handoff. Failures, including ambiguous acknowledgments, retain it.
    pub fn consume_with<T, E>(
        &mut self,
        deliver: impl FnOnce(&LocalDelivery) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        let Some(item) = self.retained.as_deref().filter(|_| self.unread) else {
            return Ok(None);
        };
        let result = deliver(item)?;
        self.unread = false;
        Ok(Some(result))
    }

    fn accept(&mut self, item: LocalDelivery) -> LocalInboxDisposition {
        let last = if let Some(prior) = &self.retained {
            if prior.as_ref() == &item {
                return LocalInboxDisposition::Accepted;
            }
            if prior.message_id == item.message_id
                || item.delivery_sequence <= prior.delivery_sequence
            {
                return LocalInboxDisposition::Unavailable;
            }
            prior.delivery_sequence
        } else {
            0
        };
        if last.checked_add(1) != Some(item.delivery_sequence) {
            return LocalInboxDisposition::Unavailable;
        }
        if self.unread {
            return LocalInboxDisposition::Full;
        }
        self.retained = Some(std::sync::Arc::new(item));
        self.unread = true;
        LocalInboxDisposition::Accepted
    }
}

/// Inputs borrowed from the current destination admission turn. The relay
/// cannot construct the verified admission from an opaque envelope.
pub struct CastAdmission<'a> {
    pub verified: &'a VerifiedCast,
    pub current: &'a OpenContext,
    pub receive: &'a SignedMailboxCapability,
    pub sequence: u64,
}

fn read_deliver_frame(
    stream: &mut impl std::io::Read,
    limits: &MailboxLocalLimits,
) -> std::io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix)?;
    let length = super::local::checked_local_body_length(&prefix, LocalRole::Deliver, limits)
        .map_err(std::io::Error::other)?;
    let mut bytes = Vec::with_capacity(4 + length);
    bytes.extend_from_slice(&prefix);
    bytes.resize(4 + length, 0);
    stream.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}

impl CastChannel {
    /// Send a Cast on the original owner's authenticated, deadline-bounded
    /// port-5257 Deliver stream. Caller retains the envelope across partial writes
    /// or lost acknowledgments. No destination receipt is issued here.
    pub fn dispatch_on<'a>(
        &self,
        io: &mut (impl std::io::Read + std::io::Write),
        current_turn: impl FnOnce() -> std::io::Result<CastAdmission<'a>>,
    ) -> std::io::Result<LocalDeliveryAck> {
        let greeting = encode_local_greeting(&self.greeting).map_err(std::io::Error::other)?;
        io.write_all(&greeting)?;
        let mut echo = [0; super::local::LOCAL_GREETING_BYTES];
        io.read_exact(&mut echo)?;
        super::local::verify_local_greeting_echo(&self.greeting, &echo)
            .map_err(std::io::Error::other)?;
        let turn = current_turn()?;
        let bytes = self
            .encode_delivery(
                self.greeting,
                turn.verified,
                turn.current,
                turn.receive,
                turn.sequence,
            )
            .map_err(std::io::Error::other)?;
        io.write_all(&bytes)?;
        let response = read_deliver_frame(io, &self.limits)?;
        let response = decode_local_frame(
            &response,
            LocalRole::Deliver,
            LocalDirection::GuestToHost,
            &self.limits,
        )
        .map_err(std::io::Error::other)?;
        match response {
            LocalFrame::DeliveryAck(ack)
                if ack.message_id
                    == turn.verified.admission().journal_view().header().message_id
                    && ack.delivery_sequence == turn.sequence =>
            {
                Ok(ack)
            }
            _ => Err(std::io::Error::other(
                "uncorrelated local Cast acknowledgment",
            )),
        }
    }

    /// Accept one transfer on a stream whose peer was already authenticated
    /// by the guest transport. Echo only the greeting installed for this role.
    pub fn receive_on(
        &self,
        io: &mut (impl std::io::Read + std::io::Write),
        now: impl FnOnce() -> i64,
        inbox: &mut CastInbox,
    ) -> std::io::Result<()> {
        let mut greeting = [0; super::local::LOCAL_GREETING_BYTES];
        io.read_exact(&mut greeting)?;
        super::local::verify_local_greeting_echo(&self.greeting, &greeting)
            .map_err(std::io::Error::other)?;
        io.write_all(&greeting)?;
        let bytes = read_deliver_frame(io, &self.limits)?;
        let ack = self
            .receive_cast(self.greeting, &bytes, now(), inbox)
            .map_err(std::io::Error::other)?;
        io.write_all(&ack)
    }
}
