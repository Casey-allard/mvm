//! Original A-side dispatch for the opt-in local-durable direction.
use super::sender_window::{Original, SenderWindow};
use super::{GuestSealer, Refusal};
use crate::mailbox_launch::MailboxTemplate;
use crate::mailbox_process::original_journal::authorization::{
    JournalCredentials, check_credentials, destination_header, now_ms,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    EncryptionContext, MailboxJournalDirectionV1, MailboxRoutingFrame, PrincipalId,
    SignedDestinationReceipt,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::reader_wire::ReaderResponse;
use mvm_core::mailbox::sender_ordinal::{MAX_ORDINAL_PAYLOAD, SenderRequestV1};
use mvm_core::mailbox::{
    OpenContext,
    frame::{OutboxMessage, send_local_receipted_frame},
    outbound::{check_projection, journal_direction_commitment},
    reader::MailboxReaderBootBinding,
};
use mvm_core::plan::ExecutionPlan;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// B's original role transfers the directional payload key alone to A. The
/// original mailbox authority signer and retained local payload key stay at B.
pub(crate) struct PairedSourceMaterial {
    pub(crate) commitment: [u8; 32],
    pub(crate) key: Key,
    pub(crate) encryption: EncryptionContext,
    pub(crate) routing: MailboxRoutingFrame,
}
impl PairedSourceMaterial {
    pub(crate) fn from_enrollment(
        commitment: [u8; 32],
        key: Key,
        encryption: EncryptionContext,
        routing: MailboxRoutingFrame,
    ) -> Self {
        Self {
            commitment,
            key,
            encryption,
            routing,
        }
    }
}

pub(crate) struct JournalPeer<'a> {
    pub(crate) context: &'a OpenContext,
    pub(crate) state: &'a Path,
}

/// A never needs B's Child handle or signing secret. A's original launcher
/// supplies one authenticated original-destination connection for each turn.
pub(crate) struct DirectedJournalSource {
    source: MailboxTemplate,
    source_context: OpenContext,
    destination_context: OpenContext,
    sealer: GuestSealer,
    direction: MailboxJournalDirectionV1,
    original_commitment: [u8; 32],
    grants: JournalCredentials,
    verifier: VerifyingKey,
    ordinal_window: Option<SenderWindow>,
    guest_settlement_key: VerifyingKey,
    source_revocations: PathBuf,
    destination_revocations: PathBuf,
}
impl DirectedJournalSource {
    /// Called only after the original A's production posture/reader boot and
    /// still-original B's peer admission have been verified by the launcher.
    pub(crate) fn from_original(
        plan: &ExecutionPlan,
        boot: &MailboxReaderBootBinding,
        original: &GuestSealer,
        source_peer: JournalPeer<'_>,
        destination_peer: JournalPeer<'_>,
        grants: JournalCredentials,
        material: PairedSourceMaterial,
    ) -> Result<Self> {
        let JournalPeer {
            context: local,
            state: source_state,
        } = source_peer;
        let JournalPeer {
            context: destination,
            state: destination_state,
        } = destination_peer;
        boot.check_plan(plan)?;
        let local_grant = plan.mailbox.as_ref().context("A has no mailbox")?;
        let d = boot
            .outbound_journal_v1
            .context("A has no journal direction")?;
        check_projection(local_grant, &d)?;
        ensure!(
            material.commitment == journal_direction_commitment(boot)?
                && boot.authority_key == original.authority_key.verifying_key().to_bytes()
                && original.sender_key.verifying_key().to_bytes() == *d.source.as_bytes()
                && original.header.mailbox == boot.mailbox
                && original.header.execution_epoch == boot.execution_epoch
                && material.encryption != original.header.encryption
                && material.routing.hop_limit == 1,
            "original A helper or directional key binding differs"
        );
        let source = MailboxTemplate {
            capability: original.capability.clone(),
            header: original.header.clone(),
            routing: original.routing.clone(),
        };
        let mut header = destination_header(original.header.clone(), &d, &grants.destination_send);
        header.sender_boot = boot.boot;
        header.encryption = material.encryption;
        let mut routing = material.routing;
        routing.expires_at_unix_ms = d.expires_at_unix_ms;
        let sealer = GuestSealer {
            encryption_key: material.key,
            sender_key: original.sender_key.clone(),
            authority_key: original.authority_key.clone(),
            capability: grants.destination_send.grant.clone(),
            header,
            routing,
            sent: 0,
            intent_dir: Some(
                original
                    .intent_dir
                    .as_ref()
                    .context("A lacks durable source intents")?
                    .clone(),
            ),
        };
        let mut result = Self {
            source,
            source_context: local.clone(),
            destination_context: destination.clone(),
            sealer,
            direction: d,
            original_commitment: material.commitment,
            grants,
            verifier: VerifyingKey::from_bytes(&d.receipt_key)?,
            ordinal_window: d
                .sender_settlement
                .map(|_| SenderWindow::reopen(source_state, material.commitment))
                .transpose()?,
            guest_settlement_key: VerifyingKey::from_bytes(&boot.ack_public_key)?,
            source_revocations: crate::mailbox_process::reader::revocations_path(source_state),
            destination_revocations: crate::mailbox_process::reader::revocations_path(
                destination_state,
            ),
        };
        result.authorize(d.max_payload_bytes)?;
        Ok(result)
    }
    pub(crate) fn recipient(&self) -> PrincipalId {
        self.direction.address.recipient
    }

    fn authorize(&mut self, length: u32) -> Result<i64, Refusal> {
        self.source_context.revoked_capabilities =
            super::durable::reader_revocations(&self.source_revocations)?;
        self.destination_context.revoked_capabilities =
            super::durable::reader_revocations(&self.destination_revocations)?;
        let now = now_ms().map_err(|_| Refusal::Unavailable)?;
        check_credentials(
            &self.source,
            &self.direction,
            &self.grants,
            &self.source_context,
            &self.destination_context,
            now,
            length,
        )
        .map_err(|_| Refusal::NotAuthorized)?;
        Ok(now)
    }

    fn ordinal_turn(
        &mut self,
        request: SenderRequestV1,
        until: Instant,
        connect: impl FnOnce(Instant) -> Result<UnixStream, Refusal>,
    ) -> Result<ReaderResponse, Refusal> {
        if self.ordinal_window.is_none() || Instant::now() >= until {
            return Err(Refusal::NotAuthorized);
        }
        match request {
            SenderRequestV1::Settle { statement } => {
                self.authorize(1)?;
                let retired_through = self
                    .ordinal_window
                    .as_ref()
                    .ok_or(Refusal::NotAuthorized)?
                    .settle(&statement, &self.guest_settlement_key)?;
                Ok(ReaderResponse::SenderSettledV1 {
                    handle: statement.handle,
                    retired_through,
                })
            }
            SenderRequestV1::Submit { handle, payload } => {
                if payload.is_empty() || payload.len() > MAX_ORDINAL_PAYLOAD {
                    return Err(Refusal::Oversized(MAX_ORDINAL_PAYLOAD));
                }
                let length = payload.len() as u32;
                let now = self.authorize(length)?;
                let deadline = until.min(
                    Instant::now()
                        .checked_add(Duration::from_millis(
                            self.direction.expires_at_unix_ms.saturating_sub(now) as u64,
                        ))
                        .unwrap_or(until),
                );
                let message = OutboxMessage {
                    recipient: self.recipient(),
                    message_id: handle.message_id()?,
                    body: payload,
                };
                let intent = mvm_core::mailbox::outbound::journal_intent_digest(&message);
                let send = &self.grants.destination_send;
                let original = self
                    .ordinal_window
                    .as_ref()
                    .ok_or(Refusal::NotAuthorized)?
                    .reserve(handle, intent, || {
                        let (cap, env, _) =
                            self.sealer.seal_at(&message, Some(send), handle.ordinal)?;
                        mvm_core::mailbox::frame::encode_frame(&cap, &env)
                    })?;
                let (bytes, prior) = match original {
                    Original::Send(bytes) => (bytes, None),
                    Original::Accepted(bytes, receipt) => (bytes, Some(*receipt)),
                };
                let role = super::OriginalSend {
                    signed: send,
                    verifier: &self.verifier,
                    commitment: self.original_commitment,
                };
                let (cap, env) =
                    self.sealer
                        .open_intent(&bytes, &message, Some(role), Some(handle.ordinal))?;
                let mut expected = self.sealer.header.clone();
                expected.message_id = message.message_id;
                let receipt = if let Some(r) = prior {
                    mvm_core::mailbox::frame::verify_expected_receipt(
                        &r,
                        &env,
                        &expected,
                        &self.verifier,
                        &[mvm_contract::protocol::mailbox::DeliveryOutcome::AcceptedLocalDurable],
                    )?;
                    r
                } else {
                    self.authorize(length)?;
                    if Instant::now() >= deadline {
                        return Err(Refusal::Unavailable);
                    }
                    let stream = connect(deadline)?;
                    self.authorize(length)?;
                    let mut stream = super::durable::GuestDeadline::new(stream, deadline)
                        .map_err(|_| Refusal::Unavailable)?;
                    send_local_receipted_frame(&mut stream, &cap, &env, &expected, &self.verifier)?
                };
                if Instant::now() >= deadline
                    || receipt.receipt.protocol_version
                        != mvm_contract::protocol::mailbox::ProtocolVersion::V2
                    || !(self.direction.not_before_unix_ms..self.direction.expires_at_unix_ms)
                        .contains(&receipt.receipt.observed_at_unix_ms)
                {
                    return Err(Refusal::NotAuthorized);
                }
                self.authorize(length)?;
                let receipt = self
                    .ordinal_window
                    .as_ref()
                    .ok_or(Refusal::NotAuthorized)?
                    .accept(handle, &bytes, receipt)?;
                Ok(ReaderResponse::SenderAcceptedV1 {
                    handle,
                    receipt: Box::new(receipt),
                })
            }
        }
    }

    /// Persist A's canonical credential/envelope before opening the
    /// authenticated B connection. The same immutable bytes can be retried
    /// after an ambiguous reply or subsequent guest redial.
    pub(crate) fn forward(
        &mut self,
        message: OutboxMessage,
        deadline: Instant,
        connect: impl FnOnce(Instant) -> Result<UnixStream, Refusal>,
    ) -> Result<SignedDestinationReceipt, Refusal> {
        let len = u32::try_from(message.body.len()).map_err(|_| Refusal::Malformed)?;
        if self.ordinal_window.is_some() || message.recipient != self.recipient() {
            return Err(Refusal::NotAuthorized);
        }
        let now = self.authorize(len)?;
        let window = (self.direction.expires_at_unix_ms - now) as u64;
        let deadline = deadline.min(
            Instant::now()
                .checked_add(Duration::from_millis(window))
                .unwrap_or(deadline),
        );
        if Instant::now() >= deadline {
            return Err(Refusal::Unavailable);
        }
        let mut expected = self.sealer.header.clone();
        expected.message_id = message.message_id;
        let (cap, envelope) = self.sealer.seal_using(
            message,
            Some(super::OriginalSend {
                signed: &self.grants.destination_send,
                verifier: &self.verifier,
                commitment: self.original_commitment,
            }),
        )?;
        self.authorize(len)?;
        let stream = connect(deadline)?;
        self.authorize(len)?;
        let mut stream = super::durable::GuestDeadline::new(stream, deadline)
            .map_err(|_| Refusal::Unavailable)?;
        let receipt =
            send_local_receipted_frame(&mut stream, &cap, &envelope, &expected, &self.verifier)?;
        if Instant::now() >= deadline
            || !(self.direction.not_before_unix_ms..self.direction.expires_at_unix_ms)
                .contains(&receipt.receipt.observed_at_unix_ms)
        {
            return Err(Refusal::Unavailable);
        }
        self.authorize(len)?;
        Ok(receipt)
    }
}

type SourceTransport<'a> = (
    &'a mut DirectedJournalSource,
    &'a mut dyn FnMut(Instant) -> Result<UnixStream, Refusal>,
);

/// The selection is made from the original boot, before A's own seal/admit.
/// Missing delegated data transport is an indeterminate directed operation,
/// and never authorizes a retry through the local journal.
pub(crate) struct SourceTurn<'a> {
    original_recipient: Option<PrincipalId>,
    original_commitment: Option<[u8; 32]>,
    transport: Option<SourceTransport<'a>>,
}

impl<'a> SourceTurn<'a> {
    pub(crate) fn from_boot(boot: &MailboxReaderBootBinding) -> Result<Self> {
        Ok(Self {
            original_commitment: boot
                .outbound_journal_v1
                .as_ref()
                .map(|_| journal_direction_commitment(boot))
                .transpose()?,
            original_recipient: boot.outbound_journal_v1.map(|d| d.address.recipient),
            transport: None,
        })
    }
    pub(super) fn own() -> Self {
        Self {
            original_recipient: None,
            original_commitment: None,
            transport: None,
        }
    }
    pub(crate) fn attach(
        mut self,
        endpoint: &'a mut DirectedJournalSource,
        connect: &'a mut dyn FnMut(Instant) -> Result<UnixStream, Refusal>,
    ) -> Result<Self, Refusal> {
        if self.original_recipient != Some(endpoint.recipient())
            || self.original_commitment != Some(endpoint.original_commitment)
        {
            return Err(Refusal::NotAuthorized);
        }
        self.transport = Some((endpoint, connect));
        Ok(self)
    }
    pub(super) fn ordinal_turn(
        &mut self,
        request: SenderRequestV1,
        until: Instant,
    ) -> Result<ReaderResponse, Refusal> {
        let (source, connect) = self.transport.as_mut().ok_or(Refusal::NotAuthorized)?;
        source.ordinal_turn(request, until, connect)
    }
    pub(super) fn send(
        &mut self,
        message: OutboxMessage,
        deadline: Instant,
        local: impl FnOnce(OutboxMessage) -> Result<SignedDestinationReceipt, Refusal>,
    ) -> Result<SignedDestinationReceipt, Refusal> {
        if Some(message.recipient) != self.original_recipient {
            return local(message);
        }
        let (endpoint, connect) = self.transport.as_mut().ok_or(Refusal::Unavailable)?;
        endpoint.forward(message, deadline, connect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_remote_recipient_never_falls_back_to_source_local_admit() {
        let b = PrincipalId::from_bytes([11; 32]);
        let mut routed = SourceTurn {
            original_recipient: Some(b),
            original_commitment: Some([4; 32]),
            transport: None,
        };
        let mut local = 0;
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = routed.send(OutboxMessage::new(b, vec![0, 7, 0]), deadline, |_| {
            local += 1;
            Err(Refusal::StorageFull)
        });
        assert!(matches!(result, Err(Refusal::Unavailable)));
        assert_eq!(local, 0);
        let own = PrincipalId::from_bytes(mvm_core::mailbox::frame::OWN_MAILBOX_RECIPIENT);
        let result = routed.send(OutboxMessage::new(own, vec![7]), deadline, |_| {
            local += 1;
            Err(Refusal::StorageFull)
        });
        assert!(matches!(result, Err(Refusal::StorageFull)));
        assert_eq!(local, 1);
    }
}
