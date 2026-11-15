//! Durable guest lease, readback and authenticated acknowledgement transitions.
use super::*;

impl MailboxJournal {
    /// Inspect the oldest unacknowledged, unexpired ciphertext under a signed
    /// Receive grant. Call `expire_next` first to durably settle expired entries;
    /// an empty read alone is not an expiry receipt.
    pub fn receive_next(
        &self,
        request: JournalReceive<'_>,
    ) -> Result<Option<ReceivedMailboxMessage>, JournalError> {
        self.receive_next_for(request, MailboxOperation::Send)
    }
    pub(super) fn receive_next_for(
        &self,
        request: JournalReceive<'_>,
        original_operation: MailboxOperation,
    ) -> Result<Option<ReceivedMailboxMessage>, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        for identity in &self.order {
            let entry = self.seen.get(identity).ok_or(JournalError::Corrupt)?;
            if entry.acknowledged
                || entry.expired_at_unix_ms.is_some()
                || request.context.now_unix_ms >= entry.envelope.routing.expires_at_unix_ms
            {
                continue;
            }
            let opened = self.open_for_reader(*identity, entry, &request, original_operation)?;
            return Ok(Some(ReceivedMailboxMessage {
                identity: *identity,
                opened,
            }));
        }
        Ok(None)
    }

    /// Commit one signed lease and its one-time possession challenge before
    /// releasing plaintext to the authenticated guest reader.
    pub fn lease_next(
        &mut self,
        request: JournalGuestLease<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<Option<LeasedMailboxMessage>, JournalError> {
        self.lease_next_inner(request, None, anchor)
    }

    /// A Reply must be anchored to the current lease of the exact original
    /// unacknowledged row. The borrow keeps this journal generation locked.
    pub fn original_object_call(
        &self,
        signed: &SignedMailboxDeliveryLease,
        now: i64,
    ) -> Result<RetainedObjectCall<'_>, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        let l = &signed.lease;
        if l.address != self.address
            || l.object_projection_v1.is_none()
            || !(l.issued_at_unix_ms..l.expires_at_unix_ms).contains(&now)
        {
            return Err(JournalError::NoActiveLease);
        }
        let id = ReplayIdentity {
            sender: l.sender,
            sender_boot: l.sender_boot,
            execution_epoch: l.execution_epoch,
            message_id: l.message_id,
        };
        let entry = self.seen.get(&id).ok_or(JournalError::NoActiveLease)?;
        let active = entry.lease.as_ref().ok_or(JournalError::NoActiveLease)?;
        if entry.acknowledged
            || entry.expired_at_unix_ms.is_some()
            || active.signed != *signed
            || entry.envelope.ciphertext_commitment != l.ciphertext_commitment
            || entry.envelope.routing.delivery_id != l.delivery_id
        {
            return Err(JournalError::NoActiveLease);
        }
        Ok(RetainedObjectCall { entry, active })
    }

    /// Lease the next original record for the opted-in pair. The independent
    /// Receive enrollment and possession checks are identical to ordinary delivery.
    pub fn lease_next_object(
        &mut self,
        request: JournalGuestLease<'_>,
        scope: ObjectLeaseScope<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<Option<LeasedMailboxMessage>, JournalError> {
        self.lease_next_inner(request, Some(ObjectCheck::Fixed(scope)), anchor)
    }

    /// The installed caller recovers the correct pending Call from the immutable
    /// source seal for the specific row chosen by this journal.
    pub fn lease_next_object_reply<'r>(
        &mut self,
        request: JournalGuestLease<'_>,
        scope: ObjectLeaseScope<'_>,
        resolve: &'r mut OriginalCallResolver<'r>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<Option<LeasedMailboxMessage>, JournalError> {
        self.lease_next_inner(
            request,
            Some(ObjectCheck::ResolveReply(scope, resolve)),
            anchor,
        )
    }

    pub(super) fn lease_next_inner(
        &mut self,
        request: JournalGuestLease<'_>,
        paired: Option<ObjectCheck<'_, '_>>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<Option<LeasedMailboxMessage>, JournalError> {
        if request.plan.durable_object_pair_sha256_v1.is_some() != paired.is_some() {
            return Err(JournalError::WrongAuthority);
        }
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if request.signer.verifying_key() != self.authority
            || request.scope.plan != request.plan
            || request.scope.receive != &request.receive.capability.grant
            || request.scope.now_unix_ms != request.receive.context.now_unix_ms
            || request.scope.current_session.as_bytes() == &[0; 32]
            || request.scope.current_boot.as_bytes() == &[0; 32]
            || request.receive.context.acting_principal != request.enrollment.enrollment.consumer
        {
            return Err(JournalError::WrongAuthority);
        }
        let key = verify_guest_reader_enrollment(
            request.enrollment,
            request.receive.capability,
            &request.scope,
            &self.authority,
            &request.receive.context.revoked_capabilities,
        )?;
        verify_reader_possession(
            request.enrollment,
            request.challenge,
            request.possession_signature,
            &key,
        )?;
        let Some(message) = self.receive_next_for(
            request.receive,
            paired
                .as_ref()
                .map_or(MailboxOperation::Send, ObjectCheck::operation),
        )?
        else {
            return Ok(None);
        };
        let identity = message.identity;
        let entry = self.seen.get(&identity).ok_or(JournalError::Corrupt)?;
        if let Some(scope) = paired {
            scope.check_original(&request.scope, entry, &request.receive)?;
        }
        let now = request.scope.now_unix_ms;
        if let Some(active) = &entry.lease
            && active.signed.lease.expires_at_unix_ms > now
        {
            if active.enrollment != *request.enrollment
                || active.receive_capability != *request.receive.capability
            {
                return Err(JournalError::Busy);
            }
            if self.used_challenges.contains_key(request.challenge) {
                return Err(JournalError::ConflictingRetry);
            }
            if active.retry_count >= MAX_LEASE_RETRIES {
                return Err(JournalError::Busy);
            }
            let signed = active.signed.clone();
            // A lost delivery response may be retried by this same enrolled
            // guest, but every fresh possession proof gets its own anchored
            // challenge event before plaintext is released again.
            self.append(
                JournalEvent::LeasedRetry {
                    identity,
                    challenge: *request.challenge,
                },
                anchor,
            )?;
            self.used_challenges.insert(*request.challenge, identity);
            self.seen
                .get_mut(&identity)
                .and_then(|entry| entry.lease.as_mut())
                .ok_or(JournalError::Corrupt)?
                .retry_count += 1;
            return Ok(Some(LeasedMailboxMessage {
                message,
                lease: signed,
            }));
        }
        if self.used_challenges.contains_key(request.challenge) {
            return Err(JournalError::ConflictingRetry);
        }
        let header = message.opened.header();
        let expires_at_unix_ms = now
            .saturating_add(30_000)
            .min(header.expires_at_unix_ms)
            .min(request.receive.capability.grant.expires_at_unix_ms)
            .min(request.enrollment.enrollment.expires_at_unix_ms);
        if expires_at_unix_ms <= now {
            return Err(JournalError::Mailbox(MailboxError::Expired));
        }
        let signed = sign_delivery_lease(
            MailboxDeliveryLease {
                object_projection_v1: request
                    .plan
                    .durable_object_pair_sha256_v1
                    .map(|pair| {
                        super::super::reader::object_delivery_commitment(
                            &pair,
                            header,
                            message.payload(),
                        )
                    })
                    .transpose()?,
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                address: self.address,
                sender: header.sender,
                sender_boot: header.sender_boot,
                message_id: header.message_id,
                delivery_id: entry.envelope.routing.delivery_id,
                execution_epoch: header.execution_epoch,
                consumer: request.enrollment.enrollment.consumer,
                consumer_session: request.scope.current_session,
                receive_capability_id: request.receive.capability.grant.capability_id,
                policy_epoch: request.receive.capability.grant.policy_epoch,
                ciphertext_commitment: entry.envelope.ciphertext_commitment,
                issued_at_unix_ms: now,
                expires_at_unix_ms,
                lease_nonce: DeliveryLeaseNonce::from_bytes(rand::random()),
            },
            request.signer,
        )?;
        verify_delivery_lease(
            &signed,
            &ReaderDeliveryContext {
                plan: request.plan,
                capability: request.receive.capability,
                reader_scope: request.scope,
                consumer_session: request.scope.current_session,
                now_unix_ms: now,
                envelope: &entry.envelope,
                header,
                authority: &self.authority,
                revoked: &request.receive.context.revoked_capabilities,
            },
        )?;
        self.append(
            JournalEvent::Leased {
                identity,
                challenge: *request.challenge,
                lease: Box::new(signed.clone()),
                enrollment: Box::new(request.enrollment.clone()),
                receive_capability: Box::new(request.receive.capability.clone()),
            },
            anchor,
        )?;
        self.used_challenges.insert(*request.challenge, identity);
        self.seen
            .get_mut(&identity)
            .ok_or(JournalError::Corrupt)?
            .lease = Some(LeaseState {
            retry_count: 0,
            signed: signed.clone(),
            enrollment: request.enrollment.clone(),
            receive_capability: request.receive.capability.clone(),
        });
        Ok(Some(LeasedMailboxMessage {
            message,
            lease: signed,
        }))
    }

    /// Fsync an append-only ACK and advance the trusted tip. An uncertain
    /// commit poisons this writer; recovery must reconcile it before retry.
    pub fn acknowledge(
        &mut self,
        identity: ReplayIdentity,
        request: JournalReceive<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        let entry = self
            .seen
            .get(&identity)
            .ok_or(JournalError::UnknownMessage)?;
        if entry.expired_at_unix_ms.is_some() {
            return Err(JournalError::Mailbox(MailboxError::Expired));
        }
        let _opened = self.open_for_reader(identity, entry, &request, MailboxOperation::Send)?;
        if entry.lease.is_some() {
            return Err(JournalError::GuestAckRequired);
        }
        if entry.acknowledged {
            return Ok(self.tip);
        }
        let tip = self.append(
            JournalEvent::Acknowledged {
                identity,
                acknowledged_at_unix_ms: request.context.now_unix_ms,
            },
            anchor,
        )?;
        self.seen
            .get_mut(&identity)
            .ok_or(JournalError::Corrupt)?
            .acknowledged = true;
        Ok(tip)
    }

    /// Verify the enrolled guest signature over the exact active lease,
    /// commit its replay identity and signed bytes, then advance the anchor.
    pub fn acknowledge_signed(
        &mut self,
        request: JournalGuestAck<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        self.acknowledge_signed_inner(request, None, anchor)
    }
    /// Record the canonical guest signature only under the same selected
    /// original Call/Reply route and still-current independent Receive authority.
    pub fn acknowledge_signed_object(
        &mut self,
        request: JournalGuestAck<'_>,
        scope: ObjectLeaseScope<'_>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        self.acknowledge_signed_inner(request, Some(ObjectCheck::Fixed(scope)), anchor)
    }
    /// Recover only the original Call for the row matched by the verified ACK.
    pub fn acknowledge_signed_object_reply<'r>(
        &mut self,
        request: JournalGuestAck<'_>,
        scope: ObjectLeaseScope<'_>,
        resolve: &'r mut OriginalCallResolver<'r>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        self.acknowledge_signed_inner(
            request,
            Some(ObjectCheck::ResolveReply(scope, resolve)),
            anchor,
        )
    }
    pub(super) fn acknowledge_signed_inner(
        &mut self,
        request: JournalGuestAck<'_>,
        paired: Option<ObjectCheck<'_, '_>>,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<JournalTip, JournalError> {
        if request.plan.durable_object_pair_sha256_v1.is_some() != paired.is_some() {
            return Err(JournalError::WrongAuthority);
        }
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if request.scope.plan != request.plan
            || request.scope.receive != &request.receive.capability.grant
            || request.scope.now_unix_ms != request.receive.context.now_unix_ms
        {
            return Err(JournalError::WrongAuthority);
        }
        let lease = &request.signed.ack.lease.lease;
        let identity = ReplayIdentity {
            sender: lease.sender,
            sender_boot: lease.sender_boot,
            execution_epoch: lease.execution_epoch,
            message_id: lease.message_id,
        };
        let entry = self
            .seen
            .get(&identity)
            .ok_or(JournalError::UnknownMessage)?;
        if entry.expired_at_unix_ms.is_some() {
            return Err(JournalError::Mailbox(MailboxError::Expired));
        }
        let active = entry.lease.as_ref().ok_or(JournalError::NoActiveLease)?;
        if active.signed != request.signed.ack.lease
            || active.enrollment != *request.enrollment
            || active.receive_capability != *request.receive.capability
        {
            return Err(JournalError::ConflictingRetry);
        }
        if request
            .receive
            .context
            .revoked_capabilities
            .contains(&request.receive.capability.grant.revocation_id)
        {
            return Err(JournalError::Mailbox(MailboxError::CapabilityRevoked));
        }
        let operation = paired
            .as_ref()
            .map_or(MailboxOperation::Send, ObjectCheck::operation);
        let opened = self.open_for_reader(identity, entry, &request.receive, operation)?;
        let guest_key = VerifyingKey::from_bytes(&request.enrollment.enrollment.ack_public_key)
            .map_err(|_| JournalError::Mailbox(MailboxError::ReaderKeyInvalid))?;
        verify_delivery_ack(
            request.signed,
            &active.signed,
            &ReaderDeliveryContext {
                plan: request.plan,
                capability: request.receive.capability,
                reader_scope: request.scope,
                consumer_session: request.scope.current_session,
                now_unix_ms: request.scope.now_unix_ms,
                envelope: &entry.envelope,
                header: opened.header(),
                authority: &self.authority,
                revoked: &request.receive.context.revoked_capabilities,
            },
            request.enrollment,
            &guest_key,
        )?;
        if let Some(scope) = paired {
            scope.check_original(&request.scope, entry, &request.receive)?;
        }
        if entry.acknowledged {
            return if entry.signed_ack.as_ref() == Some(request.signed) {
                Ok(self.tip)
            } else {
                Err(JournalError::ConflictingRetry)
            };
        }
        let tip = self.append(
            JournalEvent::AcknowledgedSigned {
                identity,
                ack: Box::new(request.signed.clone()),
            },
            anchor,
        )?;
        let entry = self.seen.get_mut(&identity).ok_or(JournalError::Corrupt)?;
        entry.acknowledged = true;
        entry.signed_ack = Some(request.signed.clone());
        Ok(tip)
    }

    pub(super) fn open_for_reader(
        &self,
        identity: ReplayIdentity,
        entry: &Seen,
        request: &JournalReceive<'_>,
        original_operation: MailboxOperation,
    ) -> Result<super::super::OpenedMailboxMessage, JournalError> {
        if request.context.required_operation != MailboxOperation::Receive
            || request.context.expected_tenant != self.address.tenant
            || request.context.expected_authorization_domain != self.address.authorization_domain
            || request.context.expected_mailbox != self.address.mailbox
            || request.context.expected_recipient != self.address.recipient
        {
            return Err(JournalError::WrongAuthority);
        }
        let mut send_context = request.context.clone();
        send_context.acting_principal = entry.capability.grant.subject;
        send_context.expected_capability_issuer = entry.capability.grant.issuer;
        send_context.required_operation = original_operation;
        let opened = open_authenticated_envelope(
            &entry.envelope,
            &entry.capability,
            &send_context,
            request.encryption_key,
            request.sender_key,
            &self.authority,
            &mut Probe::default(),
        )?;
        if ReplayIdentity::from_header(opened.header()) != identity {
            return Err(JournalError::Corrupt);
        }
        authorize_receive(
            opened.header(),
            request.capability,
            request.context,
            &self.authority,
        )?;
        Ok(opened)
    }
}
