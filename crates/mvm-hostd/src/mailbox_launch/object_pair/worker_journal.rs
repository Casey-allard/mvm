//! Canonical receive/journal operations for one already admitted original worker.
use super::*;
use crate::mailbox_launch::object_pair::operations::verify_active_call;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::mailbox::{OpenContext, journal::*, reader_wire::ReaderResponse};

impl HistoryKeyCustody for ObjectWorkerBootstrapV1 {
    fn load_existing(&self, r: &HistoryKeyRef) -> Result<Key, JournalError> {
        if r != &self.history_ref {
            return Err(JournalError::HistoryKeyMismatch);
        }
        Ok(Key::from_bytes(self.secrets.history))
    }
}

impl ObjectWorkerBootstrapV1 {
    pub(crate) fn open_journal(&self) -> Result<(MailboxJournal, FileJournalAnchor)> {
        let a = self.validate_current()?;
        let plan = a
            .local_plan
            .mailbox
            .context("original journal grant absent")?;
        let anchor = FileJournalAnchor::open(
            &self.local_anchor,
            self.history_ref.address(),
            self.secrets.anchor,
        )?;
        let mut journal = MailboxJournal::open_local_with_custody(
            &self.local_journal,
            self.history_ref,
            VerifyingKey::from_bytes(&plan.authority_key)?,
            JournalLimits {
                max_records: 10_000,
                max_bytes: 64 * 1024 * 1024,
            },
            self,
            &anchor,
            plan.retention.context("original retention absent")?,
        )?;
        match self.maintain(&mut journal, &anchor, a.now) {
            // Resume on the very next turn; the journal stays open and cannot
            // accept new input while its bounded expiry pass remains pending.
            Ok(()) | Err(JournalError::MaintenancePending) => (),
            Err(e) => return Err(e.into()),
        }
        Ok((journal, anchor))
    }
    fn maintain(
        &self,
        journal: &mut MailboxJournal,
        anchor: &FileJournalAnchor,
        now: i64,
    ) -> Result<(), JournalError> {
        let signer = SigningKey::from_bytes(&self.secrets.local_authority);
        journal.maintain_local_checkpoint(now, &signer, anchor)?;
        crate::mailbox_service::durable::settle_expired_at(journal, now, &signer, |tip| {
            anchor.advance(tip)
        })
    }
    fn incoming(&self) -> &SignedMailboxCapability {
        match self.role.role.role {
            ObjectParticipantRole::Caller => &self.role.role.reply,
            ObjectParticipantRole::Callee => &self.role.role.call,
        }
    }
    fn context(&self, a: &WorkerAuthority<'_>, read: bool) -> OpenContext {
        let g = &self.incoming().grant;
        let op = if read {
            MailboxOperation::Receive
        } else if self.role.role.role == ObjectParticipantRole::Caller {
            MailboxOperation::Reply
        } else {
            MailboxOperation::Send
        };
        let revoked = match self.role.role.role {
            ObjectParticipantRole::Caller => &a.caller_revoked,
            ObjectParticipantRole::Callee => &a.callee_revoked,
        };
        OpenContext {
            expected_tenant: g.address.tenant,
            expected_authorization_domain: g.address.authorization_domain,
            expected_mailbox: g.address.mailbox,
            expected_sender: g.subject,
            expected_recipient: g.address.recipient,
            acting_principal: if read { g.address.recipient } else { g.subject },
            expected_capability_issuer: g.issuer,
            current_execution_epoch: self.role.role.local().execution_epoch,
            current_policy_epoch: g.policy_epoch,
            required_operation: op,
            now_unix_ms: a.now,
            accepted_content_types: g.content_types.clone(),
            revoked_capabilities: revoked.clone(),
        }
    }
    pub(crate) fn admit_original(
        &self,
        journal: &mut MailboxJournal,
        anchor: &FileJournalAnchor,
        cap: &SignedMailboxCapability,
        envelope: &MailboxEnvelope,
    ) -> Result<SignedDestinationReceipt> {
        let local = self.endpoint_material()?;
        let a = self.validate_current()?;
        ensure!(
            self.incoming() == cap,
            "different original recipient credential"
        );
        self.maintain(journal, anchor, a.now)?;
        let original_window = match self.role.role.role {
            ObjectParticipantRole::Caller => {
                let (_, validity) = super::super::pending::recover(
                    &local,
                    &self.local_intents,
                    &a.pair,
                    a.state(),
                    cap,
                    envelope,
                    a.now,
                )?;
                Some(validity)
            }
            ObjectParticipantRole::Callee => {
                a.pair.pending_call(
                    envelope.clone(),
                    a.now,
                    a.state(),
                    &local.inbound_key,
                    &mut mvm_core::mailbox::InMemoryReplayProtector::default(),
                )?;
                None
            }
        };
        let current = self.validate_current()?;
        ensure!(
            original_window.is_none_or(|w| w.contains(&current.now)),
            "original Call or Reply expired before commit"
        );
        let ctx = self.context(&current, false);
        Ok(journal.admit_local(
            JournalAdmission {
                envelope,
                capability: cap,
                context: &ctx,
                encryption_key: &local.inbound_key,
                sender_key: &VerifyingKey::from_bytes(cap.grant.subject.as_bytes())?,
                signer: &SigningKey::from_bytes(&self.secrets.local_authority),
            },
            anchor,
        )?)
    }
    pub(crate) fn authorize_call(
        &self,
        journal: &MailboxJournal,
        lease: &SignedMailboxDeliveryLease,
    ) -> Result<SignedObjectRoleV1> {
        let local = self.endpoint_material()?;
        let a = self.validate_current()?;
        ensure!(
            self.role.role.role == ObjectParticipantRole::Callee,
            "only B can authorize its active Call"
        );
        let row = journal.original_object_call(lease, a.now)?;
        verify_active_call(&local, &self.role.role, &row, a.now)?;
        Ok(self.role.clone())
    }
    pub(crate) fn lease_original(
        &self,
        journal: &mut MailboxJournal,
        anchor: &FileJournalAnchor,
        challenge: &[u8; 32],
        proof: &[u8],
    ) -> Result<ReaderResponse> {
        let local = self.endpoint_material()?;
        let a = self.validate_current()?;
        self.maintain(journal, anchor, a.now)?;
        let a = self.validate_current()?;
        let ctx = self.context(&a, true);
        let sender = VerifyingKey::from_bytes(self.incoming().grant.subject.as_bytes())?;
        let scope = crate::mailbox_service::durable::guest_scope(&local.reader, &ctx);
        let signer = SigningKey::from_bytes(&self.secrets.local_authority);
        let request = JournalGuestLease {
            receive: JournalReceive {
                capability: &local.reader.capability,
                context: &ctx,
                encryption_key: &local.inbound_key,
                sender_key: &sender,
            },
            plan: &local.reader.grant,
            scope,
            enrollment: &local.reader.enrollment,
            challenge,
            possession_signature: proof,
            signer: &signer,
        };
        let enrolled = ObjectLeaseScope {
            pair: &a.pair,
            destination: self.role.role.local(),
            state: a.state(),
            original_call: None,
        };
        let lease = match self.role.role.role {
            ObjectParticipantRole::Callee => {
                journal.lease_next_object(request, enrolled, |tip| anchor.advance(tip))?
            }
            ObjectParticipantRole::Caller => journal.lease_next_object_reply(
                request,
                enrolled,
                &mut |cap, env| self.resolve_pending(&local, &a, cap, env),
                |tip| anchor.advance(tip),
            )?,
        };
        match lease {
            Some(row) => {
                Ok(row.into_reader_response(local.reader.boot.durable_object_pair_sha256_v1)?)
            }
            None => Ok(ReaderResponse::Empty),
        }
    }
    fn resolve_pending(
        &self,
        local: &EndpointMaterial,
        a: &WorkerAuthority<'_>,
        cap: &SignedMailboxCapability,
        env: &MailboxEnvelope,
    ) -> Result<mvm_core::mailbox::object_pair::PendingObjectCall, JournalError> {
        let (pending, window) = super::super::pending::recover(
            local,
            &self.local_intents,
            &a.pair,
            a.state(),
            cap,
            env,
            a.now,
        )
        .map_err(|_| JournalError::WrongAuthority)?;
        let current = self
            .validate_current()
            .map_err(|_| JournalError::WrongAuthority)?;
        if !window.contains(&current.now) {
            return Err(JournalError::WrongAuthority);
        }
        Ok(pending)
    }
    pub(crate) fn acknowledge_original(
        &self,
        journal: &mut MailboxJournal,
        anchor: &FileJournalAnchor,
        signed: &SignedMailboxDeliveryAck,
    ) -> Result<JournalTip> {
        let local = self.endpoint_material()?;
        let a = self.validate_current()?;
        self.maintain(journal, anchor, a.now)?;
        let a = self.validate_current()?;
        let ctx = self.context(&a, true);
        let sender = VerifyingKey::from_bytes(self.incoming().grant.subject.as_bytes())?;
        let scope = crate::mailbox_service::durable::guest_scope(&local.reader, &ctx);
        let request = JournalGuestAck {
            receive: JournalReceive {
                capability: &local.reader.capability,
                context: &ctx,
                encryption_key: &local.inbound_key,
                sender_key: &sender,
            },
            plan: &local.reader.grant,
            scope,
            enrollment: &local.reader.enrollment,
            signed,
        };
        let enrolled = ObjectLeaseScope {
            pair: &a.pair,
            destination: self.role.role.local(),
            state: a.state(),
            original_call: None,
        };
        Ok(match self.role.role.role {
            ObjectParticipantRole::Callee => {
                journal.acknowledge_signed_object(request, enrolled, |tip| anchor.advance(tip))?
            }
            ObjectParticipantRole::Caller => journal.acknowledge_signed_object_reply(
                request,
                enrolled,
                &mut |cap, env| self.resolve_pending(&local, &a, cap, env),
                |tip| anchor.advance(tip),
            )?,
        })
    }
}
