//! Read-only correlation against A's immutable encrypted source record. The
//! destination journal remains the sole owner of replay admission and ACK.
use super::*;
use crate::mailbox_service::object_intent::{original_record_name, read_original_object};
use mvm_core::mailbox::{
    InMemoryReplayProtector,
    frame::decode_frame,
    object_pair::{PendingObjectCall, role::ObjectParticipantRole},
    reader_wire::{ObjectSubmissionV1, original_object_intent_digest},
};

impl InstalledObjectPair<'_> {
    /// Reopen a Reply and recover the specific original pending Call for its
    /// journal lease/ACK. No caller-selected path, plaintext cache or new ID.
    pub fn original_pending_for_reply(
        &self,
        capability: &SignedMailboxCapability,
        envelope: &MailboxEnvelope,
    ) -> Result<PendingObjectCall> {
        let now = self.check_current()?;
        let signer = crate::audit::host_keypair::host_signer_id();
        let trust = [(signer.as_str(), &self.material.plan_verifier)];
        let (a, b) = (&self.caller, &self.callee);
        let ar = reader_revocations(&self.material.caller.reader.revocations_path)
            .map_err(|_| anyhow::anyhow!("current caller revocations unavailable"))?;
        let br = reader_revocations(&self.material.callee.reader.revocations_path)
            .map_err(|_| anyhow::anyhow!("current callee revocations unavailable"))?;
        let credentials = &self.prepared.credentials;
        let current = PairAuthorityState {
            caller_boot: a.boot.boot,
            callee_boot: b.boot.boot,
            caller_epoch: self.prepared.caller.epoch,
            callee_epoch: self.prepared.callee.epoch,
            caller_policy: credentials.reply.grant.policy_epoch,
            callee_policy: credentials.call.grant.policy_epoch,
            at_caller: &ar,
            at_callee: &br,
        };
        let pair = ObjectPairV1::check_originals(
            &OriginalObjectEndpoint {
                plan: a.admitted.signed(),
                boot: a.boot,
                trusted_signers: &trust,
            },
            &OriginalObjectEndpoint {
                plan: b.admitted.signed(),
                boot: b.boot,
                trusted_signers: &trust,
            },
            ObjectPairGrants {
                call: &credentials.call,
                reply: &credentials.reply,
            },
            now,
            current,
        )?;
        let pending = recover(
            &self.material.caller,
            &self.source_intents(ObjectParticipantRole::Caller)?,
            &pair,
            current,
            capability,
            envelope,
            now,
        )?;
        self.check_current()?;
        Ok(pending)
    }
}

pub(super) fn recover(
    local: &EndpointMaterial,
    dir: &Path,
    pair: &ObjectPairV1<'_>,
    current: PairAuthorityState<'_>,
    capability: &SignedMailboxCapability,
    reply: &MailboxEnvelope,
    now: i64,
) -> Result<PendingObjectCall> {
    let role = local.public_role.verify(&local.reader.boot, now)?;
    ensure!(
        role.role == ObjectParticipantRole::Caller && capability == &role.reply,
        "unexpected original Reply authority"
    );
    let opened = super::operations::open_original(
        capability,
        MailboxOperation::Reply,
        reply,
        &local.inbound_key,
        now,
    )?;
    let h = opened.header();
    ensure!(
        h.kind == MailboxMessageKind::Reply
            && h.sender_boot == role.callee.boot
            && h.encryption.key_id
                == <[u8; 32]>::from(Sha256::digest(local.inbound_key.expose_bytes())),
        "unexpected Reply source"
    );
    let id = MessageId::from_bytes(*h.causation_id.as_bytes());
    let name = original_record_name(
        role.caller
            .durable_object_pair_sha256_v1
            .context("no original pair")?,
        role.caller.boot,
        id,
    );
    let (ordinal, digest, raw) =
        read_original_object(&dir.join(name))?.context("original pending Call missing")?;
    let (cap, call) = decode_frame(&raw)?;
    ensure!(
        cap == role.call,
        "source record has a different original grant"
    );
    let original = super::operations::open_original(
        &cap,
        MailboxOperation::Send,
        &call,
        &local.outbound_key,
        now,
    )?;
    let ch = original.header();
    ensure!(
        ch.message_id == id
            && ch.sequence == ordinal
            && ch.sender_boot == role.caller.boot
            && ch.kind == MailboxMessageKind::Call
            && ch.encryption.key_id
                == <[u8; 32]>::from(Sha256::digest(local.outbound_key.expose_bytes())),
        "original Call record identity differs"
    );
    let submission = ObjectSubmissionV1::Call {
        message_id: id,
        correlation_id: ch.correlation_id,
        payload: original.payload().to_vec(),
    };
    ensure!(
        original_object_intent_digest(&submission)? == digest,
        "original Call intent digest differs"
    );
    let pending = pair.pending_call(
        call,
        now,
        current,
        &local.outbound_key,
        &mut InMemoryReplayProtector::default(),
    )?;
    pair.check_reply(
        &pending,
        reply.clone(),
        now,
        current,
        &local.inbound_key,
        &mut InMemoryReplayProtector::default(),
    )?;
    Ok(pending)
}
