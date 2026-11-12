//! Crash-safe original source seals for the selected application Call/Reply service.
use super::*;
use crate::mailbox_launch::object_pair::{
    InstalledObjectPair, OriginalObjectCallLease, SealedObjectTurn,
};
use anyhow::{Context, Result, ensure};
use mvm_core::mailbox::{
    object_pair::role::ObjectParticipantRole,
    reader_wire::{
        ObjectSubmissionV1, OriginalObjectSealV1, ReaderResponse, original_object_intent_digest,
    },
};
use std::os::unix::fs::OpenOptionsExt as _;

pub(super) struct ObjectIntentSlot {
    dir: PathBuf,
    name: String,
    _owner: FileLock,
    intent: [u8; 32],
    pub(super) sequence: SequenceNumber,
    pub(super) original: Option<Vec<u8>>,
}

impl ObjectIntentSlot {
    // dir and name are constructed by the original holder. No guest pathname.
    pub(super) fn open(dir: &Path, name: &str, intent: [u8; 32]) -> Result<Self> {
        private_fs::create_owned_private_dir(dir)?;
        sync_dir(dir.parent().context("missing mailbox custody parent")?)?;
        let owner =
            FileLock::try_acquire(&dir.join("intent"))?.context("original source writer busy")?;
        let (sequence, original) = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join(name))
        {
            Ok(file) => {
                let meta = file.metadata()?;
                private_fs::require_current_owner(&meta)?;
                ensure!(
                    meta.is_file()
                        && meta.nlink() == 1
                        && meta.mode() & 0o077 == 0
                        && meta.len() <= MAX_SOURCE_INTENT_BYTES as u64,
                    "invalid original object intent"
                );
                let mut bytes = Vec::with_capacity(meta.len() as usize);
                file.take(MAX_SOURCE_INTENT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() <= MAX_SOURCE_INTENT_BYTES && bytes.len() > 40,
                    "invalid original intent size"
                );
                ensure!(
                    bytes[8..40] == intent,
                    "stable ID reused with a different original submission"
                );
                let ordinal = u64::from_be_bytes(bytes[..8].try_into()?);
                (SequenceNumber::new(ordinal)?, Some(bytes.split_off(40)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                SequenceNumber::new(reserved_intents(dir)? as u64 + 1)?,
                None,
            ),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            dir: dir.into(),
            name: name.into(),
            _owner: owner,
            intent,
            sequence,
            original,
        })
    }

    pub(super) fn publish(&self, frame: &[u8]) -> Result<()> {
        ensure!(
            self.original.is_none()
                && !frame.is_empty()
                && frame.len() <= MAX_SOURCE_INTENT_BYTES - 40,
            "original source record occupied or oversized"
        );
        let mut bytes = Vec::with_capacity(frame.len() + 40);
        bytes.extend_from_slice(&self.sequence.get().to_be_bytes());
        bytes.extend_from_slice(&self.intent);
        bytes.extend_from_slice(frame);
        atomic_write_new(&self.dir.join(&self.name), &bytes)?;
        sync_dir(&self.dir)?;
        Ok(())
    }
}

/// Only built after the original source record and its attempt counter are durable.
pub struct RetainedObjectSubmission {
    turn: SealedObjectTurn,
    role: ObjectParticipantRole,
    original: OriginalObjectSealV1,
}

impl RetainedObjectSubmission {
    /// Send these exact bytes under the original owner's admitted carrier.
    pub fn turn(&self) -> &SealedObjectTurn {
        &self.turn
    }
}

impl InstalledObjectPair<'_> {
    /// Return only the originally persisted seal. Revalidate live authority
    /// and authenticate retained bytes even when staging an identical retry.
    pub fn retain_submission(
        &self,
        role: ObjectParticipantRole,
        pair: [u8; 32],
        boot: BootId,
        submission: &ObjectSubmissionV1,
        original: Option<OriginalObjectCallLease<'_>>,
    ) -> Result<RetainedObjectSubmission> {
        self.workload_role(role, pair, boot)?;
        match (role, submission, &original) {
            (ObjectParticipantRole::Caller, ObjectSubmissionV1::Call { .. }, None) => (),
            (
                ObjectParticipantRole::Callee,
                ObjectSubmissionV1::Reply { original_call, .. },
                Some(row),
            ) if row.lease() == original_call.as_ref() => (),
            _ => anyhow::bail!("submission does not match the original role and active Call lease"),
        }
        let dir = self.source_intents(role)?;
        let name = format!(
            "object-v1-{}-{}-{}",
            hex::encode(pair),
            hex::encode(boot.as_bytes()),
            hex::encode(submission.message_id().as_bytes())
        );
        let slot = ObjectIntentSlot::open(&dir, &name, original_object_intent_digest(submission)?)?;
        let turn = if let Some(record) = &slot.original {
            let (cap, envelope) = decode_frame(record)?;
            let turn = self.reopen_turn(
                role,
                &cap,
                envelope,
                slot.sequence,
                submission,
                original.as_ref(),
            )?;
            // A previous writer may have stopped between publishing and syncing.
            sync_dir(&dir)?;
            turn
        } else {
            let turn = match submission {
                ObjectSubmissionV1::Call {
                    message_id,
                    correlation_id,
                    payload,
                } => self.seal_call(*message_id, *correlation_id, slot.sequence, payload)?,
                ObjectSubmissionV1::Reply {
                    message_id,
                    payload,
                    ..
                } => self.seal_reply(
                    *message_id,
                    slot.sequence,
                    payload,
                    original.context("active Call lease required")?,
                )?,
            };
            slot.publish(&encode_frame(turn.capability(), turn.envelope())?)?;
            turn
        };
        charge_source_attempt(&dir, &name)?;
        let original =
            OriginalObjectSealV1::from_original(pair, boot, submission, turn.envelope())?;
        Ok(RetainedObjectSubmission {
            turn,
            role,
            original,
        })
    }

    /// Bind B's independent receipt to the source owner's retained ciphertext
    /// before the guest agent can retire an intent or acknowledge its Call lease.
    pub fn confirm_submission(
        &self,
        held: &RetainedObjectSubmission,
        receipt: mvm_contract::protocol::mailbox::SignedDestinationReceipt,
    ) -> Result<ReaderResponse> {
        self.workload_role(held.role, held.original.pair, held.original.sender_boot)?;
        self.verify_accepted(held.role, &held.turn, &receipt)?;
        Ok(ReaderResponse::ObjectSealAcceptedV1 {
            original: held.original.clone(),
            receipt: Box::new(receipt),
        })
    }
}
