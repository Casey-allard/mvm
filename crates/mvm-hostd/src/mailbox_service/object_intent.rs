//! Crash-safe original source seals for the selected application Call/Reply service.
use super::*;
use crate::mailbox_launch::object_pair::{
    InstalledObjectPair, OriginalObjectCallLease, SealedObjectTurn,
};
use crate::mailbox_process::original_journal::authorization::now_ms;
use anyhow::{Context, Result, ensure};
use mvm_core::mailbox::frame::send_local_receipted_frame;
use mvm_core::mailbox::{
    object_pair::role::ObjectParticipantRole,
    reader_wire::{
        ObjectSubmissionV1, OriginalObjectSealV1, ReaderResponse, original_object_intent_digest,
    },
};
use std::os::unix::fs::OpenOptionsExt as _;
use std::time::Instant;

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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A durable attempt means this ID already had a published seal.
                // A missing original must never mint a second ciphertext for it.
                match std::fs::symlink_metadata(dir.join(format!("{name}.attempts"))) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Ok(_) => anyhow::bail!("attempted object has lost its original seal"),
                    Err(e) => return Err(e.into()),
                }
                (
                    SequenceNumber::new(reserved_intents(dir)? as u64 + 1)?,
                    None,
                )
            }
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
struct RetainedObjectSubmission {
    turn: SealedObjectTurn,
    original: OriginalObjectSealV1,
}

impl InstalledObjectPair<'_> {
    /// Return only the originally persisted seal. Revalidate live authority
    /// and authenticate retained bytes even when staging an identical retry.
    fn retain_submission(
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
        Ok(RetainedObjectSubmission { turn, original })
    }

    /// Dispatch one canonical frame on the local peer socket selected by the
    /// original owner. The guest cannot supply a socket or a destination key.
    /// A retry enters this method again and charges a new durable attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn forward_submission(
        &self,
        role: ObjectParticipantRole,
        pair: [u8; 32],
        boot: BootId,
        submission: &ObjectSubmissionV1,
        original: Option<OriginalObjectCallLease<'_>>,
        destination: &mut crate::mailbox_process::original_journal::OriginalJournalDestination,
        deadline: Instant,
    ) -> Result<ReaderResponse> {
        ensure!(
            Instant::now() < deadline,
            "original peer exchange deadline passed"
        );
        let lease_end = original
            .as_ref()
            .map(|row| row.lease().lease.expires_at_unix_ms);
        let held = self.retain_submission(role, pair, boot, submission, original)?;
        let endpoint = self.workload_role(role, pair, boot)?;
        let verifier = VerifyingKey::from_bytes(&endpoint.role.peer().authority_key)?;
        let header = held.turn.header();
        let expires = lease_end.map_or(header.expires_at_unix_ms, |end| {
            end.min(header.expires_at_unix_ms)
        });
        let now = now_ms()?;
        ensure!(
            (header.issued_at_unix_ms..expires).contains(&now),
            "original source seal expired"
        );
        let window = Duration::from_millis(expires.abs_diff(now));
        let start = Instant::now();
        let until = deadline
            .min(start + durable::GUEST_EXCHANGE_TIMEOUT)
            .min(start.checked_add(window).unwrap_or(deadline));
        let peer = destination.connect_object_recipient(&endpoint.role, until)?;
        self.workload_role(role, pair, boot)?;
        ensure!(
            (header.issued_at_unix_ms..expires).contains(&now_ms()?),
            "original lease expired before send"
        );
        let mut peer = durable::GuestDeadline::new(peer, until)?;
        let receipt = send_local_receipted_frame(
            &mut peer,
            held.turn.capability(),
            held.turn.envelope(),
            header,
            &verifier,
        )?;
        self.workload_role(role, pair, boot)?;
        self.verify_accepted(role, &held.turn, &receipt)?;
        ensure!(
            Instant::now() < until && (header.issued_at_unix_ms..expires).contains(&now_ms()?),
            "original peer verdict expired"
        );
        Ok(ReaderResponse::ObjectSealAcceptedV1 {
            original: held.original,
            receipt: Box::new(receipt),
        })
    }
}
