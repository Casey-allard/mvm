//! Crash-safe original source seals for the selected application Call/Reply service.
use super::*;
use crate::mailbox_launch::object_pair::{
    EndpointMaterial, InstalledObjectPair, OriginalObjectCallLease, SealedObjectTurn, TurnContext,
};
use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::mailbox::{MessageId, SignedDestinationReceipt};
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

type RetainedObjectRecord = (SequenceNumber, [u8; 32], Vec<u8>);

/// A reader opens only the already atomically published original. A lookup does
/// not allocate an ID, change the attempt count, create a store or repair state.
pub(crate) fn read_original_object(path: &Path) -> Result<Option<RetainedObjectRecord>> {
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
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
            let ordinal = u64::from_be_bytes(bytes[..8].try_into()?);
            let digest = bytes[8..40].try_into()?;
            Ok(Some((
                SequenceNumber::new(ordinal)?,
                digest,
                bytes.split_off(40),
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
pub(crate) fn original_record_name(pair: [u8; 32], boot: BootId, id: MessageId) -> String {
    format!(
        "object-v1-{}-{}-{}",
        hex::encode(pair),
        hex::encode(boot.as_bytes()),
        hex::encode(id.as_bytes())
    )
}

impl ObjectIntentSlot {
    // dir and name are constructed by the original holder. No guest pathname.
    pub(super) fn open(dir: &Path, name: &str, intent: [u8; 32]) -> Result<Self> {
        private_fs::create_owned_private_dir(dir)?;
        sync_dir(dir.parent().context("missing mailbox custody parent")?)?;
        let owner = FileLock::try_acquire(&dir.join("intent"))?.ok_or(Refusal::Unavailable)?;
        let (sequence, original) = match read_original_object(&dir.join(name))? {
            Some((ordinal, digest, frame)) => {
                ensure!(
                    digest == intent,
                    "stable ID reused with a different original submission"
                );
                (ordinal, Some(frame))
            }
            None => {
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
pub(crate) struct RetainedObjectSubmission {
    expires: i64,
    turn: SealedObjectTurn,
    original: OriginalObjectSealV1,
}

/// One guest operation bound to the local boot and, for a Reply, its live Call lease.
pub(crate) struct OutboundObject<'a> {
    pub(crate) pair: [u8; 32],
    pub(crate) boot: BootId,
    pub(crate) submission: &'a ObjectSubmissionV1,
    pub(crate) original: Option<OriginalObjectCallLease<'a>>,
}

impl OutboundObject<'_> {
    pub(crate) fn retain(
        &self,
        local: &EndpointMaterial,
        dir: &Path,
        current: &impl Fn() -> Result<i64>,
    ) -> Result<RetainedObjectSubmission> {
        let role = local.public_role.role.role;
        current()?;
        ensure!(
            Some(self.pair) == local.reader.boot.durable_object_pair_sha256_v1
                && self.boot == local.reader.boot.boot,
            "different original object pair or boot"
        );
        match (role, self.submission, self.original.as_ref()) {
            (ObjectParticipantRole::Caller, ObjectSubmissionV1::Call { .. }, None) => (),
            (
                ObjectParticipantRole::Callee,
                ObjectSubmissionV1::Reply { original_call, .. },
                Some(row),
            ) if row.lease() == original_call.as_ref() => (),
            _ => anyhow::bail!("submission does not match the original role and active Call lease"),
        }
        let name = original_record_name(self.pair, self.boot, self.submission.message_id());
        let slot =
            ObjectIntentSlot::open(dir, &name, original_object_intent_digest(self.submission)?)?;
        let now = current()?;
        let turn = if let Some(record) = &slot.original {
            let (cap, envelope) = decode_frame(record)?;
            let turn = local.reopen(
                TurnContext { role, now },
                &cap,
                envelope,
                slot.sequence,
                self.submission,
                self.original.as_ref(),
            )?;
            // A previous writer may have stopped between publishing and syncing.
            sync_dir(dir)?;
            turn
        } else {
            let (corr, payload) = match self.submission {
                ObjectSubmissionV1::Call {
                    correlation_id,
                    payload,
                    ..
                } => (Some(*correlation_id), payload),
                ObjectSubmissionV1::Reply { payload, .. } => (None, payload),
            };
            let turn = local.seal_turn(
                TurnContext { role, now },
                self.submission.message_id(),
                corr,
                slot.sequence,
                payload,
                self.original.as_ref(),
            )?;
            slot.publish(&encode_frame(turn.capability(), turn.envelope())?)?;
            turn
        };
        charge_source_attempt(dir, &name)?;
        let original = OriginalObjectSealV1::from_original(
            self.pair,
            self.boot,
            self.submission,
            turn.envelope(),
        )?;
        let expires = self
            .original
            .as_ref()
            .map_or(turn.header().expires_at_unix_ms, |row| {
                row.lease()
                    .lease
                    .expires_at_unix_ms
                    .min(turn.header().expires_at_unix_ms)
            });
        Ok(RetainedObjectSubmission {
            turn,
            original,
            expires,
        })
    }

    pub(crate) fn forward(
        &self,
        local: &EndpointMaterial,
        dir: &Path,
        deadline: Instant,
        current: impl Fn() -> Result<i64>,
        exchange: impl FnOnce(&SealedObjectTurn, Instant) -> Result<SignedDestinationReceipt>,
    ) -> Result<ReaderResponse> {
        ensure!(Instant::now() < deadline, Refusal::Unavailable);
        self.retain(local, dir, &current)?
            .send(local, deadline, current, exchange)
    }
}

impl RetainedObjectSubmission {
    pub(crate) fn send(
        self,
        local: &EndpointMaterial,
        deadline: Instant,
        current: impl Fn() -> Result<i64>,
        exchange: impl FnOnce(&SealedObjectTurn, Instant) -> Result<SignedDestinationReceipt>,
    ) -> Result<ReaderResponse> {
        let held = self;
        let header = held.turn.header();
        let expires = held.expires;
        let window = header.issued_at_unix_ms..expires;
        let start = Instant::now();
        let now = current()?;
        ensure!(window.contains(&now), Refusal::Expired);
        let until = deadline.min(start + durable::GUEST_EXCHANGE_TIMEOUT).min(
            start
                .checked_add(Duration::from_millis(expires.abs_diff(now)))
                .unwrap_or(deadline),
        );
        ensure!(Instant::now() < until, Refusal::Unavailable);
        let receipt = exchange(&held.turn, until)?;
        let now = current()?;
        local.verify_accepted(local.public_role.role.role, &held.turn, &receipt)?;
        ensure!(window.contains(&now), Refusal::Expired);
        ensure!(Instant::now() < until, Refusal::Unavailable);
        Ok(ReaderResponse::ObjectSealAcceptedV1 {
            original: held.original,
            receipt: Box::new(receipt),
        })
    }
}

impl InstalledObjectPair<'_> {
    /// Send the retained seal to the peer held by the original owner.
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
        let endpoint = self.workload_role(role, pair, boot)?;
        let local = self.original_endpoint(role);
        let dir = self.source_intents(role)?;
        OutboundObject {
            pair,
            boot,
            submission,
            original,
        }
        .forward(
            local,
            &dir,
            deadline,
            || self.check_current(),
            |turn, until| {
                let stream = destination.connect_object_recipient(&endpoint.role, until)?;
                self.workload_role(role, pair, boot)?;
                let mut peer = durable::GuestDeadline::new(stream, until)?;
                Ok(send_local_receipted_frame(
                    &mut peer,
                    turn.capability(),
                    turn.envelope(),
                    turn.header(),
                    &VerifyingKey::from_bytes(&endpoint.role.peer().authority_key)?,
                )?)
            },
        )
    }
}
