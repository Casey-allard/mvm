//! One original-boot application intent. Local staging does not grant Send or
//! Reply authority and does not confirm destination or application acceptance.
use super::{atomic_write_new, lock_outbox_dir, open_outbox, sync_dir};
use mvm_core::mailbox::{
    frame::Refusal, reader::MailboxReaderBootBinding, reader_wire::ObjectSubmissionV1,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

const MAX_STAGED: usize = 16 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u8,
    pair: [u8; 32],
    boot: mvm_contract::protocol::mailbox::BootId,
    plan_nonce: mvm_contract::plan::Nonce,
    submission: ObjectSubmissionV1,
}
pub fn load(
    dir: &Path,
    boot: &MailboxReaderBootBinding,
    pair: [u8; 32],
) -> Result<ObjectSubmissionV1, Refusal> {
    let _lock = lock_outbox_dir(dir)?;
    let mut bytes = Vec::new();
    open_outbox(&slot(dir))
        .and_then(|f| f.take((MAX_STAGED + 1) as u64).read_to_end(&mut bytes))
        .map_err(|_| Refusal::Unavailable)?;
    if bytes.len() > MAX_STAGED {
        return Err(Refusal::Oversized(MAX_STAGED));
    }
    let record: Intent = serde_json::from_slice(&bytes).map_err(|_| Refusal::Malformed)?;
    if record.version != 1
        || boot.durable_object_pair_sha256_v1 != Some(pair)
        || record.pair != pair
        || record.boot != boot.boot
        || record.plan_nonce != boot.plan_nonce
    {
        return Err(Refusal::NotAuthorized);
    }
    Ok(record.submission)
}

fn slot(dir: &Path) -> PathBuf {
    dir.join("outbox-object-pair-v1")
}
pub fn stage(
    dir: &Path,
    boot: &MailboxReaderBootBinding,
    pair: [u8; 32],
    submission: &ObjectSubmissionV1,
) -> Result<(), Refusal> {
    stage_after(dir, boot, pair, submission, None)
}

/// Replace only the exact earlier intent whose destination settlement the
/// calling agent independently verified on this original boot.
pub fn stage_after(
    dir: &Path,
    boot: &MailboxReaderBootBinding,
    pair: [u8; 32],
    submission: &ObjectSubmissionV1,
    settled: Option<&ObjectSubmissionV1>,
) -> Result<(), Refusal> {
    if boot.durable_object_pair_sha256_v1 != Some(pair)
        || submission.payload().is_empty()
        || submission.message_id().as_bytes() == &[0; 32]
    {
        return Err(Refusal::NotAuthorized);
    }
    if submission.payload().len() > MAX_STAGED {
        return Err(Refusal::Oversized(MAX_STAGED));
    }
    let record = Intent {
        version: 1,
        pair,
        boot: boot.boot,
        plan_nonce: boot.plan_nonce.clone(),
        submission: submission.clone(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| Refusal::Malformed)?;
    if bytes.len() > MAX_STAGED {
        return Err(Refusal::Oversized(MAX_STAGED));
    }
    let path = slot(dir);
    let _lock = lock_outbox_dir(dir)?;
    let mut existing = Vec::new();
    match open_outbox(&path)
        .and_then(|f| f.take((MAX_STAGED + 1) as u64).read_to_end(&mut existing))
    {
        Ok(_) if existing == bytes => sync_dir(dir).map_err(|_| Refusal::Unavailable),
        Ok(_) => {
            let old: Intent = serde_json::from_slice(&existing).map_err(|_| Refusal::Malformed)?;
            if old.version != 1
                || old.boot != boot.boot
                || old.plan_nonce != boot.plan_nonce
                || old.pair != pair
                || old.submission.message_id() == submission.message_id()
                || Some(&old.submission) != settled
            {
                return Err(Refusal::QueueFull(1));
            }
            mvm_core::util::atomic_io::atomic_write_durable(&path, &bytes)
                .map_err(|_| Refusal::Unavailable)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            atomic_write_new(&path, &bytes).map_err(|_| Refusal::Unavailable)?;
            sync_dir(dir).map_err(|_| Refusal::Unavailable)
        }
        Err(_) => Err(Refusal::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::{
        plan::{Nonce, PlanId},
        protocol::mailbox::*,
    };
    fn boot() -> MailboxReaderBootBinding {
        MailboxReaderBootBinding {
            durable_object_pair_sha256_v1: Some([12; 32]),
            outbound_journal_v1: None,
            plan_id: PlanId("original".into()),
            plan_nonce: Nonce::from_bytes([13; 16]),
            mailbox: MailboxId::from_bytes([14; 32]),
            authority_key: [15; 32],
            execution_epoch: ExecutionEpoch::new(1).unwrap(),
            boot: BootId::from_bytes([16; 32]),
            guest_identity_key: [20; 32],
            ack_public_key: [21; 32],
        }
    }
    #[test]
    fn staged_intent_is_exact_bounded_and_fenced_to_its_original_boot() {
        let dir = tempfile::tempdir().unwrap();
        let mut original = boot();
        let pending = ObjectSubmissionV1::Call {
            message_id: MessageId::from_bytes([23; 32]),
            correlation_id: CorrelationId::from_bytes([24; 32]),
            payload: vec![0, 1, 0],
        };
        stage(dir.path(), &original, [12; 32], &pending).unwrap();
        let before = std::fs::read(slot(dir.path())).unwrap();
        stage(dir.path(), &original, [12; 32], &pending).unwrap();
        assert_eq!(
            stage(dir.path(), &original, [13; 32], &pending),
            Err(Refusal::NotAuthorized)
        );
        let mut conflicting = pending.clone();
        if let ObjectSubmissionV1::Call { payload, .. } = &mut conflicting {
            payload[1] = 2;
        }
        assert_eq!(
            stage(dir.path(), &original, [12; 32], &conflicting),
            Err(Refusal::QueueFull(1))
        );
        original.boot = BootId::from_bytes([22; 32]);
        assert_eq!(
            stage(dir.path(), &original, [12; 32], &pending),
            Err(Refusal::QueueFull(1))
        );
        assert_eq!(std::fs::read(slot(dir.path())).unwrap(), before);
        let huge = ObjectSubmissionV1::Call {
            message_id: MessageId::from_bytes([25; 32]),
            correlation_id: CorrelationId::from_bytes([26; 32]),
            payload: vec![7; MAX_STAGED + 1],
        };
        assert_eq!(
            stage(dir.path(), &original, [12; 32], &huge),
            Err(Refusal::Oversized(MAX_STAGED))
        );
        assert_eq!(std::fs::read(slot(dir.path())).unwrap(), before);
    }
}
