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
fn slot(dir: &Path) -> PathBuf {
    dir.join("outbox-object-pair-v1")
}
pub fn stage(
    dir: &Path,
    boot: &MailboxReaderBootBinding,
    pair: [u8; 32],
    submission: &ObjectSubmissionV1,
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
        Ok(_) => Err(Refusal::QueueFull(1)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            atomic_write_new(&path, &bytes).map_err(|_| Refusal::Unavailable)
        }
        Err(_) => Err(Refusal::Unavailable),
    }
}
