use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    MailboxGrant, MailboxJournalDirectionV1, SignedMailboxCapability,
};
use sha2::{Digest, Sha256};

use super::reader::MailboxReaderBootBinding;

/// The retained request's canonical plaintext tuple, hashed without allocating a second body.
pub fn journal_intent_digest(message: &super::frame::OutboxMessage) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(message.recipient.as_bytes());
    hash.update(message.message_id.as_bytes());
    hash.update(&message.body);
    hash.finalize().into()
}

/// Commit the canonical signed credential, including its signature.
pub fn journal_capability_digest(capability: &SignedMailboxCapability) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_jcs::to_vec(capability)?).into())
}

/// The separate host admission step authenticates both original plans, the
/// production posture, and all three credentials before allowing this shape.
pub fn check_projection(local: &MailboxGrant, d: &MailboxJournalDirectionV1) -> Result<()> {
    ensure!(
        local.retention.is_some()
            && local.mailbox != d.address.mailbox
            && d.source != d.address.recipient
            && d.address.recipient.as_bytes() != local.mailbox.as_bytes()
            && d.receipt_key != local.authority_key,
        "journal requires distinct local and destination authority"
    );
    ensure!(
        d.not_before_unix_ms >= 0
            && d.expires_at_unix_ms > d.not_before_unix_ms
            && (1..=32 * 1024).contains(&d.max_payload_bytes),
        "invalid remote journal limits"
    );
    ensure!(
        ![
            d.destination_plan_sha256,
            *d.destination_boot.as_bytes(),
            *d.source.as_bytes(),
            *d.address.recipient.as_bytes(),
            d.source_scope_grant_sha256,
            d.send_grant_sha256,
            d.receive_grant_sha256
        ]
        .contains(&[0; 32]),
        "missing remote journal identity"
    );
    VerifyingKey::from_bytes(&d.receipt_key)?;
    Ok(())
}

/// Both the originally admitted helper and guest compute the same commitment
/// after A's final plan and boot become known. It is never a bearer credential.
pub fn journal_direction_commitment(boot: &MailboxReaderBootBinding) -> Result<[u8; 32]> {
    ensure!(
        boot.outbound_journal_v1.is_some(),
        "original boot has no outbound journal direction"
    );
    let mut digest = Sha256::new();
    digest.update(b"mvm.mailbox.original-journal-direction.v1\0");
    digest.update(serde_jcs::to_vec(boot)?);
    Ok(digest.finalize().into())
}

/// A single operation slot per original cold guest direction. Stale slots
/// are never discovered or reinterpreted under another generation.
pub fn journal_slot_name(commitment: &[u8; 32]) -> String {
    format!("outbox-directed-v1-{}", hex::encode(commitment))
}
