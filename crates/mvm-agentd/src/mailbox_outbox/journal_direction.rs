//! One retained directed operation on the original guest's local-durable slot.
use super::{forward_with, send_local_outbox_message};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{MessageId, SignedDestinationReceipt};
use mvm_core::mailbox::outbound::journal_intent_digest;
use mvm_core::mailbox::{
    frame::{OWN_MAILBOX_RECIPIENT, Refusal},
    reader::MailboxReaderBootBinding,
};
use std::{
    io::{Read, Write},
    path::Path,
};

/// The canonical guest listener services one durable outbox at a time. Keep
/// at most one retry identity, including the original plaintext commitment.
#[derive(Default)]
pub struct JournalAttempts(Option<(MessageId, [u8; 32], u8)>);

pub fn forward_for_original_boot<S: Read + Write>(
    stream: &mut S,
    outbox: &Path,
    boot: &MailboxReaderBootBinding,
    attempts: &mut JournalAttempts,
    now: impl Fn() -> Result<i64, Refusal>,
) -> Result<SignedDestinationReceipt, Refusal> {
    forward_with(stream, outbox, |stream, message| {
        let remote = boot.outbound_journal_v1.as_ref().filter(|_| {
            message.recipient.as_bytes() != &OWN_MAILBOX_RECIPIENT
                && message.recipient.as_bytes() != boot.mailbox.as_bytes()
        });
        let Some(remote) = remote else {
            let key =
                VerifyingKey::from_bytes(&boot.authority_key).map_err(|_| Refusal::Malformed)?;
            return send_local_outbox_message(
                stream,
                message,
                &key,
                boot.mailbox,
                boot.execution_epoch,
            );
        };
        if message.recipient != remote.address.recipient {
            return Err(Refusal::NotAuthorized);
        }
        if message.body.len() > remote.max_payload_bytes as usize {
            return Err(Refusal::Oversized(remote.max_payload_bytes as usize));
        }
        let key = VerifyingKey::from_bytes(&remote.receipt_key).map_err(|_| Refusal::Malformed)?;
        let window = remote.not_before_unix_ms..remote.expires_at_unix_ms;
        let digest: [u8; 32] = journal_intent_digest(message);
        let id = message.message_id;
        if let Some((previous, original, count)) = attempts.0
            && previous == id
        {
            if original != digest || count >= 3 || !window.contains(&now()?) {
                return Err(Refusal::RetriesExhausted);
            }
        } else {
            if !window.contains(&now()?) {
                return Err(Refusal::Expired);
            }
            attempts.0 = Some((id, digest, 0));
        }
        let (_, _, count) = attempts.0.as_mut().ok_or(Refusal::Unavailable)?;
        *count += 1;
        // Every other response, including an unsigned refusal or dropped reply,
        // lacks evidence of acceptance. Keep this exact pending operation.
        let receipt = send_local_outbox_message(
            stream,
            message,
            &key,
            remote.address.mailbox,
            remote.execution_epoch,
        )
        .map_err(|_| Refusal::Unavailable)?;
        if receipt.receipt.address != remote.address
            || !window.contains(&receipt.receipt.observed_at_unix_ms)
            || !window.contains(&now()?)
        {
            return Err(Refusal::Unavailable);
        }
        Ok(receipt)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_outbox::write_outbox;
    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::mailbox::*;
    use mvm_core::{
        mailbox::{frame::OutboxMessage, sign_receipt},
        plan::{Nonce, PlanId},
    };
    use std::io::{self, Cursor};

    struct Peer {
        response: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }
    impl Peer {
        fn new(receipt: Option<SignedDestinationReceipt>) -> Self {
            Self {
                response: Cursor::new(
                    receipt
                        .map(|r| serde_json::to_vec(&Ok::<_, Refusal>(r)).unwrap())
                        .unwrap_or_default(),
                ),
                sent: Vec::new(),
            }
        }
    }
    impl Read for Peer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.response.read(buf)
        }
    }
    impl Write for Peer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn fixture() -> (
        MailboxReaderBootBinding,
        OutboxMessage,
        DestinationReceipt,
        SigningKey,
    ) {
        let b = SigningKey::from_bytes(&[44; 32]);
        let address = MailboxAddress {
            tenant: TenantId::from_bytes([7; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([9; 32]),
            mailbox: MailboxId::from_bytes([10; 32]),
            recipient: PrincipalId::from_bytes([11; 32]),
        };
        let epoch = ExecutionEpoch::new(1).unwrap();
        let direction = MailboxJournalDirectionV1 {
            source: PrincipalId::from_bytes([12; 32]),
            destination_plan_sha256: [1; 32],
            destination_plan_nonce: [2; 16],
            destination_boot: BootId::from_bytes([3; 32]),
            address,
            execution_epoch: epoch,
            policy_epoch: 1,
            receipt_key: b.verifying_key().to_bytes(),
            source_scope_grant_sha256: [4; 32],
            send_grant_sha256: [5; 32],
            receive_grant_sha256: [6; 32],
            not_before_unix_ms: 100,
            expires_at_unix_ms: 200,
            max_payload_bytes: 313,
        };
        let boot = MailboxReaderBootBinding {
            outbound_journal_v1: Some(direction),
            plan_id: PlanId(format!("sha256:{}", "ab".repeat(32))),
            plan_nonce: Nonce::from_bytes([6; 16]),
            mailbox: MailboxId::from_bytes([17; 32]),
            authority_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            execution_epoch: epoch,
            boot: BootId::from_bytes([19; 32]),
            guest_identity_key: [20; 32],
            ack_public_key: [21; 32],
        };
        let msg = OutboxMessage::new(address.recipient, (0..=255).chain([0]).collect());
        let receipt = DestinationReceipt {
            protocol_version: ProtocolVersion::V2,
            signature_algorithm: SignatureAlgorithm::ED25519,
            delivery_id: DeliveryId::from_bytes([13; 32]),
            message_id: msg.message_id,
            address,
            execution_epoch: epoch,
            outcome: DeliveryOutcome::AcceptedLocalDurable,
            observed_at_unix_ms: 149,
            ciphertext_commitment: [14; 32],
        };
        (boot, msg, receipt, b)
    }
    #[test]
    fn original_remote_intent_survives_lost_reply_and_wrong_domain_before_exact_b_receipt() {
        let (boot, msg, receipt, b) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let slot = dir.path().join("local");
        write_outbox(&slot, &msg).unwrap();
        let mut attempts = JournalAttempts::default();
        let mut lost = Peer::new(None);
        assert_eq!(
            forward_for_original_boot(&mut lost, &slot, &boot, &mut attempts, || Ok(150)),
            Err(Refusal::Unavailable)
        );
        let mut unrelated = receipt.clone();
        unrelated.address.authorization_domain = AuthorizationDomainId::from_bytes([27; 32]);
        let mut wrong = Peer::new(Some(sign_receipt(unrelated, &b).unwrap()));
        assert_eq!(
            forward_for_original_boot(&mut wrong, &slot, &boot, &mut attempts, || Ok(150)),
            Err(Refusal::Unavailable)
        );
        assert_eq!(std::fs::read(&slot).unwrap(), msg.encode());
        let signed = sign_receipt(receipt, &b).unwrap();
        let mut exact = Peer::new(Some(signed.clone()));
        assert_eq!(
            forward_for_original_boot(&mut exact, &slot, &boot, &mut attempts, || Ok(150)).unwrap(),
            signed
        );
        assert_eq!(lost.sent, wrong.sent);
        assert_eq!(lost.sent, exact.sent);
        assert_eq!(&exact.sent[4..], msg.encode());
        assert!(!slot.exists());
    }
    #[test]
    fn own_authority_cannot_retire_remote_intent_and_retry_credit_ends_without_dispatch() {
        let (boot, msg, receipt, _) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let slot = dir.path().join("local");
        write_outbox(&slot, &msg).unwrap();
        let wrong = sign_receipt(receipt, &SigningKey::from_bytes(&[8; 32])).unwrap();
        let mut attempts = JournalAttempts::default();
        for _ in 0..3 {
            let mut peer = Peer::new(Some(wrong.clone()));
            assert_eq!(
                forward_for_original_boot(&mut peer, &slot, &boot, &mut attempts, || Ok(150)),
                Err(Refusal::Unavailable)
            );
            assert_eq!(&peer.sent[4..], msg.encode());
            assert!(slot.exists());
        }
        let mut fourth = Peer::new(None);
        assert_eq!(
            forward_for_original_boot(&mut fourth, &slot, &boot, &mut attempts, || Ok(150)),
            Err(Refusal::RetriesExhausted)
        );
        assert!(fourth.sent.is_empty());
        let files = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        assert!(
            files[0]
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("uncertain-")
        );
        assert_eq!(std::fs::read(&files[0]).unwrap(), msg.encode());
    }
    #[test]
    fn original_signed_plan_and_boot_commit_the_destination_and_both_credentials() {
        use mvm_core::mailbox::outbound::journal_direction_commitment;
        use mvm_core::plan::{
            signing::{sign_plan, verify_plan},
            test_support::PlanFixture,
        };
        let (boot, _, _, _) = fixture();
        let key = SigningKey::from_bytes(&[31; 32]);
        let mut grant = MailboxGrant {
            outbound_journal_v1: None,
            mailbox: boot.mailbox,
            authority_key: boot.authority_key,
            epoch: boot.execution_epoch,
            report: None,
            retention: Some(MailboxRetentionPolicy::new(1000).unwrap()),
        };
        assert!(
            serde_json::to_value(grant)
                .unwrap()
                .get("outbound_journal_v1")
                .is_none()
        );
        grant.outbound_journal_v1 = boot.outbound_journal_v1;
        let mut plan = PlanFixture::new().build();
        plan.mailbox = Some(grant);
        let signed = sign_plan(&plan, &key, "original-host");
        let checked = verify_plan(&signed, &[("original-host", &key.verifying_key())]).unwrap();
        let original = MailboxReaderBootBinding::mint(
            &checked,
            key.verifying_key(),
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        original.check_plan(&checked).unwrap();
        let commitment = journal_direction_commitment(&original).unwrap();
        for edit in 0..4 {
            let mut changed = original.clone();
            let d = changed.outbound_journal_v1.as_mut().unwrap();
            match edit {
                0 => d.receipt_key = key.verifying_key().to_bytes(),
                1 => d.source_scope_grant_sha256[0] ^= 1,
                2 => d.send_grant_sha256[0] ^= 1,
                _ => d.receive_grant_sha256[0] ^= 1,
            }
            assert!(changed.check_plan(&checked).is_err());
            assert_ne!(journal_direction_commitment(&changed).unwrap(), commitment);
        }
        let other_boot = MailboxReaderBootBinding::mint(
            &checked,
            key.verifying_key(),
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_ne!(
            journal_direction_commitment(&other_boot).unwrap(),
            commitment
        );
    }

    #[test]
    fn expiry_after_dispatch_retains_original_in_uncertain_archive() {
        use std::cell::Cell;
        let (boot, msg, receipt, b) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let slot = dir.path().join("local");
        write_outbox(&slot, &msg).unwrap();
        let mut attempts = JournalAttempts::default();
        let mut peer = Peer::new(Some(sign_receipt(receipt, &b).unwrap()));
        let time = Cell::new(150);
        assert_eq!(
            forward_for_original_boot(&mut peer, &slot, &boot, &mut attempts, || Ok(
                time.replace(200)
            )),
            Err(Refusal::Unavailable)
        );
        assert_eq!(std::fs::read(&slot).unwrap(), msg.encode());
        let mut retry = Peer::new(None);
        assert_eq!(
            forward_for_original_boot(&mut retry, &slot, &boot, &mut attempts, || Ok(200)),
            Err(Refusal::RetriesExhausted)
        );
        assert!(retry.sent.is_empty());
        let stored = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert!(
            stored
                .file_name()
                .to_str()
                .unwrap()
                .starts_with("uncertain-")
        );
        assert_eq!(std::fs::read(stored.path()).unwrap(), msg.encode());
    }
}
