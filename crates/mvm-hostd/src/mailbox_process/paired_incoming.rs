//! Destination-authorized, single-source incoming profile for a local retained journal.
//! The retained private purpose keys and original B reader authority stay at B.
use super::original_journal::{
    OriginalJournalDestination,
    authorization::{JournalCredentials, now_ms},
};
use crate::{
    mailbox_custody::RetainedMailboxKeys,
    mailbox_launch::{MailboxTemplate, authority_key_for, journal_scope_before_launch},
    mailbox_service::{MailboxPolicy, directed_journal::PairedSourceMaterial},
    plan_admission::MailboxLaunchPosture,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, KeyInit, Mac};
use mvm_contract::protocol::mailbox::*;
use mvm_core::{
    crypto::aead::Key,
    mailbox::{
        OpenContext, authorize_send,
        outbound::{journal_capability_digest, journal_direction_commitment},
        reader::MailboxReaderBootBinding,
        verify_capability_signature,
    },
    plan::{ExecutionPlan, Variant},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::Zeroizing;

const MAX_POLICY_BYTES: u64 = 64 * 1024;

/// Original operator-approved public inputs. B's signed plan commits to the hash
/// of this entire value. No key seed, received ciphertext or workload input is included.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingJournalPolicy {
    pub source_mailbox: MailboxId,
    pub source_epoch: ExecutionEpoch,
    pub source_scope: SignedMailboxCapability,
    pub destination_send: SignedMailboxCapability,
    pub destination_template: MailboxTemplate,
}

impl IncomingJournalPolicy {
    pub fn commitment(&self) -> Result<[u8; 32]> {
        let bytes = serde_jcs::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_POLICY_BYTES as usize,
            "incoming policy too large"
        );
        let mut h = Sha256::new();
        h.update(b"mvm.mailbox.original-incoming-journal.v1\0");
        h.update(bytes);
        Ok(h.finalize().into())
    }

    fn path(keys: &Path, digest: [u8; 32]) -> PathBuf {
        keys.join(format!("mailbox-incoming-v1-{}.json", hex::encode(digest)))
    }

    fn load(keys: &Path, digest: [u8; 32]) -> Result<Self> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(Self::path(keys, digest))?;
        let meta = f.metadata()?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.mode() & 0o077 == 0
                && meta.len() <= MAX_POLICY_BYTES,
            "invalid incoming policy file"
        );
        let mut bytes = Vec::new();
        f.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_POLICY_BYTES as usize,
            "incoming policy exceeds bound"
        );
        let profile: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            profile.commitment()? == digest,
            "incoming policy differs from signed grant"
        );
        Ok(profile)
    }

    pub(crate) fn template(keys: &Path, digest: [u8; 32]) -> std::io::Result<MailboxTemplate> {
        Self::load(keys, digest)
            .map(|v| v.destination_template)
            .map_err(std::io::Error::other)
    }

    fn verify(&self, keys: &Path, grant: &MailboxGrant, now: i64) -> Result<()> {
        ensure!(
            grant.outbound_journal_v1.is_none()
                && grant.retention.is_some()
                && grant.incoming_journal_policy_sha256_v1 == Some(self.commitment()?),
            "missing matching destination-only retained grant"
        );
        let auth_a = authority_key_for(keys, &self.source_mailbox, self.source_epoch)?;
        let auth_b = authority_key_for(keys, &grant.mailbox, grant.epoch)?;
        ensure!(
            self.source_mailbox != grant.mailbox
                && auth_a != auth_b
                && auth_b.to_bytes() == grant.authority_key,
            "distinct original authorities required"
        );
        let a = journal_scope_before_launch(
            keys,
            &MailboxGrant {
                mailbox: self.source_mailbox,
                epoch: self.source_epoch,
                authority_key: auth_a.to_bytes(),
                report: None,
                retention: None,
                outbound_journal_v1: None,
                incoming_journal_policy_sha256_v1: None,
            },
            now,
        )?;
        let source = a.header.sender;
        let b = &self.destination_template;
        let h = &b.header;
        let b_local = b.capability.address;
        let derived_b = crate::mailbox_launch::journal_sender_for(keys, grant)?;
        ensure!(
            b_local == self.destination_send.grant.address
                && b_local.mailbox == grant.mailbox
                && b_local.recipient == h.recipient
                && b_local.tenant == h.tenant
                && b_local.authorization_domain == h.authorization_domain
                && h.tenant == a.header.tenant
                && h.authorization_domain == a.header.authorization_domain
                && h.mailbox == grant.mailbox
                && h.execution_epoch == grant.epoch
                && h.sender.as_bytes() == &derived_b.to_bytes()
                && h.sender != source
                && h.recipient != source
                && b.capability.subject == h.sender
                && b.capability.issuer.as_bytes() == &grant.authority_key
                && b.routing.hop_limit == 1
                && b.capability
                    .message_kinds
                    .contains(&MailboxMessageKind::Cast)
                && b.capability.max_payload_bytes <= 32 * 1024,
            "destination template differs from original source, recipient, or reader authority"
        );
        for (template, cap, authority) in [
            (&a, &self.source_scope, auth_a),
            (b, &self.destination_send, auth_b),
        ] {
            verify_capability_signature(cap, &authority)?;
            let address = template.capability.address;
            ensure!(
                cap.grant.subject == source
                    && cap.grant.address == address
                    && cap.grant.issuer.as_bytes() == &authority.to_bytes()
                    && cap.grant.message_kinds == [MailboxMessageKind::Cast]
                    && cap.grant.operations
                        == CapabilityOperations::from_operations(&[MailboxOperation::Send])
                    && cap.grant.minimum_execution_epoch == template.header.execution_epoch
                    && cap.grant.maximum_execution_epoch == template.header.execution_epoch
                    && cap.grant.policy_epoch == template.header.policy_epoch
                    && cap.grant.max_payload_bytes <= 32 * 1024
                    && (cap.grant.not_before_unix_ms..cap.grant.expires_at_unix_ms).contains(&now),
                "original credential identity, type, limit or validity mismatch"
            );
            let mut header = template.header.clone();
            header.sender = source;
            header.kind = MailboxMessageKind::Cast;
            header.reply_to = None;
            header.capability_id = cap.grant.capability_id;
            header.plaintext_len = 1;
            header.issued_at_unix_ms = cap.grant.not_before_unix_ms;
            header.expires_at_unix_ms = cap.grant.expires_at_unix_ms;
            let context = OpenContext {
                expected_tenant: address.tenant,
                expected_authorization_domain: address.authorization_domain,
                expected_mailbox: address.mailbox,
                expected_sender: source,
                expected_recipient: address.recipient,
                acting_principal: source,
                expected_capability_issuer: cap.grant.issuer,
                current_execution_epoch: header.execution_epoch,
                current_policy_epoch: header.policy_epoch,
                required_operation: MailboxOperation::Send,
                now_unix_ms: now,
                accepted_content_types: vec![header.content_type.clone()],
                revoked_capabilities: vec![],
            };
            authorize_send(&header, cap, &context, &authority)?;
        }
        Ok(())
    }
}

/// Created only by explicitly registering both original independent Send grants.
/// The installer must select B's matching digest in its signed plan.
#[derive(Debug)]
pub struct IncomingJournalAdmission {
    digest: [u8; 32],
}
impl IncomingJournalAdmission {
    pub fn install(grant: &MailboxGrant, profile: &IncomingJournalPolicy) -> Result<Self> {
        Self::install_at(&mvm_core::config::mvm_keys_dir(), grant, profile)
    }
    fn install_at(
        keys: &Path,
        grant: &MailboxGrant,
        profile: &IncomingJournalPolicy,
    ) -> Result<Self> {
        let digest = profile.commitment()?;
        profile.verify(keys, grant, now_ms()?)?;
        let path = IncomingJournalPolicy::path(keys, digest);
        match mvm_core::util::atomic_io::atomic_write_new(&path, &serde_json::to_vec(profile)?) {
            Ok(()) => File::open(keys)?.sync_all()?,
            Err(e) if mvm_core::util::atomic_io::is_already_exists(&e) => (),
            Err(e) => return Err(e),
        }
        IncomingJournalPolicy::load(keys, digest)?;
        Ok(Self { digest })
    }
    pub(crate) fn verify(&self, plan: &ExecutionPlan) -> Result<()> {
        let grant = plan.mailbox.as_ref().context("B has no mailbox")?;
        let keys = mvm_core::config::mvm_keys_dir();
        IncomingJournalPolicy::load(&keys, self.digest)?.verify(&keys, grant, now_ms()?)
    }
}

/// Key material is reconstructed from the original B retained payload purpose
/// key, using an independent label, signed policy, and actual original boot.
/// The resulting key can be released to A; the B parent key cannot.
pub(super) struct EnrolledIncoming {
    policy: IncomingJournalPolicy,
    key: Key,
    encryption: EncryptionContext,
    original_receive: SignedMailboxCapability,
}
impl EnrolledIncoming {
    pub(super) fn open(
        config_keys: &Path,
        grant: &MailboxGrant,
        retained: &RetainedMailboxKeys,
        boot: &MailboxReaderBootBinding,
        reader: &crate::mailbox_service::durable::GuestReaderAuthority,
    ) -> Result<Option<Self>> {
        let Some(digest) = grant.incoming_journal_policy_sha256_v1 else {
            return Ok(None);
        };
        let policy = IncomingJournalPolicy::load(config_keys, digest)?;
        // Past validity fences new sends at admission, without losing the
        // verifier used to open a still-live original B reader's retained row.
        let overlap = policy
            .source_scope
            .grant
            .not_before_unix_ms
            .max(policy.destination_send.grant.not_before_unix_ms);
        policy.verify(config_keys, grant, overlap)?;
        ensure!(
            reader.boot == *boot
                && reader.grant == *grant
                && retained.address() == policy.destination_send.grant.address
                && reader.capability.grant.address == retained.address()
                && reader.capability.grant.subject == retained.address().recipient
                && reader
                    .capability
                    .grant
                    .message_kinds
                    .contains(&MailboxMessageKind::Cast),
            "B's original boot-bound reader does not admit the incoming Cast"
        );
        let parent = retained.payload_key();
        let mut h = <Hmac<Sha256> as KeyInit>::new_from_slice(parent.expose_bytes())?;
        h.update(b"mvm.mailbox.retained-directional-payload.v1\0");
        h.update(&digest);
        h.update(boot.boot.as_bytes());
        let raw = Zeroizing::new(<[u8; 32]>::from(h.finalize().into_bytes()));
        let encryption = EncryptionContext {
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id: Sha256::digest(&raw[..]).into(),
        };
        Ok(Some(Self {
            policy,
            key: Key::from_bytes(*raw),
            encryption,
            original_receive: reader.capability.clone(),
        }))
    }
    pub(super) fn apply(&self, policy: &mut MailboxPolicy) -> Result<()> {
        let sender = self.policy.source_scope.grant.subject;
        policy.context.expected_sender = sender;
        policy.context.acting_principal = sender;
        policy.sender_key = VerifyingKey::from_bytes(sender.as_bytes())?;
        policy.encryption_key = Key::from_bytes(*self.key.expose_bytes());
        Ok(())
    }
    pub(super) fn send_guard(
        &self,
        revocations: PathBuf,
    ) -> Result<crate::mailbox_service::durable::IncomingSendGuard> {
        Ok(crate::mailbox_service::durable::IncomingSendGuard {
            digest: journal_capability_digest(&self.policy.destination_send)?,
            revocations,
        })
    }
    pub(super) fn agrees(&self, grants: &JournalCredentials) -> bool {
        self.policy.source_scope == grants.source_scope
            && self.policy.destination_send == grants.destination_send
            && self.original_receive == grants.destination_receive
    }
}

impl OriginalJournalDestination {
    pub fn original_receive(&self) -> Result<&SignedMailboxCapability> {
        Ok(&self
            .incoming
            .as_ref()
            .context("B has no signed incoming journal policy")?
            .original_receive)
    }

    pub(crate) fn source_material(
        &mut self,
        plan: &ExecutionPlan,
        posture: &MailboxLaunchPosture,
        boot: &MailboxReaderBootBinding,
        grants: &JournalCredentials,
        deadline: Instant,
    ) -> Result<PairedSourceMaterial> {
        ensure!(
            posture.variant() == Variant::Prod,
            "A requires original production posture"
        );
        posture.verify(plan, &plan.image.name)?;
        boot.check_plan(plan)?;
        mvm_core::naming::validate_vm_name(&plan.image.name)?;
        let state = mvm_core::config::vm_state_dir(&plan.image.name);
        ensure!(
            MailboxReaderBootBinding::load(&state)? == *boot,
            "A boot differs from original retained identity"
        );
        self.check_proposal(plan, grants, deadline)?;
        let enrolled = self
            .incoming
            .as_ref()
            .context("original B has no incoming enrollment")?;
        ensure!(
            enrolled.agrees(grants),
            "original A or B signed grants changed"
        );
        Ok(PairedSourceMaterial::from_enrollment(
            journal_direction_commitment(boot)?,
            Key::from_bytes(*enrolled.key.expose_bytes()),
            enrolled.encryption.clone(),
            enrolled.policy.destination_template.routing.clone(),
        ))
    }
}
