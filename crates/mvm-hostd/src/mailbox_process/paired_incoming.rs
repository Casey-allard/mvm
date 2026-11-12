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
    source_claim: PathBuf,
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
        let journal = retained.storage_paths(config_keys)?.journal;
        pin_generation(
            &journal.with_extension("original-destination-v1"),
            *boot.boot.as_bytes(),
        )?;
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
            source_claim: retained
                .storage_paths(config_keys)?
                .journal
                .with_extension("original-source-v1"),
        }))
    }
    fn bind_original_source(&self, commitment: [u8; 32]) -> Result<()> {
        pin_generation(&self.source_claim, commitment)
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

fn pin_generation(path: &Path, commitment: [u8; 32]) -> Result<()> {
    // The first final A plan+boot wins for this retained B journal.
    // A launcher loss does not permit a replacement generation to reuse its DEK.
    match mvm_core::util::atomic_io::atomic_write_new(path, &commitment) {
        Ok(()) => (),
        Err(e) if mvm_core::util::atomic_io::is_already_exists(&e) => (),
        Err(e) => return Err(e),
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = f.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 == 0 && meta.len() == 32,
        "invalid retained generation claim"
    );
    let mut held = [0; 32];
    f.read_exact(&mut held)?;
    ensure!(
        held == commitment,
        "this retained journal belongs to a different original generation"
    );
    File::open(path.parent().context("missing journal directory")?)?.sync_all()?;
    Ok(())
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
        let commitment = journal_direction_commitment(boot)?;
        enrolled.bind_original_source(commitment)?;
        Ok(PairedSourceMaterial::from_enrollment(
            commitment,
            Key::from_bytes(*enrolled.key.expose_bytes()),
            enrolled.encryption.clone(),
            enrolled.policy.destination_template.routing.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_launch::derive_launch_keys;
    use ed25519_dalek::SigningKey;
    use mvm_core::mailbox::{
        InMemoryReplayProtector, SealRequest, open_envelope, seal_envelope, sign_capability,
    };
    use mvm_core::plan::{compute_plan_id, test_support::PlanFixture};

    fn setup(dir: &Path) -> (MailboxGrant, IncomingJournalPolicy, SigningKey) {
        crate::audit::host_keypair::load_or_init_at(dir).unwrap();
        let grant = |id| {
            let mailbox = MailboxId::from_bytes([id; 32]);
            let epoch = ExecutionEpoch::new(1).unwrap();
            MailboxGrant {
                mailbox,
                epoch,
                authority_key: authority_key_for(dir, &mailbox, epoch).unwrap().to_bytes(),
                incoming_journal_policy_sha256_v1: None,
                outbound_journal_v1: None,
                report: None,
                retention: Some(MailboxRetentionPolicy::new(60000).unwrap()),
            }
        };
        let a = grant(4);
        let mut b = grant(5);
        let (_, sa) = derive_launch_keys(dir, &a, &Key::random()).unwrap().trust();
        let (_, sb) = derive_launch_keys(dir, &b, &Key::random()).unwrap().trust();
        let mut a_cap = sa.capability.clone();
        a_cap.message_kinds = vec![MailboxMessageKind::Cast];
        let mut template = MailboxTemplate {
            header: sb.header,
            routing: sb.routing,
            capability: sb.capability,
        };
        template.header.tenant = a_cap.address.tenant;
        template.header.authorization_domain = a_cap.address.authorization_domain;
        template.capability.address.tenant = a_cap.address.tenant;
        template.capability.address.authorization_domain = a_cap.address.authorization_domain;
        template.capability.message_kinds = vec![MailboxMessageKind::Cast];
        template.routing.hop_limit = 1;
        let mut external = template.capability.clone();
        external.subject = sa.header.sender;
        external.capability_id = CapabilityId::from_bytes([71; 32]);
        external.revocation_id = RevocationId::from_bytes([72; 32]);
        let incoming = IncomingJournalPolicy {
            source_mailbox: a.mailbox,
            source_epoch: a.epoch,
            source_scope: sign_capability(a_cap, &sa.authority_key).unwrap(),
            destination_send: sign_capability(external, &sb.authority_key).unwrap(),
            destination_template: template,
        };
        b.incoming_journal_policy_sha256_v1 = Some(incoming.commitment().unwrap());
        (b, incoming, sa.sender_key)
    }

    #[test]
    fn refuses_missing_unknown_or_swapped_original_credentials() {
        let keys = tempfile::tempdir().unwrap();
        let (grant, policy, _) = setup(keys.path());
        let digest = policy.commitment().unwrap();
        assert!(IncomingJournalPolicy::load(keys.path(), digest).is_err());
        let mut missing = grant;
        missing.incoming_journal_policy_sha256_v1 = None;
        assert!(IncomingJournalAdmission::install_at(keys.path(), &missing, &policy).is_err());
        let mut wrong = policy.clone();
        wrong.destination_send.signature[0] ^= 1;
        let mut substituted = grant;
        substituted.incoming_journal_policy_sha256_v1 = Some(wrong.commitment().unwrap());
        assert!(IncomingJournalAdmission::install_at(keys.path(), &substituted, &wrong).is_err());
        assert!(IncomingJournalPolicy::load(keys.path(), wrong.commitment().unwrap()).is_err());
        IncomingJournalAdmission::install_at(keys.path(), &grant, &policy).unwrap();
        assert_eq!(
            policy.commitment().unwrap(),
            IncomingJournalPolicy::load(keys.path(), digest)
                .unwrap()
                .commitment()
                .unwrap()
        );
    }

    struct Meter {
        socket: std::os::unix::net::UnixStream,
        written: usize,
        read: usize,
    }
    impl std::io::Write for Meter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let n = self.socket.write(bytes)?;
            self.written += n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.socket.flush()
        }
    }
    impl std::io::Read for Meter {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let n = self.socket.read(bytes)?;
            self.read += n;
            Ok(n)
        }
    }
    #[test]
    fn retained_original_b_reads_exact_a_bytes_after_helper_reopen() {
        let keys = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let (grant, policy, a_signer) = setup(keys.path());
        IncomingJournalAdmission::install_at(keys.path(), &grant, &policy).unwrap();
        let mut plan = PlanFixture::new().build();
        plan.mailbox = Some(grant);
        plan.plan_id = compute_plan_id(&plan);
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Prod);
        let boot = MailboxReaderBootBinding::mint(
            &plan,
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        boot.persist(state.path()).unwrap();
        let address = policy.destination_send.grant.address;
        RetainedMailboxKeys::provision_or_open(
            keys.path(),
            &plan,
            &plan.image.name,
            &posture,
            Some(boot.boot),
            address,
        )
        .unwrap();
        let reopen = || {
            let retained = RetainedMailboxKeys::open_existing(
                keys.path(),
                &plan,
                &plan.image.name,
                &posture.handoff(Some(boot.boot)),
                Some(boot.boot),
                address,
            )
            .unwrap();
            let mut derived = derive_launch_keys(keys.path(), &grant, &Key::random()).unwrap();
            derived = derived.with_retained(&retained).unwrap();
            let (mut inbound, sealer) = derived.trust();
            let reader = super::super::reader::load_or_enroll(
                state.path(),
                &grant,
                boot.clone(),
                &sealer.capability,
                &sealer.authority_key,
            )
            .unwrap();
            let incoming = EnrolledIncoming::open(keys.path(), &grant, &retained, &boot, &reader)
                .unwrap()
                .unwrap();
            assert_ne!(incoming.encryption.key_id, retained.payload_key_id());
            incoming.apply(&mut inbound).unwrap();
            assert_eq!(inbound.authority_key, sealer.authority_key.verifying_key());
            assert_eq!(inbound.sender_key, a_signer.verifying_key());
            (incoming, inbound)
        };
        let socket = state.path().join("original-b.sock");
        let start_service = |policy: MailboxPolicy, enrolled: &EnrolledIncoming| {
            let retained = RetainedMailboxKeys::open_existing(
                keys.path(),
                &plan,
                &plan.image.name,
                &posture.handoff(Some(boot.boot)),
                Some(boot.boot),
                address,
            )
            .unwrap();
            let paths = retained.storage_paths(keys.path()).unwrap();
            let signer = derive_launch_keys(keys.path(), &grant, &Key::random())
                .unwrap()
                .durable_material()
                .0;
            let anchor = mvm_core::mailbox::journal::FileJournalAnchor::open(
                &paths.anchor,
                address,
                retained.anchor_key(),
            )
            .unwrap();
            let journal = mvm_core::mailbox::journal::MailboxJournal::open_local_with_custody(
                &paths.journal,
                retained.history_reference(),
                signer.verifying_key(),
                super::super::LOCAL_JOURNAL_LIMITS,
                &retained,
                &anchor,
                grant.retention.unwrap(),
            )
            .unwrap();
            crate::mailbox_service::durable::DurableMailboxService::bind_local_incoming(
                &socket,
                crate::mailbox_launch::LAUNCH_LIMITS,
                policy,
                signer,
                journal,
                anchor,
                Some(
                    enrolled
                        .send_guard(super::super::reader::revocations_path(state.path()))
                        .unwrap(),
                ),
            )
            .unwrap()
        };
        let (first, initial_policy) = reopen();
        let initial_service = start_service(initial_policy, &first);
        first.bind_original_source([31; 32]).unwrap();
        let mut header = policy.destination_template.header.clone();
        header.sender = policy.source_scope.grant.subject;
        header.kind = MailboxMessageKind::Cast;
        header.reply_to = None;
        header.capability_id = policy.destination_send.grant.capability_id;
        header.issued_at_unix_ms = policy.destination_send.grant.not_before_unix_ms;
        header.expires_at_unix_ms = policy.destination_send.grant.expires_at_unix_ms;
        header.encryption = first.encryption.clone();
        header.message_id = MessageId::from_bytes([31; 32]);
        let bytes: Vec<u8> = (0u8..=255).chain(std::iter::once(0)).collect();
        header.plaintext_len = bytes.len() as u32;
        let mut routing = policy.destination_template.routing.clone();
        routing.expires_at_unix_ms = header.expires_at_unix_ms;
        let start = Instant::now();
        let sealed = seal_envelope(
            SealRequest {
                header: header.clone(),
                routing,
                plaintext: &bytes,
            },
            &first.key,
            &a_signer,
        )
        .unwrap();
        let original_receive = first.original_receive.clone();
        let socket_stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        socket_stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        socket_stream
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut meter = Meter {
            socket: socket_stream,
            written: 0,
            read: 0,
        };
        let receipt = mvm_core::mailbox::frame::send_local_receipted_frame(
            &mut meter,
            &policy.destination_send,
            &sealed,
            &header,
            &VerifyingKey::from_bytes(&grant.authority_key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            receipt.receipt.outcome,
            DeliveryOutcome::AcceptedLocalDurable
        );
        let accepted_ns = start.elapsed().as_nanos();
        drop(initial_service);
        drop(first);
        let (second, b) = reopen();
        assert_eq!(second.original_receive, original_receive);
        second.bind_original_source([31; 32]).unwrap();
        assert!(second.bind_original_source([32; 32]).is_err());
        let recovered = open_envelope(
            &sealed,
            &policy.destination_send,
            &b.context,
            &b.encryption_key,
            &b.sender_key,
            &b.authority_key,
            &mut InMemoryReplayProtector::default(),
        )
        .unwrap();
        assert_eq!(recovered, bytes);
        let read_context = OpenContext {
            acting_principal: address.recipient,
            required_operation: MailboxOperation::Receive,
            ..b.context.clone()
        };
        let restored = start_service(b, &second);
        let delivered = restored
            .receive_next(&original_receive, &read_context)
            .unwrap()
            .unwrap();
        assert_eq!(delivered.payload(), bytes);
        let verified_ns = start.elapsed().as_nanos();
        let revoke = super::super::reader::revocations_path(state.path());
        std::fs::write(
            revoke,
            serde_json::to_vec(&[policy.destination_send.grant.revocation_id]).unwrap(),
        )
        .unwrap();
        let mut denied = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        assert!(
            mvm_core::mailbox::frame::send_local_receipted_frame(
                &mut denied,
                &policy.destination_send,
                &sealed,
                &header,
                &VerifyingKey::from_bytes(&grant.authority_key).unwrap()
            )
            .is_err()
        );
        let key_dir = keys.path();
        let held = RetainedMailboxKeys::open_existing(
            key_dir,
            &plan,
            &plan.image.name,
            &posture.handoff(Some(boot.boot)),
            Some(boot.boot),
            address,
        )
        .unwrap();
        let destination_claim = held
            .storage_paths(key_dir)
            .unwrap()
            .journal
            .with_extension("original-destination-v1");
        assert!(pin_generation(&destination_claim, [29; 32]).is_err());

        println!(
            "incoming journal component body={} source_socket_written={} source_socket_read={} seal_through_signed_receipt_ns={} seal_through_reopen_readback_ns={}",
            bytes.len(),
            meter.written,
            meter.read,
            accepted_ns,
            verified_ns
        );
    }
}
