//! Same-installation provisioning for signed object Call/Reply. Registration
//! verifies operator inputs without launching either helper or allocating keys.
use anyhow::{Context, Result, ensure};

use mvm_contract::protocol::mailbox::*;
use mvm_core::mailbox::{object_pair::ObjectPairGrants, verify_capability_signature};
use mvm_core::plan::Nonce;
use std::path::Path;
pub mod plan;
pub use plan::OriginalObjectPlan;

/// Four original independent signed credentials. Neither transport direction
/// nor the original journal receipt is authority to read a mailbox.
#[derive(Clone)]
pub struct ObjectPairCredentials {
    pub call: SignedMailboxCapability,
    pub reply: SignedMailboxCapability,
    pub receive_at_caller: SignedMailboxCapability,
    pub receive_at_callee: SignedMailboxCapability,
}

#[derive(Clone)]
pub struct PreparedObjectPair {
    credentials: ObjectPairCredentials,
    stamp: [u8; 32],
    caller: MailboxGrant,
    callee: MailboxGrant,
    caller_nonce: Nonce,
    callee_nonce: Nonce,
}

fn material_transcript(
    stamp: [u8; 32],
    caller: &MailboxReaderBootBinding,
    callee: &MailboxReaderBootBinding,
    caller_receive: &SignedMailboxCapability,
    callee_receive: &SignedMailboxCapability,
) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"mvm.object-pair.original-material.v1\0");
    h.update(stamp);
    h.update(caller.boot.as_bytes());
    h.update(callee.boot.as_bytes());
    for b in [caller, callee] {
        h.update(Sha256::digest(b.plan_id.0.as_bytes()));
    }
    for recv in [caller_receive, callee_receive] {
        h.update(mvm_core::mailbox::outbound::journal_capability_digest(
            recv,
        )?);
    }
    Ok(h.finalize().into())
}
fn original_reader_pin(transcript: [u8; 32], call: &[u8; 32], reply: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"mvm.object-pair.original-reader.keys.v1\0");
    h.update(transcript);
    h.update(Sha256::digest(call));
    h.update(Sha256::digest(reply));
    h.finalize().into()
}

impl PreparedObjectPair {
    /// Before signing either plan, verify the operator's two original mailbox
    /// identities and all four independently issued credentials using host keys.
    pub fn prepare(
        caller: &MailboxGrant,
        caller_nonce: &Nonce,
        callee: &MailboxGrant,
        callee_nonce: &Nonce,
        credentials: ObjectPairCredentials,
    ) -> Result<Self> {
        Self::prepare_at(
            &mvm_core::config::mvm_keys_dir(),
            caller,
            caller_nonce,
            callee,
            callee_nonce,
            credentials,
            super::now_unix_ms(),
        )
    }

    fn prepare_at(
        keys: &Path,
        caller: &MailboxGrant,
        caller_nonce: &Nonce,
        callee: &MailboxGrant,
        callee_nonce: &Nonce,
        credentials: ObjectPairCredentials,
        now: i64,
    ) -> Result<Self> {
        let c = &credentials.call.grant;
        let r = &credentials.reply.grant;
        ensure!(
            caller_nonce != callee_nonce
                && caller.mailbox != callee.mailbox
                && caller.authority_key != callee.authority_key
                && c.address.tenant == r.address.tenant
                && c.address.authorization_domain == r.address.authorization_domain,
            "object pair requires distinct originals in the same admitted tenant/domain"
        );
        let stamp = ObjectPairGrants {
            call: &credentials.call,
            reply: &credentials.reply,
        }
        .commitment(caller_nonce, callee_nonce)?;
        let content = ContentType::parse("application/spiralcore-object", 1)?;
        for (local, send, receive, op, kind, local_sender) in [
            (
                caller,
                &credentials.reply,
                &credentials.receive_at_caller,
                MailboxOperation::Reply,
                MailboxMessageKind::Reply,
                c.subject,
            ),
            (
                callee,
                &credentials.call,
                &credentials.receive_at_callee,
                MailboxOperation::Send,
                MailboxMessageKind::Call,
                r.subject,
            ),
        ] {
            ensure!(
                local.retention.is_some()
                    && local.report.is_none()
                    && local.outbound_journal_v1.is_none()
                    && local.incoming_journal_policy_sha256_v1.is_none()
                    && local
                        .durable_object_pair_sha256_v1
                        .is_none_or(|s| s == stamp),
                "object profile conflicts with original grant"
            );
            let keys = super::derived_keys(keys, &local.mailbox, local.epoch)?;
            let authority = keys.authority.verifying_key();
            ensure!(
                local.authority_key == authority.to_bytes()
                    && local_sender.as_bytes() == keys.sender.verifying_key().as_bytes(),
                "original mailbox authority or sender differs from installed keys"
            );
            let flow = &send.grant;
            let read = &receive.grant;
            ensure!(
                flow.address.mailbox == local.mailbox
                    && flow.address.recipient == local_sender
                    && flow.subject != local_sender
                    && read.address == flow.address
                    && read.subject == flow.address.recipient
                    && read.capability_id != flow.capability_id
                    && read.revocation_id != flow.revocation_id
                    && read.policy_epoch == flow.policy_epoch
                    && read.max_payload_bytes <= flow.max_payload_bytes
                    && read.max_queue_contribution_bytes <= flow.max_queue_contribution_bytes
                    && read.max_outstanding_calls <= flow.max_outstanding_calls
                    && read.max_messages_per_minute <= flow.max_messages_per_minute
                    && read.not_before_unix_ms >= flow.not_before_unix_ms
                    && read.expires_at_unix_ms <= flow.expires_at_unix_ms,
                "reader exceeds this destination's original scope"
            );
            for (signed, operation) in [(send, op), (receive, MailboxOperation::Receive)] {
                let g = &signed.grant;
                ensure!(
                    g.issuer.as_bytes() == &local.authority_key
                        && g.operations == CapabilityOperations::from_operations(&[operation])
                        && g.message_kinds == [kind]
                        && g.content_types.as_slice() == std::slice::from_ref(&content)
                        && g.minimum_execution_epoch == local.epoch
                        && g.maximum_execution_epoch == local.epoch
                        && g.max_payload_bytes <= 32 * 1024
                        && u64::from(g.max_payload_bytes) <= g.max_queue_contribution_bytes
                        && (g.not_before_unix_ms..g.expires_at_unix_ms).contains(&now),
                    "credential outside this installed profile"
                );
                verify_capability_signature(signed, &authority)?;
            }
        }
        Ok(Self {
            credentials,
            stamp,
            caller: MailboxGrant {
                durable_object_pair_sha256_v1: Some(stamp),
                ..*caller
            },
            callee: MailboxGrant {
                durable_object_pair_sha256_v1: Some(stamp),
                ..*callee
            },
            caller_nonce: caller_nonce.clone(),
            callee_nonce: callee_nonce.clone(),
        })
    }

    /// Grants to include in the original caller/callee plans under their
    /// previously chosen nonces. No reader, child, key, or journal is granted here.
    pub fn selected_grants(&self) -> (MailboxGrant, MailboxGrant) {
        (self.caller, self.callee)
    }
}

use crate::mailbox_process::reader::{enroll_object_reader, revocations_path};
use crate::mailbox_service::durable::{GuestReaderAuthority, reader_revocations};
use crate::plan_admission::{AdmittedPlan, MailboxLaunchPosture};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::{
    object_pair::{ObjectPairV1, OriginalObjectEndpoint, PairAuthorityState},
    reader::MailboxReaderBootBinding,
};
use mvm_core::plan::{SignedExecutionPlan, Variant, verify_plan};
use sha2::{Digest, Sha256};

/// Public SDK input identifies an already admitted original. The SDK retains
/// the original backend and passes the boot prepared for that precise launch.
pub struct InstalledParticipant<'a> {
    admitted: &'a AdmittedPlan,
    original: OriginalNative<'a>,
    boot: &'a MailboxReaderBootBinding,
}

enum OriginalNative<'a> {
    Hvf(&'a mvm_runtime::workload_runner::runner::OwnedRuntimeLaunch),
    #[cfg(target_os = "linux")]
    Firecracker(&'a mvm_runtime::backend::OriginalObjectFirecracker),
}
impl<'a> InstalledParticipant<'a> {
    pub fn from_owned_hvf(
        admitted: &'a AdmittedPlan,
        original: &'a mvm_runtime::workload_runner::runner::OwnedRuntimeLaunch,
        boot: &'a MailboxReaderBootBinding,
    ) -> Result<Self> {
        let owner = Self {
            admitted,
            original: OriginalNative::Hvf(original),
            boot,
        };
        check_original_native(&owner)?;
        Ok(owner)
    }
    #[cfg(target_os = "linux")]
    pub fn from_original_firecracker(admitted: &'a AdmittedPlan) -> Result<Self> {
        let original = admitted.object_firecracker()?;
        let owner = Self {
            admitted,
            original: OriginalNative::Firecracker(original),
            boot: original.boot()?,
        };
        check_original_native(&owner)?;
        Ok(owner)
    }
}

fn check_original_native(participant: &InstalledParticipant<'_>) -> Result<()> {
    let original = match participant.original {
        #[cfg(target_os = "linux")]
        OriginalNative::Firecracker(native) => {
            native.require_live()?;
            anyhow::ensure!(
                participant.boot == native.boot()?,
                "different original Firecracker guest boot"
            );
            return participant.boot.check_plan(participant.admitted.plan());
        }
        OriginalNative::Hvf(original) => original,
    };
    original.validate_live()?;
    let name = &participant.admitted.plan().image.name;
    mvm_core::naming::validate_vm_name(name)?;
    ensure!(
        &original.vm_id()?.0 == name,
        "original native VM name differs"
    );
    let envelope: SignedExecutionPlan = serde_json::from_str(
        original
            .config()?
            .plan_json
            .as_deref()
            .context("original native plan missing")?,
    )?;
    ensure!(
        envelope.0.payload == participant.admitted.signed().0.payload
            && envelope.0.signature == participant.admitted.signed().0.signature
            && envelope.0.signer_id == participant.admitted.signed().0.signer_id,
        "original native launch signed a different plan"
    );
    Ok(())
}
struct BootInput<'a> {
    plan: &'a SignedExecutionPlan,
    posture: &'a MailboxLaunchPosture,
    state: &'a Path,
    boot: &'a MailboxReaderBootBinding,
    current_epoch: ExecutionEpoch,
}

pub struct InstalledObjectPair<'a> {
    caller: InstalledParticipant<'a>,
    callee: InstalledParticipant<'a>,
    prepared: PreparedObjectPair,
    registration: crate::mailbox_process::original_journal::object_registration::Registration,
    material: PairMaterial,
}
struct PairMaterial {
    plan_verifier: ed25519_dalek::VerifyingKey,
    caller: EndpointMaterial,
    callee: EndpointMaterial,
}
pub(crate) struct EndpointMaterial {
    custody: crate::mailbox_custody::RetainedMailboxKeys,
    pub(crate) routing: MailboxRoutingFrame,
    pub(crate) public_role: mvm_core::mailbox::object_pair::role::SignedObjectRoleV1,
    pub(crate) reader: GuestReaderAuthority,
    pub(crate) inbound_key: Key,
    pub(crate) outbound_key: Key,
    pub(crate) sender: ed25519_dalek::SigningKey,
}
impl InstalledObjectPair<'_> {
    pub(crate) fn source_intents(
        &self,
        role: mvm_core::mailbox::object_pair::role::ObjectParticipantRole,
    ) -> Result<std::path::PathBuf> {
        use mvm_core::mailbox::object_pair::role::ObjectParticipantRole;
        self.check_current()?;
        let (local, owner) = match role {
            ObjectParticipantRole::Caller => (&self.material.caller, &self.caller),
            ObjectParticipantRole::Callee => (&self.material.callee, &self.callee),
        };
        ensure!(
            local
                .custody
                .matches_original(owner.admitted.plan(), local.reader.capability.grant.address),
            "retained outbound storage belongs to different admitted original"
        );
        Ok(local
            .custody
            .storage_paths(&mvm_core::config::mvm_keys_dir())?
            .source_intents)
    }

    /// Only public verifiers and signed reader proofs are observable by the SDK.
    pub fn original_readers(
        &self,
    ) -> Result<(
        &SignedMailboxGuestReaderEnrollment,
        &SignedMailboxGuestReaderEnrollment,
    )> {
        self.check_current()?;
        Ok((
            &self.material.caller.reader.enrollment,
            &self.material.callee.reader.enrollment,
        ))
    }
}

impl PreparedObjectPair {
    /// After both native launches: retain kernel lifetime observations, require
    /// exact production postures, live epoch and persisted public boot identities.
    /// Unsupported installed services continue to refuse admission before this.
    pub fn bind_originals<'a>(
        &self,
        caller: InstalledParticipant<'a>,
        callee: InstalledParticipant<'a>,
    ) -> Result<InstalledObjectPair<'a>> {
        check_original_native(&caller)?;
        check_original_native(&callee)?;
        let ap = caller
            .admitted
            .mailbox_posture()
            .context("caller mailbox not admitted")?;
        let bp = callee
            .admitted
            .mailbox_posture()
            .context("callee mailbox not admitted")?;
        let name_a = &caller.admitted.plan().image.name;
        let name_b = &callee.admitted.plan().image.name;
        ensure!(name_a != name_b, "same original VM name");
        let ad = mvm_core::config::vm_state_dir(name_a);
        let bd = mvm_core::config::vm_state_dir(name_b);
        let epoch = |name: &str| -> Result<ExecutionEpoch> {
            Ok(ExecutionEpoch::new(
                mvm_core::plan::synthesis::current_local_epoch(name)?,
            )?)
        };
        let keys = mvm_core::config::mvm_keys_dir();
        ensure!(
            caller.admitted.plan().mailbox == Some(self.caller)
                && callee.admitted.plan().mailbox == Some(self.callee)
                && caller.admitted.plan().nonce == self.caller_nonce
                && callee.admitted.plan().nonce == self.callee_nonce,
            "original admissions differ from prepared object pair"
        );
        let registration =
            crate::mailbox_process::original_journal::object_registration::Registration::claim(
                &keys,
                (name_a, &ad),
                (name_b, &bd),
            )?;
        let material = self.bind_at(
            &keys,
            BootInput {
                plan: caller.admitted.signed(),
                posture: &ap,
                state: &ad,
                boot: caller.boot,
                current_epoch: epoch(name_a)?,
            },
            BootInput {
                plan: callee.admitted.signed(),
                posture: &bp,
                state: &bd,
                boot: callee.boot,
                current_epoch: epoch(name_b)?,
            },
            super::now_unix_ms(),
        )?;
        check_original_native(&caller)?;
        check_original_native(&callee)?;
        registration.require_originals()?;
        Ok(InstalledObjectPair {
            registration,
            caller,
            callee,
            prepared: self.clone(),
            material,
        })
    }

    fn bind_at(
        &self,
        keys: &Path,
        a: BootInput<'_>,
        b: BootInput<'_>,
        now: i64,
    ) -> Result<PairMaterial> {
        let (_, host) = mvm_core::crypto::ed25519_keypair::load_existing(
            &keys.join(super::SIGNER_SECRET),
            &keys.join(super::SIGNER_PUBLIC),
        )?;
        let signer = crate::audit::host_keypair::host_signer_id();
        // The initial same-installation profile admits host-signed plans only.
        let trust = [(signer.as_str(), &host)];
        let pa = verify_plan(a.plan, &trust)?;
        let pb = verify_plan(b.plan, &trust)?;
        ensure!(
            pa.mailbox == Some(self.caller)
                && pb.mailbox == Some(self.callee)
                && pa.nonce == self.caller_nonce
                && pb.nonce == self.callee_nonce
                && pa.image.name != pb.image.name,
            "original pair plans changed"
        );
        let credentials = &self.credentials;
        let mut policies = [0_u64; 2];
        let mut routes = Vec::with_capacity(2);
        for (idx, (role, plan, grant)) in [(&a, &pa, &self.caller), (&b, &pb, &self.callee)]
            .into_iter()
            .enumerate()
        {
            role.posture.verify(plan, &plan.image.name)?;
            ensure!(
                role.posture.variant() == Variant::Prod
                    && MailboxReaderBootBinding::load(role.state)? == *role.boot,
                "requires original production mailbox boot"
            );
            role.boot.check_plan(plan)?;
            let d = super::derived_keys(keys, &grant.mailbox, grant.epoch)?;
            let template = super::template_for(keys, &d, grant, now)?;
            ensure!(
                template.header.policy_epoch == template.capability.policy_epoch,
                "inconsistent installed policy epoch"
            );
            policies[idx] = template.header.policy_epoch;
            routes.push(template.routing);
        }
        let read_revoked = |dir: &Path| {
            reader_revocations(&revocations_path(dir))
                .map_err(|_| anyhow::anyhow!("current mailbox revocations unavailable"))
        };
        let ar = read_revoked(a.state)?;
        let br = read_revoked(b.state)?;
        let live = PairAuthorityState {
            caller_boot: a.boot.boot,
            callee_boot: b.boot.boot,
            caller_epoch: a.current_epoch,
            callee_epoch: b.current_epoch,
            caller_policy: policies[0],
            callee_policy: policies[1],
            at_caller: &ar,
            at_callee: &br,
        };
        ObjectPairV1::check_originals(
            &OriginalObjectEndpoint {
                plan: a.plan,
                trusted_signers: &trust,
                boot: a.boot,
            },
            &OriginalObjectEndpoint {
                plan: b.plan,
                trusted_signers: &trust,
                boot: b.boot,
            },
            ObjectPairGrants {
                call: &credentials.call,
                reply: &credentials.reply,
            },
            now,
            live,
        )?;
        for (recv, revoked) in [
            (&credentials.receive_at_caller, &ar),
            (&credentials.receive_at_callee, &br),
        ] {
            ensure!(
                (recv.grant.not_before_unix_ms..recv.grant.expires_at_unix_ms).contains(&now)
                    && !revoked.contains(&recv.grant.revocation_id),
                "original Receive expired or revoked"
            );
        }
        let transcript = material_transcript(
            self.stamp,
            a.boot,
            b.boot,
            &credentials.receive_at_caller,
            &credentials.receive_at_callee,
        )?;
        let root = load_private_root(keys)?;
        let fk = super::derive_with(
            root.expose_bytes(),
            b"mvm.object-pair.call.key.v1",
            &self.callee.mailbox,
            self.callee.epoch,
            &transcript,
        );
        let rk = super::derive_with(
            root.expose_bytes(),
            b"mvm.object-pair.reply.key.v1",
            &self.caller.mailbox,
            self.caller.epoch,
            &transcript,
        );
        let pin = original_reader_pin(transcript, &fk, &rk);
        let endpoint = |role: &BootInput<'_>,
                        g: &MailboxGrant,
                        flow: &SignedMailboxCapability,
                        recv: &SignedMailboxCapability,
                        revoked: &[RevocationId],
                        incoming: &[u8; 32],
                        outgoing: &[u8; 32]|
         -> Result<EndpointMaterial> {
            let d = super::derived_keys(keys, &g.mailbox, g.epoch)?;
            let reader = enroll_object_reader(
                role.state,
                g,
                role.boot,
                flow,
                recv,
                &d.authority,
                pin,
                revoked,
                now,
            )?;
            let begin = pa
                .valid_from
                .timestamp_millis()
                .max(pb.valid_from.timestamp_millis())
                .max(credentials.call.grant.not_before_unix_ms)
                .max(credentials.reply.grant.not_before_unix_ms)
                .max(credentials.receive_at_caller.grant.not_before_unix_ms)
                .max(credentials.receive_at_callee.grant.not_before_unix_ms);
            let end = pa
                .valid_until
                .timestamp_millis()
                .min(pb.valid_until.timestamp_millis())
                .min(credentials.call.grant.expires_at_unix_ms)
                .min(credentials.reply.grant.expires_at_unix_ms)
                .min(credentials.receive_at_caller.grant.expires_at_unix_ms)
                .min(credentials.receive_at_callee.grant.expires_at_unix_ms);
            use mvm_core::mailbox::object_pair::role::*;
            let public_role = SignedObjectRoleV1::issue(
                ObjectRoleV1 {
                    role: if g.mailbox == self.caller.mailbox {
                        ObjectParticipantRole::Caller
                    } else {
                        ObjectParticipantRole::Callee
                    },
                    caller: a.boot.clone(),
                    callee: b.boot.clone(),
                    call: credentials.call.clone(),
                    reply: credentials.reply.clone(),
                    not_before_unix_ms: begin,
                    expires_at_unix_ms: end,
                },
                &d.authority,
                now,
            )?;
            let plan = if g.mailbox == self.caller.mailbox {
                &pa
            } else {
                &pb
            };
            let custody = crate::mailbox_custody::RetainedMailboxKeys::for_object_role(
                keys,
                plan,
                role.posture,
                role.boot,
                &public_role,
                now,
            )?;
            Ok(EndpointMaterial {
                custody,
                routing: routes[if g.mailbox == self.caller.mailbox {
                    1
                } else {
                    0
                }]
                .clone(),
                public_role,
                reader,
                sender: d.sender,
                inbound_key: Key::from_bytes(*incoming),
                outbound_key: Key::from_bytes(*outgoing),
            })
        };
        Ok(PairMaterial {
            plan_verifier: host,
            caller: endpoint(
                &a,
                &self.caller,
                &credentials.reply,
                &credentials.receive_at_caller,
                &ar,
                &rk,
                &fk,
            )?,
            callee: endpoint(
                &b,
                &self.callee,
                &credentials.call,
                &credentials.receive_at_callee,
                &br,
                &fk,
                &rk,
            )?,
        })
    }
}

fn load_private_root(keys: &Path) -> Result<Key> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(keys.join(super::ENCRYPTION_ROOT))
        .context("original installation encryption root is required")?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o077 == 0 && m.len() == 32,
        "invalid original encryption root"
    );
    let mut buf = zeroize::Zeroizing::new([0u8; 32]);
    file.read_exact(&mut buf[..])?;
    Ok(Key::from_bytes(*buf))
}

#[cfg(target_os = "linux")]
pub(crate) mod bootstrap;
mod operations;
mod pending;
pub use operations::{OriginalObjectCallLease, SealedObjectTurn};

#[cfg(test)]
mod tests;
