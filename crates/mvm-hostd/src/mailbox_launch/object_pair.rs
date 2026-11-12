//! Same-installation provisioning for signed object Call/Reply. Registration
//! verifies operator inputs without launching either helper or allocating keys.
use anyhow::{Context, Result, ensure};

use mvm_contract::protocol::mailbox::*;
use mvm_core::mailbox::{object_pair::ObjectPairGrants, verify_capability_signature};
use mvm_core::plan::Nonce;
use std::path::Path;

/// Four original independent signed credentials. Neither transport direction
/// nor the original journal receipt is authority to read a mailbox.
#[derive(Clone)]
pub struct ObjectPairCredentials {
    pub call: SignedMailboxCapability,
    pub reply: SignedMailboxCapability,
    pub receive_at_caller: SignedMailboxCapability,
    pub receive_at_callee: SignedMailboxCapability,
}

pub struct PreparedObjectPair {
    credentials: ObjectPairCredentials,
    stamp: [u8; 32],
    caller: MailboxGrant,
    callee: MailboxGrant,
    caller_nonce: Nonce,
    callee_nonce: Nonce,
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
    pub admitted: &'a AdmittedPlan,
    pub backend: &'a mvm_runtime::AnyBackend,
    pub boot: &'a MailboxReaderBootBinding,
}

struct HeldVmm {
    id: mvm_vmm::host::network_endpoint_spawn::EndpointPid,
    watch: mvm_vmm::host::process_exit::ProcessExitObserver,
}
impl HeldVmm {
    fn capture(participant: &InstalledParticipant<'_>) -> Result<Self> {
        let name = &participant.admitted.plan().image.name;
        mvm_core::naming::validate_vm_name(name)?;
        let pid = participant
            .backend
            .host_process_id(&mvm_contract::protocol::vm_backend::VmId(name.clone()))?
            .context("missing original VMM")?;
        let id = mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(pid);
        ensure!(id.is_live_and_ours(), "missing original VMM identity");
        let this = Self {
            id,
            watch: mvm_vmm::host::process_exit::ProcessExitObserver::arm(id.pid)?,
        };
        this.check()?;
        Ok(this)
    }
    fn check(&self) -> Result<()> {
        ensure!(
            self.id.is_live_and_ours()
                && self.watch.wait_event(std::time::Instant::now())?
                    == mvm_vmm::host::process_exit::ProcessExitWait::TimedOut,
            "original VMM no longer live"
        );
        Ok(())
    }
}

struct BootInput<'a> {
    plan: &'a SignedExecutionPlan,
    posture: &'a MailboxLaunchPosture,
    state: &'a Path,
    boot: &'a MailboxReaderBootBinding,
    current_epoch: ExecutionEpoch,
}

pub struct InstalledObjectPair {
    _caller: HeldVmm,
    _callee: HeldVmm,
    material: PairMaterial,
}
struct PairMaterial {
    caller: EndpointMaterial,
    callee: EndpointMaterial,
}
pub(crate) struct EndpointMaterial {
    pub(crate) reader: GuestReaderAuthority,
    pub(crate) inbound_key: Key,
    pub(crate) outbound_key: Key,
    pub(crate) sender: ed25519_dalek::SigningKey,
}
impl InstalledObjectPair {
    /// Only public verifiers and signed reader proofs are observable by the SDK.
    pub fn original_readers(
        &self,
    ) -> Result<(
        &SignedMailboxGuestReaderEnrollment,
        &SignedMailboxGuestReaderEnrollment,
    )> {
        self._caller.check()?;
        self._callee.check()?;
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
    pub fn bind_originals(
        &self,
        caller: InstalledParticipant<'_>,
        callee: InstalledParticipant<'_>,
    ) -> Result<InstalledObjectPair> {
        let (a, b) = (HeldVmm::capture(&caller)?, HeldVmm::capture(&callee)?);
        ensure!(a.id.pid != b.id.pid, "same original VMM");
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
        let material = self.bind_at(
            &mvm_core::config::mvm_keys_dir(),
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
        a.check()?;
        b.check()?;
        Ok(InstalledObjectPair {
            _caller: a,
            _callee: b,
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
        let mut hash = Sha256::new();
        hash.update(b"mvm.object-pair.original-material.v1\0");
        hash.update(self.stamp);
        hash.update(a.boot.boot.as_bytes());
        hash.update(b.boot.boot.as_bytes());
        // The plan IDs are content-addressed. Hash their canonical representation
        // to fixed widths before appending to this purpose-separated transcript.
        for p in [&pa, &pb] {
            hash.update(Sha256::digest(p.plan_id.0.as_bytes()));
        }
        for r in [
            &credentials.receive_at_caller,
            &credentials.receive_at_callee,
        ] {
            hash.update(mvm_core::mailbox::outbound::journal_capability_digest(r)?);
        }
        let transcript: [u8; 32] = hash.finalize().into();
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
        let mut pin = Sha256::new();
        pin.update(b"mvm.object-pair.original-reader.keys.v1\0");
        pin.update(transcript);
        pin.update(Sha256::digest(&fk[..]));
        pin.update(Sha256::digest(&rk[..]));
        let pin: [u8; 32] = pin.finalize().into();
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
            Ok(EndpointMaterial {
                reader,
                sender: d.sender,
                inbound_key: Key::from_bytes(*incoming),
                outbound_key: Key::from_bytes(*outgoing),
            })
        };
        Ok(PairMaterial {
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

#[cfg(test)]
mod tests;
