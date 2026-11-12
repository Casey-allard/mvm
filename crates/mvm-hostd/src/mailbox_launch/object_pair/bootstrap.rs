//! Private, original owner to per-VM process configuration. Only the public
//! role and enrollment are exposed by the guest reader. The two Linux pidfds
//! travel separately on the original child's anonymous Unix control channel.
use super::*;
use mvm_core::mailbox::journal::{HistoryKeyCustody, HistoryKeyRef};
use mvm_core::mailbox::object_pair::role::{ObjectParticipantRole, SignedObjectRoleV1};
use mvm_core::vm_backend::{BackendKind, HostDialRoute};
use mvm_runtime::AnyBackend;
use serde::{Deserialize, Serialize};
use std::os::fd::BorrowedFd;
use std::path::PathBuf;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalVmmId {
    pub(crate) pid: u32,
    pub(crate) birth: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjectWorkerBootstrapV1 {
    pub(crate) role: SignedObjectRoleV1,
    pub(crate) caller_plan: SignedExecutionPlan,
    pub(crate) callee_plan: SignedExecutionPlan,
    pub(crate) plan_verifier: [u8; 32],
    pub(crate) caller_receive: SignedMailboxCapability,
    pub(crate) callee_receive: SignedMailboxCapability,
    pub(crate) reader_enrollment: SignedMailboxGuestReaderEnrollment,
    pub(crate) caller_vmm: OriginalVmmId,
    pub(crate) callee_vmm: OriginalVmmId,
    pub(crate) home: PathBuf,
    pub(crate) route: HostDialRoute,
    pub(crate) routing: MailboxRoutingFrame,
    pub(crate) local_journal: PathBuf,
    pub(crate) local_anchor: PathBuf,
    pub(crate) local_intents: PathBuf,
    pub(crate) history_ref: HistoryKeyRef,
    pub(crate) secrets: ObjectWorkerSecrets,
}

// No Debug or Clone: never format the private handoff; decoded buffers clear
// their own secret material. The peer's signer and host signing key are absent.
#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjectWorkerSecrets {
    pub(crate) local_sender: [u8; 32],
    pub(crate) local_authority: [u8; 32],
    pub(crate) inbound: [u8; 32],
    pub(crate) outbound: [u8; 32],
    pub(crate) history: [u8; 32],
    pub(crate) anchor: [u8; 32],
}

impl InstalledParticipant<'_> {
    fn worker_pidfd(&self) -> Result<(OriginalVmmId, BorrowedFd<'_>)> {
        let OriginalNative::Firecracker(native) = self.original else {
            anyhow::bail!("object worker pidfd handoff requires original Linux Firecracker");
        };
        let (pid, fd) = native.original_peer()?;
        let generation = mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(pid);
        let birth = generation
            .started
            .context("original VMM birth unavailable")?;
        ensure!(
            generation.is_live_and_ours(),
            "original VMM changed during capture"
        );
        native.require_live()?;
        Ok((OriginalVmmId { pid, birth }, fd))
    }
}

impl InstalledObjectPair<'_> {
    pub(crate) fn original_worker_bootstrap(
        &self,
        local_role: ObjectParticipantRole,
        backend: &AnyBackend,
    ) -> Result<(ObjectWorkerBootstrapV1, [BorrowedFd<'_>; 2])> {
        self.check_current()?;
        ensure!(
            backend.kind() == BackendKind::Firecracker,
            "wrong mailbox backend"
        );
        let (a, afd) = self.caller.worker_pidfd()?;
        let (b, bfd) = self.callee.worker_pidfd()?;
        ensure!(a.pid != b.pid, "two object endpoints selected the same VMM");
        let (source, local) = match local_role {
            ObjectParticipantRole::Caller => (&self.caller, &self.material.caller),
            ObjectParticipantRole::Callee => (&self.callee, &self.material.callee),
        };
        let state = mvm_core::config::vm_state_dir(&source.admitted.plan().image.name);
        let route = backend
            .host_dial_route(&state, MAILBOX_PORT)
            .context("no admitted guest mailbox route")?;
        let config = self.material.local_bootstrap(
            local,
            &self.prepared.credentials,
            [self.caller.admitted.signed(), self.callee.admitted.signed()],
            [a, b],
            route,
        )?;
        self.check_current()?;
        Ok((config, [afd, bfd]))
    }
}

impl PairMaterial {
    pub(super) fn local_bootstrap(
        &self,
        local: &InstalledEndpointMaterial,
        creds: &ObjectPairCredentials,
        plans: [&SignedExecutionPlan; 2],
        [a, b]: [OriginalVmmId; 2],
        route: HostDialRoute,
    ) -> Result<ObjectWorkerBootstrapV1> {
        let keys = mvm_core::config::mvm_keys_dir();
        let paths = local.custody.storage_paths(&keys)?;
        let local_keys = super::super::derived_keys(
            &keys,
            &local.reader.grant.mailbox,
            local.reader.grant.epoch,
        )?;
        ensure!(
            local_keys.authority.verifying_key().to_bytes() == local.reader.grant.authority_key
                && local_keys.sender.verifying_key() == local.sender.verifying_key(),
            "local worker signer changed"
        );
        let history_ref = local.custody.history_reference();
        let history = local.custody.load_existing(&history_ref)?;
        let config = ObjectWorkerBootstrapV1 {
            role: local.public_role.clone(),
            caller_plan: plans[0].clone(),
            callee_plan: plans[1].clone(),
            plan_verifier: self.plan_verifier.to_bytes(),
            caller_receive: creds.receive_at_caller.clone(),
            callee_receive: creds.receive_at_callee.clone(),
            reader_enrollment: local.reader.enrollment.clone(),
            caller_vmm: a,
            callee_vmm: b,
            home: mvm_core::config::mvm_home_strict()?,
            route,
            routing: local.routing.clone(),
            local_journal: paths.journal,
            local_anchor: paths.anchor,
            local_intents: paths.source_intents,
            history_ref,
            secrets: ObjectWorkerSecrets {
                local_sender: local.sender.to_bytes(),
                local_authority: local_keys.authority.to_bytes(),
                inbound: *local.inbound_key.expose_bytes(),
                outbound: *local.outbound_key.expose_bytes(),
                history: *history.expose_bytes(),
                anchor: local.custody.anchor_key(),
            },
        };
        Ok(config)
    }
}

pub(crate) struct WorkerAuthority<'a> {
    pub(crate) pair: ObjectPairV1<'a>,
    pub(crate) local_plan: mvm_core::plan::ExecutionPlan,
    pub(crate) local_state: PathBuf,
    pub(crate) peer_state: PathBuf,
    pub(crate) now: i64,
    caller_revoked: Vec<RevocationId>,
    callee_revoked: Vec<RevocationId>,
    role: &'a SignedObjectRoleV1,
}
impl WorkerAuthority<'_> {
    pub(crate) fn state(&self) -> PairAuthorityState<'_> {
        let r = &self.role.role;
        PairAuthorityState {
            caller_boot: r.caller.boot,
            callee_boot: r.callee.boot,
            caller_epoch: r.caller.execution_epoch,
            callee_epoch: r.callee.execution_epoch,
            caller_policy: r.reply.grant.policy_epoch,
            callee_policy: r.call.grant.policy_epoch,
            at_caller: &self.caller_revoked,
            at_callee: &self.callee_revoked,
        }
    }
}

fn read_public(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, Read};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    mvm_core::private_fs::require_current_owner(&m)?;
    if !m.is_file() || m.nlink() != 1 || m.mode() & 0o022 != 0 || m.len() > limit as u64 {
        return Err(Error::other("invalid installed public metadata"));
    }
    let mut data = Vec::new();
    f.take(limit as u64 + 1).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(Error::other("oversized public metadata"));
    }
    Ok(data)
}

impl ObjectWorkerBootstrapV1 {
    /// Validate the original public admission and both retained reader records
    /// on the worker's private endpoint. The caller separately holds/checks
    /// the two transferred original VMM pidfds before service and on each use.
    pub(crate) fn validate_current(&self) -> Result<WorkerAuthority<'_>> {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use mvm_core::mailbox::reader::verify_guest_reader_enrollment;
        ensure!(
            self.home.is_absolute(),
            "worker installation must be absolute"
        );
        let keys = mvm_core::config::mvm_keys_dir_at(&self.home);
        ensure!(
            read_public(&keys.join(super::super::SIGNER_PUBLIC), 32)? == self.plan_verifier,
            "installed plan verifier changed"
        );
        let signer = VerifyingKey::from_bytes(&self.plan_verifier)?;
        let name = self.caller_plan.0.signer_id.as_str();
        ensure!(
            name == self.callee_plan.0.signer_id,
            "plans have different original signer"
        );
        let trust = [(name, &signer)];
        let a = verify_plan(&self.caller_plan, &trust)?;
        let b = verify_plan(&self.callee_plan, &trust)?;
        let role = &self.role.role;
        let ad = mvm_core::config::vm_state_dir_at(&self.home, &a.image.name);
        let bd = mvm_core::config::vm_state_dir_at(&self.home, &b.image.name);
        let ledger = mvm_core::host_interface::workload::WorkloadLedger::load_at(&self.home)?;
        let template = match read_public(&keys.join(super::super::TEMPLATE_FILE), 64 * 1024) {
            Ok(body) => {
                let t: super::super::MailboxTemplate = serde_json::from_slice(&body)?;
                ensure!(
                    t.header.policy_epoch == t.capability.policy_epoch,
                    "inconsistent installed policy epoch"
                );
                t.header.policy_epoch
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 1,
            Err(e) => return Err(e.into()),
        };
        let stamp = role
            .local()
            .durable_object_pair_sha256_v1
            .context("missing pair selection")?;
        let transcript = material_transcript(
            stamp,
            &role.caller,
            &role.callee,
            &self.caller_receive,
            &self.callee_receive,
        )?;
        let (fk, rk) = match role.role {
            ObjectParticipantRole::Caller => (&self.secrets.outbound, &self.secrets.inbound),
            ObjectParticipantRole::Callee => (&self.secrets.inbound, &self.secrets.outbound),
        };
        let pin = original_reader_pin(transcript, fk, rk);
        let read_revocations = |state: &Path| {
            reader_revocations(&revocations_path(state))
                .map_err(|_| anyhow::anyhow!("current original revocations unavailable"))
        };
        let ar = read_revocations(&ad)?;
        let br = read_revocations(&bd)?;
        let mut readers = Vec::with_capacity(2);
        for (plan, state, boot, incoming, receive, revoked) in [
            (
                &a,
                &ad,
                &role.caller,
                &role.reply,
                &self.caller_receive,
                &ar,
            ),
            (&b, &bd, &role.callee, &role.call, &self.callee_receive, &br),
        ] {
            mvm_core::naming::validate_vm_name(&plan.image.name)?;
            ensure!(
                crate::mailbox_process::load_admitted_plan(state)? == *plan
                    && MailboxReaderBootBinding::load(state)? == *boot
                    && !ledger.entry(&plan.image.name).quarantined
                    && ledger.entry(&plan.image.name).epoch.0 == boot.execution_epoch.get()
                    && incoming.grant.policy_epoch == template
                    && !revoked.contains(&incoming.grant.revocation_id),
                "original installed plan/boot/epoch or direction changed"
            );
            let g = plan.mailbox.context("missing admitted mailbox")?;
            let enrolled = crate::mailbox_process::reader::check_object_worker_record(
                state, boot, incoming, receive, pin,
            )?;
            readers.push((g, plan, boot, receive, revoked, enrolled));
        }
        // Sample once after loading both originals; the exact instant also
        // governs the later journal admission and pending-Call window.
        let now = super::super::now_unix_ms();
        self.role.verify(role.local(), now)?;
        for (g, plan, boot, receive, revoked, enrolled) in readers {
            let scope = MailboxGuestReaderScope {
                plan: &g,
                plan_id: &plan.plan_id,
                plan_nonce: &plan.nonce,
                receive: &receive.grant,
                current_boot: boot.boot,
                current_session: enrolled.enrollment.consumer_session,
                now_unix_ms: now,
            };
            verify_guest_reader_enrollment(
                &enrolled,
                receive,
                &scope,
                &VerifyingKey::from_bytes(&boot.authority_key)?,
                revoked,
            )?;
            if boot == role.local() {
                ensure!(
                    enrolled == self.reader_enrollment,
                    "different local reader enrollment"
                );
            }
        }
        let state = PairAuthorityState {
            caller_boot: role.caller.boot,
            callee_boot: role.callee.boot,
            caller_epoch: role.caller.execution_epoch,
            callee_epoch: role.callee.execution_epoch,
            caller_policy: template,
            callee_policy: template,
            at_caller: &ar,
            at_callee: &br,
        };
        let pair = ObjectPairV1::check_originals(
            &OriginalObjectEndpoint {
                plan: &self.caller_plan,
                trusted_signers: &trust,
                boot: &role.caller,
            },
            &OriginalObjectEndpoint {
                plan: &self.callee_plan,
                trusted_signers: &trust,
                boot: &role.callee,
            },
            ObjectPairGrants {
                call: &role.call,
                reply: &role.reply,
            },
            now,
            state,
        )?;
        let (local_plan, local_state, peer_state, incoming) = match role.role {
            ObjectParticipantRole::Caller => (a, ad, bd, &role.reply),
            ObjectParticipantRole::Callee => (b, bd, ad, &role.call),
        };
        let address = incoming.grant.address;
        crate::mailbox_custody::RetainedMailboxKeys::verify_object_worker_storage(
            &keys,
            &local_plan,
            address,
            &signer,
            &self.history_ref,
            &self.secrets.anchor,
        )?;
        let paths = crate::mailbox_custody::RetainedMailboxKeys::object_storage_paths(
            &keys,
            &local_plan,
            address,
        )?;
        ensure!(
            self.local_journal == paths.journal
                && self.local_anchor == paths.anchor
                && self.local_intents == paths.source_intents
                && self.route
                    == HostDialRoute::Mux(PathBuf::from(mvm_agentd::vsock::vsock_uds_path(
                        &local_state.to_string_lossy()
                    )))
                && self.history_ref.address() == address
                && self.history_ref.execution_epoch() == role.local().execution_epoch
                && self.history_ref.key_id()
                    == &<[u8; 32]>::from(Sha256::digest(self.secrets.history))
                && SigningKey::from_bytes(&self.secrets.local_authority)
                    .verifying_key()
                    .to_bytes()
                    == role.local().authority_key
                && SigningKey::from_bytes(&self.secrets.local_sender)
                    .verifying_key()
                    .as_bytes()
                    == role.outbound().grant.subject.as_bytes(),
            "role-local custody, guest route or signer changed"
        );
        Ok(WorkerAuthority {
            pair,
            local_plan,
            local_state,
            peer_state,
            now,
            caller_revoked: ar,
            callee_revoked: br,
            role: &self.role,
        })
    }
}

impl ObjectWorkerBootstrapV1 {
    /// Role-local source/destination material. The remote receipt signer and
    /// host private plan signer are never part of this worker handoff.
    pub(crate) fn endpoint_material(&self) -> Result<EndpointMaterial> {
        let a = self.validate_current()?;
        let role = &self.role.role;
        let recv = match role.role {
            ObjectParticipantRole::Caller => &self.caller_receive,
            ObjectParticipantRole::Callee => &self.callee_receive,
        };
        Ok(EndpointMaterial {
            routing: self.routing.clone(),
            public_role: self.role.clone(),
            sender: ed25519_dalek::SigningKey::from_bytes(&self.secrets.local_sender),
            inbound_key: Key::from_bytes(self.secrets.inbound),
            outbound_key: Key::from_bytes(self.secrets.outbound),
            reader: GuestReaderAuthority {
                grant: a.local_plan.mailbox.context("original grant missing")?,
                boot: role.local().clone(),
                capability: recv.clone(),
                enrollment: self.reader_enrollment.clone(),
                revocations_path: revocations_path(&a.local_state),
            },
        })
    }
}

#[path = "worker_journal.rs"]
mod journal;
