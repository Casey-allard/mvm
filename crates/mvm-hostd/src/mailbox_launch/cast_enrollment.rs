//! Before the original destination VMM boots, project its authenticated
//! reservation and plan into the guest's existing host-signed boot lineage.
use super::cast_pair::InstalledCastParticipant;
use crate::host_signer::keystore::Keystore;
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::{
    mailbox::local::LocalGreeting,
    mailbox_worker::{MailboxWorkerOwner, MailboxWorkerState},
};
use mvm_core::{
    mailbox::{
        OpenContext,
        frame::cast::{CastChannel, route::AddressedCastGrants},
    },
    protocol::{mailbox_worker_control::context_commitment, vm_backend::VerbGrantEnvelope},
};
use sha2::{Digest, Sha256};
use std::time::Instant;

pub struct OriginalCastBoot<'a> {
    pub source: InstalledCastParticipant<'a>,
    pub destination: InstalledCastParticipant<'a>,
    pub source_policy: &'a OpenContext,
    pub destination_policy: &'a OpenContext,
    pub grants: AddressedCastGrants<'a>,
    pub trusted_plan_signers: &'a [(&'a str, &'a VerifyingKey)],
    pub destination_greeting: LocalGreeting,
    pub direction_commitment: [u8; 32],
}

/// One prepared publication for the SDK's still-held destination VM claim.
pub struct PreparedOriginalCastBoot {
    owner: MailboxWorkerOwner,
    plan: [u8; 32],
    prior: VerbGrantEnvelope,
    boot: VerbGrantEnvelope,
}

impl PreparedOriginalCastBoot {
    /// Called inside the original SDK per-name lock, before starting the VMM.
    /// The projection and its signed digest replace one existing file atomically.
    pub fn into_bytes_for_original(
        self,
        destination: &crate::mailbox_process::owned_client::InstalledMailboxClient,
        config: &mvm_core::vm_backend::VmStartConfig,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        ensure!(
            destination.owner() == Some(&self.owner)
                && destination.acquire_request().plan_commitment == self.plan
                && config.name == destination.acquire_request().vm_id
                && config
                    .installed_mailbox_owner
                    .as_ref()
                    .is_some_and(|b| b.owner == self.owner && b.plan_commitment == self.plan)
                && destination.query(deadline)? == MailboxWorkerState::Reserved,
            "original destination lost before boot"
        );
        let current = mvm_runtime::microvm::read_verb_grant_envelope(&config.name)?
            .context("missing original gate")?;
        ensure!(
            serde_json::to_vec(&current)? == serde_json::to_vec(&self.prior)?,
            "original boot sidecar changed"
        );
        let actual = mvm_runtime::microvm::build_activation_environment(config)?;
        ensure!(
            self.boot
                .cast_delivery_v1
                .as_ref()
                .is_some_and(|p| Some(p.mount_commitment) == actual.cast_mount_commitment().ok()),
            "original mounts changed"
        );
        let bytes = serde_json::to_vec(&self.boot)?;
        ensure!(bytes.len() <= 16384, "oversized Cast boot grant");
        Ok(bytes)
    }
}

fn original(
    participant: &InstalledCastParticipant<'_>,
    destination: bool,
    deadline: Instant,
) -> Result<MailboxWorkerOwner> {
    let request = participant.worker.acquire_request();
    let plan = participant.plan.plan();
    let owner = participant
        .worker
        .owner()
        .context("original Cast reservation missing")?;
    ensure!(
        request.vm_id == plan.workload.0
            && request.workload_id == plan.workload.0
            && request.tenant == plan.tenant.0
            && plan.mailbox == Some(request.mailbox_grant)
            && format!("sha256:{}", hex::encode(request.plan_commitment))
                == participant.plan.plan_id().0
            && context_commitment(request)? == owner.context_commitment,
        "original Cast reservation differs from signed plan"
    );
    let state = participant.worker.query(deadline)?;
    ensure!(
        state == MailboxWorkerState::Reserved
            || (!destination && state == MailboxWorkerState::Serving),
        "Cast reservation is not in its eligible original state"
    );
    Ok(owner.clone())
}

impl OriginalCastBoot<'_> {
    /// The dev controller supplies the pinned sidecar grant, checked boot config
    /// and original direction. No bearer lease or encryption key enters the guest.
    pub fn prepare(
        &self,
        signer: &Keystore,
        original_grant: &VerbGrantEnvelope,
        config: &mvm_core::vm_backend::VmStartConfig,
        deadline: Instant,
    ) -> Result<PreparedOriginalCastBoot> {
        let left = original(&self.source, false, deadline)?;
        let right = original(&self.destination, true, deadline)?;
        ensure!(
            left.daemon_boot_nonce == right.daemon_boot_nonce
                && left.lease != right.lease
                && left.context_commitment != right.context_commitment,
            "expected two distinct original Cast leases of one installed coordinator"
        );
        let dst = self.destination.plan.plan();
        ensure!(
            config.name == dst.workload.0
                && config
                    .plan_json
                    .as_deref()
                    .and_then(|v| serde_json::from_str::<
                        mvm_core::plan::signing::SignedExecutionPlan,
                    >(v)
                    .ok())
                    .is_some_and(|s| {
                        let p = &self.destination.plan.signed().0;
                        s.0.payload == p.payload
                            && s.0.signer_id == p.signer_id
                            && s.0.signature == p.signature
                    }),
            "selected VMM differs from admitted destination"
        );
        let key = VerifyingKey::from_bytes(
            &signer
                .pub_key()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid host signer"))?,
        )?;
        ensure!(
            original_grant.pubkey_hex == hex::encode(key.as_bytes())
                && original_grant.plan_nonce_hex == dst.nonce.as_hex()
                && original_grant.predecessor_session_id.is_none()
                && original_grant.predecessor_plan_nonce_hex.is_none()
                && original_grant.grant.cast_delivery_v1.is_none()
                && original_grant.cast_delivery_v1.is_none(),
            "expected an original unbound boot grant"
        );
        let now = chrono::Utc::now();
        original_grant
            .grant
            .verify(&key, &config.name, &dst.nonce, now)?;
        let hash = mvm_core::crypto::image_verify::sha256_file_cached(std::path::Path::new(
            &config.rootfs_path,
        ))?;
        ensure!(
            hash == dst.image.sha256,
            "selected root image differs from admitted workload"
        );
        let activation = mvm_runtime::microvm::build_activation_environment(config)?;
        let root = activation
            .rootfs
            .roothash
            .as_deref()
            .map(|v| -> Result<[u8; 32]> {
                Ok(hex::decode(v)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid verity root"))?)
            })
            .transpose()?;
        let mut origin = self.source_policy.clone();
        let mut target = self.destination_policy.clone();
        origin.now_unix_ms = now.timestamp_millis();
        target.now_unix_ms = now.timestamp_millis();
        let channel = CastChannel::from_signed_pair(
            self.source.plan.signed(),
            self.destination.plan.signed(),
            self.trusted_plan_signers,
            (self.source.plan.plan_id(), self.destination.plan.plan_id()),
            self.destination_greeting,
            origin.expected_sender,
            target.expected_recipient,
            now.timestamp_millis(),
        )?;
        channel.authorize_addressed(self.grants, &origin, &target)?;
        let mut hash_owner = Sha256::new();
        hash_owner.update(b"mvm-cast-guest-original-owner-v1\0");
        hash_owner.update(right.daemon_boot_nonce);
        hash_owner.update(right.generation.to_be_bytes());
        hash_owner.update(right.lease);
        hash_owner.update(right.context_commitment);
        let mut projection = channel.guest_enrollment(
            self.source.worker.acquire_request().plan_commitment,
            self.destination.worker.acquire_request().plan_commitment,
            hash_owner.finalize().into(),
            self.direction_commitment,
            hex::decode(hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid image digest"))?,
            activation.cast_mount_commitment()?,
            root,
            config.name.clone(),
        )?;
        for grant in [
            self.grants.source_scope,
            self.grants.send,
            self.grants.receive,
        ] {
            projection.narrow_validity(
                grant.grant.not_before_unix_ms,
                grant.grant.expires_at_unix_ms,
            )?;
        }
        projection.narrow_validity(i64::MIN, original_grant.grant.not_after.timestamp_millis())?;
        let mut boot = original_grant.clone();
        boot.grant.cast_delivery_v1 = Some(projection.commitment()?);
        boot.grant.sig = signer.sign(&boot.grant.signing_bytes()).signature;
        boot.cast_delivery_v1 = Some(projection);
        Ok(PreparedOriginalCastBoot {
            owner: right,
            plan: self.destination.worker.acquire_request().plan_commitment,
            prior: original_grant.clone(),
            boot,
        })
    }
}
