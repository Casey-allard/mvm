//! One signed control turn for an explicitly prepared immutable role pair.
//! The original broker revalidates public evidence. No private config or wrapped
//! key enters this record; only the endpoint helper holds its wrapping key.
use super::super::{MapParticipant, map_original_pair};
use super::*;
use crate::broker::mailbox_workers::MailboxWorkers;
use mvm_core::plan::{
    signing::{SignedExecutionPlan, verify_plan},
    verify_plan_id,
};
use mvm_core::protocol::mailbox_worker_control::{MailboxWorkerOperation, MailboxWorkerRequest};
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCastControl {
    fields: DirectionFields,
    plans: [SignedExecutionPlan; 2],
    scopes: [SignedMailboxCapability; 3],
    policies: [destination::Policy; 2],
}
impl PreparedDevelopment {
    /// Copy the public data while the issuer still holds the prepared roles.
    pub fn public_control(&self) -> Result<PublicCastControl> {
        let projection = self
            .destination
            .setup
            .destination
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("immutable original Cast preparation required"))?;
        Ok(projection.public_control())
    }
}
impl PublicCastControl {
    pub(super) fn new(
        fields: DirectionFields,
        plans: [SignedExecutionPlan; 2],
        scopes: [SignedMailboxCapability; 3],
        policies: [destination::Policy; 2],
    ) -> Self {
        Self {
            fields,
            plans,
            scopes,
            policies,
        }
    }
    pub(crate) fn commitment(&self) -> Result<[u8; 32]> {
        commit(b"mvm-development-directional-aes-256-gcm-v1", &self.fields)
    }
    pub(crate) fn binds(&self, a: &MailboxWorkerOwner, b: &MailboxWorkerOwner) -> Result<()> {
        self.fields.source.original(a)?;
        self.fields.destination.original(b)?;
        ensure!(
            self.fields.immutable_policy.is_some(),
            "mutable Cast control unavailable"
        );
        Ok(())
    }
}
pub(crate) fn execute(
    workers: &MailboxWorkers,
    request: &MailboxWorkerRequest,
    host_anchor: &VerifyingKey,
    home: &Path,
    deadline: Instant,
) -> Result<()> {
    let MailboxWorkerOperation::ForwardCastV1 {
        owner,
        destination_vm,
        destination_owner,
        projection,
        ..
    } = &request.operation
    else {
        anyhow::bail!("expected addressed Cast control")
    };
    use mvm_contract::protocol::mailbox::local_service::MailboxLocalServiceGrant;
    ensure!(
        request.backend == MailboxWorkerBackend::Firecracker
            && request.mailbox_grant.local_service
                == Some(MailboxLocalServiceGrant::original_cast_v1()),
        "named Firecracker Cast profile required"
    );
    let p: PublicCastControl = serde_json::from_str(projection)?;
    p.binds(owner, destination_owner)?;
    let direction = DevelopmentDirection {
        commitment: p.commitment()?,
        fields: p.fields.clone(),
    };
    let grants = AddressedCastGrants {
        source_scope: &p.scopes[0],
        send: &p.scopes[1],
        receive: &p.scopes[2],
    };
    ensure!(
        credentials(grants)? == direction.fields.credentials,
        "original Cast scopes changed"
    );
    // This development role admits plans signed by the original host signer.
    // Operator-pinned external plan signers require their own enrolled profile.
    let host_id = crate::audit::host_keypair::host_signer_id();
    let anchors = [(host_id.as_str(), host_anchor)];
    let left = verify_plan(&p.plans[0], &anchors)?;
    let right = verify_plan(&p.plans[1], &anchors)?;
    verify_plan_id(&left)?;
    verify_plan_id(&right)?;
    ensure!(
        right.mailbox.as_ref().and_then(|g| g.local_service)
            == Some(MailboxLocalServiceGrant::original_cast_v1()),
        "destination plan lacks compact original Cast grant"
    );
    ensure!(
        left.plan_id == direction.fields.plans.0
            && right.plan_id == direction.fields.plans.1
            && left.workload.0 == request.vm_id
            && right.workload.0 == *destination_vm,
        "signed control changed original plans"
    );
    let original = || -> Result<(OpenContext, OpenContext)> {
        let now = i64::try_from(workers.now_unix_ms()?)?;
        direction.live(now)?;
        let (a, b) = (p.policies[0].current(now), p.policies[1].current(now));
        ensure!(
            Some(destination::policy_digest(&a, &b)?) == direction.fields.immutable_policy,
            "original policies changed"
        );
        Ok((a, b))
    };
    let (a, b) = original()?;
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(match request.backend {
        MailboxWorkerBackend::Firecracker => "firecracker",
        MailboxWorkerBackend::Hvf => "hvf",
    });
    let pair = map_original_pair(
        workers,
        MapParticipant {
            plan: &left,
            signed: &p.plans[0],
            current: &a,
            owner,
        },
        MapParticipant {
            plan: &right,
            signed: &p.plans[1],
            current: &b,
            owner: destination_owner,
        },
        &backend,
        &anchors,
        direction.destination_greeting(),
        grants,
        home,
    )?;
    direction.matches(&pair, grants, &a, &b)?;
    workers.claim_original_cast_turn(
        (&request.vm_id, owner),
        (destination_vm, destination_owner),
        direction.commitment(),
        request.request_nonce,
    )?;
    pair.forward_one_from_original_source(workers, &direction, grants, deadline, original)??;
    Ok(())
}
