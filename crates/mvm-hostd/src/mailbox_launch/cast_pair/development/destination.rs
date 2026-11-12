//! Original B's private enrollment projection. The public relay never supplies
//! any trust key, policy, direction, or role configuration to this decoder.
use super::*;
use mvm_contract::protocol::mailbox::{ContentType, RevocationId};
use mvm_core::plan::{PlanId, signing::SignedExecutionPlan};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    tenant: mvm_contract::protocol::mailbox::TenantId,
    domain: mvm_contract::protocol::mailbox::AuthorizationDomainId,
    mailbox: mvm_contract::protocol::mailbox::MailboxId,
    sender: PrincipalId,
    recipient: PrincipalId,
    actor: PrincipalId,
    issuer: PrincipalId,
    epoch: mvm_contract::protocol::mailbox::ExecutionEpoch,
    policy_epoch: u64,
    accepted: Vec<ContentType>,
    revoked: Vec<RevocationId>,
}
impl Policy {
    fn from_live(p: &OpenContext) -> Result<Self> {
        ensure!(
            p.required_operation == MailboxOperation::Send
                && p.accepted_content_types.len() <= 4
                && p.revoked_capabilities.len() <= 32,
            "unsupported immutable policy"
        );
        Ok(Self {
            tenant: p.expected_tenant,
            domain: p.expected_authorization_domain,
            mailbox: p.expected_mailbox,
            sender: p.expected_sender,
            recipient: p.expected_recipient,
            actor: p.acting_principal,
            issuer: p.expected_capability_issuer,
            epoch: p.current_execution_epoch,
            policy_epoch: p.current_policy_epoch,
            accepted: p.accepted_content_types.clone(),
            revoked: p.revoked_capabilities.clone(),
        })
    }
    fn current(&self, now: i64) -> OpenContext {
        OpenContext {
            expected_tenant: self.tenant,
            expected_authorization_domain: self.domain,
            expected_mailbox: self.mailbox,
            expected_sender: self.sender,
            expected_recipient: self.recipient,
            acting_principal: self.actor,
            expected_capability_issuer: self.issuer,
            current_execution_epoch: self.epoch,
            current_policy_epoch: self.policy_epoch,
            accepted_content_types: self.accepted.clone(),
            revoked_capabilities: self.revoked.clone(),
            now_unix_ms: now,
            required_operation: MailboxOperation::Send,
        }
    }
}
pub(super) fn policy_digest(a: &OpenContext, b: &OpenContext) -> Result<[u8; 32]> {
    commit(
        b"mvm-dev-fixed-original-cast-policy-v1",
        &[Policy::from_live(a)?, Policy::from_live(b)?],
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateDestination {
    fields: DirectionFields,
    capsule: Vec<u8>,
    plans: [SignedExecutionPlan; 2],
    authorities: [(String, [u8; 32]); 2],
    scopes: [SignedMailboxCapability; 3],
    policies: [Policy; 2],
}
impl PrivateDestination {
    pub(super) fn for_source(&self, capsule: &Capsule) -> Self {
        let mut source = self.clone();
        source.capsule = capsule.0.to_vec();
        source
    }

    pub(super) fn new(
        delivery: &DirectionDelivery,
        a: &SignedExecutionPlan,
        b: &SignedExecutionPlan,
        signers: &[(&str, &VerifyingKey)],
        grants: AddressedCastGrants<'_>,
        source: &OpenContext,
        dest: &OpenContext,
    ) -> Result<Self> {
        fn anchor(
            p: &SignedExecutionPlan,
            signers: &[(&str, &VerifyingKey)],
        ) -> Result<(String, [u8; 32])> {
            ensure!(
                p.0.signer_id.len() <= 128
                    && p.0.signature.len() == 64
                    && p.0.payload.len() <= 16 * 1024,
                "oversized private plan"
            );
            let mut keys = signers.iter().filter(|(name, _)| *name == p.0.signer_id);
            let (_, k) = keys
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing original plan signer"))?;
            ensure!(keys.next().is_none(), "ambiguous plan signer");
            Ok((p.0.signer_id.clone(), k.to_bytes()))
        }
        ensure!(
            delivery.direction.fields.immutable_policy == Some(policy_digest(source, dest)?),
            "original policy digest mismatch"
        );
        Ok(Self {
            fields: delivery.direction.fields.clone(),
            capsule: delivery.destination.0.to_vec(),
            plans: [a.clone(), b.clone()],
            authorities: [anchor(a, signers)?, anchor(b, signers)?],
            scopes: [
                grants.source_scope.clone(),
                grants.send.clone(),
                grants.receive.clone(),
            ],
            policies: [Policy::from_live(source)?, Policy::from_live(dest)?],
        })
    }
}
pub(crate) struct DestinationRole {
    pub(crate) direction: DevelopmentDirection,
    pub(crate) channel: CastChannel,
    creds: [SignedMailboxCapability; 3],
    policies: [Policy; 2],
}
impl DestinationRole {
    pub(crate) fn source_for<'a>(&'a self, key: &'a InstalledDirection) -> VerifiedSourceRole<'a> {
        VerifiedSourceRole {
            channel: &self.channel,
            grants: self.grants(),
            direction: &self.direction,
            key,
        }
    }

    pub(crate) fn grants(&self) -> AddressedCastGrants<'_> {
        AddressedCastGrants {
            source_scope: &self.creds[0],
            send: &self.creds[1],
            receive: &self.creds[2],
        }
    }
    /// No in-place policy change is authorized in this foreground profile.
    /// A revoked generation has to lose the original FD3 before its replacement.
    pub(crate) fn policies(&self, now: i64) -> Result<(OpenContext, OpenContext)> {
        self.direction.live(now)?;
        let a = self.policies[0].current(now);
        let mut b = self.policies[1].current(now);
        ensure!(
            self.direction.fields.immutable_policy == Some(policy_digest(&a, &b)?),
            "original immutable policy changed"
        );
        b.expected_sender = a.expected_sender;
        b.acting_principal = a.acting_principal;
        b.current_execution_epoch = a.current_execution_epoch;
        self.channel.authorize_addressed(self.grants(), &a, &b)?;
        Ok((a, b))
    }
}
impl PrivateSlot {
    pub(crate) fn open_immutable_destination(
        &mut self,
        owner: &MailboxWorkerOwner,
        original_grant: &MailboxGrant,
    ) -> Result<Option<DestinationRole>> {
        self.open_immutable_role(owner, original_grant, EndpointRole::Destination)
    }

    pub(crate) fn open_immutable_role(
        &mut self,
        owner: &MailboxWorkerOwner,
        original_grant: &MailboxGrant,
        endpoint: EndpointRole,
    ) -> Result<Option<DestinationRole>> {
        let Self::Pending(p) = self else {
            return Ok(None);
        };
        ensure!(
            p.destination.is_none() || p.source.is_none(),
            "ambiguous original private roles"
        );
        let original = match endpoint {
            EndpointRole::Source => &mut p.source,
            EndpointRole::Destination => &mut p.destination,
        };
        let Some(bundle) = original.take() else {
            return Ok(None);
        };
        let now = super::super::now_unix_ms();
        let fields = bundle.fields;
        let direction = DevelopmentDirection {
            commitment: commit(b"mvm-development-directional-aes-256-gcm-v1", &fields)?,
            fields,
        };
        direction.end(endpoint).original(owner)?;
        ensure!(
            p.end.role == endpoint && p.direction == Some(direction.commitment()),
            "private direction or recipient mismatch"
        );
        let keys = [
            VerifyingKey::from_bytes(&bundle.authorities[0].1)?,
            VerifyingKey::from_bytes(&bundle.authorities[1].1)?,
        ];
        let anchors = [
            (bundle.authorities[0].0.as_str(), &keys[0]),
            (bundle.authorities[1].0.as_str(), &keys[1]),
        ];
        ensure!(
            anchors[0].0 != anchors[1].0 || keys[0] == keys[1],
            "conflicting original authorities"
        );
        let ids: (&PlanId, &PlanId) = (&direction.fields.plans.0, &direction.fields.plans.1);
        let mut channel = CastChannel::from_signed_pair(
            &bundle.plans[0],
            &bundle.plans[1],
            &anchors,
            ids,
            direction.destination_greeting(),
            bundle.policies[0].sender,
            bundle.policies[1].recipient,
            now,
        )?;
        channel.restrict_frame_budget(super::super::CAST_BODY_LIMIT as u32)?;
        ensure!(
            match endpoint {
                EndpointRole::Source =>
                    channel.is_bounded_source(original_grant, super::super::CAST_BODY_LIMIT),
                EndpointRole::Destination =>
                    channel.is_bounded_destination(original_grant, super::super::CAST_BODY_LIMIT),
            },
            "signed plans do not bind original destination"
        );
        let role = DestinationRole {
            channel,
            direction,
            creds: bundle.scopes,
            policies: bundle.policies,
        };
        ensure!(
            role.creds[if endpoint == EndpointRole::Source {
                0
            } else {
                2
            }] == p.scope
                && credentials(role.grants())? == role.direction.fields.credentials,
            "signed original grant changed"
        );
        role.policies(now)?;
        let wrapped = Capsule(
            bundle
                .capsule
                .try_into()
                .map_err(|_| anyhow::anyhow!("wrong wrapped key length"))?,
        );
        self.accept(&role.direction, endpoint, owner, &wrapped, now)?;
        Ok(Some(role))
    }
}
