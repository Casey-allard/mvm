//! Development-only, one-direction enrollment under two original worker leases.
//! The launcher uses each worker's once-delegated private config descriptor.
//! The relay sees only a public direction and fixed-size, separately wrapped keys.
pub(crate) mod destination;
use super::{InstalledCastParticipant, RoutedCast};
use crate::mailbox_process::MailboxProcessConfig;
use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::{
    mailbox::{
        BootId, EncryptionAlgorithm, EncryptionContext, MailboxGrant, MailboxMessageKind,
        MailboxOperation, MailboxRoutingFrame, PrincipalId, SignedMailboxCapability,
        local::{LocalGreeting, LocalRole},
    },
    mailbox_worker::{MailboxWorkerBackend, MailboxWorkerOwner, MailboxWorkerState},
};
use mvm_core::{
    crypto::aead::Key,
    mailbox::{
        OpenContext,
        frame::cast::{CastChannel, route::AddressedCastGrants},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    Source,
    Destination,
}

/// A public commitment only. No lease token or private descriptor is exposed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct End {
    owner_hash: [u8; 32],
    role: EndpointRole,
    generation: u64,
    boot: [u8; 32],
    binding: [u8; 32],
    scope_hash: [u8; 32],
}
impl End {
    fn new(owner: &MailboxWorkerOwner, role: EndpointRole, scope_hash: [u8; 32]) -> Result<Self> {
        ensure!(
            owner.generation > 0 && owner.lease != [0; 32] && owner.context_commitment != [0; 32],
            "empty original lease"
        );
        let owner_hash = commit(b"mvm-dev-cast-original-v1", owner)?;
        // Independent random public IDs. Neither one exposes the other or a secret.
        let boot = *Key::random().expose_bytes();
        let binding = *Key::random().expose_bytes();
        Ok(Self {
            owner_hash,
            role,
            generation: owner.generation,
            boot,
            binding,
            scope_hash,
        })
    }
    fn greeting(&self) -> LocalGreeting {
        let role = match self.role {
            EndpointRole::Source => LocalRole::Submit,
            EndpointRole::Destination => LocalRole::Deliver,
        };
        LocalGreeting {
            role,
            binding: self.binding,
            generation: self.generation,
        }
    }
    fn original(&self, owner: &MailboxWorkerOwner) -> Result<()> {
        ensure!(
            self.generation == owner.generation
                && self.owner_hash == commit(b"mvm-dev-cast-original-v1", owner)?,
            "not the original worker"
        );
        Ok(())
    }
}

fn commit(domain: &[u8], value: &impl Serialize) -> Result<[u8; 32]> {
    let bytes = serde_jcs::to_vec(value)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(bytes);
    Ok(hash.finalize().into())
}
fn credentials(g: AddressedCastGrants<'_>) -> Result<[u8; 32]> {
    commit(
        b"mvm-dev-cast-signed-scopes-v1",
        &(g.source_scope, g.send, g.receive),
    )
}

/// Present only in the original helper's protected config. No Debug or public
/// constructor. Serialize solely for the existing bounded, zeroized config pipe.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateLaunch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination: Option<Box<destination::PrivateDestination>>,
    direction: Option<[u8; 32]>,
    end: End,
    wrapping: [u8; 32],
    scope: SignedMailboxCapability,
}
impl Drop for PrivateLaunch {
    fn drop(&mut self) {
        self.wrapping.zeroize();
    }
}

/// Trusted launcher side of a private, single-use role registration.
pub struct LaunchCustody {
    end: End,
    wrapping: Key,
    grant: MailboxGrant,
    original: OpenContext,
    routing: MailboxRoutingFrame,
}
impl LaunchCustody {
    fn create(
        grant: MailboxGrant,
        original: OpenContext,
        routing: MailboxRoutingFrame,
        owner: &MailboxWorkerOwner,
        role: EndpointRole,
        scope: &SignedMailboxCapability,
    ) -> Result<(Self, PreparedRole)> {
        ensure!(
            grant.local_service.is_some(),
            "development enrollment requires admitted reliable profile"
        );
        let end = End::new(owner, role, scope_hash(scope)?)?;
        let wrapping = Key::random();
        let setup = PrivateLaunch {
            destination: None,
            direction: None,
            end: end.clone(),
            wrapping: *wrapping.expose_bytes(),
            scope: scope.clone(),
        };
        Ok((
            Self {
                end,
                wrapping,
                grant,
                original,
                routing,
            },
            PreparedRole { setup, grant },
        ))
    }
    pub fn greeting(&self) -> LocalGreeting {
        self.end.greeting()
    }
    pub fn policy(&self) -> &OpenContext {
        &self.original
    }
}

fn scope_hash(scope: &SignedMailboxCapability) -> Result<[u8; 32]> {
    ensure!(
        scope.grant.content_types.len() <= 4
            && scope.grant.message_kinds.len() <= 3
            && scope.signature.len() == 64,
        "scope exceeds development profile"
    );
    commit(b"mvm-development-original-scope-v1", scope)
}

fn authorized_role_policy(
    config: &MailboxProcessConfig,
    role: EndpointRole,
    scope: &SignedMailboxCapability,
) -> Result<OpenContext> {
    scope_hash(scope)?;
    let (policy, _) = config.keys.trust();
    let current = policy.context;
    checked_role_policy(
        config.grant,
        current,
        policy.authority_key,
        policy.sender_key,
        role,
        scope,
    )
}
fn checked_role_policy(
    grant: MailboxGrant,
    mut current: OpenContext,
    authority: VerifyingKey,
    sender: VerifyingKey,
    role: EndpointRole,
    scope: &SignedMailboxCapability,
) -> Result<OpenContext> {
    scope_hash(scope)?;
    let g = &scope.grant;
    ensure!(
        authority.to_bytes() == grant.authority_key
            && current.expected_sender == PrincipalId::from_bytes(sender.to_bytes()),
        "invalid original signing identity"
    );
    mvm_core::mailbox::verify_capability_signature(scope, &authority)?;
    let (subject, op) = match role {
        EndpointRole::Source => (current.expected_sender, MailboxOperation::Send),
        EndpointRole::Destination => (current.expected_recipient, MailboxOperation::Receive),
    };
    ensure!(
        g.issuer == current.expected_capability_issuer
            && g.subject == subject
            && g.operations.allows(op)
            && g.address.mailbox == grant.mailbox
            && g.address.recipient == current.expected_recipient
            && g.policy_epoch == current.current_policy_epoch
            && grant.epoch >= g.minimum_execution_epoch
            && grant.epoch <= g.maximum_execution_epoch
            && current.now_unix_ms >= g.not_before_unix_ms
            && current.now_unix_ms < g.expires_at_unix_ms
            && g.message_kinds.contains(&MailboxMessageKind::Cast),
        "role scope does not cover original endpoint"
    );
    // Only this separately signed development view changes. The loopback
    // template and existing mailbox service keep their original policy.
    current.expected_tenant = g.address.tenant;
    current.expected_authorization_domain = g.address.authorization_domain;
    current
        .accepted_content_types
        .retain(|t| g.content_types.contains(t));
    ensure!(
        !current.accepted_content_types.is_empty(),
        "no admitted content type"
    );
    Ok(current)
}

/// Original policies and two independently authenticated participant handles.
/// The original policy owner's revocations can tighten the launch snapshot.
pub struct Participant<'a> {
    pub installed: InstalledCastParticipant<'a>,
    pub current: &'a OpenContext,
}

fn check_policy(original: &OpenContext, current: &OpenContext) -> Result<()> {
    ensure!(
        current.expected_tenant == original.expected_tenant
            && current.expected_authorization_domain == original.expected_authorization_domain
            && current.expected_mailbox == original.expected_mailbox
            && current.expected_recipient == original.expected_recipient
            && current.expected_sender == original.expected_sender
            && current.acting_principal == original.acting_principal
            && current.expected_capability_issuer == original.expected_capability_issuer
            && current.current_execution_epoch == original.current_execution_epoch
            && current.current_policy_epoch == original.current_policy_epoch
            && current.required_operation == original.required_operation
            && original
                .revoked_capabilities
                .iter()
                .all(|c| current.revoked_capabilities.contains(c))
            && current
                .accepted_content_types
                .iter()
                .all(|c| original.accepted_content_types.contains(c)),
        "policy differs from original private configuration"
    );
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectionFields {
    immutable_policy: Option<[u8; 32]>,
    plans: (mvm_core::plan::PlanId, mvm_core::plan::PlanId),
    authorities: [[u8; 32]; 2],
    source: End,
    destination: End,
    credentials: [u8; 32],
    source_policy_epoch: u64,
    destination_policy_epoch: u64,
    start: i64,
    end: i64,
    key_id: [u8; 32],
    routing: MailboxRoutingFrame,
}
/// Constructed only after plan, lease and capability verification. A commitment
/// is an identifier, not proof that the caller can install or open anything.
pub struct DevelopmentDirection {
    fields: DirectionFields,
    commitment: [u8; 32],
}
impl DevelopmentDirection {
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
    pub fn sender_boot(&self) -> BootId {
        BootId::from_bytes(self.fields.source.boot)
    }
    pub fn source_greeting(&self) -> LocalGreeting {
        self.fields.source.greeting()
    }
    pub fn destination_greeting(&self) -> LocalGreeting {
        self.fields.destination.greeting()
    }
    /// Verify the prepared public direction before building the original B
    /// guest's boot record. The caller also authenticates its two plan IDs.
    pub fn original_deliver_enrollment(
        &self,
        source: &MailboxWorkerOwner,
        dest: &MailboxWorkerOwner,
        grants: AddressedCastGrants<'_>,
        now_ms: i64,
    ) -> Result<([u8; 32], LocalGreeting, i64)> {
        self.fields.source.original(source)?;
        self.fields.destination.original(dest)?;
        self.live(now_ms)?;
        for (cap, key) in [
            (grants.source_scope, self.fields.authorities[0]),
            (grants.send, self.fields.authorities[1]),
            (grants.receive, self.fields.authorities[1]),
        ] {
            scope_hash(cap)?;
            mvm_core::mailbox::verify_capability_signature(cap, &VerifyingKey::from_bytes(&key)?)?;
        }
        ensure!(
            credentials(grants)? == self.fields.credentials,
            "boot grants changed"
        );
        Ok((
            self.commitment(),
            self.destination_greeting(),
            self.fields.end,
        ))
    }
    fn live(&self, now: i64) -> Result<()> {
        ensure!(
            now >= self.fields.start && now < self.fields.end,
            "expired development direction"
        );
        Ok(())
    }
    fn end(&self, role: EndpointRole) -> &End {
        match role {
            EndpointRole::Source => &self.fields.source,
            EndpointRole::Destination => &self.fields.destination,
        }
    }
    fn aad(&self, role: EndpointRole) -> [u8; 33] {
        let mut aad = [0; 33];
        aad[..32].copy_from_slice(&self.commitment);
        aad[32] = match role {
            EndpointRole::Source => 1,
            EndpointRole::Destination => 2,
        };
        aad
    }
}

const WRAPPED: usize = mvm_core::crypto::aead::KEY_SIZE
    + mvm_core::crypto::aead::NONCE_SIZE
    + mvm_core::crypto::aead::TAG_SIZE;
/// A fixed-size authenticated ciphertext safe for an opaque control relay.
pub struct Capsule(pub [u8; WRAPPED]);
pub struct DirectionDelivery {
    pub direction: DevelopmentDirection,
    pub source: Capsule,
    pub destination: Capsule,
}

/// Only the original SDK holds this nonclone secret. Its exclusive config
/// descriptor is consumed once, later, without a second key mint or rebind.
pub struct PreparedRole {
    setup: PrivateLaunch,
    grant: MailboxGrant,
}
impl PreparedRole {
    pub(crate) fn binds_boot(&self, commitment: [u8; 32], endpoint: EndpointRole) -> bool {
        self.setup.direction == Some(commitment) && self.setup.end.role == endpoint
    }

    fn bind(&mut self, d: &DevelopmentDirection) -> Result<()> {
        ensure!(
            self.setup.direction.is_none() && &self.setup.end == d.end(self.setup.end.role),
            "cannot change original role direction"
        );
        self.setup.direction = Some(d.commitment());
        Ok(())
    }
    pub(crate) fn check_recipient(
        &self,
        owner: &MailboxWorkerOwner,
        context: Option<[u8; 32]>,
    ) -> Result<()> {
        self.setup.end.original(owner)?;
        ensure!(
            self.setup.direction.is_some() && self.setup.direction == context,
            "wrong prepared original issuer or direction"
        );
        Ok(())
    }
    pub(crate) fn install(
        self,
        config: &mut MailboxProcessConfig,
        owner: &MailboxWorkerOwner,
    ) -> Result<()> {
        self.setup.end.original(owner)?;
        ensure!(
            self.setup.direction.is_some()
                && self.grant == config.grant
                && config.keys.development_cast.is_none(),
            "original granted config changed"
        );
        authorized_role_policy(config, self.setup.end.role, &self.setup.scope)?;
        config.keys.development_cast = Some(self.setup);
        Ok(())
    }
}
pub struct PreparedDevelopment {
    pub delivery: DirectionDelivery,
    pub source: PreparedRole,
    pub destination: PreparedRole,
}

fn prepare_original(
    p: &Participant<'_>,
    owner: &MailboxWorkerOwner,
    role: EndpointRole,
    scope: &SignedMailboxCapability,
    now: i64,
) -> Result<(LaunchCustody, PreparedRole)> {
    let grant = p.installed.worker.acquire_request().mailbox_grant;
    let (issuer, setup) = prepare_at(
        &mvm_core::config::mvm_keys_dir(),
        grant,
        owner,
        role,
        scope,
        now,
    )?;
    check_policy(&issuer.original, p.current)?;
    Ok((issuer, setup))
}
fn prepare_at(
    keys: &std::path::Path,
    grant: MailboxGrant,
    owner: &MailboxWorkerOwner,
    role: EndpointRole,
    scope: &SignedMailboxCapability,
    now: i64,
) -> Result<(LaunchCustody, PreparedRole)> {
    let trusted = super::derived_keys(keys, &grant.mailbox, grant.epoch)?;
    let template = super::template_for(keys, &trusted, &grant, now)?;
    let original = checked_role_policy(
        grant,
        template.launch_context(),
        trusted.authority.verifying_key(),
        trusted.sender.verifying_key(),
        role,
        scope,
    )?;
    LaunchCustody::create(grant, original, template.routing, owner, role, scope)
}

/// Before either VM boots, authenticate its existing Reserved owner, its exact
/// admitted plan, and its pre-existing signed scope. Preparing public boot
/// identity and two private capsules neither starts a helper nor spends a data
/// admission. Both original workers must subsequently reach Serving for use.
pub fn prepare(
    source: Participant<'_>,
    destination: Participant<'_>,
    backend: MailboxWorkerBackend,
    signers: &[(&str, &VerifyingKey)],
    grants: AddressedCastGrants<'_>,
    deadline: Instant,
) -> Result<PreparedDevelopment> {
    prepare_profile(
        source,
        destination,
        backend,
        signers,
        grants,
        deadline,
        false,
    )
}
/// The development policy is fixed for the original helper generation. A
/// policy change requires stopping this owner and starting a new generation.
pub fn prepare_immutable_generation(
    source: Participant<'_>,
    destination: Participant<'_>,
    backend: MailboxWorkerBackend,
    signers: &[(&str, &VerifyingKey)],
    grants: AddressedCastGrants<'_>,
    deadline: Instant,
) -> Result<PreparedDevelopment> {
    prepare_profile(
        source,
        destination,
        backend,
        signers,
        grants,
        deadline,
        true,
    )
}
fn prepare_profile(
    source: Participant<'_>,
    destination: Participant<'_>,
    backend: MailboxWorkerBackend,
    signers: &[(&str, &VerifyingKey)],
    grants: AddressedCastGrants<'_>,
    deadline: Instant,
    immutable: bool,
) -> Result<PreparedDevelopment> {
    grants.check_compact_policy(source.current, destination.current)?;
    let a = source
        .installed
        .owner_in_state(backend, deadline, MailboxWorkerState::Reserved)?;
    let b =
        destination
            .installed
            .owner_in_state(backend, deadline, MailboxWorkerState::Reserved)?;
    ensure!(
        a.daemon_boot_nonce == b.daemon_boot_nonce
            && a.lease != b.lease
            && a.context_commitment != b.context_commitment,
        "two distinct original Reserved leases required"
    );
    let now = super::now_unix_ms();
    let (src, mut source_setup) =
        prepare_original(&source, a, EndpointRole::Source, grants.source_scope, now)?;
    let (dst, mut destination_setup) = prepare_original(
        &destination,
        b,
        EndpointRole::Destination,
        grants.receive,
        now,
    )?;
    let channel = CastChannel::from_signed_pair(
        source.installed.plan.signed(),
        destination.installed.plan.signed(),
        signers,
        (
            source.installed.plan.plan_id(),
            destination.installed.plan.plan_id(),
        ),
        dst.greeting(),
        src.original.expected_sender,
        dst.original.expected_recipient,
        now,
    )?;
    let delivery = issue_with_policy(
        &channel,
        src,
        dst,
        grants,
        source.current,
        destination.current,
        now,
        immutable
            .then(|| destination::policy_digest(source.current, destination.current))
            .transpose()?,
    )?;
    if immutable {
        destination_setup.setup.destination = Some(Box::new(destination::PrivateDestination::new(
            &delivery,
            source.installed.plan.signed(),
            destination.installed.plan.signed(),
            signers,
            grants,
            source.current,
            destination.current,
        )?));
    }
    source
        .installed
        .owner_in_state(backend, deadline, MailboxWorkerState::Reserved)?;
    destination
        .installed
        .owner_in_state(backend, deadline, MailboxWorkerState::Reserved)?;
    source.installed.worker.bind_development_pair(
        destination.installed.worker,
        delivery.direction.commitment(),
    )?;
    source_setup.bind(&delivery.direction)?;
    destination_setup.bind(&delivery.direction)?;
    Ok(PreparedDevelopment {
        delivery,
        source: source_setup,
        destination: destination_setup,
    })
}
fn issue_with_policy(
    channel: &CastChannel,
    source: LaunchCustody,
    destination: LaunchCustody,
    grants: AddressedCastGrants<'_>,
    source_policy: &OpenContext,
    destination_policy: &OpenContext,
    now: i64,
    immutable_policy: Option<[u8; 32]>,
) -> Result<DirectionDelivery> {
    issue_with_policy(
        channel,
        source,
        destination,
        grants,
        source_policy,
        destination_policy,
        now,
        None,
    )
}
fn issue_with_policy(
    channel: &CastChannel,
    source: LaunchCustody,
    destination: LaunchCustody,
    grants: AddressedCastGrants<'_>,
    source_policy: &OpenContext,
    destination_policy: &OpenContext,
    now: i64,
    immutable_policy: Option<[u8; 32]>,
) -> Result<DirectionDelivery> {
    ensure!(
        source.end.role == EndpointRole::Source
            && destination.end.role == EndpointRole::Destination
            && source.end.scope_hash == scope_hash(grants.source_scope)?
            && destination.end.scope_hash == scope_hash(grants.receive)?,
        "changed original role/scope"
    );
    check_policy(&source.original, source_policy)?;
    check_policy(&destination.original, destination_policy)?;
    grants.check_compact_policy(source_policy, destination_policy)?;
    let mut sa = source_policy.clone();
    sa.now_unix_ms = now;
    let mut db = destination_policy.clone();
    db.now_unix_ms = now;
    db.expected_sender = sa.expected_sender;
    db.acting_principal = sa.acting_principal;
    db.current_execution_epoch = sa.current_execution_epoch;
    db.required_operation = sa.required_operation;
    channel.authorize_addressed(grants, &sa, &db)?;
    let valid = channel.guest_validity();
    let caps = [grants.source_scope, grants.send, grants.receive];
    let start = caps
        .iter()
        .fold(valid.start, |v, c| v.max(c.grant.not_before_unix_ms));
    let end = caps.iter().fold(
        valid.end.min(destination.routing.expires_at_unix_ms),
        |v, c| v.min(c.grant.expires_at_unix_ms),
    );
    let plans = channel.original_plan_pair();
    let fields = DirectionFields {
        immutable_policy,
        plans: (plans.0.clone(), plans.1.clone()),
        authorities: [source.grant.authority_key, destination.grant.authority_key],
        source: source.end,
        destination: destination.end,
        credentials: credentials(grants)?,
        source_policy_epoch: sa.current_policy_epoch,
        destination_policy_epoch: db.current_policy_epoch,
        start,
        end,
        key_id: *Key::random().expose_bytes(),
        routing: destination.routing,
    };
    wrap(fields, source.wrapping, destination.wrapping, now)
}

fn wrap(fields: DirectionFields, source: Key, dest: Key, now: i64) -> Result<DirectionDelivery> {
    let commitment = commit(b"mvm-development-directional-aes-256-gcm-v1", &fields)?;
    let direction = DevelopmentDirection { fields, commitment };
    direction.live(now)?;
    let data = Key::random();
    let packet = |key: &Key, role| -> Result<Capsule> {
        Ok(Capsule(
            data.wrap_under(key, &direction.aad(role))
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid wrapped DEK length"))?,
        ))
    };
    let source = packet(&source, EndpointRole::Source)?;
    let destination = packet(&dest, EndpointRole::Destination)?;
    Ok(DirectionDelivery {
        direction,
        source,
        destination,
    })
}

pub(crate) struct InstalledDirection {
    commitment: [u8; 32],
    context: EncryptionContext,
    key: Key,
    scope: SignedMailboxCapability,
    sender_boot: BootId,
    routing: MailboxRoutingFrame,
    expires: i64,
}
impl InstalledDirection {
    pub(crate) fn sender_boot(&self) -> BootId {
        self.sender_boot
    }
    pub(crate) fn admits_routing(&self, r: &MailboxRoutingFrame) -> bool {
        let base = &self.routing;
        r.protocol_version == base.protocol_version
            && r.authorization_domain_route_label == base.authorization_domain_route_label
            && r.destination_route_token == base.destination_route_token
            && r.transport_binding_id == base.transport_binding_id
            && r.hop_limit == base.hop_limit
            && r.padding == base.padding
            && r.expires_at_unix_ms <= self.expires
    }
    pub(crate) fn scope(&self) -> &SignedMailboxCapability {
        &self.scope
    }
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }
    pub(crate) fn context(&self) -> &EncryptionContext {
        &self.context
    }
}

pub(crate) enum PrivateSlot {
    Disabled,
    Pending(PrivateLaunch),
    Installed(InstalledDirection),
}
impl PrivateSlot {
    pub(crate) fn new(
        config: &mut MailboxProcessConfig,
        owner: &MailboxWorkerOwner,
    ) -> Result<Self> {
        if let Some(p) = config.keys.development_cast.take() {
            p.end.original(owner)?;
            authorized_role_policy(config, p.end.role, &p.scope)?;
            ensure!(
                p.end.scope_hash == scope_hash(&p.scope)?,
                "scope differs from original enrollment"
            );
            Ok(Self::Pending(p))
        } else {
            Ok(Self::Disabled)
        }
    }
    fn accept(
        &mut self,
        d: &DevelopmentDirection,
        role: EndpointRole,
        owner: &MailboxWorkerOwner,
        capsule: &Capsule,
        now: i64,
    ) -> Result<()> {
        d.live(now)?;
        let Self::Pending(p) = self else {
            anyhow::bail!("missing or spent original role slot")
        };
        p.end.original(owner)?;
        ensure!(
            &p.end == d.end(role) && p.direction == Some(d.commitment()),
            "wrong original endpoint for this direction"
        );
        let wrapping = Key::from_slice(&p.wrapping)?;
        let key = Key::unwrap_under(&wrapping, &capsule.0, &d.aad(role))?;
        *self = Self::Installed(InstalledDirection {
            commitment: d.commitment(),
            key,
            scope: p.scope.clone(),
            sender_boot: d.sender_boot(),
            routing: d.fields.routing.clone(),
            expires: d.fields.end,
            context: EncryptionContext {
                algorithm: EncryptionAlgorithm::AES_256_GCM,
                key_id: d.fields.key_id,
            },
        });
        Ok(())
    }
    pub(crate) fn accept_turn(
        &mut self,
        turn: &DirectionTurn<'_>,
        role: EndpointRole,
        owner: &MailboxWorkerOwner,
        capsule: &Capsule,
    ) -> Result<()> {
        turn.validate()?;
        self.accept(turn.d, role, owner, capsule, super::now_unix_ms())
    }
    pub(crate) fn installed(
        &self,
        d: &DevelopmentDirection,
        role: EndpointRole,
        owner: &MailboxWorkerOwner,
    ) -> Result<&InstalledDirection> {
        d.live(super::now_unix_ms())?;
        d.end(role).original(owner)?;
        let Self::Installed(key) = self else {
            anyhow::bail!("missing installed directional key")
        };
        ensure!(
            key.commitment == d.commitment(),
            "wrong directional key generation"
        );
        Ok(key)
    }
}

/// This turn checks the previously acquired serving pair independently of an
/// envelope. Source enrollment can therefore precede the first encryption.
pub struct DirectionTurn<'a> {
    d: &'a DevelopmentDirection,
    mapping: &'a super::ServingCastMapping,
    workers: &'a crate::broker::mailbox_workers::MailboxWorkers,
    grants: AddressedCastGrants<'a>,
    source: &'a OpenContext,
    dest: &'a OpenContext,
}
impl<'a> DirectionTurn<'a> {
    pub fn from_serving(
        d: &'a DevelopmentDirection,
        mapping: &'a super::ServingCastMapping,
        workers: &'a crate::broker::mailbox_workers::MailboxWorkers,
        grants: AddressedCastGrants<'a>,
        source: &'a OpenContext,
        dest: &'a OpenContext,
    ) -> Result<Self> {
        let turn = Self {
            d,
            mapping,
            workers,
            grants,
            source,
            dest,
        };
        turn.validate()?;
        Ok(turn)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let m = self.mapping;
        self.workers.original_cast_pair(
            (&m.source_vm, &m.source_owner),
            (&m.destination_vm, &m.destination_owner),
        )?;
        self.grants.check_compact_policy(self.source, self.dest)?;
        let (a, b) = m.current_policies(self.workers, self.source, self.dest)?;
        m.channel.authorize_addressed(self.grants, &a, &b)?;
        self.d.matches(m, self.grants, self.source, self.dest)
    }
    pub(crate) fn source_credit(
        &self,
    ) -> Result<crate::broker::mailbox_workers::cast_credit::SourceCredit<'a>> {
        self.validate()?;
        use crate::broker::mailbox_workers::cast_credit::CAST_WORK_BYTES;
        ensure!(
            self.mapping
                .channel
                .admits_workspace((CAST_WORK_BYTES * 2) as u64),
            "signed workspace cannot sustain retained source and destination turn"
        );
        let m = self.mapping;
        Ok(self.workers.reserve_cast_source(
            (&m.source_vm, &m.source_owner),
            (&m.destination_vm, &m.destination_owner),
        )?)
    }
    pub(crate) fn source_view<'s, C>(
        &'s self,
        sealer: &'s mut crate::mailbox_service::GuestSealer,
        key: &'s InstalledDirection,
        slot: &'s mut mvm_core::mailbox::frame::cast::source::SourceCastSlot<C>,
    ) -> Result<mvm_core::mailbox::frame::cast::source::CastSource<'s, C>> {
        self.validate()?;
        let original = VerifiedSourceRole {
            channel: &self.mapping.channel,
            grants: self.grants,
            direction: self.d,
            key,
        };
        Ok(sealer.enrolled_addressed_source(original, slot)?)
    }
    pub(crate) fn policies(&self) -> Result<(OpenContext, OpenContext)> {
        self.mapping
            .current_policies(self.workers, self.source, self.dest)
    }
    pub(crate) fn direction(&self) -> &DevelopmentDirection {
        self.d
    }
}
/// Constructible by the original serving turn only; secret key, IDs and
/// routing are derived together, never paired with a caller-chosen raw role.
pub(crate) struct VerifiedSourceRole<'a> {
    channel: &'a CastChannel,
    grants: AddressedCastGrants<'a>,
    direction: &'a DevelopmentDirection,
    key: &'a InstalledDirection,
}
impl<'a> VerifiedSourceRole<'a> {
    pub(crate) fn for_original_sealer(
        self,
        h: &mvm_contract::protocol::mailbox::MailboxEnvelopeHeader,
    ) -> Result<(
        &'a CastChannel,
        AddressedCastGrants<'a>,
        crate::mailbox_service::cast_source::OriginalSourceRole<'a>,
    )> {
        let d = self.direction;
        let key = self.key;
        let g = &self.grants.source_scope.grant;
        d.live(super::now_unix_ms())?;
        ensure!(
            key.commitment == d.commitment()
                && key.scope() == self.grants.source_scope
                && credentials(self.grants)? == d.fields.credentials
                && scope_hash(self.grants.source_scope)? == d.fields.source.scope_hash
                && h.mailbox == g.address.mailbox
                && h.sender == g.subject
                && h.recipient == g.address.recipient
                && h.policy_epoch == g.policy_epoch
                && h.execution_epoch >= g.minimum_execution_epoch
                && h.execution_epoch <= g.maximum_execution_epoch,
            "source enrollment differs from sealed role or original private template"
        );
        Ok((
            self.channel,
            self.grants,
            crate::mailbox_service::cast_source::OriginalSourceRole {
                source_binding: d.source_greeting().binding,
                enrollment_commitment: d.commitment(),
                sender_boot: d.sender_boot(),
                encryption: key.context().clone(),
                data_key: key.key(),
                routing: d.fields.routing.clone(),
            },
        ))
    }
}
impl DevelopmentDirection {
    fn matches(
        &self,
        m: &super::ServingCastMapping,
        grants: AddressedCastGrants<'_>,
        source: &OpenContext,
        dest: &OpenContext,
    ) -> Result<()> {
        if let Some(expected) = self.fields.immutable_policy {
            ensure!(
                expected == destination::policy_digest(source, dest)?,
                "immutable generation policy changed; original worker must stop"
            );
        }
        self.live(super::now_unix_ms())?;
        self.fields.source.original(&m.source_owner)?;
        self.fields.destination.original(&m.destination_owner)?;
        ensure!(
            m.destination_greeting == self.destination_greeting()
                && credentials(grants)? == self.fields.credentials
                && source.current_policy_epoch == self.fields.source_policy_epoch
                && dest.current_policy_epoch == self.fields.destination_policy_epoch,
            "Cast differs from enrolled direction"
        );
        Ok(())
    }
}
impl RoutedCast<'_> {
    pub(crate) fn check_direction(
        &self,
        d: &DevelopmentDirection,
        source: &OpenContext,
        dest: &OpenContext,
    ) -> Result<()> {
        self.for_original_destination(&self.mapping.destination_owner, source, dest)?;
        d.matches(self.mapping, self.grants, source, dest)?;
        ensure!(
            self.envelope.encryption.key_id == d.fields.key_id,
            "Cast envelope key generation changed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
