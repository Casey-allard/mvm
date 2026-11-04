//! Built-in own-initiator scope from the original private child context.

use super::*;
use base64::Engine as _;
use mvm_core::host_lifetime::EndpointStoreLocator;
use mvm_vmm::host::network_endpoint_spawn::{AdmittedNetworkPlan, InstalledEndpointLease};
use spiralcore_mvm_flowmux::scope::PinnedScopePolicy;
use spiralcore_transfer::{
    resource_profile::ResourceProfile,
    session::SelectionPolicy,
    shared_runtime::{OutputKind, Recipe, State},
    shared_transfer::PreparedPrediction,
};
use std::{fs::File, os::unix::fs::MetadataExt};

impl SpiralCorePayloadFactory {
    /// Consume no projected DTO as authority and never create another pool.
    pub fn from_installed_resources(
        original: &crate::installed_endpoint::InstalledEndpointResources,
    ) -> io::Result<Option<Self>> {
        let Some(config) = original.network_config() else {
            return Ok(None);
        };
        let Some(policy) = config
            .network_policy
            .as_ref()
            .filter(|policy| policy.payload_mapping().is_some())
        else {
            return Ok(None);
        };
        original.lease().check_current().map_err(invalid)?;
        let plan = config
            .admitted_network_plan
            .as_ref()
            .ok_or_else(|| invalid("original admitted network plan missing"))?;
        plan.validate_for(policy, &config.tenant_id, &config.instance_id)
            .map_err(invalid)?;
        if policy.payload_mapping().is_none_or(|mapping| {
            mapping
                .peers()
                .iter()
                .any(|peer| peer.profile != PayloadMappingProfile::SpiralCoreObjectStreamSmallV1)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installed payload profile unqualified",
            ));
        }
        let pool = original
            .payload_pool()
            .ok_or_else(|| invalid("original payload pool missing"))?
            .clone();
        let locator = original
            .store_locator()
            .ok_or_else(|| invalid("original payload store missing"))?
            .clone();
        let configured = config
            .flowmux_identity
            .as_ref()
            .ok_or_else(|| invalid("original guest identity missing"))?;
        // Original canonical identity material is exactly32-byte Ed25519 keys.
        // Bound before decode; diagnostics never include the supplied material.
        let private = zeroize::Zeroizing::new(decode_key(&configured.host_signing_key_base64)?);
        let key = SigningKey::from_bytes(&private);
        let identity = pinned_identity(&key)?;
        let directory = File::from(rustix::fs::open(
            &locator.path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        let meta = directory.metadata()?;
        if !meta.is_dir() || meta.dev() != locator.device || meta.ino() != locator.inode {
            return Err(invalid("original payload store identity differs"));
        }
        mvm_core::private_fs::require_current_owner(&meta)?;
        if meta.mode() & 0o077 != 0 {
            return Err(invalid("original payload store is not private"));
        }
        let controller = InstalledScopeController {
            plan: plan.clone(),
            policy: policy
                .payload_mapping()
                .ok_or_else(|| invalid("original peer selection missing"))?
                .clone(),
            session: configured.session_id.clone(),
            guest_key: decode_key(&configured.guest_verifying_key_base64)?,
            host_spki: identity.spki_sha256(),
            pool,
            lease: original.lease().clone(),
            locator,
            directory,
        };
        controller.lease.check_current().map_err(invalid)?;
        Ok(Some(Self {
            identity,
            controller: Arc::new(controller),
        }))
    }
}

fn decode_key(encoded: &str) -> io::Result<[u8; 32]> {
    if encoded.len() != 44 {
        return Err(invalid("canonical endpoint key shape"));
    }
    let bytes = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("canonical endpoint key encoding"))?,
    );
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("canonical endpoint key size"))
}

struct InstalledScopeController {
    plan: AdmittedNetworkPlan,
    policy: mvm_contract::policy::network_policy::CooperatingPayloadPolicy,
    session: String,
    guest_key: [u8; 32],
    host_spki: [u8; 32],
    pool: PayloadResourcePool,
    lease: InstalledEndpointLease,
    locator: EndpointStoreLocator,
    directory: File,
}
impl fmt::Debug for InstalledScopeController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstalledScopeController")
            .finish_non_exhaustive()
    }
}
impl InstalledScopeController {
    fn validate(
        &self,
        request: &AdmittedTcpPayload,
        facts: &ScopeFacts,
        profile: NegotiatedProfile,
    ) -> io::Result<()> {
        let selected = self
            .policy
            .select(request.requested_host(), request.requested_port());
        if request.plan() != &self.plan
            || request.session_id() != self.session
            || request.guest_key() != self.guest_key
            || selected != Some(request.selected())
            || profile.capabilities().profile != 2
            || facts.object_profile != 2
            || facts.policy_sha256 != digest::<32>(&self.plan.policy_sha256)?
            || facts.plan_id != self.plan.plan_id.0
            || facts.plan_version != self.plan.plan_version
            || facts.plan_nonce != digest::<16>(self.plan.plan_nonce.as_hex())?
            || facts.bundle_sha256 != digest::<32>(&self.plan.bundle_sha256)?
            || facts.tenant != self.plan.tenant_id
            || facts.instance != self.plan.instance_id
            || facts.session != self.session
            || facts.guest_key != self.guest_key
            || facts.stream_id != request.stream_id()
            || facts.requested_host != request.requested_host()
            || facts.requested_port != request.requested_port()
            || facts.actual_peer != request.actual_peer()
            || facts.route != request.route()
            || facts.initiator_spki != self.host_spki
            || facts.acceptor_spki != request.selected().spki_sha256
        {
            return Err(invalid("payload scope differs from original own admission"));
        }
        facts.canonical_bytes().map_err(invalid)?;
        self.lease.check_current().map_err(invalid)
    }
    fn create_store(
        &self,
        mut permit: PayloadResourcePermit,
        facts: &ScopeFacts,
    ) -> io::Result<(PayloadResourcePermit, std::path::PathBuf)> {
        let name = format!("flow-{}", hex::encode(facts.commitment().map_err(invalid)?));
        if let Err(error) = rustix::fs::mkdirat(
            &self.directory,
            name.as_str(),
            rustix::fs::Mode::from_raw_mode(0o700),
        ) {
            // An uncertain creation must not refund its admitted storage. An
            // existing foreign namespace is never adopted or removed.
            if error != rustix::io::Errno::EXIST {
                permit.uncertain = true;
            }
            return Err(error.into());
        }
        let directory = match rustix::fs::openat(
            &self.directory,
            name.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(directory) => File::from(directory),
            Err(error) => {
                permit.uncertain = true;
                return Err(error.into());
            }
        };
        let path = self.locator.path.join(name);
        let permit = permit.with_owned_directory(path.clone(), directory)?;
        self.lease.check_current().map_err(invalid)?;
        Ok((permit, path))
    }
}
impl PayloadScopeController for InstalledScopeController {
    fn prepare(
        &self,
        request: &AdmittedTcpPayload,
        facts: &ScopeFacts,
        profile: NegotiatedProfile,
        deadline: Instant,
    ) -> io::Result<PreparedPayloadSession> {
        if deadline != request.deadline() {
            return Err(invalid("payload setup deadline changed"));
        }
        remaining(deadline)?;
        self.validate(request, facts, profile)?;
        let scopes = PinnedScopePolicy::new(1).map_err(invalid)?;
        let until = Instant::now()
            .checked_add(Duration::from_secs(300))
            .ok_or_else(|| invalid("payload scope lifetime overflow"))?;
        scopes
            .enroll(facts, facts.acceptor_spki, Role::Initiator, until)
            .map_err(invalid)?;
        let authority = scopes
            .authorize_scope(facts, facts.acceptor_spki, Role::Initiator)
            .map_err(invalid)?;
        let resources = ResourceProfile::SmallV1;
        let permit = self.pool.reserve_profile(resources)?;
        let (permit, path) = self.create_store(permit, facts)?;
        remaining(deadline)?;
        let context = authority.context();
        let checkpoint = State::seeded(32)
            .map_err(invalid)?
            .encode()
            .map_err(invalid)?;
        let prediction = PreparedPrediction::new_with_resource_profile(
            &checkpoint,
            &Recipe {
                steps: 16,
                payload: 1.25,
                output: OutputKind::Trace,
            },
            resources,
        )
        .map_err(invalid)?;
        let sample: &[u8] = b"{\"kind\":\"flowmux\",\"value\":0}\n";
        let schema = spiralcore_transfer::schema::fit(&[sample]).map_err(invalid)?;
        remaining(deadline)?;
        let sender = ObjectSender::with_combined_resource_profile(
            context,
            prediction,
            &schema,
            SelectionPolicy::Exhaustive,
            profile,
            resources,
        )
        .map_err(invalid)?;
        let endpoint = ObjectEndpoint::open_with_resource_profile(
            &path,
            resources.receiver_limits(),
            authority.clone(),
            profile,
            resources,
        )
        .map_err(invalid)?;
        remaining(deadline)?;
        PreparedPayloadSession::new(authority, sender, endpoint, permit)?
            .with_artifacts(vec![PayloadArtifact::Schema, PayloadArtifact::Checkpoint])
    }
}
