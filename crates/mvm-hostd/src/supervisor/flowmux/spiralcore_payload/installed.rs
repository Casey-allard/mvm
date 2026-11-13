//! Built-in own-initiator scope from the original private child context.

use super::*;
use base64::Engine as _;
use mvm_vmm::host::network_endpoint_spawn::{AdmittedNetworkPlan, InstalledEndpointLease};
use spiralcore_mvm_flowmux::scope::PinnedScopePolicy;
use spiralcore_transfer::{
    resource_profile::ResourceProfile,
    session::SelectionPolicy,
    shared_runtime::{OutputKind, Recipe, State},
    shared_transfer::PreparedPrediction,
};
use std::{fs::File, os::unix::fs::MetadataExt};

const READER_METADATA_BYTES: u64 = 64 << 10;

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
        let streams = u64::from(original.lease().projection().limits.max_streams);
        let builder = u64::try_from(spiralcore_mvm_flowmux::READER_STACK_BYTES).map_err(invalid)?;
        let stack = mvm_core::host_lifetime::native_thread_stack_terms(builder)
            .map_err(invalid)?
            .known_rust_bytes
            .checked_mul(streams)
            .ok_or_else(|| invalid("reader stack sum overflow"))?;
        let metadata = READER_METADATA_BYTES
            .checked_mul(streams)
            .ok_or_else(|| invalid("reader metadata sum overflow"))?;
        let reader_resources = Arc::new(original.claim_codec_readers(stack, metadata)?);
        reader_resources.check_current()?;
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
            host_key: key.verifying_key().to_bytes(),
            pool,
            lease: original.lease().clone(),
            directory: Arc::new(directory),
            reader_resources,
        };
        controller.lease.check_current().map_err(invalid)?;
        Ok(Some(Self {
            identity,
            controller: Controller::Installed(Box::new(controller)),
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

pub(super) struct InstalledScopeController {
    plan: AdmittedNetworkPlan,
    policy: mvm_contract::policy::network_policy::CooperatingPayloadPolicy,
    session: String,
    guest_key: [u8; 32],
    host_spki: [u8; 32],
    host_key: [u8; 32],
    pool: PayloadResourcePool,
    lease: InstalledEndpointLease,
    directory: Arc<File>,
    reader_resources: Arc<crate::installed_endpoint::InstalledEndpointComponentPermit>,
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
        self.check_before_carrier(request)?;
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
        self.reader_resources.check_current()?;
        self.lease.check_current().map_err(invalid)
    }
    fn create_store(
        &self,
        permit: &mut PayloadResourcePermit,
        facts: &ScopeFacts,
    ) -> io::Result<std::path::PathBuf> {
        let name = format!("flow-{}", hex::encode(facts.commitment().map_err(invalid)?));
        if let Err(error) = rustix::fs::mkdirat(
            self.directory.as_ref(),
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
            self.directory.as_ref(),
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
        // Anchor every codec path under the original retained parent FD.
        // Keep the final component a real private directory for the codec's
        // no-symlink checks. The controller holds the parent through the relay.
        use std::os::fd::AsRawFd;
        let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
            .join(&name);
        permit.attach_owned_directory(path.clone(), directory, Arc::clone(&self.directory))?;

        self.lease.check_current().map_err(invalid)?;
        Ok(path)
    }
    pub(super) fn reserve(
        &self,
        request: &AdmittedTcpPayload,
    ) -> io::Result<PayloadResourcePermit> {
        self.check_before_carrier(request)?;
        self.pool
            .reserve_installed_profile(ResourceProfile::SmallV1)
    }
    pub(super) fn check_owned_tcp_relays(
        &self,
        group: &super::super::OwnedTcpRelays,
        plan: &AdmittedNetworkPlan,
        session: &str,
        host: [u8; 32],
        guest: [u8; 32],
    ) -> io::Result<()> {
        group.check_reader_partition(&self.reader_resources)?;
        if plan != &self.plan
            || session != self.session
            || host != self.host_key
            || guest != self.guest_key
        {
            return Err(invalid("owned relay original session differs"));
        }
        self.lease.check_current().map_err(invalid)
    }
    fn check_before_carrier(&self, request: &AdmittedTcpPayload) -> io::Result<()> {
        self.reader_resources.check_current()?;
        request
            .owned_relay()
            .ok_or_else(|| invalid("installed payload requires original relay reservation"))?
            .check(&self.reader_resources)?;
        if request.plan() != &self.plan
            || request.session_id() != self.session
            || request.guest_key() != self.guest_key
            || self
                .policy
                .select(request.requested_host(), request.requested_port())
                != Some(request.selected())
        {
            return Err(invalid("installed payload original admission differs"));
        }
        self.lease.check_current().map_err(invalid)
    }
    pub(super) fn prepare(
        &self,
        request: &AdmittedTcpPayload,
        facts: &ScopeFacts,
        profile: NegotiatedProfile,
        deadline: Instant,
        pending: &mut Option<PayloadResourcePermit>,
    ) -> io::Result<PreparedPayloadSession> {
        if deadline != request.deadline() {
            return Err(invalid("payload setup deadline changed"));
        }
        remaining(deadline)?;
        self.validate(request, facts, profile)?;
        let resources = ResourceProfile::SmallV1;
        let permit = pending
            .as_mut()
            .ok_or_else(|| invalid("original pending payload reservation missing"))?;
        if !Arc::ptr_eq(&permit.inner, &self.pool.inner)
            || permit.profile != Some(resources)
            || permit.carrier_bytes == 0
        {
            return Err(invalid(
                "pending payload reservation differs from original pool",
            ));
        }
        permit.check_current()?;
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
        let path = self.create_store(permit, facts)?;
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
        PreparedPayloadSession::check_parts(&authority, &sender, &endpoint, permit)?;
        let relay = request
            .owned_relay()
            .ok_or_else(|| invalid("installed reader relay witness missing"))?;
        relay.check(&self.reader_resources)?;
        let artifacts = vec![PayloadArtifact::Schema, PayloadArtifact::Checkpoint];
        Ok(PreparedPayloadSession {
            artifacts,
            authority,
            sender,
            endpoint,
            resources: pending.take().expect("original checked pending permit"),
            reader_resources: Some(self.reader_resources.clone()),
            relay_witness: Some(relay.clone()),
        })
    }
}
