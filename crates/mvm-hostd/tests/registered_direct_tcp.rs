#![cfg(unix)]

use anyhow::{Result, ensure};
use mvm_core::protocol::broker::ServiceId;
use mvm_core::{
    config,
    host_lifetime::{HostLeaseExpectation, PreparedHostLifetimeLease},
    util::test_env::TestEnv,
};
use mvm_vmm::host::host_agent_spawn::{
    HostAgentParentPermit, HostAgentServicesParams, OwnedHostAgent, OwnedHostAgentInputs,
    OwnedHostAgentRegistrar, OwnedVmRegistration,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct Parent {
    current: AtomicBool,
}
impl HostAgentParentPermit for Parent {
    fn check_current(&self, tenant: &str) -> Result<()> {
        ensure!(
            tenant == "local" && self.current.load(Ordering::Acquire),
            "fixture parent refused"
        );
        Ok(())
    }
    fn owned_process_address_space_limit(
        &self,
        tenant: &str,
    ) -> Result<Option<std::num::NonZeroU64>> {
        self.check_current(tenant)?;
        Ok(if OwnedHostAgent::supports_process_address_space_limit() {
            std::num::NonZeroU64::new(256 << 20)
        } else {
            None
        })
    }
    fn owned_audit_chain_bytes(&self, tenant: &str) -> Result<Option<std::num::NonZeroU64>> {
        self.check_current(tenant)?;
        Ok(std::num::NonZeroU64::new(256 << 10))
    }
    fn installed_endpoint_settings(
        &self,
        params: &HostAgentServicesParams<'_>,
    ) -> Result<&mvm_vmm::host::network_endpoint_spawn::InstalledEndpointSettings> {
        self.check_registration(params)?;
        Ok(&mvm_vmm::host::network_endpoint_spawn::InstalledEndpointSettings::ResolvedDirect)
    }
    fn check_registration(&self, params: &HostAgentServicesParams<'_>) -> Result<()> {
        self.check_current(params.tenant_id.unwrap_or_default())?;
        ensure!(
            ["vm-1", "vm-2"].contains(&params.vm_name),
            "fixture VM not admitted"
        );
        Ok(())
    }
}
struct Fixture {
    _env: TestEnv,
    _home: tempfile::TempDir,
    lease: tempfile::TempDir,
    parent: Arc<Parent>,
    host_signer: ed25519_dalek::SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let mut env = TestEnv::new();
        let home = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        env.set("MVM_HOME", home.path());
        env.set("MVM_HOST_AGENT_PATH", env!("CARGO_BIN_EXE_mvm-host-agent"));
        env.set(
            "MVM_SIGNER_HELPER_PATH",
            env!("CARGO_BIN_EXE_mvm-signer-helper"),
        );
        env.set("MVM_HOST_AGENT_DAEMON", "1");
        let host_signer = mvm_hostd::audit::host_keypair::load_or_init_at(&config::mvm_keys_dir())
            .unwrap()
            .signing;
        let lease = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut state = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lease.path().join("state"))
            .unwrap();
        state.write_all(b"original fixture state").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lease.path().join("holders"))
            .unwrap();
        Self {
            _env: env,
            _home: home,
            lease,
            parent: Arc::new(Parent {
                current: AtomicBool::new(true),
            }),
            host_signer,
        }
    }
    fn inputs(&self) -> OwnedHostAgentInputs {
        OwnedHostAgentInputs {
            tenant: "local".into(),
            parent: self.parent.clone(),
            holder: PreparedHostLifetimeLease::bind(
                File::open(self.lease.path()).unwrap(),
                File::open(self.lease.path().join("holders")).unwrap(),
                HostLeaseExpectation {
                    state_name: "state".into(),
                    state_bytes: 22,
                    state_sha256: Sha256::digest(b"original fixture state").into(),
                    absent_names: ["intent".into(), "dirty".into()],
                },
            )
            .unwrap(),
        }
    }
    fn vm(&self, name: &str) -> (PathBuf, PathBuf) {
        let state = config::vm_state_dir(name);
        config::create_private_dir(&state).unwrap();
        let socket = config::vm_socket_dir_at(&state).join("owned-broker.sock");
        (state, socket)
    }
}
fn register(
    registrar: &OwnedHostAgentRegistrar,
    vm: &str,
    state: &Path,
    socket: &Path,
) -> Result<OwnedVmRegistration> {
    registrar.register(HostAgentServicesParams {
        workload_id: vm,
        tenant_id: Some("local"),
        vm_name: vm,
        state_dir: state,
        broker_listen_socket: socket,
        services: &[ServiceId::parse("host.audit.v1").unwrap()],
        capability_bindings: &[],
        service_proxies: &[],
    })
}
struct ArchiveRetry(AtomicBool);

impl mvm_vmm::host::host_agent_spawn::RegisteredEndpointOwner for ArchiveRetry {
    fn bind_registration(
        &self,
        _registrar: &OwnedHostAgentRegistrar,
        registration: &OwnedVmRegistration,
        _params: &HostAgentServicesParams<'_>,
    ) -> Result<()> {
        ensure!(
            registration
                .registered_audit()
                .is_some_and(|f| f.terminal().is_none())
        );
        Ok(())
    }
    fn retired_audit(
        &self,
        _registration: &OwnedVmRegistration,
        file: &mvm_vmm::host::host_agent_spawn::RegisteredAuditFile,
    ) -> Result<()> {
        let ended = file
            .terminal()
            .ok_or_else(|| anyhow::anyhow!("original signed terminal missing"))?;
        let key = file.verifying_key();
        let opening = mvm_core::protocol::audit_inventory::verify(file.signed_registered(), &key)?;
        let closing = mvm_core::protocol::audit_inventory::verify(
            file.signed_terminal().ok_or_else(|| anyhow::anyhow!("missing signed closing inventory"))?, &key,
        )?;
        ensure!(&opening == file.registered() && &closing == ended);
        ensure!(opening.same_registration(&closing));
        if self.0.swap(false, Ordering::SeqCst) {
            anyhow::bail!("fixture archive busy");
        }
        Ok(())
    }
}
#[test]
fn a_terminal_archive_retry_retains_only_its_original_registration() -> Result<()> {
    let f = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(f.inputs())?;
    let registrar = agent
        .registrar()
        .with_registration_owner(Arc::new(ArchiveRetry(AtomicBool::new(true))))?;
    let (state, socket) = f.vm("vm-1");
    let mut first = register(&registrar, "vm-1", &state, &socket)?;
    ensure!(
        first
            .shutdown()
            .unwrap_err()
            .to_string()
            .contains("fixture archive busy")
    );
    let (state2, socket2) = f.vm("vm-2");
    let mut second = register(&registrar, "vm-2", &state2, &socket2)?;
    ensure!(
        first
            .registered_audit()
            .unwrap()
            .terminal()
            .is_some_and(|row| row.length == 0)
    );
    first.shutdown()?;
    second.shutdown()?;
    agent.shutdown()?;
    Ok(())
}

#[path = "support/registered_direct_peer.rs"]
mod peer;
mod registered_prepare {
    use super::peer::*;
    use super::*;
    use anyhow::Context;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::network_flow::{Opcode, hello::Handshake};
    use mvm_core::{
        host_lifetime::{
            CoreCurrentParentPermit, EndpointPartitionGuard, EndpointPartitionLimits,
            EndpointPartitionProjection, EndpointStoreLocator, HostLaunchBinding,
            HostLifetimeInputs, PreparedEndpointHandoff, PreparedEndpointPartition,
            PreparedHostLifetime,
        },
        plan::{compute_plan_id, sign_plan, test_support::PlanFixture},
        policy::network_policy::NetworkPolicy,
        vm_backend::{BackendKind, VmStartConfig},
    };
    use mvm_vmm::host::network_endpoint_spawn::{
        AdmittedNetworkPlan, EgressProxySpawnConfig, EndpointLifetime, EndpointTransport,
        FlowMuxIdentitySpawnConfig, InstalledHostServices, SubstitutionSpawnParams,
        spawn_network_endpoint_installed_registered,
    };
    use spiralcore_mvm_flowmux::tls::TlsCarrier;
    use std::time::{Duration, Instant};
    use std::{
        io::Read,
        os::{fd::AsFd, unix::fs::MetadataExt},
        sync::Mutex,
    };
    struct Guard {
        projection: EndpointPartitionProjection,
        retained: Option<Mutex<FixtureRetention>>,
    }
    struct FixtureRetention {
        state_path: PathBuf,
        original_state: File,
        prepared: bool,
        files: Option<(File, File)>,
    }
    fn file_id(file: &File) -> Result<(u64, u64)> {
        let metadata = file.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    impl EndpointPartitionGuard for Guard {
        fn check_current(&self, facts: &EndpointPartitionProjection) -> Result<()> {
            ensure!(facts == &self.projection, "foreign functional partition");
            Ok(())
        }
        fn prepare_retained_telemetry(
            &self,
            facts: &EndpointPartitionProjection,
            state_path: &Path,
            state: &File,
        ) -> Result<()> {
            self.check_current(facts)?;
            let mut retained = self
                .retained
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("unselected functional retained owner"))?
                .lock()
                .unwrap();
            ensure!(
                state_path == retained.state_path
                    && file_id(state)? == file_id(&retained.original_state)?
            );
            ensure!(!retained.prepared && retained.files.is_none());
            // This test owner checks ordering/identity only. It is not a durable
            // Root catalog, quota reservation or installation permission source.
            for name in [
                mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE,
                mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_KEY_FILE,
            ] {
                ensure!(
                    !state_path.join(name).exists(),
                    "key/writer effect preceded retained prepare"
                );
            }
            retained.prepared = true;
            Ok(())
        }
        fn bind_retained_telemetry_files(
            &self,
            facts: &EndpointPartitionProjection,
            state_path: &Path,
            state: &File,
            records: &File,
            wrapped_key: &File,
        ) -> Result<()> {
            self.check_current(facts)?;
            let mut retained = self
                .retained
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("unselected functional retained owner"))?
                .lock()
                .unwrap();
            ensure!(
                state_path == retained.state_path
                    && file_id(state)? == file_id(&retained.original_state)?
            );
            ensure!(
                retained.prepared && retained.files.is_none(),
                "bind preceded prepare or repeated"
            );
            let named_records =
                state_path.join(mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE);
            let named_key =
                state_path.join(mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_KEY_FILE);
            ensure!(file_id(records)? == file_id(&File::open(named_records)?)?);
            ensure!(file_id(wrapped_key)? == file_id(&File::open(named_key)?)?);
            let flags = rustix::fs::fcntl_getfl(records.as_fd())?;
            ensure!(
                flags & rustix::fs::OFlags::ACCMODE == rustix::fs::OFlags::RDWR
                    && flags.contains(rustix::fs::OFlags::APPEND)
            );
            ensure!(
                rustix::fs::fcntl_getfl(wrapped_key.as_fd())? & rustix::fs::OFlags::ACCMODE
                    == rustix::fs::OFlags::RDONLY
            );
            ensure!(records.metadata()?.len() == 0 && wrapped_key.metadata()?.len() <= 1024);
            retained.files = Some((records.try_clone()?, wrapped_key.try_clone()?));
            Ok(())
        }
    }
    struct Parent(EndpointPartitionProjection, Arc<dyn EndpointPartitionGuard>);
    impl CoreCurrentParentPermit for Parent {
        fn check_current(&self, binding: &HostLaunchBinding) -> Result<()> {
            ensure!(binding == &self.0.binding, "foreign functional binding");
            Ok(())
        }
        fn prepare_endpoint_partition(
            &self,
            binding: &HostLaunchBinding,
        ) -> Result<PreparedEndpointPartition> {
            self.check_current(binding)?;
            PreparedEndpointPartition::new(self.0.clone(), self.1.clone())
        }
    }

    fn handoff(
        holder: &PreparedHostLifetimeLease,
        store: &Path,
        state: &Path,
        policy: &NetworkPolicy,
    ) -> Result<(PreparedEndpointHandoff, AdmittedNetworkPlan, Arc<Guard>)> {
        let mut plan = PlanFixture::new().workload("vm-1").build();
        plan.network_mode = mvm_core::plan::NetworkMode::HostVsockProxy;
        plan.asset_identities
            .push(mvm_core::plan::AssetIdentity::new(
                mvm_core::plan::AssetKind::Policy,
                "network_policy",
                mvm_core::policy::network_policy::content_sha256(policy),
            )?);
        plan.bundle = Some(mvm_core::plan::bundle::PlanArtifact::new(
            "11".repeat(32),
            &[8; 64],
            mvm_core::plan::bundle::KeyId("original-fixture".into()),
        ));
        plan.plan_id = compute_plan_id(&plan);
        let issuer = SigningKey::from_bytes(&[8; 32]);
        let signed = sign_plan(&plan, &issuer, "fixture");
        let plan = mvm_core::plan::verify_plan(&signed, &[("fixture", &issuer.verifying_key())])?;
        let projection = AdmittedNetworkPlan::from_plan(&plan, "vm-1", policy)?;
        let metadata = store.metadata()?;
        let facts = EndpointPartitionProjection {
            version: 1,
            binding: HostLaunchBinding {
                installation: [1; 32],
                profile: [2; 32],
                generation: 1,
                grant_serial: 1,
                vm_name: "vm-1".into(),
                backend: BackendKind::Firecracker,
                cpus: 1,
                memory_mib: 128,
            },
            admitted_plan_id: plan.plan_id.0.clone(),
            session: [3; 32],
            partition_serial: 1,
            profile: 2,
            store: Some(EndpointStoreLocator {
                version: 1,
                path: store.into(),
                device: metadata.dev(),
                inode: metadata.ino(),
                reservation_serial: 1,
                tenant: [0; 32],
                session: [3; 32],
            }),
            // Explicit functional envelope. No aggregate host quota is represented
            // by these test guards. Child debits real bootstrap/Audit/relay/reader
            // claims from its ONE supplied ledger (Audit workspace alone is 8MiB).
            limits: EndpointPartitionLimits {
                host_plaintext_bytes: 1 << 20,
                host_codec_bytes: 16 << 20,
                host_carrier_bytes: 1 << 20,
                host_metadata_bytes: 240 << 20,
                // Experimental controller fixture includes main8MiB + original
                // session2MiB + collector6MiB + relay2MiB + reader2MiB supplements.
                // This is not a Root production profile or capacity claim.
                host_stack_bytes: 24 << 20,
                cache_disk_bytes: (16 << 20)
                    + mvm_vmm::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP
                    + mvm_core::runtime_state_protection::INSTALLED_TELEMETRY_SIDECAR_BYTES,
                staging_disk_bytes: 16 << 20,
                workers: 1,
                max_streams: 1,
            },
        };
        let anchor = PreparedHostLifetime::bind(
            HostLifetimeInputs {
                directory: holder.directory().try_clone()?,
                holder: holder.holder().try_clone()?,
                expected: holder.expectation().clone(),
                binding: facts.binding.clone(),
            },
            (),
        )?
        .into_anchor();
        let mut config = VmStartConfig {
            name: "vm-1".into(),
            cpus: 1,
            memory_mib: 128,
            network_policy: policy.clone(),
            ..Default::default()
        };
        anchor.bind_to_config(&mut config)?;
        config.plan_json = Some(serde_json::to_string(&signed)?);
        anchor.bind_admitted(&config, BackendKind::Firecracker, &plan)?;
        let guard = Arc::new(Guard {
            projection: facts.clone(),
            retained: Some({
                Mutex::new(FixtureRetention {
                    state_path: state.into(),
                    original_state: File::open(state).unwrap(),
                    prepared: false,
                    files: None,
                })
            }),
        });
        anchor.bind_parent_permit(
            &config,
            BackendKind::Firecracker,
            Arc::new(Parent(facts, guard.clone())),
        )?;
        Ok((
            anchor.prepare_endpoint_handoff(&config, BackendKind::Firecracker)?,
            projection,
            guard,
        ))
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "selected process requires Linux address-space enforcement"
    )]
    fn registered_direct_tcp_transfers_exact_bytes_and_refunds_a_failed_peer() -> Result<()> {
        use mvm_contract::policy::network_policy::{
            CooperatingPayloadPolicy, CooperatingTcpPeer, PayloadMappingProfile,
        };
        let mut fixture = Fixture::new();
        fixture._env.set(
            "MVM_SUBSTITUTION_ENDPOINT_PATH",
            env!("CARGO_BIN_EXE_mvm-network-endpoint"),
        );
        let holder = fixture.inputs().holder;
        let mut agent = OwnedHostAgent::spawn(fixture.inputs())?;
        let registrar = agent
            .registrar()
            .with_registration_owner(Arc::new(ArchiveRetry(AtomicBool::new(true))))?;
        let (state, socket) = fixture.vm("vm-1");
        let mut registration = register(&registrar, "vm-1", &state, &socket)?;
        let store = state.join("codec-functional-store");
        config::create_private_dir(&store)?;

        let services = [ServiceId::parse("host.audit.v1")?];
        let original = InstalledHostServices::new(
            &registrar,
            &registration,
            HostAgentServicesParams {
                workload_id: "vm-1",
                tenant_id: Some("local"),
                vm_name: "vm-1",
                state_dir: &state,
                broker_listen_socket: &socket,
                services: &services,
                capability_bindings: &[],
                service_proxies: &[],
            },
        )?;
        use mvm_contract::peer::{PeerBinding, PeerName};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let peer_key = fixture_identity(&SigningKey::from_bytes(&[11; 32]));
        let policy = NetworkPolicy::deny_all()
            .with_peers(vec![PeerBinding {
                name: PeerName::parse(TARGET)?,
                port: 443,
                host_addr: address.ip().to_string(),
                host_port: address.port(),
            }])
            .with_payload_mapping(Some(CooperatingPayloadPolicy::new(vec![
                CooperatingTcpPeer {
                    host: TARGET.into(),
                    port: 443,
                    server_name: TARGET.into(),
                    spki_sha256: peer_key.spki_sha256(),
                    profile: PayloadMappingProfile::SpiralCoreObjectStreamSmallV1,
                },
            ])?));
        let (handoff, plan, guard) = handoff(&holder, &store, &state, &policy)?;
        let redaction = Default::default();
        let params = SubstitutionSpawnParams::builder()
            .vm_name("vm-1")
            .state_dir(&state)
            .lifetime(EndpointLifetime::Launcher)
            .tenant("local")
            .secrets(&[])
            .redaction(&redaction)
            .transport(EndpointTransport::Uds {
                path: state.join("network.sock"),
            })
            .telemetry(true)
            // The test explicitly selects the canonical empty operator table;
            // production may not normalize absent/unresolved proxy settings here.
            .egress_proxy(EgressProxySpawnConfig::default())
            .network_policy(&policy)
            .admitted_network_plan(plan.clone())
            .network_limits(Default::default())
            .ingress(&[])
            .flowmux_identity(FlowMuxIdentitySpawnConfig {
                session_id: hex::encode([3; 32]),
                host_signing_key_base64: STANDARD.encode(fixture.host_signer.to_bytes()),
                guest_verifying_key_base64: STANDARD
                    .encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
            })
            .build()?;

        let endpoint_diagnostic = || {
            let path = state.join("network-endpoint.stderr.log");
            let mut diagnostic = String::new();
            if let Ok(file) = File::open(path) {
                let _ = file.take(2048).read_to_string(&mut diagnostic);
            }
            format!("signed controller stderr: {diagnostic}")
        };
        let mut substituted = plan.clone();
        substituted.plan_nonce = mvm_core::plan::Nonce::from_bytes([88; 16]);
        ensure!(
            handoff
                .check_direct_network(&substituted, &Default::default(), &redaction)
                .is_err()
        );
        let mut changed_limits = mvm_core::plan::NetworkLimits::default();
        changed_limits.max_tcp_flows = 2;
        ensure!(
            handoff
                .check_direct_network(&plan, &changed_limits, &redaction)
                .is_err()
        );
        let launched = spawn_network_endpoint_installed_registered(params, handoff, &original);
        let mut endpoint = launched.with_context(endpoint_diagnostic)?;
        drop(original);
        ensure!(
            registration.shutdown().is_err(),
            "active endpoint lost original audit pin"
        );
        ensure!(
            endpoint.take_retirement().is_err(),
            "startup published retirement"
        );

        let mut guest = std::os::unix::net::UnixStream::connect(state.join("network.sock"))?;
        let timeout = Some(std::time::Duration::from_secs(3));
        guest.set_read_timeout(timeout)?;
        guest.set_write_timeout(timeout)?;
        let (mut session, _) = mvm_core::net::session::Session::guest(
            &mut guest,
            SigningKey::from_bytes(&[7; 32]),
            &fixture.host_signer.verifying_key(),
        )?;

        // The canonical launcher waits for post-handshake session publication.
        let readiness_path = config::vm_socket_dir_at(&state)
            .join(mvm_vmm::host::network_endpoint_spawn::SUBST_SESSION_READY_SOCKET);
        let mut readiness = std::os::unix::net::UnixStream::connect(readiness_path)?;
        readiness.set_read_timeout(timeout)?;
        let mut ready = [0];
        readiness
            .read_exact(&mut ready)
            .with_context(endpoint_diagnostic)?;
        ensure!(ready == [1], "authenticated session readiness differs");

        send(
            &mut guest,
            &mut session,
            Opcode::Hello,
            0,
            &Handshake::local("registered-direct-tcp").encode(),
        );
        ensure!(receive(&mut guest, &mut session).0 == Opcode::HelloAck);
        send(
            &mut guest,
            &mut session,
            Opcode::OpenTcp,
            1,
            b"unbound.mvm.peer:443",
        );
        ensure!(receive(&mut guest, &mut session).0 == Opcode::Refused);
        ensure!(
            listener
                .accept()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
        );
        let initiator_spki = fixture_identity(&fixture.host_signer).spki_sha256();
        let peer = std::thread::spawn(move || -> Result<()> {
            let wrong = fixture_identity(&SigningKey::from_bytes(&[12; 32]));
            let first = accept(&listener)?;
            // Accept may finish the TLS handshake before learning that the initiator rejected its SPKI.
            if let Ok(mut wrong_session) = TlsCarrier::accept(
                first,
                &wrong,
                initiator_spki,
                Instant::now() + Duration::from_secs(4),
            ) {
                let mut byte = [0];
                ensure!(
                    wrong_session.read(&mut byte).unwrap_or(0) == 0,
                    "failed peer received application bytes"
                );
            }
            serve_original(
                accept(&listener)?,
                address,
                peer_key,
                initiator_spki,
                plan,
                5,
            )?;
            ensure!(
                listener
                    .accept()
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
            );
            Ok(())
        });
        send(
            &mut guest,
            &mut session,
            Opcode::OpenTcp,
            3,
            format!("{TARGET}:443").as_bytes(),
        );
        let refusal = receive(&mut guest, &mut session);
        ensure!(
            refusal.1 == 3
                && matches!(
                    refusal.0,
                    Opcode::ConnectFailed | Opcode::Refused | Opcode::Reset
                ),
            "wrong peer response {refusal:?}"
        );
        send(
            &mut guest,
            &mut session,
            Opcode::OpenTcp,
            5,
            format!("{TARGET}:443").as_bytes(),
        );
        let opened = receive(&mut guest, &mut session);
        ensure!(
            (opened.0, opened.1) == (Opcode::Opened, 5),
            "correct original failed after refusal: {opened:?}"
        );
        let body = payload();
        send(&mut guest, &mut session, Opcode::Data, 5, &body);
        send(&mut guest, &mut session, Opcode::HalfClose, 5, &[]);
        let mut restored = Vec::new();
        loop {
            let (op, id, bytes) = receive(&mut guest, &mut session);
            ensure!(id == 5);
            match op {
                Opcode::Data => {
                    ensure!(restored.len() + bytes.len() <= body.len());
                    restored.extend_from_slice(&bytes);
                }
                Opcode::WindowUpdate => (),
                Opcode::HalfClose => break,
                _ => anyhow::bail!("unexpected flow response {op:?}"),
            }
        }
        ensure!(body == restored);
        peer.join()
            .map_err(|_| anyhow::anyhow!("original peer fixture failed"))??;
        endpoint.shutdown().with_context(endpoint_diagnostic)?;
        ensure!(
            guest.read(&mut [0; 1])? == 0,
            "authenticated guest did not close"
        );
        let retirement = endpoint.take_retirement()?;
        let original_guard: Arc<dyn EndpointPartitionGuard> = guard.clone();
        ensure!(
            retirement.retains_partition_guard(&original_guard),
            "foreign retirement"
        );
        ensure!(
            endpoint.take_retirement().is_err(),
            "retirement was not single-use"
        );
        drop(endpoint);
        let retained = guard.retained.as_ref().unwrap().lock().unwrap();
        let (records, wrapped) = retained
            .files
            .as_ref()
            .context("original file binding missing")?;
        ensure!(
            file_id(records)?
                == file_id(&File::open(state.join(
                    mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE
                ))?)?
        );
        ensure!(
            file_id(wrapped)?
                == file_id(&File::open(state.join(
                    mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_KEY_FILE
                ))?)?
        );
        drop(retained);
        ensure!(
            registration
                .shutdown()
                .unwrap_err()
                .to_string()
                .contains("fixture archive busy")
        );
        let (second_state, second_socket) = fixture.vm("vm-2");
        let mut second = register(&registrar, "vm-2", &second_state, &second_socket)?;
        ensure!(
            registration
                .registered_audit()
                .unwrap()
                .terminal()
                .is_some()
        );
        registration.shutdown()?;
        second.shutdown()?;
        agent.shutdown()?;
        Ok(())
    }
}
