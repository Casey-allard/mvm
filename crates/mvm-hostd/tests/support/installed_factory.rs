use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use mvm_contract::protocol::network_flow::{Opcode, hello::Handshake};
use mvm_core::net::session::{Session, read_sealed_frame, write_sealed_frame};
use mvm_hostd::{
    installed_endpoint::{InstalledEndpointProgram, InstalledEndpointResources},
    supervisor::flowmux::{
        FlowMuxAccept, FlowMuxSession, OwnedTcpRelays, PayloadMappingConfig, PayloadResourceLimits,
        PayloadResourcePool, PreparedPayloadSession, SpiralCorePayloadFactory,
        accept_enrolled_payload, registry::RegistryLimits,
    },
};
use mvm_vmm::host::network_endpoint_spawn::{AdmittedNetworkPlan, InstalledEndpointChild};
use spiralcore_mvm_flowmux::{
    Role,
    scope::{PinnedScopePolicy, ScopeFacts},
    tls::{PinnedIdentity, TlsCarrier},
};
use spiralcore_transfer::{
    resource_profile::ResourceProfile,
    v1::{Capabilities, ObjectEndpoint, ObjectMode, ObjectSender},
};
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener},
    os::{
        fd::AsRawFd,
        unix::net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

const TARGET: &str = "cooperator.mvm.peer";
const HOST_SEED: [u8; 32] = [9; 32];
const GUEST_SEED: [u8; 32] = [7; 32];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Duplex,
    Capacity,
    BlockedWrite,
    BlockedRead,
    ExpiredJoin,
    StalledTls,
    StalledArtifact,
    AttachClose,
    AttachPoison,
}
impl Case {
    fn mode(self) -> &'static str {
        match self {
            Self::Duplex => "factory",
            Self::Capacity => "owned-capacity",
            Self::BlockedWrite => "blocked-guest-write",
            Self::BlockedRead => "blocked-upstream-read",
            Self::ExpiredJoin => "expired-join",
            Self::StalledTls => "stalled-tls",
            Self::StalledArtifact => "stalled-artifact",
            Self::AttachClose => "owned-attach-close",
            Self::AttachPoison => "owned-attach-poison",
        }
    }
}

fn identity(key: &SigningKey) -> PinnedIdentity {
    PinnedIdentity::from_pkcs8(key.to_pkcs8_der().unwrap().as_bytes().to_vec()).unwrap()
}

fn payload() -> Vec<u8> {
    b"{\"kind\":\"flowmux\",\"value\":1}\n".repeat(400)
}

fn fixture_bootstrap_budget(
    config: &serde_json::Value,
    projection: &mut mvm_core::host_lifetime::EndpointPartitionProjection,
) -> anyhow::Result<()> {
    let raw = serde_json::to_string(config)?;
    let required =
        mvm_vmm::host::network_endpoint_spawn::installed_endpoint_bootstrap_requirement(&raw)?;
    // Explicit functional-test envelope. The actual child repeats this query
    // and debits bootstrap plus both component claims from ONE ledger.
    projection.limits.host_metadata_bytes = 8 << 20;
    anyhow::ensure!(required < projection.limits.host_metadata_bytes);
    eprintln!(
        "installed factory bootstrap: config_bytes={} required_bytes={required}",
        raw.len()
    );
    Ok(())
}

pub fn paired() {
    paired_mode(Case::Duplex);
}

pub fn paired_owned() {
    paired_mode(Case::Capacity);
}

pub fn blocked_guest_write() {
    paired_mode(Case::BlockedWrite);
}
pub fn blocked_upstream_read() {
    paired_mode(Case::BlockedRead);
}

pub fn expired_join() {
    paired_mode(Case::ExpiredJoin);
}

pub fn stalled_tls() {
    paired_mode(Case::StalledTls);
}

pub fn stalled_artifact() {
    paired_mode(Case::StalledArtifact);
}

pub fn attach_close_parent(child_name: &str) {
    paired_with_child(Case::AttachClose, child_name);
}
pub fn attach_poison_parent(child_name: &str) {
    paired_with_child(Case::AttachPoison, child_name);
}

pub fn foreign_resources_parent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(
        super::installed_resource_fixture::resource_exchange_handoffs_with(
            "foreign-owner",
            &[
                "--exact",
                "foreign_resources_child",
                "--nocapture",
                "--test-threads=1",
            ],
            2,
            |config, projection, _| {
                config["flowmux_identity"]["host_signing_key_base64"] =
                    STANDARD.encode(HOST_SEED).into();
                config["flowmux_identity"]["guest_verifying_key_base64"] = STANDARD
                    .encode(
                        SigningKey::from_bytes(&GUEST_SEED)
                            .verifying_key()
                            .to_bytes(),
                    )
                    .into();
                projection.limits.host_stack_bytes = 16 << 20;
                fixture_bootstrap_budget(config, projection)?;
                Ok(())
            },
        ),
    );
}

pub fn foreign_resources_child() {
    // SAFETY: the original fixture reserves fd199 for private protocol output.
    assert!(unsafe { libc::dup2(199, 1) } >= 0);
    let mut first = InstalledEndpointChild::from_stdio().unwrap();
    let resources = InstalledEndpointResources::from_child(&mut first).unwrap();
    let group = OwnedTcpRelays::from_installed_resources(&resources).unwrap();
    let (first_program, first_lease, first_pool) = resources.into_parts();
    let mut second = InstalledEndpointChild::from_stdio().unwrap();
    let resources = InstalledEndpointResources::from_child(&mut second).unwrap();
    let factory = SpiralCorePayloadFactory::from_installed_resources(&resources)
        .unwrap()
        .unwrap();
    let store = resources.store_locator().unwrap().path.clone();
    let (second_program, second_lease, second_pool) = resources.into_parts();
    // Context1 is checked only after context2 fully consumed its own Prepare.
    first_lease.check_current().unwrap();
    let InstalledEndpointProgram::Network(first_config) = first_program else {
        panic!("first network config")
    };
    let InstalledEndpointProgram::Network(config) = second_program else {
        panic!("second network config")
    };
    use sha2::{Digest, Sha256};
    assert_eq!(
        Sha256::digest(serde_json::to_vec(&first_config).unwrap()),
        Sha256::digest(serde_json::to_vec(&config).unwrap()),
        "same public configuration facts"
    );
    let mapping = Arc::new(
        PayloadMappingConfig::new(
            config.network_policy.as_ref().unwrap(),
            config.admitted_network_plan.clone().unwrap(),
        )
        .unwrap()
        .with_factory(Arc::new(factory)),
    );
    let session_id = config.flowmux_identity.unwrap().session_id;
    std::thread::scope(|scope| {
        let (host_stream, mut guest) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let wrong_group = group.clone();
        let host = scope.spawn(move || {
            FlowMuxSession::accept_with(
                host_stream,
                FlowMuxAccept::new(
                    &session_id,
                    SigningKey::from_bytes(&HOST_SEED),
                    SigningKey::from_bytes(&GUEST_SEED).verifying_key(),
                    RegistryLimits::default(),
                    mvm_vmm::vsock_egress_bridge::egress_gate::EgressGate::default_deny(),
                )
                .with_payload_mapping(Some(mapping))
                .with_owned_tcp_relays(Some(wrong_group)),
            )
        });
        let mut byte = [0u8; 1];
        let observed = guest.read(&mut byte);
        // Always wake/join the original test thread even in the expected RED.
        drop(guest);
        let result = host.join().unwrap();
        assert_eq!(
            observed.unwrap(),
            0,
            "foreign resource owner emitted handshake bytes"
        );
        assert!(matches!(
            result,
            Err(mvm_hostd::supervisor::flowmux::FlowMuxError::FrameRefused(
                _
            ))
        ));
    });
    group
        .close_and_join(Instant::now() + Duration::from_secs(2))
        .unwrap();
    for pool in [first_pool.unwrap(), second_pool.unwrap()] {
        assert_eq!(pool.snapshot().unwrap(), Default::default());
        pool.close_admission().unwrap();
        assert!(pool.drained().unwrap());
    }
    assert_eq!(std::fs::read_dir(store).unwrap().count(), 0);
    finish_child(second, second_lease);
}

fn paired_mode(case: Case) {
    paired_with_child(case, "installed_factory_child");
}

fn paired_with_child(case: Case, child_name: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = identity(&SigningKey::from_bytes(&[8; 32]));
    let server_spki = server.spki_sha256();
    let (config_tx, config_rx) = std::sync::mpsc::sync_channel(1);
    // Structured joining also applies if the original child fixture fails.
    std::thread::scope(|scope| {
        let peer = scope.spawn(move || {
            let (config, root) = config_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            peer(listener, address, server, config, case, root);
        });
        runtime.block_on(super::installed_resource_fixture::resource_exchange_with(
            case.mode(),
            &["--exact", child_name, "--nocapture", "--test-threads=1"],
            move |config, projection, root| {
                use mvm_contract::{
                    peer::{PeerBinding, PeerName},
                    policy::network_policy::{
                        CooperatingPayloadPolicy, CooperatingTcpPeer, NetworkPolicy,
                        PayloadMappingProfile,
                    },
                };
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
                            spki_sha256: server_spki,
                            profile: PayloadMappingProfile::SpiralCoreObjectStreamSmallV1,
                        },
                    ])?));
                config["network_policy"] = serde_json::to_value(&policy)?;
                config["admitted_network_plan"]["policy_sha256"] =
                    mvm_core::policy::network_policy::content_sha256(&policy).into();
                config["flowmux_identity"]["host_signing_key_base64"] =
                    STANDARD.encode(HOST_SEED).into();
                config["flowmux_identity"]["guest_verifying_key_base64"] = STANDARD
                    .encode(
                        SigningKey::from_bytes(&GUEST_SEED)
                            .verifying_key()
                            .to_bytes(),
                    )
                    .into();
                // Explicit component fixture envelope, not an aggregate
                // parent/RSS/native capacity claim. The real resource owner
                // subdivides it before any codec or relay thread exists.
                projection.limits.host_stack_bytes = 16 << 20;
                fixture_bootstrap_budget(config, projection)?;
                if case != Case::Duplex {
                    projection.limits.max_streams = 1;
                }
                // Exact enrollment is provisioned by this fixture's initiating
                // controller before private handoff, never from peer claims.
                config_tx.send((config.clone(), root.to_path_buf()))?;
                Ok(())
            },
        ));
        peer.join().unwrap();
    });
}

fn peer(
    listener: TcpListener,
    address: SocketAddr,
    server_identity: PinnedIdentity,
    config: serde_json::Value,
    case: Case,
    root: PathBuf,
) {
    let until = Instant::now() + Duration::from_secs(3);
    let (socket, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < until, "original peer accept deadline");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("peer accept: {error}"),
        }
    };
    if case == Case::StalledTls {
        let mut socket = socket;
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut first = [0u8; 1];
        socket.read_exact(&mut first).unwrap();
        assert_eq!(first, [22], "actual TLS handshake began on admitted socket");
        let mut event = UnixStream::connect(root.join("setup-seen.sock")).unwrap();
        event.write_all(&[1]).unwrap();
        let mut remaining = Vec::new();
        (&mut socket)
            .take(65537)
            .read_to_end(&mut remaining)
            .unwrap();
        assert!(remaining.len() < 65537, "bounded TLS setup input");
        return;
    }
    let initiator = identity(&SigningKey::from_bytes(&HOST_SEED));
    let tls = TlsCarrier::accept(socket, &server_identity, initiator.spki_sha256(), until).unwrap();
    let plan: AdmittedNetworkPlan =
        serde_json::from_value(config["admitted_network_plan"].clone()).unwrap();
    let facts = ScopeFacts {
        object_profile: 2,
        policy_sha256: hex::decode(&plan.policy_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
        plan_id: plan.plan_id.0,
        plan_version: plan.plan_version,
        plan_nonce: hex::decode(plan.plan_nonce.as_hex())
            .unwrap()
            .try_into()
            .unwrap(),
        bundle_sha256: hex::decode(&plan.bundle_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
        tenant: plan.tenant_id,
        instance: plan.instance_id,
        session: config["flowmux_identity"]["session_id"]
            .as_str()
            .unwrap()
            .into(),
        guest_key: SigningKey::from_bytes(&GUEST_SEED)
            .verifying_key()
            .to_bytes(),
        stream_id: 1,
        requested_host: TARGET.into(),
        requested_port: 443,
        actual_peer: address,
        route: "peer".into(),
        initiator_spki: tls.peer_spki_sha256(),
        acceptor_spki: tls.local_spki_sha256(),
        tls_exporter: tls.exporter(),
    };
    let scopes = PinnedScopePolicy::new(1).unwrap();
    scopes
        .enroll(&facts, facts.initiator_spki, Role::Acceptor, until)
        .unwrap();
    let authority = scopes
        .authorize_scope(&facts, facts.initiator_spki, Role::Acceptor)
        .unwrap();
    if case == Case::StalledArtifact {
        let mut probe = tls.try_clone().unwrap();
        probe
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let caps = Capabilities::small_v1();
        let _channel = spiralcore_mvm_flowmux::ObjectChannel::from_authenticated(
            tls,
            &authority,
            Duration::from_secs(2),
            Role::Acceptor,
            caps,
            caps,
        )
        .unwrap();
        let mut first = [0u8; 1];
        assert_eq!(
            probe.peek(&mut first).unwrap(),
            1,
            "actual artifact request before stop"
        );
        let mut event = UnixStream::connect(root.join("setup-seen.sock")).unwrap();
        event.write_all(&[1]).unwrap();
        let mut remaining = Vec::new();
        match (&mut probe).take(65537).read_to_end(&mut remaining) {
            Ok(_) => {}
            Err(error) => assert_terminal_error(&error),
        }
        assert!(
            remaining.len() < 65537,
            "bounded unacknowledged artifact input"
        );
        return;
    }
    let namespace = spiralcore_transfer::hex(&authority.context().namespace().unwrap());
    let resources = ResourceProfile::SmallV1;
    // A separate cooperating endpoint in the test controller, explicitly not
    // another local child subdivision or a production host capacity grant.
    let pool = PayloadResourcePool::for_qualification(PayloadResourceLimits {
        max_active: 1,
        resident_bytes: 8 << 20,
        disk_bytes: 32 << 20,
    })
    .unwrap();
    let permit = pool.reserve_profile(resources).unwrap();
    let store = tempfile::tempdir().unwrap();
    let path = store.path().join("peer");
    let profile = Capabilities::small_v1()
        .negotiate(&Capabilities::small_v1())
        .unwrap();
    let sender = ObjectSender::new_with_resource_profile(
        ObjectMode::Whole,
        authority.context(),
        None,
        profile,
        resources,
    )
    .unwrap();
    let endpoint = ObjectEndpoint::open_with_resource_profile(
        &path,
        resources.receiver_limits(),
        authority.clone(),
        profile,
        resources,
    )
    .unwrap();
    let prepared = PreparedPayloadSession::new(
        authority,
        sender,
        endpoint,
        permit.with_owned_store(path.clone()).unwrap(),
    )
    .unwrap();
    let mut mapped = accept_enrolled_payload(tls, prepared, until).unwrap();
    let mut received = Vec::new();
    if matches!(case, Case::AttachClose | Case::AttachPoison) {
        let mut byte = [0u8; 1];
        assert_terminal_error(
            &mapped
                .read(&mut byte)
                .expect_err("incomplete setup cannot become application FIN"),
        );
    } else if matches!(case, Case::BlockedRead | Case::ExpiredJoin) {
        let mut byte = [0u8; 1];
        assert_cancelled_read(mapped.read(&mut byte));
    } else if case == Case::BlockedWrite {
        received.resize(payload().len(), 0);
        mapped.read_exact(&mut received).unwrap();
        assert_eq!(received, payload(), "exact target before blocked response");
    } else {
        (&mut mapped)
            .take(u64::try_from(payload().len() + 1).unwrap())
            .read_to_end(&mut received)
            .unwrap();
        assert_eq!(
            received,
            payload(),
            "setup artifacts are not application bytes"
        );
    }
    // These are the actual core publications at the peer, not nominal setup
    // counters or bytes reconstructed from the application stream.
    if !matches!(case, Case::AttachClose | Case::AttachPoison) {
        for artifact in [
            spiralcore_transfer::schema::fit(&[b"{\"kind\":\"flowmux\",\"value\":0}\n"]).unwrap(),
            spiralcore_transfer::shared_runtime::State::seeded(32)
                .unwrap()
                .encode()
                .unwrap(),
        ] {
            let object = spiralcore_transfer::hex(&spiralcore_transfer::object_id(&artifact));
            let mut file =
                std::fs::File::open(path.join(&namespace).join(format!("{object}.object")))
                    .expect("canonical verified setup publication");
            let mut stored = Vec::new();
            (&mut file)
                .take(65536 + 128)
                .read_to_end(&mut stored)
                .unwrap();
            assert!(stored.len() <= artifact.len() + 128);
            assert!(
                stored.ends_with(&artifact),
                "exact persisted artifact readback"
            );
        }
    }
    if case == Case::BlockedWrite {
        if let Err(error) = mapped.write_all(&received) {
            assert_terminal_error(&error);
        }
    } else if !matches!(
        case,
        Case::BlockedRead | Case::ExpiredJoin | Case::AttachClose | Case::AttachPoison
    ) {
        mapped.write_all(&received).unwrap();
        mapped.shutdown(Shutdown::Write).unwrap();
    }
    drop(mapped);
    if case == Case::Capacity {
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("overflow performed a second peer connection: {other:?}"),
        }
    }
    pool.close_admission().unwrap();
    assert!(
        pool.drained().unwrap(),
        "peer joined before reservation refund"
    );
    assert!(!path.exists(), "owned peer store removed after exact I/O");
}

pub fn child() {
    child_mode(Case::Duplex, |_, _| {}, |_, _| {});
}

pub fn child_owned() {
    child_owned_with(|_, _| {}, |_, _| {});
}

pub fn child_owned_with(
    install: impl FnOnce(&Arc<OwnedTcpRelays>, &PayloadResourcePool),
    observe: impl FnOnce(&Arc<OwnedTcpRelays>, &PayloadResourcePool),
) {
    let case = match std::env::var("MVM_INSTALLED_RESOURCES_FIXTURE")
        .unwrap()
        .as_str()
    {
        "blocked-guest-write" => Case::BlockedWrite,
        "blocked-upstream-read" => Case::BlockedRead,
        "expired-join" => Case::ExpiredJoin,
        "stalled-tls" => Case::StalledTls,
        "stalled-artifact" => Case::StalledArtifact,
        "owned-attach-close" => Case::AttachClose,
        "owned-attach-poison" => Case::AttachPoison,
        _ => Case::Capacity,
    };
    child_mode(case, install, observe);
}

fn child_mode(
    case: Case,
    install: impl FnOnce(&Arc<OwnedTcpRelays>, &PayloadResourcePool),
    observe: impl FnOnce(&Arc<OwnedTcpRelays>, &PayloadResourcePool),
) {
    // SAFETY: the original fixture reserves fd199 for its private protocol.
    assert!(unsafe { libc::dup2(199, 1) } >= 0);
    let mut child = InstalledEndpointChild::from_stdio().unwrap();
    let resources = InstalledEndpointResources::from_child(&mut child).unwrap();
    let relays = Some(OwnedTcpRelays::from_installed_resources(&resources).unwrap());
    if case != Case::Duplex {
        assert!(OwnedTcpRelays::from_installed_resources(&resources).is_err());
    }
    let factory = SpiralCorePayloadFactory::from_installed_resources(&resources)
        .unwrap()
        .unwrap();
    let store = resources.store_locator().unwrap().path.clone();
    let (program, lease, pool) = resources.into_parts();
    let InstalledEndpointProgram::Network(config) = program else {
        panic!("network profile")
    };
    let pool = pool.unwrap();
    install(relays.as_ref().unwrap(), &pool);
    let policy = config.network_policy.unwrap();
    let plan = config.admitted_network_plan.unwrap();
    let session_id = config.flowmux_identity.unwrap().session_id;
    let mapping = Arc::new(
        PayloadMappingConfig::new(&policy, plan)
            .unwrap()
            .with_factory(Arc::new(factory)),
    );
    let gate = mvm_hostd::supervisor::network_endpoint::build_egress_gate(&policy);
    let host_key = SigningKey::from_bytes(&HOST_SEED);
    let host_anchor = host_key.verifying_key();
    let guest_key = SigningKey::from_bytes(&GUEST_SEED);
    let guest_anchor = guest_key.verifying_key();
    let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();
    let send_buffer = if case == Case::BlockedWrite {
        Some(small_send_buffer(&host_stream))
    } else {
        None
    };
    let setup_observer = if matches!(case, Case::StalledTls | Case::StalledArtifact) {
        Some(UnixListener::bind(store.parent().unwrap().join("setup-seen.sock")).unwrap())
    } else {
        None
    };
    guest_stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    guest_stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    std::thread::scope(|scope| {
        let session_relays = relays.clone();
        let host = scope.spawn(move || {
            let mut host = FlowMuxSession::accept_with(
                host_stream,
                FlowMuxAccept::new(
                    &session_id,
                    host_key,
                    guest_anchor,
                    RegistryLimits::default(),
                    gate,
                )
                .with_payload_mapping(Some(mapping))
                .with_owned_tcp_relays(session_relays),
            )
            .unwrap();
            host.serve()
        });
        let (mut session, _) = Session::guest(&mut guest_stream, guest_key, &host_anchor).unwrap();
        send(
            &mut guest_stream,
            &mut session,
            Opcode::Hello,
            0,
            &Handshake::local("installed-fixture").encode(),
        );
        assert_eq!(receive(&mut guest_stream, &mut session).0, Opcode::HelloAck);
        send(
            &mut guest_stream,
            &mut session,
            Opcode::OpenTcp,
            1,
            format!("{TARGET}:443").as_bytes(),
        );
        if let Some(observer) = &setup_observer {
            let mut ready = libc::pollfd {
                fd: observer.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: arm the original fixture event before accepting its
            // bounded notification; no sleep-based readiness guess is used.
            assert!(unsafe { libc::poll(&mut ready, 1, 3000) } > 0);
            let (mut event, _) = observer.accept().unwrap();
            event
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut byte = [0u8; 1];
            event.read_exact(&mut byte).unwrap();
            assert_eq!(byte, [1]);
            assert_eq!(
                pool.snapshot().unwrap().active,
                u16::from(case == Case::StalledArtifact),
                "codec exists only after authenticated setup"
            );
            let joined = relays
                .as_ref()
                .unwrap()
                .close_and_join(Instant::now() + Duration::from_secs(2));
            eprintln!("stalled original setup cleanup: {joined:?}");
            let _ = guest_stream.shutdown(Shutdown::Both);
            drop(guest_stream);
            assert_cancelled_session(host.join().unwrap());
            joined.unwrap();
            return;
        }
        if case == Case::AttachClose {
            let mut byte = [0u8; 1];
            assert_cancelled_read(guest_stream.read(&mut byte));
            drop(guest_stream);
            assert_cancelled_session(host.join().unwrap());
            return;
        }
        if case == Case::AttachPoison {
            let refused = receive(&mut guest_stream, &mut session);
            assert_eq!((refused.0, refused.1), (Opcode::Refused, 1));
            drop(guest_stream);
            host.join().unwrap().unwrap();
            return;
        }
        let opened = receive(&mut guest_stream, &mut session);
        assert_eq!(
            opened.0,
            Opcode::Opened,
            "{}",
            String::from_utf8_lossy(&opened.2)
        );
        assert_eq!(pool.snapshot().unwrap().active, 1);
        if matches!(case, Case::BlockedRead | Case::ExpiredJoin) {
            if case == Case::ExpiredJoin {
                let error = relays
                    .as_ref()
                    .unwrap()
                    .close_and_join(Instant::now())
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                // The original group still owns its relay/wake and mapped
                // codec charge. Expiry is not a successful cleanup receipt.
                assert_eq!(pool.snapshot().unwrap().active, 1);
            }
            relays
                .as_ref()
                .unwrap()
                .close_and_join(Instant::now() + Duration::from_secs(2))
                .unwrap();
            drop(guest_stream);
            assert_cancelled_session(host.join().unwrap());
            return;
        }
        if case == Case::Capacity {
            send(
                &mut guest_stream,
                &mut session,
                Opcode::OpenTcp,
                3,
                format!("{TARGET}:443").as_bytes(),
            );
            let overflow = receive(&mut guest_stream, &mut session);
            assert_eq!((overflow.0, overflow.1), (Opcode::Refused, 3));
        }
        send(&mut guest_stream, &mut session, Opcode::Data, 1, &payload());
        send(&mut guest_stream, &mut session, Opcode::HalfClose, 1, &[]);
        if case == Case::BlockedWrite {
            observe_partial_large_frame(&mut guest_stream, &mut session, send_buffer.unwrap());
            relays
                .as_ref()
                .unwrap()
                .close_and_join(Instant::now() + Duration::from_secs(2))
                .unwrap();
            drop(guest_stream);
            assert_cancelled_session(host.join().unwrap());
            return;
        }
        let mut returned = Vec::new();
        loop {
            let (opcode, stream, bytes) = receive(&mut guest_stream, &mut session);
            assert_eq!(stream, 1);
            match opcode {
                Opcode::WindowUpdate => {}
                Opcode::Data => {
                    assert!(returned.len() + bytes.len() <= payload().len());
                    returned.extend_from_slice(&bytes);
                }
                Opcode::HalfClose => break,
                other => panic!("unexpected {other:?}: {}", String::from_utf8_lossy(&bytes)),
            }
        }
        assert_eq!(returned, payload(), "exact reverse application bytes");
        drop(guest_stream);
        host.join().unwrap().unwrap();
    });
    observe(relays.as_ref().unwrap(), &pool);
    if case == Case::AttachPoison {
        assert_eq!(
            pool.snapshot().unwrap().active,
            1,
            "uncertain original reader charge retained"
        );
        // Deliberately no Ready/Drained: only original process exit can release
        // this corrupted ledger's quarantined handles and inherited holder.
        std::process::exit(0);
    }
    if let Some(relays) = relays {
        let alias = relays.clone();
        relays
            .close_and_join(Instant::now() + Duration::from_secs(2))
            .unwrap();
        alias
            .close_and_join(Instant::now() + Duration::from_secs(2))
            .unwrap();
    }
    pool.close_admission().unwrap();
    assert!(
        pool.drained().unwrap(),
        "child reader joined and store cleaned"
    );
    assert_eq!(std::fs::read_dir(store).unwrap().count(), 0);
    lease.check_current().unwrap();
    finish_child(child, lease);
}

fn finish_child(
    mut child: InstalledEndpointChild,
    lease: mvm_vmm::host::network_endpoint_spawn::InstalledEndpointLease,
) -> ! {
    child
        .send_ready(Default::default(), Instant::now() + Duration::from_secs(2))
        .unwrap();
    let mut event = libc::pollfd {
        fd: child.control_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: bounded wait on the original parent control descriptor.
    assert!(unsafe { libc::poll(&mut event, 1, 3000) } > 0);
    assert!(lease.check_current().is_err());
    child
        .send_drained(Instant::now() + Duration::from_secs(2))
        .unwrap();
    std::process::exit(0);
}

fn small_send_buffer(stream: &UnixStream) -> usize {
    let requested: libc::c_int = 1024;
    // SAFETY: both values have the exact SOL_SOCKET integer ABI and the
    // descriptor remains borrowed from the original fixture socket.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&requested as *const libc::c_int).cast(),
                std::mem::size_of_val(&requested) as libc::socklen_t,
            )
        },
        0
    );
    let mut observed: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&observed) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&mut observed as *mut libc::c_int).cast(),
                &mut length,
            )
        },
        0
    );
    assert_eq!(length as usize, std::mem::size_of_val(&observed));
    let observed = usize::try_from(observed).unwrap();
    assert!(observed > 0 && observed + 64 < payload().len());
    observed
}

fn observe_partial_large_frame(stream: &mut UnixStream, session: &mut Session, send_buffer: usize) {
    for _ in 0..4 {
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        assert!(length > 0 && length <= 1 << 20);
        if length > send_buffer + 64 {
            let mut body = [0u8; 64];
            stream.read_exact(&mut body).unwrap();
            // The frame is deliberately incomplete; no authenticated frame or
            // returned write count is inferred from this physical progress.
            assert!(length - body.len() > send_buffer);
            return;
        }
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).unwrap();
        let sealed = mvm_core::net::session::SealedFrame::decode(&body).unwrap();
        let plain = session.open(&sealed).unwrap();
        let frame = mvm_contract::protocol::network_flow::decode(&plain).unwrap();
        assert_eq!(
            (frame.header.opcode, frame.header.stream_id),
            (Opcode::WindowUpdate, 1)
        );
    }
    panic!("no incomplete response frame observed");
}

fn assert_terminal_error(error: &std::io::Error) {
    use std::io::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionReset
            | ErrorKind::UnexpectedEof
            | ErrorKind::NotConnected
    ) {
        return;
    }
    if let Some(mapping) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<spiralcore_mvm_flowmux::Error>())
    {
        match mapping {
            spiralcore_mvm_flowmux::Error::Closed
            | spiralcore_mvm_flowmux::Error::Cancelled
            | spiralcore_mvm_flowmux::Error::Truncated => return,
            spiralcore_mvm_flowmux::Error::Io(inner) => return assert_terminal_error(inner),
            _ => {}
        }
    }
    panic!("expected physical cancellation, observed {error:?}");
}

fn assert_cancelled_read(result: std::io::Result<usize>) {
    match result {
        Ok(0) => {}
        Ok(bytes) => panic!("cancelled empty stream delivered {bytes} application bytes"),
        Err(error) => assert_terminal_error(&error),
    }
}

fn assert_cancelled_session(result: Result<(), mvm_hostd::supervisor::flowmux::FlowMuxError>) {
    match result {
        Ok(()) => {}
        Err(mvm_hostd::supervisor::flowmux::FlowMuxError::Transport(error)) => {
            assert_terminal_error(&error)
        }
        Err(error) => panic!("unexpected cancelled session outcome: {error:?}"),
    }
}

fn send(stream: &mut UnixStream, session: &mut Session, opcode: Opcode, id: u32, bytes: &[u8]) {
    let frame = mvm_contract::protocol::network_flow::encode(opcode, id, bytes).unwrap();
    write_sealed_frame(stream, &session.seal(&frame).unwrap()).unwrap();
}

fn receive(stream: &mut UnixStream, session: &mut Session) -> (Opcode, u32, Vec<u8>) {
    let sealed = read_sealed_frame(stream, 1 << 20).unwrap();
    let plain = session.open(&sealed).unwrap();
    let frame = mvm_contract::protocol::network_flow::decode(&plain).unwrap();
    (
        frame.header.opcode,
        frame.header.stream_id,
        frame.payload.to_vec(),
    )
}
