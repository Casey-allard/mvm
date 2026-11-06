#![cfg(unix)]

use anyhow::{Result, ensure};
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};
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
    verifying: ed25519_dalek::VerifyingKey,
}
impl Fixture {
    fn new() -> Self {
        let mut env = TestEnv::new();
        let home = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        env.set("MVM_HOME", home.path());
        env.set(
            "MVM_HOST_AGENT_PATH",
            std::env::var_os("OWNED_AGENT_TEST_BIN")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_mvm-host-agent").into()),
        );
        env.set(
            "MVM_SIGNER_HELPER_PATH",
            std::env::var_os("OWNED_SIGNER_TEST_BIN")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_mvm-signer-helper").into()),
        );
        env.set("MVM_HOST_AGENT_DAEMON", "1");
        let verifying = mvm_hostd::audit::host_keypair::load_or_init_at(&config::mvm_keys_dir())
            .unwrap()
            .verifying;
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
            verifying,
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
fn emit(socket: &Path, event: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
        mvm_hostd::broker::server::write_frame(&mut stream, &ServiceCall {
            service: ServiceId::parse("host.audit.v1").unwrap(), verb: "emit".into(), correlation_id: CorrelationId::new("guest-ignored"),
            payload: serde_json::json!({ "ts":"2026-11-03T00:00:00Z", "fields": { "event":event } }), capability: None,
        }).await.unwrap();
        let response: ServiceResponse = mvm_hostd::broker::server::read_frame(&mut stream, 65536).await.unwrap();
        assert!(matches!(response, ServiceResponse::Ok { .. }), "{response:?}");
    });
}

#[cfg(target_os = "linux")]
fn actual_stack_and_holder(pid: u32, holder: &Path) {
    use std::os::unix::fs::MetadataExt;
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let stack: Vec<_> = limits
        .lines()
        .find(|line| line.starts_with("Max stack size"))
        .unwrap()
        .split_whitespace()
        .collect();
    assert_eq!(&stack[3..5], &["8388608", "8388608"]);
    assert!(
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .count()
            <= 5
    );
    let expected = holder.metadata().unwrap();
    let mut found = false;
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .take(128)
    {
        let entry = entry.unwrap();
        if let Ok(meta) = entry.path().metadata()
            && (meta.dev(), meta.ino()) == (expected.dev(), expected.ino())
        {
            let info = std::fs::read_to_string(format!(
                "/proc/{pid}/fdinfo/{}",
                entry.file_name().to_string_lossy()
            ))
            .unwrap();
            found |= info.contains("FLOCK") && info.contains("READ");
        }
    }
    assert!(
        found,
        "actual original shared holder is present in child {pid}"
    );
}

#[test]
fn owned_host_agent_has_distinct_sendable_owner_registrar_and_registration() {
    fn send<T: Send>() {}
    send::<OwnedHostAgent>();
    send::<OwnedHostAgentRegistrar>();
    send::<OwnedVmRegistration>();
    let _: fn(OwnedHostAgentInputs) -> anyhow::Result<OwnedHostAgent> = OwnedHostAgent::spawn;
}

#[test]
fn two_signed_registrations_share_original_child_and_stop_independently() {
    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let original = agent.child_id().unwrap();
    let registrar = agent.registrar();
    let sibling = registrar.clone();
    let (a, sa) = fixture.vm("vm-1");
    let (b, sb) = fixture.vm("vm-2");
    let mut first = register(&registrar, "vm-1", &a, &sa).unwrap();
    let mut second = register(&sibling, "vm-2", &b, &sb).unwrap();
    assert_eq!(agent.child_id().unwrap(), original);
    #[cfg(target_os = "linux")]
    {
        actual_stack_and_holder(original, &fixture.lease.path().join("holders"));
        let children =
            std::fs::read_to_string(format!("/proc/{original}/task/{original}/children")).unwrap();
        let children: Vec<u32> = children
            .split_whitespace()
            .map(|pid| pid.parse().unwrap())
            .collect();
        assert_eq!(
            children.len(),
            1,
            "one actual signer, no worker wrapper or per-VM fork"
        );
        actual_stack_and_holder(children[0], &fixture.lease.path().join("holders"));
    }
    emit(&sa, "first");
    emit(&sb, "second");
    first.shutdown().unwrap();
    assert!(!sa.exists());
    emit(&sb, "second-after-first-stop");
    let mut replacement = register(&registrar, "vm-1", &a, &sa).unwrap();
    first.shutdown().unwrap();
    drop(first);
    emit(&sa, "replacement-survives-retired-guard");
    replacement.shutdown().unwrap();
    second.shutdown().unwrap();
    agent.shutdown().unwrap();
    agent.shutdown().unwrap();
    for vm in ["vm-1", "vm-2"] {
        assert_eq!(
            mvm_hostd::audit_signer::verify::verify_workload_chain(
                &config::workload_audit_path("local", vm),
                &fixture.verifying
            )
            .unwrap(),
            2
        );
    }
    assert!(!config::host_agent_control_socket("local").exists());
    assert!(!config::host_agent_signer_helper_socket("local").exists());
    assert!(
        !config::host_agent_dir("local")
            .join("registrations.json")
            .exists()
    );
    assert!(register(&registrar, "vm-1", &a, &sa).is_err());
}

#[test]
fn busy_final_stop_closes_shared_admission_but_allows_owned_cleanup() {
    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let registrar = agent.registrar();
    let (a, sa) = fixture.vm("vm-1");
    let (b, sb) = fixture.vm("vm-2");
    let mut first = register(&registrar, "vm-1", &a, &sa).unwrap();
    assert!(agent.shutdown().is_err());
    assert!(register(&registrar.clone(), "vm-2", &b, &sb).is_err());
    assert!(!sb.exists());
    emit(&sa, "survives-busy-stop");
    fixture.parent.current.store(false, Ordering::Release);
    first.shutdown().unwrap();
    agent.shutdown().unwrap();
}

#[test]
fn original_registrar_query_checks_tenant_holder_parent_and_closed_admission() {
    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let registrar = agent.registrar();
    let original = agent.child_id().unwrap();
    registrar.check_current_for_tenant("local").unwrap();
    assert!(registrar.check_current_for_tenant("foreign").is_err());
    std::fs::write(
        fixture.lease.path().join("state"),
        b"changed original state",
    )
    .unwrap();
    assert!(registrar.check_current_for_tenant("local").is_err());
    std::fs::write(
        fixture.lease.path().join("state"),
        b"original fixture state",
    )
    .unwrap();
    registrar.check_current_for_tenant("local").unwrap();
    assert_eq!(agent.child_id().unwrap(), original);
    fixture.parent.current.store(false, Ordering::Release);
    assert!(registrar.check_current_for_tenant("local").is_err());
    // Cleanup has its original owner and must remain possible after revocation.
    agent.shutdown().unwrap();
    assert!(registrar.check_current_for_tenant("local").is_err());
    assert!(!config::host_agent_control_socket("local").exists());
    assert!(!config::host_agent_signer_helper_socket("local").exists());
}

#[test]
fn preexisting_unowned_evidence_and_parent_refusal_have_no_spawn_effects() {
    let fixture = Fixture::new();
    fixture.parent.current.store(false, Ordering::Release);
    assert!(OwnedHostAgent::spawn(fixture.inputs()).is_err());
    assert!(!config::host_agent_dir("local").exists());
    fixture.parent.current.store(true, Ordering::Release);
    mvm_core::private_fs::create_owned_private_dir(config::host_agent_root()).unwrap();
    mvm_core::private_fs::create_owned_private_dir(config::host_agent_dir("local")).unwrap();
    let marker = config::host_agent_dir("local").join("daemon.pid");
    std::fs::write(&marker, b"unowned-evidence").unwrap();
    assert!(OwnedHostAgent::spawn(fixture.inputs()).is_err());
    assert_eq!(std::fs::read(marker).unwrap(), b"unowned-evidence");
    assert!(!config::host_agent_control_socket("local").exists());
    assert!(!config::host_agent_signer_helper_socket("local").exists());
}

#[test]
fn owned_journal_replacement_keeps_cleanup_uncertain_until_original_is_restored() {
    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let registrar = agent.registrar();
    let (state, socket) = fixture.vm("vm-1");
    let mut registration = register(&registrar, "vm-1", &state, &socket).unwrap();
    let journal = config::host_agent_dir("local").join("registrations.json");
    let original = journal.with_file_name("retained-original-journal");
    let foreign = journal.with_file_name("retained-foreign-evidence");
    std::fs::rename(&journal, &original).unwrap();
    std::fs::write(&journal, b"foreign replacement evidence").unwrap();
    assert!(registration.shutdown().is_err());
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        b"foreign replacement evidence"
    );
    assert!(agent.shutdown().is_err());
    let holder = File::open(fixture.lease.path().join("holders")).unwrap();
    assert!(
        rustix::fs::flock(
            &holder,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        )
        .is_err()
    );
    std::fs::rename(&journal, &foreign).unwrap();
    std::fs::rename(&original, &journal).unwrap();
    registration.shutdown().unwrap();
    agent.shutdown().unwrap();
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"foreign replacement evidence"
    );
    drop(registration);
    drop(registrar);
    drop(agent);
    rustix::fs::flock(
        &holder,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
}

#[test]
fn owned_telemetry_uses_actual_canonical_handshake_and_original_host_key() {
    use mvm_core::net::telemetry::{TelemetryReceiver, TelemetrySender};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let host_key = fixture.verifying;
    let guest_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let guest_public = guest_key.verifying_key();
    let (mut host_io, mut guest_io) = UnixStream::pair().unwrap();
    for stream in [&host_io, &guest_io] {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }
    let guest = std::thread::spawn(move || {
        TelemetrySender::connect(&mut guest_io, guest_key, &host_key).unwrap()
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = mvm_hostd::audit_signer::helper_client::SignerHelperClient::new(
        config::host_agent_signer_helper_socket("local"),
    );
    let receiver = TelemetryReceiver::connect_authenticated(
        &mut host_io,
        &host_key,
        &guest_public,
        |hello, ack| {
            runtime
                .block_on(client.sign_telemetry_handshake(
                    hello,
                    ack,
                    &host_key,
                    Duration::from_secs(5),
                ))
                .map_err(|_| {
                    mvm_core::net::session::SessionError::InvalidHandshake(
                        "owned telemetry signer refused".into(),
                    )
                })
        },
    );
    let sender = guest.join().unwrap();
    assert!(
        receiver.is_ok(),
        "owned required telemetry handshake must remain authenticated"
    );
    drop((sender, receiver));
    agent.shutdown().unwrap();
}

#[test]
fn installed_signer_requires_the_original_current_registration() {
    use mvm_vmm::host::network_endpoint_spawn::InstalledHostServices;

    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let registrar = agent.registrar();
    let sibling = registrar.clone();
    let (state, socket) = fixture.vm("vm-1");
    let (other_state, other_socket) = fixture.vm("vm-2");
    let mut registration = register(&registrar, "vm-1", &state, &socket).unwrap();
    let audit = [ServiceId::parse("host.audit.v1").unwrap()];
    let time = [ServiceId::parse("host.time.v1").unwrap()];
    let params = || HostAgentServicesParams {
        workload_id: "vm-1",
        tenant_id: Some("local"),
        vm_name: "vm-1",
        state_dir: &state,
        broker_listen_socket: &socket,
        services: &audit,
        capability_bindings: &[],
        service_proxies: &[],
    };
    #[cfg(target_os = "macos")]
    if mvm_vmm::host::host_agent_spawn::OwnedAuditSideband::supported().unwrap()
        == mvm_vmm::host::host_agent_spawn::OwnedAuditSideband::Unavailable
    {
        let error = registration
            .prepare_endpoint_audit(&registrar, &params())
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::Unsupported
        );
    }
    let original_anchor = fixture.verifying.to_bytes();
    let foreign_anchor = ed25519_dalek::SigningKey::from_bytes(&[17; 32])
        .verifying_key()
        .to_bytes();
    {
        let original = InstalledHostServices::new(&sibling, &registration, params()).unwrap();
        original
            .check_endpoint_binding("vm-1", "local", &state)
            .unwrap();
        original
            .check_flowmux_host_anchor(&original_anchor)
            .unwrap();
        assert!(original.check_flowmux_host_anchor(&foreign_anchor).is_err());
        assert!(
            original
                .check_endpoint_binding("vm-1", "local", &other_state)
                .is_err()
        );

        let mut changed = params();
        changed.workload_id = "changed";
        assert!(InstalledHostServices::new(&registrar, &registration, changed).is_err());
        let mut changed = params();
        changed.broker_listen_socket = &other_socket;
        assert!(InstalledHostServices::new(&registrar, &registration, changed).is_err());
        let mut changed = params();
        changed.services = &time;
        assert!(InstalledHostServices::new(&registrar, &registration, changed).is_err());

        fixture.parent.current.store(false, Ordering::Release);
        assert!(
            original
                .check_flowmux_host_anchor(&original_anchor)
                .is_err()
        );
        fixture.parent.current.store(true, Ordering::Release);
    }
    registration.shutdown().unwrap();
    let mut replacement = register(&registrar, "vm-1", &state, &socket).unwrap();
    assert!(InstalledHostServices::new(&registrar, &registration, params()).is_err());
    InstalledHostServices::new(&registrar, &replacement, params())
        .unwrap()
        .check_flowmux_host_anchor(&original_anchor)
        .unwrap();
    replacement.shutdown().unwrap();
    agent.shutdown().unwrap();
}

#[test]
fn installed_runtime_broker_uses_the_original_registrar_even_without_services() {
    use mvm_runtime::workload_runner::{
        BrokerRegisterRequest, BrokerRegistrar, RealBrokerRegistrar,
    };

    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let registrar = agent.registrar();
    let (state, socket) = fixture.vm("vm-1");
    let request = BrokerRegisterRequest {
        vm_name: "vm-1",
        state_dir: &state,
        tenant: Some("local"),
        broker_listen_socket: Some(&socket),
        services: &[],
        capability_bindings: &[],
        service_proxies: &[],
    };

    let mut broker = RealBrokerRegistrar
        .register_installed(&request, &registrar)
        .unwrap();
    assert!(socket.exists());
    assert!(register(&registrar, "vm-1", &state, &socket).is_err());
    broker.defuse();
    drop(broker);
    assert!(!socket.exists());
    let mut replacement = register(&registrar, "vm-1", &state, &socket).unwrap();
    replacement.shutdown().unwrap();
    agent.shutdown().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn original_registered_audit_event_is_claimed_once_and_pins_cleanup() {
    let fixture = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(fixture.inputs()).unwrap();
    let registrar = agent.registrar();
    let (state, socket) = fixture.vm("vm-1");
    let mut registration = register(&registrar, "vm-1", &state, &socket).unwrap();
    let audit = [ServiceId::parse("host.audit.v1").unwrap()];
    let params = || HostAgentServicesParams {
        workload_id: "vm-1",
        tenant_id: Some("local"),
        vm_name: "vm-1",
        state_dir: &state,
        broker_listen_socket: &socket,
        services: &audit,
        capability_bindings: &[],
        service_proxies: &[],
    };

    let mut changed = params();
    changed.workload_id = "foreign";
    assert!(
        registration
            .prepare_endpoint_audit(&registrar, &changed)
            .is_err()
    );

    let capability = registration
        .prepare_endpoint_audit(&registrar, &params())
        .unwrap();
    capability.check_current().unwrap();
    assert_eq!(capability.vm(), "vm-1");
    assert_eq!(capability.tenant(), "local");
    assert_eq!(
        capability.socket(),
        config::host_agent_signer_helper_socket("local")
    );
    assert!(capability.signer_pid() > 1);
    assert!(
        registration
            .prepare_endpoint_audit(&registrar, &params())
            .is_err()
    );

    assert!(registration.shutdown().is_err());
    capability.check_current().unwrap();
    drop(capability);
    registration.shutdown().unwrap();
    agent.shutdown().unwrap();
}

#[cfg(target_os = "linux")]
mod registered_prepare {
    use super::*;
    use anyhow::Context;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use mvm_core::{
        host_lifetime::{
            CoreCurrentParentPermit, EndpointPartitionGuard, EndpointPartitionLimits,
            EndpointPartitionProjection, EndpointStoreLocator, HostLaunchBinding,
            HostLifetimeInputs, PreparedEndpointHandoff, PreparedEndpointPartition,
            PreparedHostLifetime,
        },
        plan::{PlanId, compute_plan_id, sign_plan, test_support::PlanFixture},
        policy::network_policy::{HostPort, NetworkPolicy},
        vm_backend::{BackendKind, VmStartConfig},
    };
    use mvm_vmm::host::network_endpoint_spawn::{
        AdmittedNetworkPlan, EgressProxySpawnConfig, EndpointLifetime, EndpointTransport,
        FlowMuxIdentitySpawnConfig, InstalledHostServices, SubstitutionSpawnParams,
        spawn_network_endpoint_installed_registered,
    };
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
        retained: bool,
    ) -> Result<(PreparedEndpointHandoff, PlanId, Arc<Guard>)> {
        let mut plan = PlanFixture::new().workload("vm-1").build();
        plan.plan_id = compute_plan_id(&plan);
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
                host_metadata_bytes: if retained { 128 << 20 } else { 32 << 20 },
                // Experimental controller fixture includes main8MiB + original
                // session2MiB + collector6MiB + relay2MiB + reader2MiB supplements.
                // This is not a Root production profile or capacity claim.
                host_stack_bytes: 24 << 20,
                cache_disk_bytes: (16 << 20)
                    + if retained {
                        mvm_vmm::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP
                            + mvm_core::runtime_state_protection::INSTALLED_TELEMETRY_SIDECAR_BYTES
                    } else {
                        0
                    },
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
            ..Default::default()
        };
        anchor.bind_to_config(&mut config)?;
        config.plan_json = Some(serde_json::to_string(&sign_plan(
            &plan,
            &SigningKey::from_bytes(&[8; 32]),
            "fixture",
        ))?);
        anchor.bind_admitted(&config, BackendKind::Firecracker, &plan)?;
        let guard = Arc::new(Guard {
            projection: facts.clone(),
            retained: retained.then(|| {
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
            plan.plan_id,
            guard,
        ))
    }

    #[test]
    fn signed_parent_delivers_original_audit_and_records_to_canonical_child() -> Result<()> {
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
        let registrar = agent.registrar();
        let (state, socket) = fixture.vm("vm-1");
        let mut registration = register(&registrar, "vm-1", &state, &socket)?;
        let store = state.join("codec-functional-store");
        config::create_private_dir(&store)?;
        let (handoff, plan_id, guard) = handoff(&holder, &store, &state, true)?;
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
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("peer.example", 443)])
            .with_payload_mapping(Some(CooperatingPayloadPolicy::new(vec![
                CooperatingTcpPeer {
                    host: "peer.example".into(),
                    port: 443,
                    server_name: "peer.example".into(),
                    spki_sha256: [5; 32],
                    profile: PayloadMappingProfile::SpiralCoreObjectStreamSmallV1,
                },
            ])?));
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
            .admitted_network_plan(AdmittedNetworkPlan {
                plan_id,
                plan_version: 1,
                plan_nonce: mvm_core::plan::Nonce::from_bytes([4; 16]),
                bundle_sha256: "11".repeat(32),
                tenant_id: "local".into(),
                instance_id: "vm-1".into(),
                policy_sha256: mvm_core::policy::network_policy::content_sha256(&policy),
            })
            .network_limits(Default::default())
            .ingress(&[])
            .flowmux_identity(FlowMuxIdentitySpawnConfig {
                session_id: hex::encode([3; 32]),
                host_signing_key_base64: STANDARD.encode([9; 32]),
                guest_verifying_key_base64: STANDARD
                    .encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
            })
            .build()?;

        let error = match spawn_network_endpoint_installed_registered(params, handoff, &original) {
            Ok(_) => anyhow::bail!("endpoint published readiness before controller startup"),
            Err(error) => error,
        };
        drop(error);
        let log = File::open(state.join("network-endpoint.stderr.log"))?;
        let mut diagnostics = String::new();
        log.take(8192).read_to_string(&mut diagnostics)?;
        ensure!(
            diagnostics.contains("installed endpoint controller unavailable"),
            "real child did not adopt its original Prepare: {diagnostics}"
        );
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
        drop(original);
        registration.shutdown()?;
        agent.shutdown()?;
        Ok(())
    }
}
