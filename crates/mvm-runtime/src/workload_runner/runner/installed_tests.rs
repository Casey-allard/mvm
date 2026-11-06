use super::*;
use crate::driver::{DuplexStream, MockDriver};
use mvm_core::host_lifetime::{
    HostLaunchBinding, HostLeaseExpectation, HostLifetimeInputs, PreparedHostLifetime,
};
use mvm_core::plan::{sign_plan, test_support::PlanFixture};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};

struct NativeDriver {
    inner: MockDriver,
    dropped: Arc<AtomicUsize>,
    attached: Arc<AtomicUsize>,
}
struct NativeVm {
    inner: Box<dyn RunningVm>,
    _holder: Option<mvm_core::host_lifetime::PreparedHostLifetimeLease>,
    dropped: Arc<AtomicUsize>,
}
impl Drop for NativeVm {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl RunningVm for NativeVm {
    fn id(&self) -> &VmId {
        self.inner.id()
    }
    fn wait(&self) -> Result<VmExitStatus> {
        self.inner.wait()
    }
    fn kill(&self) -> Result<()> {
        self.inner.kill()
    }
    fn pause(&self) -> Result<()> {
        self.inner.pause()
    }
    fn resume(&self) -> Result<()> {
        self.inner.resume()
    }
    fn status(&self) -> Result<VmStatus> {
        self.inner.status()
    }
    fn vsock_connect(&self, port: u32) -> Result<Box<dyn DuplexStream>> {
        self.inner.vsock_connect(port)
    }
}
impl VmmDriver for NativeDriver {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn kind(&self) -> BackendKind {
        self.inner.kind()
    }
    fn is_available(&self) -> Result<bool> {
        self.inner.is_available()
    }
    fn capabilities(&self) -> VmCapabilities {
        self.inner.capabilities()
    }
    fn security_profile(&self) -> BackendSecurityProfile {
        self.inner.security_profile()
    }
    fn workload_base_bootargs(&self, disk: bool) -> String {
        self.inner.workload_base_bootargs(disk)
    }
    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        self.inner.guest_channel_info(id)
    }
    fn boot(&self, spec: &crate::driver::VmmSpec) -> Result<Box<dyn RunningVm>> {
        Ok(Box::new(NativeVm {
            inner: self.inner.boot(spec)?,
            _holder: None,
            dropped: self.dropped.clone(),
        }))
    }
    fn attach(&self, _id: &VmId) -> Result<Box<dyn RunningVm>> {
        self.attached.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("a reconstructed handle is not the original fixture")
    }
    fn supports_host_lifetime(&self) -> bool {
        true
    }
    fn boot_custodied_with_host_lifetime(
        &self,
        spec: &crate::driver::VmmSpec,
        _kernel: Option<&mvm_vmm::host::restore_image::VerifiedRestoreFile>,
        disks: mvm_vmm::driver::prepared_disks::PreparedWritableDisks,
        lease: mvm_core::host_lifetime::PreparedHostLifetimeLease,
        _binding: &mvm_core::host_lifetime::HostLaunchBinding,
    ) -> Result<Box<dyn RunningVm>> {
        assert!(disks.is_empty());
        Ok(Box::new(NativeVm {
            inner: self.inner.boot(spec)?,
            _holder: Some(lease),
            dropped: self.dropped.clone(),
        }))
    }
}
struct NoEndpoint;
struct FixturePermit(HostLaunchBinding);
impl mvm_core::host_lifetime::CoreCurrentParentPermit for FixturePermit {
    fn check_current(&self, binding: &HostLaunchBinding) -> Result<()> {
        anyhow::ensure!(binding == &self.0, "foreign fixture parent");
        Ok(())
    }
}
impl NetworkEndpointSpawner for NoEndpoint {
    fn spawn_installed(
        &self,
        _: &NetworkEndpointSpawnRequest<'_>,
        _: &VmStartConfig,
        _: Option<&mvm_vmm::host::host_agent_spawn::OwnedHostAgentRegistrar>,
    ) -> Result<InstalledSpawnedEndpoint> {
        // This sentinel driver fixture deliberately has no helper effects;
        // it does not establish production endpoint or telemetry support.
        Ok(InstalledSpawnedEndpoint {
            egress_uds: None,
            identity_drive: None,
            owner: None,
            telemetry: false,
        })
    }
    fn spawn(&self, _: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
        anyhow::bail!("fixture grants no network")
    }
    fn prepare_identity(&self, _: &NetworkEndpointSpawnRequest<'_>) -> Result<Option<PathBuf>> {
        Ok(None)
    }
}
struct NoBroker;
impl BrokerRegistrar for NoBroker {
    fn register(&self, _: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        Ok(BrokerGuard::defused())
    }
}

#[test]
fn owned_native_handle_survives_canonical_runner_start_return() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    env.isolate_mvm_home(root.path());
    let state = root.path().join(".state");
    std::fs::write(&state, b"a").unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.path().join("holders.lock"))
        .unwrap();
    let rootfs = root.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"rootfs").unwrap();
    let mut sidecar =
        mvm_build::builder_vm::GuestSidecar::for_oci_run("original-native", false, true);
    // A synthetic baked-protocol image for MockDriver; this exercises handle
    // custody, not real runtime artifacts or a bootable native guest.
    sidecar.protocol_version = mvm_agentd::vsock::PROTOCOL_VERSION.try_into().unwrap();
    sidecar.write_to_dir(root.path()).unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let attached = Arc::new(AtomicUsize::new(0));
    let driver = NativeDriver {
        inner: MockDriver::default(),
        dropped: dropped.clone(),
        attached: attached.clone(),
    };
    let backend = driver.kind();
    let anchor = PreparedHostLifetime::bind(
        HostLifetimeInputs {
            directory: File::open(root.path()).unwrap(),
            holder,
            expected: HostLeaseExpectation {
                state_name: ".state".into(),
                state_bytes: 1,
                state_sha256: hex::decode(
                    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                absent_names: [".state.intent".into(), ".state.next".into()],
            },
            binding: HostLaunchBinding {
                installation: [1; 32],
                profile: [2; 32],
                generation: 1,
                grant_serial: 1,
                vm_name: "original-native".into(),
                backend,
                cpus: 1,
                memory_mib: 128,
            },
        },
        (),
    )
    .unwrap()
    .into_anchor();
    let mut config = VmStartConfig {
        name: "original-native".into(),
        rootfs_path: rootfs.display().to_string(),
        cpus: 1,
        memory_mib: 128,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = PlanFixture::new().runtime_profile("mock").build();
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    config.plan_json = Some(
        serde_json::to_string(&sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
            "test",
        ))
        .unwrap(),
    );
    anchor.bind_admitted(&config, backend, &plan).unwrap();
    anchor
        .bind_parent_permit(
            &config,
            backend,
            Arc::new(FixturePermit(anchor.binding().clone())),
        )
        .unwrap();
    let runner = WorkloadRunner::new(driver, NoEndpoint, NoBroker);
    // An installed mapped workload must not accept an anchor preinserted by
    // a caller. The genuine signer is selected at original endpoint startup.
    use mvm_contract::policy::network_policy::{
        CooperatingPayloadPolicy, CooperatingTcpPeer, PayloadMappingProfile,
    };
    let mut injected_config = config.clone();
    injected_config.network_policy =
        NetworkPolicy::allow_list(vec![mvm_core::policy::network_policy::HostPort::new(
            "peer.example",
            443,
        )])
        .with_payload_mapping(Some(
            CooperatingPayloadPolicy::new(vec![CooperatingTcpPeer {
                host: "peer.example".into(),
                port: 443,
                server_name: "peer.example".into(),
                spki_sha256: [5; 32],
                profile: PayloadMappingProfile::SpiralCoreObjectStreamSmallV1,
            }])
            .unwrap(),
        ));
    let state_dir = vm_state_dir(&config.name);
    mvm_core::config::create_private_dir(&state_dir).unwrap();
    let keys = mvm_core::config::mvm_keys_dir();
    mvm_core::config::create_private_dir(&keys).unwrap();
    let signer = keys.join(mvm_vmm::host::broker_services_spawn::HOST_SIGNER_PUB);
    std::fs::write(
        &signer,
        ed25519_dalek::SigningKey::from_bytes(&[19; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let render = |config| cmdline::runner_cmdline(config, &state_dir, |_| "console=ttyS0".into());
    assert!(mvm_agentd::vsock::host_signer_pub_token(&render(&config)).is_some());
    assert!(mvm_agentd::vsock::host_signer_pub_token(&render(&injected_config)).is_none());
    std::fs::remove_file(signer).unwrap();
    let redaction = RedactionPolicy::default();
    let injected = WorkloadLaunchInputs {
        config: &injected_config,
        tenant: "local",
        secrets: &[],
        redaction: &redaction,
        network_policy: &injected_config.network_policy,
        cmdline: format!(
            "console=ttyS0 mvm.host_signer_pub={}",
            hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[19; 32])
                    .verifying_key()
                    .to_bytes()
            )
        ),
    };
    let refused = runner
        .start_workload(&injected)
        .err()
        .expect("injected signer");
    assert!(
        refused.to_string().contains("unbound host signer anchor"),
        "{refused:#}"
    );
    let mismatched = WorkloadLaunchInputs {
        config: &config,
        cmdline: injected.cmdline.clone(),
        ..injected
    };
    let refused = runner
        .start_workload(&mismatched)
        .err()
        .expect("policy mismatch");
    assert!(
        refused
            .to_string()
            .contains("installed endpoint policy differs"),
        "{refused:#}"
    );
    let id = VmId(config.name.clone());
    assert!(!installed::marker(&id).exists());
    assert!(runner.installed.find(&id).unwrap().is_none());
    runner.start(&config).unwrap();
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "start discarded the actual original native handle"
    );
    assert_eq!(attached.load(Ordering::SeqCst), 0);
    assert!(
        runner.status(&id).is_ok(),
        "owned status uses the original handle"
    );
    assert!(
        runner.start(&config).is_err(),
        "same identity cannot reserve another slot"
    );
    assert!(
        runner.stop_owned(&id, &anchor).is_err(),
        "MockDriver cannot fabricate native exit proof"
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "missing exit proof retains original custody"
    );
    let other = WorkloadRunner::new(
        NativeDriver {
            inner: MockDriver::default(),
            dropped: dropped.clone(),
            attached: attached.clone(),
        },
        NoEndpoint,
        NoBroker,
    );
    assert!(
        other.status(&id).is_err(),
        "a different runner cannot attach through an installed marker"
    );
    assert!(other.stop_owned(&id, &anchor).is_err());
    assert_eq!(attached.load(Ordering::SeqCst), 0);
    drop(runner);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "controller drop quarantines unconfirmed custody"
    );
}
