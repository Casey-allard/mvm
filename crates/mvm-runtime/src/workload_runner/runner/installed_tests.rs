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

struct ControlledReport {
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl mvm_vmm::driver::OriginalWorkloadReport for ControlledReport {
    fn wait_until(&self, until: std::time::Instant) -> Result<VmExitStatus> {
        let remaining = until
            .checked_duration_since(std::time::Instant::now())
            .context("expired fixture wait")?;
        self.entered.send(())?;
        self.release.lock().unwrap().recv_timeout(remaining)?;
        Ok(VmExitStatus {
            code: Some(19),
            success: false,
        })
    }
}
struct NativeDriver {
    report: Option<Arc<ControlledReport>>,
    inner: MockDriver,
    dropped: Arc<AtomicUsize>,
    attached: Arc<AtomicUsize>,
    dispatched: Arc<AtomicUsize>,
}
struct NativeVm {
    report: Option<Arc<ControlledReport>>,
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
    fn wait_with_deadline(&self, until: std::time::Instant) -> Result<VmExitStatus> {
        self.original_workload_report()
            .context("no report")?
            .wait_until(until)
    }
    fn original_workload_report(&self) -> Option<Arc<dyn mvm_vmm::driver::OriginalWorkloadReport>> {
        self.report.as_ref().map(|report| Arc::clone(report) as _)
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
            report: self.report.clone(),
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
        files: mvm_vmm::driver::prepared_disks::PreparedBootFiles<'_>,
        lease: mvm_core::host_lifetime::PreparedHostLifetimeLease,
        _binding: &mvm_core::host_lifetime::HostLaunchBinding,
    ) -> Result<Box<dyn RunningVm>> {
        self.dispatched.fetch_add(1, Ordering::SeqCst);
        assert!(files.writable.is_empty());
        Ok(Box::new(NativeVm {
            inner: self.inner.boot(spec)?,
            report: self.report.clone(),
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
        _: Option<&mvm_vmm::host::network_endpoint_spawn::InstalledHostServices<'_>>,
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

fn fixture(
    portable: bool,
) -> (
    mvm_core::util::test_env::TestEnv,
    tempfile::TempDir,
    NativeDriver,
    VmStartConfig,
    Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
) {
    fixture_with_collector(portable, false)
}

fn fixture_with_collector(
    portable: bool,
    collector: bool,
) -> (
    mvm_core::util::test_env::TestEnv,
    tempfile::TempDir,
    NativeDriver,
    VmStartConfig,
    Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
) {
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
        report: None,
        dropped: dropped.clone(),
        attached: attached.clone(),
        dispatched: Arc::new(AtomicUsize::new(0)),
    };
    let backend = driver.kind();
    use mvm_core::plan::{KeyId, PlanArtifact};
    let portable_pin =
        portable.then(|| PlanArtifact::new("a".repeat(64), &[7; 64], KeyId("test".into())));
    let prepared = PreparedHostLifetime::bind(
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
    .unwrap();
    let prepared = match &portable_pin {
        Some(pin) => prepared
            .with_portable_archive(pin.clone(), std::num::NonZeroU64::new(4).unwrap())
            .unwrap(),
        None => prepared,
    };
    let anchor = prepared.into_anchor();
    let mut config = VmStartConfig {
        name: "original-native".into(),
        rootfs_path: rootfs.display().to_string(),
        cpus: 1,
        memory_mib: 128,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = PlanFixture::new().runtime_profile("mock").build();
    if collector {
        config.network_policy = NetworkPolicy::deny_all();
        plan.asset_identities.push(
            mvm_core::plan::AssetIdentity::new(
                mvm_core::plan::AssetKind::Policy,
                "network_policy",
                mvm_core::policy::network_policy::content_sha256(&config.network_policy),
            )
            .unwrap(),
        );
    }
    if let Some(pin) = portable_pin {
        config.legacy_portable_runtime = Some(mvm_core::vm_backend::LegacyPortableRuntimeProof {
            archive: root.path().join("missing.mvmpkg"),
            pin: pin.clone(),
            manifest_sha256: "b".repeat(64),
            arch: mvm_core::arch::GuestArch::host(),
        });
        plan.bundle = Some(pin);
    }
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
    (env, root, driver, config, anchor)
}

#[test]
fn deny_all_installed_collector_uses_the_original_registered_host_anchor() {
    let (_env, _root, _driver, mut config, _anchor) = fixture_with_collector(false, true);
    assert!(config.network_policy.payload_mapping().is_none());
    assert!(mvm_vmm::host::cmdline::uses_installed_payload_anchor(
        &config
    ));
    config.host_lifetime = None;
    assert!(!mvm_vmm::host::cmdline::uses_installed_payload_anchor(
        &config
    ));
}

#[test]
fn unselected_installed_deny_all_does_not_select_a_registered_collector() {
    let (_env, _root, _driver, config, _anchor) = fixture(false);
    assert_eq!(config.network_policy, NetworkPolicy::deny_all());
    assert!(!mvm_vmm::host::cmdline::uses_installed_payload_anchor(
        &config
    ));
}

#[test]
fn selected_installed_collector_refuses_an_unsupported_spawner_before_dispatch() {
    let (_env, _root, driver, config, _anchor) = fixture_with_collector(false, true);
    let dispatched = Arc::clone(&driver.dispatched);
    let runner = WorkloadRunner::new(driver, NoEndpoint, NoBroker);
    let redaction = RedactionPolicy::default();
    let inputs = WorkloadLaunchInputs {
        config: &config,
        tenant: "local",
        secrets: &[],
        redaction: &redaction,
        network_policy: &config.network_policy,
        cmdline: "console=ttyS0".into(),
    };
    let refused = runner
        .start_workload(&inputs)
        .err()
        .expect("unsupported collector");
    assert!(
        refused
            .to_string()
            .contains("registered installed endpoint startup unavailable"),
        "{refused:#}"
    );
    assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    assert!(
        !vm_state_dir(&config.name)
            .join(mvm_core::host_lifetime::INSTALLED_NATIVE_CUSTODY_MARKER)
            .exists()
    );
}

#[test]
fn owned_native_handle_survives_canonical_runner_start_return() {
    let (_env, _root, mut driver, config, anchor) = fixture(false);
    let (entered, waiting) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    driver.report = Some(Arc::new(ControlledReport {
        entered,
        release: std::sync::Mutex::new(released),
    }));
    let dropped = Arc::clone(&driver.dropped);
    let attached = Arc::clone(&driver.attached);
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
    let stale = state_dir.join("verb-grant.json");
    std::fs::write(&stale, b"predecessor").unwrap();
    assert!(render(&config).contains("mvm.require_grant=1"));
    assert_eq!(
        render(&injected_config).contains("mvm.require_grant="),
        cfg!(not(target_os = "linux")),
        "an installed boot inherited the predecessor grant by VM name"
    );
    std::fs::remove_file(stale).unwrap();
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
    let unsupported = WorkloadLaunchInputs {
        config: &injected_config,
        network_policy: &injected_config.network_policy,
        cmdline: "console=ttyS0".into(),
        ..mismatched
    };
    let refused = runner
        .start_workload(&unsupported)
        .err()
        .expect("unsupported spawner");
    assert!(
        refused
            .to_string()
            .contains("registered installed endpoint startup unavailable"),
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
            report: None,
            dropped: dropped.clone(),
            attached: attached.clone(),
            dispatched: Arc::new(AtomicUsize::new(0)),
        },
        NoEndpoint,
        NoBroker,
    );
    assert!(
        other.status(&id).is_err(),
        "a different runner cannot attach through an installed marker"
    );
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    assert!(other.wait_owned_until(&id, &anchor, until).is_err());
    assert!(
        runner
            .wait_owned_until(&id, &anchor, std::time::Instant::now())
            .is_err()
    );
    std::thread::scope(|scope| {
        let wait = scope.spawn(|| runner.wait_owned_until(&id, &anchor, until));
        waiting
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let status = runner.status(&id);
        release.send(()).unwrap();
        assert_eq!(wait.join().unwrap().unwrap().code, Some(19));
        status.expect("waiting for the original report must leave original custody available");
    });
    assert!(other.stop_owned(&id, &anchor).is_err());
    assert_eq!(attached.load(Ordering::SeqCst), 0);
    drop(runner);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "controller drop quarantines unconfirmed custody"
    );
}

#[derive(Default)]
struct CleanupObserver {
    slot: std::sync::Mutex<Option<Arc<installed::InstalledSlot>>>,
    calls: AtomicUsize,
}
impl ConsoleStreamer for CleanupObserver {
    fn start(&self, _capture: &ConsoleCapture<'_>) {}
    fn stop(&self, _vm_name: &str) {
        let slot = self.slot.lock().unwrap().as_ref().cloned().unwrap();
        let refused = slot.view().status().expect_err("cleanup owns the slot");
        assert_eq!(
            refused.to_string(),
            "original installed cleanup in progress"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn installed_pre_dispatch_failure_retains_and_retires_endpoint() {
    let (_env, _root, driver, config, anchor) = fixture(false);
    let dispatched = Arc::clone(&driver.dispatched);
    let observer = Arc::new(CleanupObserver::default());
    let runner =
        WorkloadRunner::new(driver, NoEndpoint, NoBroker).with_console_streamer(observer.clone());
    let id = VmId(config.name.clone());
    mvm_core::config::create_private_dir(vm_state_dir(&config.name)).unwrap();
    let redaction = RedactionPolicy::default();
    let inputs = WorkloadLaunchInputs {
        config: &config,
        tenant: "local",
        secrets: &[],
        redaction: &redaction,
        network_policy: &config.network_policy,
        cmdline: "x".repeat(65_536),
    };
    assert!(runner.start_workload(&inputs).is_err());
    assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    let slot = runner.installed.find(&id).unwrap().unwrap();
    assert!(
        slot.endpoint_retained_for_test(),
        "post-spawn failure lost the original endpoint handle"
    );
    assert!(installed::marker(&id).exists());
    *observer.slot.lock().unwrap() = Some(slot);
    runner.stop_owned(&id, &anchor).unwrap();
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
    assert!(!installed::marker(&id).exists());
    let retirement = runner.take_owned_retirement(&id, &anchor).unwrap();
    assert_eq!(retirement.binding(), anchor.binding());
    assert!(runner.take_owned_retirement(&id, &anchor).is_err());
}

#[test]
fn unsupported_native_driver_refuses_before_reserving_installed_custody() {
    let (_env, _root, driver, config, _anchor) = fixture(false);
    let runner = WorkloadRunner::new(driver.inner, NoEndpoint, NoBroker);
    let id = VmId(config.name.clone());
    mvm_core::config::create_private_dir(vm_state_dir(&config.name)).unwrap();
    let redaction = RedactionPolicy::default();
    let inputs = WorkloadLaunchInputs {
        config: &config,
        tenant: "local",
        secrets: &[],
        redaction: &redaction,
        network_policy: &config.network_policy,
        cmdline: "console=ttyS0".into(),
    };

    let refused = runner
        .start_workload(&inputs)
        .err()
        .expect("unsupported native backend");
    assert!(
        refused
            .to_string()
            .contains("installed native backend unavailable"),
        "{refused:#}"
    );
    assert!(!installed::marker(&id).exists());
    assert!(runner.installed.find(&id).unwrap().is_none());
}

#[test]
fn portable_startup_requires_original_workspace_before_runtime_effects() {
    let (_env, _root, driver, config, _) = fixture(true);
    let dispatched = Arc::clone(&driver.dispatched);
    let runner = WorkloadRunner::new(driver, NoEndpoint, NoBroker);
    let redaction = RedactionPolicy::default();
    let mut stripped = config.clone();
    stripped.legacy_portable_runtime = None;
    for (config, reason) in [
        (&stripped, "original admission missing or changed"),
        (&config, "original parent startup workspace unavailable"),
    ] {
        let inputs = WorkloadLaunchInputs {
            config,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &config.network_policy,
            cmdline: "console=ttyS0".into(),
        };
        let error = runner
            .start_workload(&inputs)
            .err()
            .expect("startup refused");
        assert!(error.to_string().contains(reason), "{error:#}");
        assert!(!runner.installed.has_any().unwrap());
        assert!(!installed::marker(&VmId(config.name.clone())).exists());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    }
}
