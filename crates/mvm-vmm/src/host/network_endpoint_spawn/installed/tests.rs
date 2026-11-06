//! Real private-pipe/holder qualification only, not a boot or aggregate quota
//! witness. The fixture constructs bounded control records, never a permit.
use super::*;
use anyhow::ensure;
use mvm_core::host_lifetime::{EndpointPartitionLimits, HostLaunchBinding};
use std::{
    fs::OpenOptions,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
        process::CommandExt,
    },
    process::{Child, Command, Stdio},
};

const FIXTURE: &str = "MVM_INSTALLED_ENDPOINT_PIPE_FIXTURE";
const COORD: &str = "MVM_INSTALLED_ENDPOINT_COORD_FD";

#[test]
fn installed_endpoint_fixture_child() {
    let Some(mode) = std::env::var_os(FIXTURE) else {
        return;
    };
    // SAFETY: the original fixture's pre_exec reserved its protocol stdout on
    // fd199 while libtest wrote banners to stderr. Restore before FIRST read.
    assert!(unsafe { libc::dup2(199, 1) } >= 0);
    let context = InstalledEndpointChild::from_stdio();
    if mode == "wrong-nonce" {
        assert!(context.is_err());
        std::process::exit(0);
    }
    let mut context = context.unwrap();
    context
        .with_verification_state(|state| {
            assert!(state.metadata()?.is_file());
            Ok(())
        })
        .unwrap();
    let lease = context.lease();
    let alias = lease.clone();
    assert_eq!(lease.projection(), context.projection());
    lease.check_current().unwrap();
    lease.claim_payload_pool().unwrap();
    assert!(
        alias.claim_payload_pool().is_err(),
        "one pool across aliases"
    );
    assert_eq!(
        context.take_config().unwrap(),
        serde_json::json!({"fixture":true})
    );
    assert!(context.take_config().is_err());
    context
        .send_ready(
            EndpointHandshake::default(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    if mode == "stale-holder" {
        let fd: i32 = std::env::var(COORD).unwrap().parse().unwrap();
        // SAFETY: only this fixture's pre_exec inherited its owned Unix socket.
        let mut coord = unsafe { UnixStream::from_raw_fd(fd) };
        let mut event = [0; 1];
        coord.read_exact(&mut event).unwrap();
        assert!(lease.check_current().is_err());
        coord.write_all(&[1]).unwrap();
        coord.read_exact(&mut event).unwrap();
        assert!(
            alias.check_current().is_err(),
            "restored bytes cannot reset fence"
        );
        coord.write_all(&[1]).unwrap();
    }
    while !context.parent_closed().unwrap() {
        assert!(Instant::now() < deadline);
        std::thread::park_timeout(Duration::from_millis(1));
    }
    assert!(context.check_parent().is_err());
    context.send_drained(deadline).unwrap();
    assert!(context.send_drained(deadline).is_err());
    drop(context);
    std::process::exit(0);
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0
            && child.try_wait().ok().flatten().is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn fixture_handoff(
    directory: &File,
    holder: &File,
    expected: HostLeaseExpectation,
) -> (
    PreparedEndpointHandoff,
    std::sync::Arc<dyn mvm_core::host_lifetime::EndpointPartitionGuard>,
) {
    use mvm_core::{
        host_lifetime::{
            CoreCurrentParentPermit, EndpointPartitionGuard, HostLifetimeInputs,
            PreparedEndpointPartition, PreparedHostLifetime,
        },
        plan::{sign_plan, test_support::PlanFixture},
        vm_backend::VmStartConfig,
    };
    use std::sync::Arc;
    struct Guard(EndpointPartitionProjection);
    impl EndpointPartitionGuard for Guard {
        fn check_current(&self, facts: &EndpointPartitionProjection) -> Result<()> {
            ensure!(facts == &self.0, "foreign fixture partition");
            Ok(())
        }
    }
    struct Parent(EndpointPartitionProjection, Arc<dyn EndpointPartitionGuard>);
    impl CoreCurrentParentPermit for Parent {
        fn check_current(&self, binding: &HostLaunchBinding) -> Result<()> {
            ensure!(binding == &self.0.binding, "foreign fixture parent");
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
    // This real holder/pipe fixture tests ownership movement, not aggregate
    // admission: its trusted test guards do not represent a host resource pool.
    let mut facts = projection();
    let mut plan = PlanFixture::new().runtime_profile("firecracker").build();
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    facts.admitted_plan_id = plan.plan_id.0.clone();
    let anchor = PreparedHostLifetime::bind(
        HostLifetimeInputs {
            directory: directory.try_clone().unwrap(),
            holder: holder.try_clone().unwrap(),
            expected,
            binding: facts.binding.clone(),
        },
        (),
    )
    .unwrap()
    .into_anchor();
    let mut config = VmStartConfig {
        name: facts.binding.vm_name.clone(),
        cpus: facts.binding.cpus,
        memory_mib: facts.binding.memory_mib,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    config.plan_json = Some(
        serde_json::to_string(&sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
            "fixture",
        ))
        .unwrap(),
    );
    anchor
        .bind_admitted(&config, facts.binding.backend, &plan)
        .unwrap();
    let guard: Arc<dyn EndpointPartitionGuard> = Arc::new(Guard(facts.clone()));
    anchor
        .bind_parent_permit(
            &config,
            facts.binding.backend,
            Arc::new(Parent(facts.clone(), guard.clone())),
        )
        .unwrap();
    (
        anchor
            .prepare_endpoint_handoff(&config, facts.binding.backend)
            .unwrap(),
        guard,
    )
}

fn projection() -> EndpointPartitionProjection {
    EndpointPartitionProjection {
        version: 1,
        binding: HostLaunchBinding {
            installation: [1; 32],
            profile: [2; 32],
            generation: 1,
            grant_serial: 1,
            vm_name: "endpoint-pipe".into(),
            backend: mvm_core::vm_backend::BackendKind::Firecracker,
            cpus: 1,
            memory_mib: 128,
        },
        admitted_plan_id: "fixture-control-not-admission".into(),
        session: [3; 32],
        partition_serial: 1,
        profile: 2,
        store: Some(mvm_core::host_lifetime::EndpointStoreLocator {
            version: 1,
            path: "/nonexistent-endpoint-fixture/store".into(),
            device: 1,
            inode: 1,
            reservation_serial: 1,
            tenant: [0; 32],
            session: [3; 32],
        }),
        limits: EndpointPartitionLimits {
            host_plaintext_bytes: 1,
            host_codec_bytes: 1,
            host_carrier_bytes: 1,
            host_metadata_bytes: INSTALLED_CONTROL_BUFFER_BYTES,
            host_stack_bytes: 1,
            cache_disk_bytes: 0,
            staging_disk_bytes: 0,
            workers: 1,
            max_streams: 1,
        },
    }
}

fn pipe_exchange(mode: &str) {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.path().join(".state");
    std::fs::write(&state, b"a").unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    let directory = File::open(root.path()).unwrap();
    let holder_path = root.path().join("holders.lock");
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&holder_path)
        .unwrap();
    let expected = HostLeaseExpectation {
        state_name: ".state".into(),
        state_bytes: 1,
        state_sha256: hex::decode(
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        )
        .unwrap()
        .try_into()
        .unwrap(),
        absent_names: [".state.intent".into(), ".state.next".into()],
    };
    let mut handoff =
        (mode == "retirement").then(|| fixture_handoff(&directory, &holder, expected.clone()));
    let facts = handoff
        .as_ref()
        .map(|(handoff, _)| handoff.partition().projection().clone())
        .unwrap_or_else(projection);
    let target = format!(
        "{}::installed_endpoint_fixture_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut command = Command::new(std::env::current_exe().unwrap());
    let (mut coord, child_coord) = UnixStream::pair().unwrap();
    coord
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    coord
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    child_coord
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    child_coord
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    command
        .args(["--exact", &target, "--nocapture", "--test-threads=1"])
        .env(FIXTURE, mode)
        .env(COORD, child_coord.as_raw_fd().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::host::restore_image::inherit_descriptors(
        &mut command,
        vec![
            directory.as_raw_fd(),
            holder.as_raw_fd(),
            child_coord.as_raw_fd(),
        ],
    );
    // SAFETY: only duplicate/redirect fixed descriptors in this owned fixture.
    unsafe {
        command.pre_exec(|| {
            if libc::dup2(1, 199) < 0 || libc::dup2(2, 1) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = ChildGuard(Some(command.spawn().unwrap()));
    drop(child_coord);
    let original = child.0.as_mut().unwrap();
    let observer = ProcessExitObserver::arm(original.id().try_into().unwrap()).unwrap();
    let mut input = original.stdin.take().unwrap();
    let mut output = original.stdout.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let challenge: Challenge = read_frame(&mut output, CONTROL_LIMIT, deadline).unwrap();
    assert_ne!(challenge.nonce, [0; 32]);
    let nonce = if mode == "wrong-nonce" {
        [0; 32]
    } else {
        challenge.nonce
    };
    write_frame(
        &mut input,
        &Prepare {
            version: 1,
            nonce,
            projection: facts.clone(),
            directory: directory.as_raw_fd(),
            holder: holder.as_raw_fd(),
            expected,
            config: serde_json::json!({"fixture":true}),
            telemetry_records: None,
            audit: None,
        },
        CONFIG_LIMIT,
        deadline,
    )
    .unwrap();
    if mode != "wrong-nonce" {
        let ready: Ready = read_frame(&mut output, CONFIG_LIMIT, deadline).unwrap();
        assert_eq!(ready.nonce, challenge.nonce);
        assert_eq!(ready.session, projection().session);
        if mode == "stale-holder" {
            std::fs::write(&state, b"b").unwrap();
            coord.write_all(&[1]).unwrap();
            coord.read_exact(&mut [0; 1]).unwrap();
            std::fs::write(&state, b"a").unwrap();
            coord.write_all(&[1]).unwrap();
            coord.read_exact(&mut [0; 1]).unwrap();
        }
        drop(directory);
        drop(holder);
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&holder_path)
            .unwrap();
        assert!(
            probe.try_lock().is_err(),
            "child retains original SH after parent files drop"
        );
        if let Some((handoff, guard)) = handoff.take() {
            let mut endpoint = OwnedEndpoint::new(child.0.take().unwrap());
            endpoint.installed = Some(InstalledCustody {
                handoff,
                input: Some(input),
                output: Some(output),
                nonce: challenge.nonce,
                drained: false,
            });
            assert!(endpoint.take_retirement().is_err());
            endpoint.shutdown().unwrap();
            let receipt = endpoint.take_retirement().unwrap();
            assert_eq!(receipt.projection(), &facts);
            assert!(receipt.retains_partition_guard(&guard));
            assert!(endpoint.take_retirement().is_err());
            drop(endpoint);
            assert!(probe.try_lock().is_err(), "receipt retains original SH");
            drop(receipt);
            probe.try_lock().unwrap();
            return;
        }
        drop(input);
        let drained: Drained = read_frame(&mut output, CONTROL_LIMIT, deadline).unwrap();
        assert_eq!(drained.nonce, challenge.nonce);
        assert_eq!(drained.session, projection().session);
        assert_eq!(drained.serial, 1);
        assert_eq!(
            observer.wait_event(deadline).unwrap(),
            ProcessExitWait::Exited
        );
        assert!(child.0.as_mut().unwrap().wait().unwrap().success());
        probe.try_lock().unwrap();
    } else {
        drop(input);
        assert_eq!(
            observer.wait_event(deadline).unwrap(),
            ProcessExitWait::Exited
        );
        assert!(child.0.as_mut().unwrap().wait().unwrap().success());
        assert!(read_frame::<_, Ready>(&mut output, CONFIG_LIMIT, deadline).is_err());
    }
}

#[test]
fn private_endpoint_handshake_holds_original_sh_until_drained_and_child_exit() {
    pipe_exchange("ready-drain");
}
#[test]
fn wrong_private_parent_nonce_refuses_before_readiness() {
    pipe_exchange("wrong-nonce");
}

#[test]
fn endpoint_retirement_requires_drained_and_original_child_and_retains_sh() {
    pipe_exchange("retirement");
}

#[test]
fn real_child_lease_checks_original_holder_and_never_resets_after_failure() {
    pipe_exchange("stale-holder");
}

#[test]
fn control_prefix_partial_deadline_and_encode_limit_preserve_bounds() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert!(
        read_frame::<_, Challenge>(
            &mut reader,
            CONTROL_LIMIT,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(&[0, 0]).unwrap();
    let began = Instant::now();
    assert!(
        read_frame::<_, Challenge>(
            &mut reader,
            CONTROL_LIMIT,
            began + Duration::from_millis(20)
        )
        .is_err()
    );
    assert!(began.elapsed() < Duration::from_secs(1));
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    assert!(
        write_frame(
            &mut writer,
            &vec![b'x'; CONTROL_LIMIT * 2],
            CONTROL_LIMIT,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
    reader.set_nonblocking(true).unwrap();
    assert_eq!(
        reader.read(&mut [0; 4]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
