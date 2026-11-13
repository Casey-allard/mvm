use std::{
    fs::File,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    process::Stdio,
    time::Duration,
};

const FIXTURE: &str = "MVM_INSTALLED_RESOURCES_FIXTURE";

pub async fn resource_exchange(mode: &str, child_args: &[&str]) {
    resource_exchange_with(mode, child_args, |_, _, _| Ok(())).await;
}

pub async fn resource_exchange_with(
    mode: &str,
    child_args: &[&str],
    configure: impl FnOnce(
        &mut serde_json::Value,
        &mut mvm_core::host_lifetime::EndpointPartitionProjection,
        &std::path::Path,
    ) -> anyhow::Result<()>,
) {
    resource_exchange_handoffs_with(mode, child_args, 1, configure).await;
}

pub async fn resource_exchange_handoffs_with(
    mode: &str,
    child_args: &[&str],
    handoffs: usize,
    configure: impl FnOnce(
        &mut serde_json::Value,
        &mut mvm_core::host_lifetime::EndpointPartitionProjection,
        &std::path::Path,
    ) -> anyhow::Result<()>,
) {
    resource_exchange_program_handoffs_with(mode, child_args, handoffs, None, configure).await;
}

pub async fn resource_exchange_program_with(
    mode: &str,
    child_args: &[&str],
    program: &std::path::Path,
    configure: impl FnOnce(
        &mut serde_json::Value,
        &mut mvm_core::host_lifetime::EndpointPartitionProjection,
        &std::path::Path,
    ) -> anyhow::Result<()>,
) {
    resource_exchange_program_handoffs_with(mode, child_args, 1, Some(program), configure).await;
}

async fn resource_exchange_program_handoffs_with(
    mode: &str,
    child_args: &[&str],
    handoffs: usize,
    program: Option<&std::path::Path>,
    configure: impl FnOnce(
        &mut serde_json::Value,
        &mut mvm_core::host_lifetime::EndpointPartitionProjection,
        &std::path::Path,
    ) -> anyhow::Result<()>,
) {
    assert!(matches!(handoffs, 1 | 2));
    use mvm_core::host_lifetime::{
        EndpointPartitionLimits, EndpointPartitionProjection, EndpointStoreLocator,
        HostLaunchBinding, HostLeaseExpectation,
    };
    use mvm_hostd::framing::{read_json_frame, write_json_frame_bounded};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    // Real anonymous pipes, current private files and Child; no aggregate host
    // reservation, codec, collector threads, guest or native backend is claimed.
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.path().join(".state");
    std::fs::write(&state, b"a").unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    let directory = File::open(root.path()).unwrap();
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.path().join("holders.lock"))
        .unwrap();
    // Each context adopts its descriptor numbers. Duplicates share the same
    // original OFDs but must never create two owners of one raw fd number.
    let second =
        (handoffs == 2).then(|| (directory.try_clone().unwrap(), holder.try_clone().unwrap()));
    let mut projection = EndpointPartitionProjection {
        version: 1,
        binding: HostLaunchBinding {
            installation: [1; 32],
            profile: [2; 32],
            generation: 1,
            grant_serial: 1,
            vm_name: "resources-collector".into(),
            backend: mvm_core::vm_backend::BackendKind::Firecracker,
            cpus: 1,
            memory_mib: 128,
        },
        admitted_plan_id: "fixture-not-canonical-admission".into(),
        session: [3; 32],
        partition_serial: 1,
        profile: 1,
        store: None,
        limits: EndpointPartitionLimits {
            host_plaintext_bytes: 1,
            host_codec_bytes: 0,
            host_carrier_bytes: 1,
            // Functional fixture envelope, not an aggregate host reservation.
            // Real bootstrap query and reader/relay claims must each fit.
            host_metadata_bytes: 8 << 20,
            host_stack_bytes: 16 << 20,
            cache_disk_bytes: 0,
            staging_disk_bytes: 0,
            workers: 1,
            max_streams: 1,
        },
    };
    let store_path = root.path().join("codec-store");
    let collector = matches!(
        mode,
        "collector" | "collector-status-failure" | "collector-missing-records"
    );
    if !collector {
        std::fs::create_dir(&store_path).unwrap();
        std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(&store_path).unwrap();
        projection.profile = 2;
        let store_work =
            mvm_hostd::supervisor::flowmux::SpiralCorePayloadFactory::owned_store_requirements()
                .expect("SmallV1 store work");
        projection.limits.host_codec_bytes =
            spiralcore_transfer::resource_profile::ResourceProfile::SmallV1
                .operation_charge()
                .expect("SmallV1 engine charge")
                .checked_add(store_work.workspace_bytes)
                .expect("one funded engine and store");
        projection.limits.cache_disk_bytes = 16 << 20;
        projection.limits.staging_disk_bytes = 16 << 20;
        projection.limits.max_streams = 2;
        projection.store = Some(EndpointStoreLocator {
            version: 1,
            path: store_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            reservation_serial: 1,
            tenant: [0; 32],
            session: [3; 32],
        });
        if mode == "replaced-store" {
            std::fs::rename(&store_path, root.path().join("retained-original-store")).unwrap();
            std::fs::create_dir(&store_path).unwrap();
            std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    if collector {
        projection.limits.cache_disk_bytes =
            mvm_vmm::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP
                + mvm_core::runtime_state_protection::INSTALLED_TELEMETRY_SIDECAR_BYTES;
    }
    let mut config = json!({"telemetry_only": {
        "instance_id":"resources-collector", "redaction":mvm_core::policy::RedactionPolicy::default(),
        "telemetry": {"state_dir":root.path(), "telemetry_sock":root.path().join("t.sock"),
            "signer_sock":root.path().join("s.sock"), "host_anchor_path":root.path().join("a.pub"),
            "records_byte_cap":1024, "records_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
    }});
    if !collector {
        use mvm_contract::policy::network_policy::{
            CooperatingPayloadPolicy, CooperatingTcpPeer, PayloadMappingProfile,
        };
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("peer.example", 443)])
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
        let plan = mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan {
            plan_id: mvm_core::plan::PlanId(projection.admitted_plan_id.clone()),
            plan_version: 1,
            plan_nonce: mvm_core::plan::Nonce::from_bytes([4; 16]),
            bundle_sha256: "11".repeat(32),
            tenant_id: "local".into(),
            instance_id: projection.binding.vm_name.clone(),
            policy_sha256: mvm_core::policy::network_policy::content_sha256(&policy),
        };
        let session = if mode == "foreign-session" {
            [4; 32]
        } else {
            [3; 32]
        };
        config = json!({"tenant_id":"local","instance_id":projection.binding.vm_name,"secrets":[],
            "transport":{"kind":"uds","path":root.path().join("network.sock")},
            "network_policy":policy,"admitted_network_plan":plan,"egress_mode":"flow_mux",
            "flowmux_identity":{"session_id":hex::encode(session),
                "host_signing_key_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "guest_verifying_key_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
        });
    }
    if mode == "undercharged-config" {
        projection.limits.host_metadata_bytes = 262144;
    }
    configure(&mut config, &mut projection, root.path()).unwrap();
    if mode == "sensitive-error" {
        config["secrets"] = json!("SYNTHETIC_PRIVATE_CONFIG_VALUE");
    }
    // Actual functional-fixture records descriptor, created before exec and
    // inherited only when the original configured program selects telemetry.
    // These files are not a Root retained-catalog admission or quota witness.
    let selected_telemetry = config
        .get("telemetry_only")
        .and_then(|value| value.get("telemetry"))
        .or_else(|| config.get("telemetry"))
        .is_some_and(|value| !value.is_null());
    let records = (selected_telemetry && mode != "collector-missing-records").then(|| {
        std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(
                root.path()
                    .join(mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE),
            )
            .unwrap()
    });
    let second_records = (handoffs == 2)
        .then(|| records.as_ref().map(|file| file.try_clone().unwrap()))
        .flatten();
    let records_mapping = |file: &File| {
        let directory = directory.metadata().unwrap();
        let record = file.metadata().unwrap();
        json!({"version":1,"descriptor":file.as_raw_fd(),"state_path":root.path(),
            "state_device":directory.dev(),"state_inode":directory.ino(),
            "device":record.dev(),"inode":record.ino()})
    };
    let record_mappings = [
        records.as_ref().map(records_mapping),
        second_records.as_ref().map(records_mapping),
    ];
    let default_program = std::env::current_exe().unwrap();
    let mut command = tokio::process::Command::new(program.unwrap_or(&default_program));
    command
        .args(child_args)
        .env(FIXTURE, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut inherited = vec![directory.as_raw_fd(), holder.as_raw_fd()];
    if let Some((directory, holder)) = &second {
        inherited.extend([directory.as_raw_fd(), holder.as_raw_fd()]);
    }
    inherited.extend(records.as_ref().map(AsRawFd::as_raw_fd));
    inherited.extend(second_records.as_ref().map(AsRawFd::as_raw_fd));
    mvm_vmm::host::restore_image::inherit_descriptors(command.as_std_mut(), inherited);
    if program.is_none() {
        // SAFETY: after fork this closure uses only async-signal-safe dup2 on
        // the child's stdio, preserving stdout on 199 before redirecting it.
        // A failed call returns the saved errno without allocating or locking.
        unsafe {
            command.as_std_mut().pre_exec(|| {
                if libc::dup2(1, 199) < 0 || libc::dup2(2, 1) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn().unwrap();
    let child_stderr = child.stderr.take().unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let expected_refusal = matches!(
        mode,
        "foreign-session"
            | "replaced-store"
            | "restored-store"
            | "sensitive-error"
            | "undercharged-config"
            | "owned-attach-poison"
            | "collector-status-failure"
            | "collector-missing-records"
            | "sidecar-cache-underflow"
    );
    let exchange = async move {
        let mut challenge: Value = read_json_frame(&mut output, 1024).await?;
        let expected = HostLeaseExpectation {
            state_name: ".state".into(),
            state_bytes: 1,
            state_sha256: Sha256::digest(b"a").into(),
            absent_names: [".state.intent".into(), ".state.next".into()],
        };
        for (index, records_mapping) in record_mappings.iter().enumerate().take(handoffs) {
            let (directory_fd, holder_fd) = if index == 0 {
                (directory.as_raw_fd(), holder.as_raw_fd())
            } else {
                let (directory, holder) = second.as_ref().unwrap();
                (directory.as_raw_fd(), holder.as_raw_fd())
            };
            let mut prepare = json!({"version":1,"nonce":challenge["nonce"],
                "projection":&projection,"directory":directory_fd,"holder":holder_fd,
                "expected":&expected,"config":&config});
            if let Some(records) = records_mapping {
                prepare["telemetry_records"] = records.clone();
            }
            write_json_frame_bounded(&mut input, &prepare, 65536).await?;
            if index + 1 < handoffs {
                challenge = read_json_frame(&mut output, 1024).await?;
            }
        }
        if expected_refusal {
            let ready: Result<Value, _> = read_json_frame(&mut output, 65536).await;
            anyhow::ensure!(ready.is_err(), "refused config reported Ready");
            // Keep original parent admission live through the child's actual
            // constructor/refusal. EOF must not mask the intended countercase.
            drop(input);
            return Ok::<(), anyhow::Error>(());
        }
        let ready: Value = read_json_frame(&mut output, 65536).await?;
        anyhow::ensure!(
            ready["nonce"] == challenge["nonce"],
            "original private challenge differs"
        );
        drop(input);
        let drained: Value = read_json_frame(&mut output, 1024).await?;
        anyhow::ensure!(
            drained["nonce"] == challenge["nonce"],
            "original private drain differs"
        );
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::time::timeout(Duration::from_secs(5), exchange).await;
    let passed = matches!(&result, Ok(Ok(())));
    if !passed {
        let _ = child.start_kill();
    }
    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .unwrap()
        .unwrap();
    use tokio::io::AsyncReadExt;
    let mut diagnostics = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        child_stderr.take(8192).read_to_end(&mut diagnostics),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        passed,
        "private resource exchange failed: {result:?}; child {status:?}: {}",
        String::from_utf8_lossy(&diagnostics)
    );
    assert!(
        status.success(),
        "child diagnostics: {}",
        String::from_utf8_lossy(&diagnostics)
    );
}
