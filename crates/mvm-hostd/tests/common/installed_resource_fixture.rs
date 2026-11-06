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

pub(super) async fn resource_exchange(mode: &str, child_args: &[&str]) {
    exchange_with_program(mode, child_args, None).await;
}

pub(super) async fn exchange_with_program(mode: &str, child_args: &[&str], endpoint: Option<&str>) {
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
            host_metadata_bytes: 262144,
            host_stack_bytes: 1,
            cache_disk_bytes: 0,
            staging_disk_bytes: 0,
            workers: 1,
            max_streams: 1,
        },
    };
    let store_path = root.path().join("codec-store");
    if mode != "collector" {
        std::fs::create_dir(&store_path).unwrap();
        std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(&store_path).unwrap();
        projection.profile = 2;
        projection.limits.host_codec_bytes = 8 << 20;
        if mode == "carrier-funded" {
            projection.limits.host_carrier_bytes = 1 << 20;
        }
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
    let records = matches!(
        mode,
        "records-original" | "records-alias" | "records-inspect"
    )
    .then(|| {
        let name = mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE;
        let records = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join(name))
            .unwrap();
        let state = directory.metadata().unwrap();
        let metadata = records.metadata().unwrap();
        let descriptor = if mode == "records-alias" {
            holder.as_raw_fd()
        } else {
            records.as_raw_fd()
        };
        let projection = json!({
            "version":1, "descriptor":descriptor,
            "state_path":root.path().canonicalize().unwrap(),
            "state_device":state.dev(), "state_inode":state.ino(),
            "device":metadata.dev(), "inode":metadata.ino()
        });
        (records, projection)
    });
    let mut command = if let Some(endpoint) = endpoint {
        let mut command = tokio::process::Command::new(endpoint);
        command.arg("--installed-partition");
        command
    } else {
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command.args(child_args).env(FIXTURE, mode);
        command
    };
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut descriptors = vec![directory.as_raw_fd(), holder.as_raw_fd()];
    if let Some((file, _)) = records.as_ref() {
        descriptors.push(file.as_raw_fd());
    }
    mvm_vmm::host::restore_image::inherit_descriptors(command.as_std_mut(), descriptors);
    if endpoint.is_none() {
        // SAFETY: descriptor-only operations in the fixture's owned child.
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
        "foreign-session" | "replaced-store" | "restored-store"
    );
    let aliases_original = mode == "records-alias";
    let mode = mode.to_owned();
    let exchange = async move {
        let challenge: Value = read_json_frame(&mut output, 1024).await?;
        let mut config = json!({"telemetry_only": {
            "instance_id":"resources-collector", "redaction":mvm_core::policy::RedactionPolicy::default(),
            "telemetry": {"state_dir":root.path(), "telemetry_sock":root.path().join("t.sock"),
                "signer_sock":root.path().join("s.sock"), "host_anchor_path":root.path().join("a.pub"),
                "records_byte_cap":1024, "records_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
        }});
        if mode != "collector" {
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
        let expected = HostLeaseExpectation {
            state_name: ".state".into(),
            state_bytes: 1,
            state_sha256: Sha256::digest(b"a").into(),
            absent_names: [".state.intent".into(), ".state.next".into()],
        };
        let mut prepare = json!({"version":1,"nonce":challenge["nonce"],
            "projection":projection,"directory":directory.as_raw_fd(),"holder":holder.as_raw_fd(),
            "expected":expected,"config":config});
        if let Some((_, records)) = records.as_ref() {
            prepare["telemetry_records"] = records.clone();
        }
        write_json_frame_bounded(&mut input, &prepare, 65536).await?;
        if endpoint.is_some() {
            let mut first_byte = [0];
            anyhow::ensure!(
                output.read(&mut first_byte).await? == 0,
                "endpoint without a controller emitted protocol output after Prepare"
            );
            drop(input);
            return Ok::<(), anyhow::Error>(());
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
    let diagnostics = String::from_utf8_lossy(&diagnostics);
    if endpoint.is_some() {
        assert!(!status.success());
        let expected = if aliases_original {
            "installed endpoint handshake failed"
        } else {
            "installed endpoint controller unavailable"
        };
        assert!(
            diagnostics.contains(expected),
            "unexpected original resource result: {diagnostics}"
        );
    } else {
        assert!(status.success(), "child diagnostics: {diagnostics}");
    }
}
