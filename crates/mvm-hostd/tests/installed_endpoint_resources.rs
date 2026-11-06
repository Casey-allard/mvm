#![cfg(unix)]

#[path = "common/installed_resource_fixture.rs"]
mod installed_resource_fixture;

use mvm_vmm::host::network_endpoint_spawn::InstalledEndpointChild;
use std::{
    os::unix::fs::PermissionsExt,
    time::{Duration, Instant},
};

const FIXTURE: &str = "MVM_INSTALLED_RESOURCES_FIXTURE";

#[test]
fn resources_fixture_child() {
    let Some(mode) = std::env::var_os(FIXTURE) else {
        return;
    };
    // SAFETY: only the original fixture's pre_exec reserved protocol fd199.
    assert!(unsafe { libc::dup2(199, 1) } >= 0);
    let mut child = InstalledEndpointChild::from_stdio().unwrap();
    if mode == "records-partial" {
        use std::io::Write as _;
        let mut records = child.take_telemetry_records().unwrap().unwrap();
        child.take_config().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        child.send_ready(Default::default(), deadline).unwrap();
        while !child.parent_closed().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::park_timeout(Duration::from_millis(1));
        }
        let offset = records.current_len().unwrap();
        // Simulate bytes already landed when the queued append failed after EOF.
        records.write_all(b"{").unwrap();
        assert!(records.rollback_to(offset).is_err());
        assert!(child.send_drained(deadline).is_err());
        std::process::exit(0);
    }
    if mode != "collector" {
        let records = child.take_telemetry_records().unwrap();
        if mode == "records-inspect" {
            assert_eq!(records.unwrap().current_len().unwrap(), 0);
        } else {
            assert!(records.is_none());
        }
        assert!(child.take_telemetry_records().is_err());
    }
    let resources =
        mvm_hostd::installed_endpoint::InstalledEndpointResources::from_child(&mut child);
    if mode == "foreign-session" || mode == "replaced-store" {
        assert!(resources.is_err());
        if mode == "foreign-session" {
            assert!(
                child.lease().claim_payload_pool().is_err(),
                "failed authorization burns claim"
            );
        }
        assert!(
            mvm_hostd::installed_endpoint::InstalledEndpointResources::from_child(&mut child)
                .is_err()
        );
        std::process::exit(0);
    }
    let resources = resources.unwrap();
    let factory =
        mvm_hostd::supervisor::flowmux::SpiralCorePayloadFactory::from_installed_resources(
            &resources,
        )
        .unwrap();
    assert_eq!(factory.is_none(), mode == "collector");
    assert_eq!(resources.store_locator().is_some(), mode != "collector");
    let captured_store = resources.store_locator().cloned();
    let (program, lease, pool) = resources.into_parts();
    if mode == "collector" {
        assert!(matches!(
            program,
            mvm_hostd::installed_endpoint::InstalledEndpointProgram::TelemetryOnly(_)
        ));
        assert!(
            pool.is_none(),
            "collector-only never constructs a codec quota"
        );
    } else {
        assert!(matches!(
            program,
            mvm_hostd::installed_endpoint::InstalledEndpointProgram::Network(_)
        ));
        let pool = pool.unwrap();
        assert_eq!(pool.snapshot().unwrap(), Default::default());
        let profile = spiralcore_transfer::resource_profile::ResourceProfile::SmallV1;
        if mode == "restored-store" {
            let path = captured_store.unwrap().path;
            let moved = path.with_extension("retained-original");
            std::fs::rename(&path, &moved).unwrap();
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(pool.reserve_profile(profile).is_err());
            std::fs::remove_dir(&path).unwrap();
            std::fs::rename(&moved, &path).unwrap();
            let resumed = pool.reserve_profile(profile);
            let refused = resumed.is_err();
            drop(resumed);
            assert!(
                refused,
                "restoring a substituted store cannot reset its fence"
            );
            std::process::exit(0);
        }
        let first = pool.reserve_profile(profile).unwrap();
        assert!(
            pool.clone().reserve_profile(profile).is_err(),
            "one shared codec ceiling"
        );
        assert!(lease.claim_payload_pool().is_err());
        pool.close_admission().unwrap();
        assert!(!pool.drained().unwrap());
        drop(first);
        assert!(pool.drained().unwrap());
    }
    assert!(
        mvm_hostd::installed_endpoint::InstalledEndpointResources::from_child(&mut child).is_err()
    );
    lease.check_current().unwrap();
    child
        .send_ready(Default::default(), Instant::now() + Duration::from_secs(2))
        .unwrap();
    let mut event = libc::pollfd {
        fd: child.control_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: bounded event wait on this fixture's original live control pipe.
    assert!(unsafe { libc::poll(&mut event, 1, 3000) } > 0);
    assert!(lease.check_current().is_err());
    child
        .send_drained(Instant::now() + Duration::from_secs(2))
        .unwrap();
    std::process::exit(0);
}

#[tokio::test]
async fn real_collector_context_needs_no_object_mapping_or_independent_codec_pool() {
    resource_exchange("collector").await;
}

#[tokio::test]
async fn real_network_context_has_one_charged_shared_pool_before_ready() {
    resource_exchange("network").await;
}

#[tokio::test]
async fn foreign_config_session_cannot_reauthorize_the_same_child_pool() {
    resource_exchange("foreign-session").await;
}

#[tokio::test]
async fn replaced_captured_store_is_refused_before_ready() {
    resource_exchange("replaced-store").await;
}

#[tokio::test]
async fn restored_store_does_not_resume_after_an_observed_substitution() {
    resource_exchange("restored-store").await;
}

async fn resource_exchange(mode: &str) {
    installed_resource_fixture::resource_exchange(
        mode,
        &[
            "--exact",
            "resources_fixture_child",
            "--nocapture",
            "--test-threads=1",
        ],
    )
    .await;
}

#[test]
fn installed_resources_require_the_actual_child_and_return_one_shared_pool() {
    use mvm_hostd::installed_endpoint::{InstalledEndpointProgram, InstalledEndpointResources};
    fn prepare(
        child: &mut InstalledEndpointChild,
    ) -> anyhow::Result<(
        InstalledEndpointProgram,
        mvm_vmm::host::network_endpoint_spawn::InstalledEndpointLease,
        Option<mvm_hostd::supervisor::flowmux::PayloadResourcePool>,
    )> {
        Ok(InstalledEndpointResources::from_child(child)?.into_parts())
    }
    let _ = prepare;
}

#[tokio::test]
async fn canonical_endpoint_binary_enters_installed_stdio_before_legacy_input() {
    use mvm_hostd::framing::read_json_frame;
    use std::process::Stdio;

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_mvm-network-endpoint"))
        .arg("--installed-partition")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = child.stdout.take().unwrap();
    let challenge: serde_json::Value =
        tokio::time::timeout(Duration::from_secs(3), read_json_frame(&mut output, 1024))
            .await
            .expect("installed endpoint did not send Challenge while parent input was open")
            .unwrap();
    assert_eq!(challenge["version"], 1);
    let nonce = challenge["nonce"]
        .as_array()
        .expect("installed challenge nonce");
    assert_eq!(nonce.len(), 32);
    assert!(
        nonce
            .iter()
            .any(|byte| byte.as_u64().is_some_and(|byte| byte != 0))
    );

    // Closing before the authenticated Prepare must not report Ready.
    drop(child.stdin.take());
    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
    use tokio::io::AsyncReadExt;
    let mut remaining = [0; 1];
    let bytes = tokio::time::timeout(Duration::from_secs(1), output.read(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, 0, "truncated Prepare must emit no additional frame");
}

#[tokio::test]
async fn canonical_endpoint_binary_adopts_valid_prepare_without_unowned_ready() {
    installed_resource_fixture::exchange_with_program(
        "network",
        &[],
        Some(env!("CARGO_BIN_EXE_mvm-network-endpoint")),
    )
    .await;
}

#[tokio::test]
async fn canonical_endpoint_binary_refuses_mixed_installed_and_probe_arguments() {
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_mvm-network-endpoint"))
            .args(["--installed-partition", "--contract-version"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid installed endpoint arguments")
    );
}

#[tokio::test]
async fn canonical_endpoint_binary_adopts_original_records_prepare() {
    installed_resource_fixture::exchange_with_program(
        "records-original",
        &[],
        Some(env!("CARGO_BIN_EXE_mvm-network-endpoint")),
    )
    .await;
}

#[tokio::test]
async fn canonical_endpoint_binary_refuses_records_aliasing_holder() {
    installed_resource_fixture::exchange_with_program(
        "records-alias",
        &[],
        Some(env!("CARGO_BIN_EXE_mvm-network-endpoint")),
    )
    .await;
}

#[tokio::test]
async fn installed_records_writer_can_be_taken_only_once() {
    resource_exchange("records-inspect").await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn canonical_endpoint_binary_adopts_audit_events_with_original_records() {
    installed_resource_fixture::exchange_with_program(
        "audit-original",
        &[],
        Some(env!("CARGO_BIN_EXE_mvm-network-endpoint")),
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn canonical_endpoint_binary_refuses_audit_for_a_foreign_vm() {
    installed_resource_fixture::exchange_with_program(
        "audit-foreign",
        &[],
        Some(env!("CARGO_BIN_EXE_mvm-network-endpoint")),
    )
    .await;
}

#[tokio::test]
async fn uncertain_records_append_after_eof_refuses_drained() {
    resource_exchange("records-partial").await;
}
