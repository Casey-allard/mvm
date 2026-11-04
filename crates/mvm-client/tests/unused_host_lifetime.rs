//! Pure preflight custody only; no native backend is invoked by these cases.
#![cfg(all(unix, feature = "test-support"))]

use mvm_client::{LaunchRequest, LifecycleMode, LocalBackend, RootfsSource};
use mvm_core::{host_lifetime::*, util::test_env::TestEnv, vm_backend::BackendKind};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

fn preparation(root: &std::path::Path, original: Arc<String>) -> PreparedHostLifetime {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("state"), b"prepared").unwrap();
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.join("holders.lock"), b"").unwrap();
    fs::set_permissions(root.join("holders.lock"), fs::Permissions::from_mode(0o600)).unwrap();
    PreparedHostLifetime::bind(
        HostLifetimeInputs {
            directory: fs::File::open(root).unwrap(),
            holder: fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join("holders.lock"))
                .unwrap(),
            expected: HostLeaseExpectation {
                state_name: "state".into(),
                state_bytes: 8,
                state_sha256: Sha256::digest(b"prepared").into(),
                absent_names: [".state.next".into(), ".state.intent".into()],
            },
            binding: HostLaunchBinding {
                installation: [1; 32],
                profile: [2; 32],
                generation: 1,
                grant_serial: 1,
                vm_name: "pure-refusal".into(),
                backend: BackendKind::Firecracker,
                cpus: 1,
                memory_mib: 128,
            },
        },
        original,
    )
    .unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn shape_backend_and_missing_provider_refusals_return_the_same_unused_owner() {
    let home = tempfile::tempdir().unwrap();
    let mut environment = TestEnv::new();
    environment.isolate_mvm_home(home.path());
    assert!(mvm_hostd::host_lifetime_parent::require_installed().is_err());
    let client = LocalBackend::with_hypervisor("firecracker");
    for (mode, backend, expected) in [
        (
            LifecycleMode::Persistent,
            None,
            "explicitly named transient",
        ),
        (
            LifecycleMode::Transient,
            Some("hvf"),
            "original LocalBackend",
        ),
        (
            LifecycleMode::Transient,
            None,
            "original parent admission provider",
        ),
    ] {
        let files = tempfile::tempdir().unwrap();
        let original = Arc::new(String::from("original resource owner"));
        let lifetime = preparation(files.path(), original.clone());
        let binding = lifetime.binding().clone();
        let mut request = LaunchRequest::builder(
            mode,
            RootfsSource::LocalPath(home.path().join("missing-rootfs")),
        )
        .name("pure-refusal")
        .cpus(1)
        .memory_mib(128);
        if let Some(backend) = backend {
            request = request.backend(backend);
        }
        let failure = runtime()
            .block_on(client.try_launch_with_host_lifetime(request.build().unwrap(), lifetime))
            .unwrap_err();
        assert!(failure.error().to_string().contains(expected));
        let (_, unused) = failure.into_parts();
        let unused = unused.expect("only this actual pure refusal returns intact preparation");
        assert_eq!(unused.binding(), &binding);
        assert!(unused.retains_parent_owner(&original));
        assert!(!unused.retains_parent_owner(&Arc::new(String::from("original resource owner"))));
        let retry = unused.into_prepared();
        assert!(retry.retains_parent_owner(&original));
        assert_eq!(Arc::strong_count(&original), 2);
        drop(retry);
        assert_eq!(Arc::strong_count(&original), 1);
        assert!(!mvm_core::config::machine_spec_path("pure-refusal").exists());
        assert!(!mvm_core::config::vm_state_dir("pure-refusal").exists());
    }
}

#[test]
fn unsupported_backend_process_case() {
    if std::env::var_os("SPIRALCORE_UNUSED_PREFLIGHT_CHILD").is_none() {
        return;
    }
    struct RejectAdmission;
    impl mvm_hostd::host_lifetime_parent::ParentAdmissionProvider for RejectAdmission {
        fn bind(
            &self,
            _: &mvm_hostd::plan_admission::AdmittedPlan,
            _: &HostLaunchBinding,
        ) -> anyhow::Result<Arc<dyn CoreCurrentParentPermit>> {
            panic!("pure unsupported preflight must never enter admission")
        }
    }
    let provider = Arc::new(RejectAdmission);
    mvm_hostd::host_lifetime_parent::install(provider.clone()).unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut environment = TestEnv::new();
    environment.isolate_mvm_home(home.path());
    let files = tempfile::tempdir().unwrap();
    let original = Arc::new(String::from("unsupported original owner"));
    let request = LaunchRequest::builder(
        LifecycleMode::Transient,
        RootfsSource::LocalPath(home.path().join("missing-rootfs")),
    )
    .name("pure-refusal")
    .backend("mock")
    .cpus(1)
    .memory_mib(128)
    .build()
    .unwrap();
    let failure = runtime()
        .block_on(
            LocalBackend::with_hypervisor("mock").try_launch_with_host_lifetime(
                request,
                preparation(files.path(), original.clone()),
            ),
        )
        .unwrap_err();
    assert!(
        failure
            .error()
            .to_string()
            .contains("no original installed native lifetime")
    );
    let (_, unused) = failure.into_parts();
    assert!(unused.unwrap().retains_parent_owner(&original));
    assert_eq!(Arc::strong_count(&original), 1);
    assert!(!mvm_core::config::vm_state_dir("pure-refusal").exists());
}

#[test]
fn installed_unsupported_backend_returns_unused_without_entering_admission() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "unsupported_backend_process_case", "--nocapture"])
        .env("SPIRALCORE_UNUSED_PREFLIGHT_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn legacy_error_wrapper_preserves_its_error_and_original_drop_behavior() {
    let home = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let mut environment = TestEnv::new();
    environment.isolate_mvm_home(home.path());
    let original = Arc::new(String::from("legacy resource owner"));
    let request = LaunchRequest::builder(
        LifecycleMode::Persistent,
        RootfsSource::LocalPath(home.path().join("missing-rootfs")),
    )
    .name("pure-refusal")
    .cpus(1)
    .memory_mib(128)
    .build()
    .unwrap();
    let error = runtime()
        .block_on(
            LocalBackend::with_hypervisor("firecracker")
                .launch_with_host_lifetime(request, preparation(files.path(), original.clone())),
        )
        .unwrap_err();
    assert!(error.to_string().contains("explicitly named transient"));
    assert_eq!(Arc::strong_count(&original), 1);
}
