#![cfg(unix)]

use mvm_client::LocalBackend;

#[test]
fn public_installed_entry_and_owned_stop_are_additive() {
    let _ = LocalBackend::launch_with_host_lifetime;
    let _ = LocalBackend::stop_owned;
}

#[test]
fn pending_installed_cleanup_returns_linear_retirement_ownership() {
    let _ = LocalBackend::stop_owned_pending;
    let _: Option<mvm_client::OwnedRetirement> = None;
}

#[test]
fn original_outcome_exposes_only_a_scoped_borrow_of_positive_retirement() {
    fn inspect(outcome: &mvm_client::LaunchOutcome) -> mvm_client::Result<u64> {
        outcome.with_owned_retirement(|receipt| receipt.binding().generation)
    }
    let _ = inspect;
}

#[test]
fn endpoint_retirement_transfers_outside_the_vm_receipt_mutex() {
    fn take(
        outcome: &mvm_client::LaunchOutcome,
    ) -> mvm_client::Result<Option<mvm_client::EndpointRetirement>> {
        outcome.take_endpoint_retirement()
    }
    let _ = take;
}

#[tokio::test]
async fn missing_pending_custody_is_never_a_successful_retirement_by_absence() {
    use mvm_core::{host_lifetime::HostLaunchBinding, vm_backend::BackendKind};
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let backend = LocalBackend::with_hypervisor("firecracker");
    let mut binding = HostLaunchBinding {
        installation: [1; 32],
        profile: [2; 32],
        generation: 1,
        grant_serial: 1,
        vm_name: "missing-original-custody".into(),
        backend: BackendKind::Firecracker,
        cpus: 1,
        memory_mib: 128,
    };
    assert!(backend.stop_owned_pending(&binding).await.is_err());
    assert!(
        backend.stop_owned_pending(&binding).await.is_err(),
        "an absent record cannot turn a repeated stop into success"
    );
    binding.backend = BackendKind::Hvf;
    assert!(backend.stop_owned_pending(&binding).await.is_err());
    assert!(!mvm_core::config::vm_state_dir(&binding.vm_name).exists());
    assert!(!mvm_core::config::machine_spec_path(&binding.vm_name).exists());
}

#[test]
fn installed_refusal_marker_is_never_absence_authorizing_name_cleanup() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let state = mvm_core::config::vm_state_dir("retained-installed");
    std::fs::create_dir_all(&state).unwrap();
    let marker = state.join(".installed-native-custody");
    std::fs::write(&marker, b"refusal index, never an exit proof").unwrap();
    let data = state.join("original-retained-evidence");
    std::fs::write(&data, b"must survive unowned cleanup").unwrap();
    let backend = LocalBackend::with_hypervisor("firecracker");
    assert!(
        backend.cleanup_transient("retained-installed").is_err(),
        "a status refusal must not release/delete original installed state"
    );
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"refusal index, never an exit proof"
    );
    assert_eq!(
        std::fs::read(data).unwrap(),
        b"must survive unowned cleanup"
    );
}

fn lifetime(
    root: &std::path::Path,
    backend: mvm_core::vm_backend::BackendKind,
    dropped: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> mvm_core::host_lifetime::PreparedHostLifetime {
    use mvm_core::host_lifetime::*;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    struct Parent(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Parent {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join(".state");
    std::fs::write(&state, b"active").unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("holders.lock"))
        .unwrap();
    PreparedHostLifetime::bind(
        HostLifetimeInputs {
            directory: std::fs::File::open(root).unwrap(),
            holder,
            expected: HostLeaseExpectation {
                state_name: ".state".into(),
                state_bytes: 6,
                state_sha256: Sha256::digest(b"active").into(),
                absent_names: [".state.intent".into(), ".state.next".into()],
            },
            binding: HostLaunchBinding {
                installation: [1; 32],
                profile: [2; 32],
                generation: 1,
                grant_serial: 1,
                vm_name: "installed-refusal".into(),
                backend,
                cpus: 1,
                memory_mib: 1024,
            },
        },
        Parent(dropped),
    )
    .unwrap()
}

#[tokio::test]
async fn persistent_and_foreign_backend_refuse_before_definition_or_runtime_effects() {
    use mvm_client::{LaunchRequest, LifecycleMode, RootfsSource};
    use mvm_core::{util::test_env::TestEnv, vm_backend::BackendKind};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let backend = LocalBackend::with_hypervisor("firecracker");
    for (mode, override_name, wanted) in [
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
    ] {
        let resources = tempfile::tempdir().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut request = LaunchRequest::builder(
            mode,
            RootfsSource::LocalPath(home.path().join("missing-rootfs")),
        )
        .name("installed-refusal")
        .cpus(1)
        .memory_mib(1024);
        if let Some(name) = override_name {
            request = request.backend(name);
        }
        let error = backend
            .launch_with_host_lifetime(
                request.build().unwrap(),
                lifetime(resources.path(), BackendKind::Firecracker, dropped.clone()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains(wanted), "{error}");
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "unused parent ownership is released exactly once"
        );
        assert!(!mvm_core::config::machine_spec_path("installed-refusal").exists());
        assert!(!mvm_core::config::vm_state_dir("installed-refusal").exists());
    }
}
