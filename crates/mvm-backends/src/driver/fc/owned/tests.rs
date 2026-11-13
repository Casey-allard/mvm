use super::*;
use mvm_core::host_lifetime::HostLeaseExpectation;
use mvm_vmm::driver::{
    RunningVm, VmmDriver,
    prepared_disks::{PreparedBootFiles, PreparedWritableDisks},
};
use std::{
    fs::File,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::Stdio,
    time::Duration,
};

#[test]
fn the_original_running_handle_waits_for_its_worker_and_never_a_stale_file() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let socket = root.path().join("exit.sock");
    let mut state = state(root.path());
    state.exit_capture =
        Some(super::super::owned_capture::CaptureWorker::spawn(&socket, root.path()).unwrap());
    let state = Arc::new(Mutex::new(state));
    let report = state
        .lock()
        .unwrap()
        .exit_capture
        .as_ref()
        .unwrap()
        .report();
    let vm = super::super::running::FcRunningVm {
        owned: Some(Arc::clone(&state)),
        original_report: Some(report),
        id: mvm_core::vm_backend::VmId("w".into()),
        state_dir: root.path().into(),
        pid_file: root.path().join("unused.pid"),
        pid: None,
        vsock_uds: "unused".into(),
        flush_via_agent: false,
    };
    std::fs::write(root.path().join("workload.exit"), b"0").unwrap();
    {
        let guard = state.lock().unwrap();
        let (sender, done) = std::sync::mpsc::sync_channel(1);
        let pending = std::thread::spawn(move || {
            let result = vm.wait_with_deadline(Instant::now());
            sender.send((vm, result)).unwrap();
        });
        let result = done.recv_timeout(Duration::from_secs(2));
        drop(guard);
        pending.join().unwrap();
        let (returned, result) =
            result.expect("original wait must not block behind lifecycle cleanup");
        assert_eq!(result.unwrap(), mvm_core::vm_backend::VmExitStatus::UNKNOWN);
        original_wait_after_report(returned, &state, root.path(), &socket);
    }
}

fn original_wait_after_report(
    vm: super::super::running::FcRunningVm,
    state: &Arc<Mutex<OwnedFcState>>,
    root: &std::path::Path,
    socket: &std::path::Path,
) {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(&42_i32.to_le_bytes()).unwrap();
    let mut ack = [0];
    stream.read_exact(&mut ack).unwrap();
    assert_eq!(ack, [1]);
    let result = vm
        .wait_with_deadline(Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert_eq!(result.code, Some(42));
    assert!(!result.success);
    std::fs::write(root.join("workload.exit"), b"0").unwrap();
    assert_eq!(vm.wait_with_deadline(Instant::now()).unwrap(), result);
    let original_report = vm
        .original_workload_report()
        .expect("original report evidence");
    state
        .lock()
        .unwrap()
        .exit_capture
        .as_mut()
        .unwrap()
        .stop(Instant::now() + Duration::from_secs(3))
        .unwrap();
    drop(vm);
    assert_eq!(
        Arc::strong_count(state),
        1,
        "a report must not retain VM custody"
    );
    assert_eq!(original_report.wait_until(Instant::now()).unwrap(), result);
}

fn lease(root: &std::path::Path) -> PreparedHostLifetimeLease {
    let state = b"original Firecracker admission";
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("state.bin"), state).unwrap();
    std::fs::set_permissions(
        root.join("state.bin"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let digest = mvm_core::crypto::image_verify::sha256_generated_bytes(state).unwrap();
    let mut state_sha256 = [0; 32];
    for (i, byte) in state_sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16).unwrap();
    }
    PreparedHostLifetimeLease::bind(
        File::open(root).unwrap(),
        File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("holder.lock"))
            .unwrap(),
        HostLeaseExpectation {
            state_name: "state.bin".into(),
            state_bytes: u16::try_from(state.len()).unwrap(),
            state_sha256,
            absent_names: [".state.next".into(), ".state.intent".into()],
        },
    )
    .unwrap()
}

fn binding() -> HostLaunchBinding {
    HostLaunchBinding {
        installation: [1; 32],
        profile: [2; 32],
        generation: 3,
        grant_serial: 4,
        vm_name: "w".into(),
        backend: mvm_core::vm_backend::BackendKind::Firecracker,
        cpus: 2,
        memory_mib: 512,
    }
}

fn state(root: &std::path::Path) -> OwnedFcState {
    OwnedFcState {
        binding: binding(),
        lease: Some(lease(root)),
        child: None,
        lifetime: None,
        spawn_attempted: false,
        retired: false,
        authenticated: false,
        exit_capture: None,
    }
}

#[test]
fn a_wrong_original_shape_is_refused_with_the_unchanged_unspawned_lease() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let lease = lease(root.path());
    let holder_id = lease.holder_object_id();
    let directory_id = lease.directory_object_id();
    let mut binding = binding();
    binding.memory_mib -= 1;
    let spec =
        super::super::tests::spec_with(mvm_vmm::driver::spec::KernelImage::Bundled, vec![], vec![]);
    let files = PreparedBootFiles {
        kernel: None,
        workload_root: None,
        writable: PreparedWritableDisks::empty(),
        data: None,
    };
    let result = super::super::FcDriver::new()
        .boot_custodied_with_host_lifetime(&spec, files, lease, &binding);
    let error = match result {
        Ok(_) => panic!("wrong shape unexpectedly booted"),
        Err(error) => error,
    };
    let original = error
        .downcast_ref::<OriginalFcNotSpawned>()
        .expect("positive no-spawn refusal");
    assert_eq!(original.binding(), &binding);
    assert_eq!(original.lease().holder_object_id(), holder_id);
    assert_eq!(original.lease().directory_object_id(), directory_id);
    original.lease().verify_current().unwrap();
}

#[test]
fn original_custody_survives_a_kernel_recipe_refusal_before_spawn() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let lease = lease(root.path());
    let holder_id = lease.holder_object_id();
    let spec =
        super::super::tests::spec_with(mvm_vmm::driver::spec::KernelImage::Bundled, vec![], vec![]);
    let files = PreparedBootFiles {
        kernel: None,
        workload_root: None,
        writable: PreparedWritableDisks::empty(),
        data: None,
    };
    let result = super::super::FcDriver::new().boot_custodied_with_host_lifetime(
        &spec,
        files,
        lease,
        &binding(),
    );
    let error = match result {
        Ok(_) => panic!("bundled kernel unexpectedly booted"),
        Err(error) => error,
    };
    let original = error
        .downcast_ref::<OriginalFcNotSpawned>()
        .expect("positive no-spawn refusal");
    assert_eq!(original.lease().holder_object_id(), holder_id);
    original.lease().verify_current().unwrap();
}

fn child(state: &mut OwnedFcState) {
    let mut command = mvm_core::env_hygiene::helper_command("/bin/cat");
    command.stdin(Stdio::piped()).stdout(Stdio::null());
    state.begin_spawn().unwrap();
    let mut child = command.spawn().unwrap();
    let original = OriginalProcess::observe(&mut child).unwrap();
    state.record_spawn(Ok((child, original))).unwrap();
}

#[test]
fn an_expired_stop_deadline_keeps_the_original_child_alive_for_retry() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut state = state(root.path());
    child(&mut state);
    let failed = state.stop_original(Instant::now()).is_err();
    let live = state.process().unwrap().require_live().is_ok();
    state
        .stop_original(Instant::now() + Duration::from_secs(3))
        .unwrap();
    state.retired = true;
    assert!(failed);
    assert!(live);
    assert!(state.child.as_mut().unwrap().try_wait().unwrap().is_some());
}

#[test]
fn a_spawned_unverified_process_cannot_manufacture_a_firecracker_receipt() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut state = state(root.path());
    child(&mut state);
    let original = Arc::new(Mutex::new(state));
    let error = boot_failure(
        Arc::clone(&original),
        anyhow::anyhow!("injected config failure"),
    );
    assert!(error.downcast_ref::<OriginalFcNotSpawned>().is_none());
    let mut failure = error.downcast::<OwnedFcBootFailure>().unwrap();
    assert!(
        failure
            .collect_original(Instant::now() + Duration::from_secs(3))
            .is_err()
    );
    let mut state = original.lock().unwrap();
    assert!(state.child.as_mut().unwrap().try_wait().unwrap().is_some());
    assert!(!state.retired);
    state
        .lifetime
        .as_ref()
        .unwrap()
        .lease()
        .unwrap()
        .verify_current()
        .unwrap();
    state.retired = true;
}
