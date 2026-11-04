use super::*;
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::process::Command;

const MODE: &str = "MVM_FC_GUARDIAN_OWNED_FIXTURE";

fn fixture_binding() -> HostLaunchBinding {
    HostLaunchBinding {
        installation: [1; 32],
        profile: [2; 32],
        generation: 1,
        grant_serial: 1,
        vm_name: "guardian-fixture".into(),
        backend: mvm_core::vm_backend::BackendKind::Firecracker,
        cpus: 1,
        memory_mib: 1024,
    }
}

#[test]
fn guardian_fixture_child() {
    let Some(path) = std::env::var_os(MODE) else {
        return;
    };
    // The harness banners stay on stderr; only production control uses fd199.
    // SAFETY: this exact owned fixture's pre_exec transferred descriptor199.
    let mut output = unsafe { File::from_raw_fd(199) };
    let mut input = duplicate_stdio(0).unwrap();
    let prepare: Prepare = read_frame(
        &mut input,
        CONFIG_LIMIT,
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    holder.lock_shared().unwrap();
    let child = Command::new("/bin/sh")
        .args(["-c", "read -r owned_fixture_input"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    serve_child(child, holder, prepare, &mut input, &mut output).unwrap();
}

fn spawn_fixture(holder: &std::path::Path) -> Child {
    let target = format!(
        "{}::guardian_fixture_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &target, "--nocapture", "--test-threads=1"])
        .env(MODE, holder)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: only descriptor operations in this owned fixture child. Preserve
    // the protocol pipe before directing libtest's unrelated banners elsewhere.
    unsafe {
        command.pre_exec(|| {
            if libc::dup2(1, 199) < 0 || libc::dup2(2, 1) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

#[test]
fn original_guardian_reaps_native_child_and_launcher_before_confirming_exit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("holders.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    let meta = file.metadata().unwrap();
    let output = OutputFile {
        parent_pid: std::process::id(),
        fd: file.as_raw_fd(),
        object: (meta.dev(), meta.ino()),
        uid: meta.uid(),
    };
    let mut config = FcGuardianConfig {
        binding: fixture_binding(),
        program: "/not-used-by-owned-fixture".into(),
        api_socket: root.path().join("api.sock"),
        state_dir: root.path().to_owned(),
        holder_object: (meta.dev(), meta.ino()),
        holder_uid: meta.uid(),
        console: output.clone(),
        stderr: output,
    };
    // Distinct fixed metadata is enough for this loop-only fixture; native output
    // reopen is separately tested and actual executable injection is test-only.
    config.console.object.1 = config.console.object.1.checked_add(1).unwrap();
    config.stderr.object.1 = config.stderr.object.1.checked_add(2).unwrap();
    let child = spawn_fixture(&path);
    let mut owner =
        OwnedFcLauncher::start(child, config, Instant::now() + Duration::from_secs(3)).unwrap();
    assert!(owner.native_pid().is_some());
    assert!(file.try_lock().is_err(), "live guardian must retain SH");
    let exit = owner.stop(Instant::now() + Duration::from_secs(3)).unwrap();
    assert_eq!(exit.binding(), &fixture_binding());
    assert_eq!(exit.native_pid(), owner.native_pid());
    file.try_lock().unwrap();
    assert!(
        owner.stop(Instant::now()).is_ok(),
        "confirmed completion is idempotent"
    );
}

#[test]
fn incomplete_ready_can_retire_only_after_eof_and_original_guardian_success() {
    use std::os::fd::OwnedFd;
    use std::sync::mpsc;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("holders.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    let meta = file.metadata().unwrap();
    let output = OutputFile {
        parent_pid: std::process::id(),
        fd: file.as_raw_fd(),
        object: (meta.dev(), meta.ino().checked_add(1).unwrap()),
        uid: meta.uid(),
    };
    let mut config = FcGuardianConfig {
        binding: fixture_binding(),
        program: "/not-used-by-owned-fixture".into(),
        api_socket: root.path().join("api.sock"),
        state_dir: root.path().to_owned(),
        holder_object: (meta.dev(), meta.ino()),
        holder_uid: meta.uid(),
        console: output.clone(),
        stderr: output,
    };
    config.stderr.object.1 = config.stderr.object.1.checked_add(1).unwrap();
    let mut child = spawn_fixture(&path);
    let observer = ProcessExitObserver::arm(child.id().try_into().unwrap()).unwrap();
    let mut original = child.stdout.take().unwrap();
    let (reader, mut writer) = std::io::pipe().unwrap();
    child.stdout = Some(ChildStdout::from(OwnedFd::from(reader)));
    let (release, wait) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let gate = scope.spawn(move || {
            let mut prefix = [0; 2];
            original.read_exact(&mut prefix).unwrap();
            writer.write_all(&prefix).unwrap();
            wait.recv_timeout(Duration::from_secs(3)).unwrap();
            // Preserve all real response bytes after the deliberately partial
            // prefix. No fabricated readiness or terminal response is injected.
            if let Err(error) = std::io::copy(&mut original, &mut writer) {
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            }
        });
        let failure =
            OwnedFcLauncher::start(child, config, Instant::now() + Duration::from_millis(100))
                .err()
                .expect("the actual Ready frame is incomplete");
        let (_, mut owner) = failure.downcast::<LaunchFailure>().unwrap().into_parts();
        assert!(owner.native_pid().is_none());
        assert!(file.try_lock().is_err(), "the actual guardian retains SH");
        release.send(()).unwrap();
        let result = owner.stop(Instant::now() + Duration::from_secs(2));
        let retired = result.is_ok();
        // The original implementation fails this operation. Always close its
        // own pipe and collect the exact original helper before asserting RED.
        owner.input.take();
        assert_eq!(
            observer
                .wait_event(Instant::now() + Duration::from_secs(3))
                .unwrap(),
            ProcessExitWait::Exited
        );
        let status = collect_after_exit_event(Instant::now() + Duration::from_secs(1), || {
            owner.child.as_mut().unwrap().try_wait()
        })
        .unwrap()
        .unwrap();
        assert!(status.success());
        gate.join().unwrap();
        file.try_lock().unwrap();
        assert!(
            retired,
            "positive original EOF cleanup must permit retirement"
        );
        let proof = result.unwrap();
        assert_eq!(proof.binding(), &fixture_binding());
        assert_eq!(proof.native_pid(), None);
    });
}

#[test]
fn nonzero_original_launcher_exit_cannot_confirm_eof_cleanup() {
    let child = Command::new("/bin/sh")
        .args(["-c", "read -r ignored; exit 7"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut owner = OwnedFcLauncher::hold_unprepared(child, fixture_binding());
    assert!(owner.stop(Instant::now() + Duration::from_secs(2)).is_err());
    assert_eq!(owner.native_pid(), None);
    assert!(owner.confirmed.is_none());
    assert_eq!(
        owner
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .unwrap()
            .code(),
        Some(7)
    );
    assert!(owner.stop(Instant::now() + Duration::from_secs(1)).is_err());
    assert!(owner.confirmed.is_none());
}

#[test]
fn oversized_prefix_and_partial_prefix_refuse_inside_original_deadline() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(&u32::MAX.to_be_bytes()).unwrap();
    let bad: Result<Reply> = read_frame(
        &mut reader,
        CONTROL_LIMIT,
        Instant::now() + Duration::from_secs(1),
    );
    assert!(bad.is_err());
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(&[0]).unwrap();
    let started = Instant::now();
    let partial: Result<Reply> = read_frame(
        &mut reader,
        CONTROL_LIMIT,
        started + Duration::from_millis(15),
    );
    assert!(partial.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn original_output_reopen_refuses_substitution_without_truncating_source() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("output");
    std::fs::write(&path, b"original").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    let meta = file.metadata().unwrap();
    let mut source = OutputFile {
        parent_pid: std::process::id(),
        fd: file.as_raw_fd(),
        object: (meta.dev(), meta.ino()),
        uid: meta.uid(),
    };
    assert!(reopen_output(&source).is_ok());
    source.object.1 = source.object.1.checked_add(1).unwrap();
    assert!(reopen_output(&source).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
}
