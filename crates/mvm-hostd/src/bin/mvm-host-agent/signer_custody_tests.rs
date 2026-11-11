//! Fresh-process regression for the actual worker-mode signer spawn path.
use super::*;
use std::os::unix::fs::PermissionsExt;

const ENTRY: &str = "SC_SIGNER_CUSTODY_ENTRY";
const HELPER: &str = "SC_SIGNER_CUSTODY_HELPER";

#[cfg(target_os = "linux")]
fn force_tokio_signal_fallback() {
    // Tokio 1.53.3 requests PIDFD_NONBLOCK; the canonical observer requests 0.
    // Only this isolated process and its fixture descendants inherit the filter.
    let mut filter = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: libc::SYS_pidfd_open.try_into().unwrap(),
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 24,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::PIDFD_NONBLOCK,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | u32::try_from(libc::ENOSYS).unwrap(),
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len().try_into().unwrap(),
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: process-local no-new-privileges; no global or other-process state.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    // SAFETY: valid bounded classic BPF program. It denies only pidfd_open's
    // NONBLOCK variant, leaving the original-child observer's zero-flags call.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
}

#[test]
fn production_signer_start_preserves_original_child_custody() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "signer_custody_tests::isolated_signer_custody_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENTRY, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated production signer regression failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// Invoked only by the parent above, so a process-global signal registration or
// a Linux filter cannot contaminate another test or its original child custody.
#[test]
fn isolated_signer_custody_entry() {
    if std::env::var_os(ENTRY).is_none() {
        return;
    }
    mvm_vmm::host::process_exit::require_owned_child_custody().unwrap();
    #[cfg(target_os = "linux")]
    force_tokio_signal_fallback();
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("signer-fixture");
    let executable = std::env::current_exe().unwrap();
    let quoted = executable.to_str().unwrap().replace('\'', "'\\''");
    std::fs::write(&fixture, format!("#!/bin/sh\n{HELPER}=1 exec '{quoted}' --exact signer_custody_tests::signer_helper_fixture --nocapture --test-threads=1\n")).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut environment = mvm_core::util::test_env::TestEnv::new();
    environment.set("MVM_SIGNER_HELPER_PATH", &fixture);
    let config = HostAgentConfig {
        tenant_id: "signer-custody-fixture".into(),
        control_socket: directory.path().join("control.sock"),
        registration_journal_path: None,
        host_signer_public_key_path: directory.path().join("unused-public-key"),
        signer_helper_uds_path: directory.path().join("signer.sock"),
        software_chain_key_path: directory.path().join("unused-chain-key"),
        max_frame_bytes: 65_536,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut child = spawn_signer_helper(&config)
            .await
            .expect("actual production signer spawn/readiness");
        let custody = mvm_vmm::host::process_exit::require_owned_child_custody();
        // Always terminate/collect the actual fixture before reporting the RED.
        child.kill().await.expect("kill original fixture child");
        let status = child.wait().await.expect("collect original fixture child");
        assert!(!status.success());
        custody
            .expect("production signer installed a SIGCHLD handler before mailbox worker custody");
        mvm_vmm::host::process_exit::require_owned_child_custody()
            .expect("custody remains valid after original collection");
    });
}

// Fixed stand-in signer: reads the real production config and binds its actual
// readiness socket, but never reads a signing key and never forks a descendant.
#[test]
fn signer_helper_fixture() {
    if std::env::var_os(HELPER).is_none() {
        return;
    }
    let raw = read_stdin_blocking().unwrap();
    let config: SignerHelperConfig = serde_json::from_slice(&raw).unwrap();
    if std::env::var_os("SC_SIGNER_CUSTODY_HOLD").is_some() {
        loop {
            std::thread::park();
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(config.uds_path).unwrap();
    for connection in listener.incoming() {
        drop(connection.unwrap());
    }
}

// These bounded test-only notifications witness the production call/collection
// sites. No fixture observes or reaps a process through a numeric PID.
static CONNECT_ATTEMPT: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<()>>> =
    std::sync::Mutex::new(None);
static COLLECTED: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<std::process::ExitStatus>>> =
    std::sync::Mutex::new(None);
pub(super) fn record_connect_attempt() {
    if let Some(sender) = CONNECT_ATTEMPT.lock().unwrap().as_ref() {
        let _ = sender.try_send(());
    }
}
pub(super) fn record_collection(status: std::process::ExitStatus) {
    if let Some(sender) = COLLECTED.lock().unwrap().as_ref() {
        let _ = sender.try_send(status);
    }
}

#[test]
fn saturated_signer_socket_cancellation_collects_original_child() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "signer_custody_tests::isolated_saturated_signer_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENTRY, "backlog")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated saturated signer regression failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn isolated_saturated_signer_entry() {
    if std::env::var_os(ENTRY).is_none() {
        return;
    }
    mvm_vmm::host::process_exit::require_owned_child_custody().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("signer.sock");
    let listener = {
        let _runtime = runtime.enter();
        let socket = tokio::net::UnixSocket::new_stream().unwrap();
        socket.bind(&socket_path).unwrap();
        // A controlled tiny backlog, not the platform's large default. This is
        // only the fault fixture; no production listener limit changes.
        socket.listen(1).unwrap().into_std().unwrap()
    };
    let mut queued = Vec::new();
    let mut full = false;
    let setup_deadline = Instant::now() + Duration::from_secs(5);
    for _ in 0..512 {
        assert!(
            Instant::now() < setup_deadline,
            "bounded backlog setup expired before saturation"
        );
        let probe = runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(
                    setup_deadline.min(Instant::now() + Duration::from_millis(100)),
                ),
                tokio::net::UnixSocket::new_stream()
                    .unwrap()
                    .connect(&socket_path),
            )
            .await
        });
        match probe {
            Ok(Ok(stream)) => {
                assert!(
                    stream.peer_addr().is_ok(),
                    "queued probe must actually be connected"
                );
                queued.push(stream.into_std().unwrap());
            }
            Ok(Err(error)) if error.raw_os_error() == Some(libc::EAGAIN) => {
                // A real nonblocking connect refused for backlog pressure,
                // after actual connected sockets filled this owned listener.
                eprintln!(
                    "SIGNER_BACKLOG_WITNESS queued={} unconnected_errno={}",
                    queued.len(),
                    libc::EAGAIN
                );
                full = true;
                break;
            }
            other => {
                panic!("backlog setup did not establish an unconnected EAGAIN probe: {other:?}")
            }
        }
    }
    assert!(
        full && !queued.is_empty(),
        "actual bounded UDS backlog must be saturated"
    );
    let fixture = directory.path().join("signer-fixture");
    let executable = std::env::current_exe().unwrap();
    let quoted = executable.to_str().unwrap().replace('\'', "'\\''");
    std::fs::write(&fixture, format!("#!/bin/sh\n{HELPER}=1 SC_SIGNER_CUSTODY_HOLD=1 exec '{quoted}' --exact signer_custody_tests::signer_helper_fixture --nocapture --test-threads=1\n")).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut environment = mvm_core::util::test_env::TestEnv::new();
    environment.set("MVM_SIGNER_HELPER_PATH", &fixture);
    let config = HostAgentConfig {
        tenant_id: "signer-backlog-fixture".into(),
        control_socket: directory.path().join("control.sock"),
        registration_journal_path: None,
        host_signer_public_key_path: directory.path().join("unused-public-key"),
        signer_helper_uds_path: socket_path,
        software_chain_key_path: directory.path().join("unused-chain-key"),
        max_frame_bytes: 65_536,
    };
    let (connecting, connected) = std::sync::mpsc::sync_channel(1);
    let (collection, collected) = std::sync::mpsc::sync_channel(1);
    *CONNECT_ATTEMPT.lock().unwrap() = Some(connecting);
    *COLLECTED.lock().unwrap() = Some(collection);
    runtime.block_on(async move {
        let attempt = tokio::spawn(async move { spawn_signer_helper(&config).await });
        let connect_seen = tokio::task::spawn_blocking(move || connected.recv_timeout(SIGNER_HELPER_READY_TIMEOUT + Duration::from_secs(2))).await.unwrap();
        attempt.abort();
        drop(attempt.await); // A successful task result must also drop its facade.
        let (collected, before_release) = tokio::task::spawn_blocking(move || {
            let status = collected.recv_timeout(Duration::from_secs(2));
            (collected, status)
        }).await.unwrap();
        let collected_before_release = before_release.is_ok();
        // Always release the owned fault before asserting RED. A blocked old
        // connect then returns; its original actor must collect the helper.
        drop(listener);
        drop(queued);
        let status = match before_release {
            Ok(status) => status,
            Err(_) => tokio::task::spawn_blocking(move || collected.recv_timeout(Duration::from_secs(5))).await.unwrap().expect("original helper collected after releasing owned backlog"),
        };
        assert!(!status.success(), "actual fixture helper was stopped");
        connect_seen.expect("production actor reached actual connect attempt");
        assert!(collected_before_release, "cancellation failed to interrupt saturated readiness connect; original helper collected only after releasing backlog");
    });
}

#[test]
fn preexisting_sigchld_handler_refuses_signer_before_spawn() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "signer_custody_tests::isolated_sigchld_guard_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENTRY, "guard")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated custody refusal failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

extern "C" fn notification_only_sigchld(_: libc::c_int) {}
#[test]
fn isolated_sigchld_guard_entry() {
    if std::env::var_os(ENTRY).is_none() {
        return;
    }
    // This fresh child owns no signer. Never restore a handler around a live
    // uncertain owner just to make fixture cleanup pass.
    // SAFETY: zeroed sigaction with an initialized empty signal mask and a
    // no-op async-signal-safe handler, installed only in this test subprocess.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = notification_only_sigchld as *const () as libc::sighandler_t;
    // SAFETY: valid mask storage and a valid action for this process only.
    unsafe {
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(
            libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()),
            0
        );
    }
    assert!(mvm_vmm::host::process_exit::require_owned_child_custody().is_err());
    let directory = tempfile::tempdir().unwrap();
    let mut environment = mvm_core::util::test_env::TestEnv::new();
    environment.set(
        "MVM_SIGNER_HELPER_PATH",
        directory.path().join("missing-helper"),
    );
    let config = HostAgentConfig {
        tenant_id: "signer-guard-fixture".into(),
        control_socket: directory.path().join("control.sock"),
        registration_journal_path: None,
        host_signer_public_key_path: directory.path().join("unused-public-key"),
        signer_helper_uds_path: directory.path().join("signer.sock"),
        software_chain_key_path: directory.path().join("unused-chain-key"),
        max_frame_bytes: 65_536,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        match spawn_signer_helper(&config).await {
            Err(error) => assert!(
                format!("{error:#}").contains("requires default SIGCHLD"),
                "must refuse custody before trying missing helper: {error:#}"
            ),
            Ok(mut child) => {
                child.request_stop();
                let _ = child.wait().await;
                panic!("nondefault SIGCHLD cannot authorize a signer spawn");
            }
        }
    });
}
