//! A real child owns the Unix listener and inherits the original holder. It
//! speaks the guest session protocol, without starting a Firecracker guest.
use crate::driver::fc::{
    owned::{OwnedFcState, tests as owned_fixture},
    running::FcRunningVm,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_agentd::vsock::{
    ActivateEnvironment, AuthenticatedSession, EntrypointEvent, GuestRequest, GuestResponse,
    RootfsConfig,
};
use mvm_core::{host_lifetime::HostLifetimeAnchor, util::test_env::TestEnv};
use mvm_vmm::{
    driver::{OriginalEntrypointChannel, OriginalEntrypointIdentity, RunningVm},
    host::{fc_lifetime::OriginalProcess, process_exit::ProcessExitWait},
};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::net::{UnixListener, UnixStream},
    },
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const PEER_TEST: &str = "driver::fc::entrypoint::tests::original_guest_protocol_child";
const BUDGET: Duration = Duration::from_secs(10);
const OUTPUT: &[u8] = b"out\0\xff\0";

fn until() -> Instant {
    Instant::now() + BUDGET
}

fn read_byte(stream: &mut UnixStream) -> u8 {
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    byte[0]
}

fn activation() -> GuestRequest {
    GuestRequest::ActivateEnvironment(ActivateEnvironment {
        rootfs: RootfsConfig {
            data_dev: "/dev/vda".into(),
            hash_dev: Some("/dev/vdb".into()),
            roothash: Some("a".repeat(64)),
            virtiofs_tag: None,
            in_place: false,
        },
        runtime: None,
        volumes: vec![],
        extensions: vec![],
        verb_grant_envelope: None,
    })
}

fn run(stream_input: bool) -> GuestRequest {
    GuestRequest::RunEntrypoint {
        stdin: b"in\0".to_vec(),
        timeout_secs: 2,
        env: vec![],
        stream_input,
    }
}

// Both positive and negative cases require a clean child test result. The
// private readiness socket keeps the process live until the host post-checks
// finish, independently of whether the control stream was closed or poisoned.
#[test]
#[ignore = "peer subprocess for the original entrypoint component tests"]
fn original_guest_protocol_child() {
    let Some(path) = std::env::var_os("MVM_TEST_ORIGINAL_CONTROL_SOCKET") else {
        return;
    };
    let mode = std::env::var("MVM_TEST_ORIGINAL_CONTROL_MODE").unwrap();
    let public: [u8; 32] = hex::decode(std::env::var("MVM_TEST_ORIGINAL_CONTROL_HOST").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut events = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
    events.set_read_timeout(Some(BUDGET)).unwrap();
    let listener = UnixListener::bind(path).unwrap();
    events.write_all(b"R").unwrap();
    // First connection is used only for authentication of the original config
    // peer. The second is the one-shot protected control stream.
    drop(listener.accept().unwrap());
    if mode != "unopened" {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(BUDGET)).unwrap();
        stream.set_write_timeout(Some(BUDGET)).unwrap();
        let mut connect = [0u8; 13];
        stream.read_exact(&mut connect).unwrap();
        assert_eq!(&connect, b"CONNECT 5252\n");
        stream.write_all(b"OK 8123\n").unwrap();

        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut seed)
            .unwrap();
        let mut session = AuthenticatedSession::guest(
            &mut stream,
            SigningKey::from_bytes(&seed),
            &VerifyingKey::from_bytes(&public).unwrap(),
        )
        .unwrap();
        if mode != "expired" {
            assert!(matches!(
                session.read(&mut stream).unwrap(),
                GuestRequest::ActivateEnvironment(_)
            ));
            session
                .write(&mut stream, &GuestResponse::ActivateEnvironmentAck)
                .unwrap();
        }
        if mode.starts_with("journal-") {
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            serve_journal(
                &listener,
                SigningKey::from_bytes(&seed),
                &VerifyingKey::from_bytes(&public).unwrap(),
                &mode,
            );
        }
        if matches!(mode.as_str(), "complete" | "panic" | "partial") {
            assert!(matches!(
                session.read(&mut stream).unwrap(),
                GuestRequest::RunEntrypoint { stdin, timeout_secs: 2, env, stream_input: false }
                    if stdin == b"in\0" && env.is_empty()
            ));
            if mode == "partial" {
                let mut encoded = vec![];
                session
                    .write(
                        &mut encoded,
                        &GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code: 0 }),
                    )
                    .unwrap();
                stream.write_all(&encoded[..encoded.len() - 1]).unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
            } else {
                session
                    .write(
                        &mut stream,
                        &GuestResponse::EntrypointEvent(EntrypointEvent::Stdout {
                            chunk: OUTPUT.to_vec(),
                        }),
                    )
                    .unwrap();
                if mode == "complete" {
                    session
                        .write(
                            &mut stream,
                            &GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code: 42 }),
                        )
                        .unwrap();
                    assert!(matches!(
                        session.read(&mut stream).unwrap(),
                        GuestRequest::SyncFilesystems
                    ));
                    session
                        .write(&mut stream, &GuestResponse::FilesystemsSynced)
                        .unwrap();
                }
            }
        }
        // No extra bytes after a successful flush, a pre-write refusal, or a
        // poisoned partial frame/observer. Encrypted bytes are still bytes.
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    }
    assert_eq!(read_byte(&mut events), b'F');
    // No second control connection was even queued by any refused reopen.
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn serve_journal(listener: &UnixListener, guest: SigningKey, host: &VerifyingKey, mode: &str) {
    let count = if mode == "journal-complete" {
        3
    } else if mode == "journal-key" {
        1
    } else {
        2
    };
    for index in 0..count {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(BUDGET)).unwrap();
        stream.set_write_timeout(Some(BUDGET)).unwrap();
        let mut connect = [0; 13];
        stream.read_exact(&mut connect).unwrap();
        assert_eq!(&connect, b"CONNECT 5252\n");
        stream.write_all(b"OK 8123\n").unwrap();
        let signer = if mode == "journal-key" {
            SigningKey::from_bytes(&[71; 32])
        } else {
            guest.clone()
        };
        let mut session = AuthenticatedSession::guest(&mut stream, signer, host).unwrap();
        if mode == "journal-key" || (index > 0 && mode == "journal-input") {
            assert!(session.read::<GuestRequest>(&mut stream).is_err());
            continue;
        }
        if index == 0 {
            assert!(matches!(
                session.read(&mut stream).unwrap(),
                GuestRequest::Ping
            ));
            session.write(&mut stream, &GuestResponse::Pong).unwrap();
        } else {
            assert!(
                matches!(session.read(&mut stream).unwrap(), GuestRequest::RunEntrypoint { stdin, timeout_secs: 2, env, stream_input: false }
                if stdin == b"in\0" && env.is_empty())
            );
            if mode == "journal-partial" {
                let mut frame = vec![];
                session
                    .write(
                        &mut frame,
                        &GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code: 42 }),
                    )
                    .unwrap();
                stream.write_all(&frame[..frame.len() - 1]).unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
            } else {
                let chunk = if mode == "journal-output" {
                    vec![0; 64 << 10]
                } else {
                    OUTPUT.to_vec()
                };
                for _ in 0..if mode == "journal-output" { 3 } else { 1 } {
                    session
                        .write(
                            &mut stream,
                            &GuestResponse::EntrypointEvent(EntrypointEvent::Stdout {
                                chunk: chunk.clone(),
                            }),
                        )
                        .unwrap();
                }
                if mode != "journal-panic" {
                    session
                        .write(
                            &mut stream,
                            &GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code: 42 }),
                        )
                        .unwrap();
                }
            }
        }
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn journal_activation_closes_before_ready_and_reuses_only_terminal_calls() {
    let fixture = Fixture::new("journal-complete");
    let mut journal = fixture
        .activated()
        .finish_journal_activation(until())
        .unwrap();
    journal.ready(until()).unwrap();
    for _ in 0..2 {
        let mut output = vec![];
        let terminal = journal
            .entrypoint(&run(false), until(), &mut |event| {
                output.push(event.clone())
            })
            .unwrap();
        assert_eq!(terminal, EntrypointEvent::Exit { code: 42 });
        assert_eq!(
            output,
            [EntrypointEvent::Stdout {
                chunk: OUTPUT.to_vec()
            }]
        );
    }
    assert!(fixture.open().is_err());
    drop(journal);
    fixture.finish();
}

#[test]
fn journal_changed_guest_key_fences_without_replacing_original() {
    let fixture = Fixture::new("journal-key");
    let mut journal = fixture
        .activated()
        .finish_journal_activation(until())
        .unwrap();
    assert!(journal.ready(until()).is_err());
    assert!(journal.ready(until()).is_err());
    drop(journal);
    fixture.finish();
}

#[test]
fn journal_partial_reply_and_output_overflow_fence_reuse() {
    for mode in ["journal-partial", "journal-output"] {
        let fixture = Fixture::new(mode);
        let mut journal = fixture
            .activated()
            .finish_journal_activation(until())
            .unwrap();
        journal.ready(until()).unwrap();
        let mut bytes = 0;
        assert!(
            journal
                .entrypoint(&run(false), until(), &mut |event| {
                    if let EntrypointEvent::Stdout { chunk } = event {
                        bytes += chunk.len();
                    }
                })
                .is_err()
        );
        assert!(bytes <= 128 << 10);
        assert!(journal.ready(until()).is_err());
        drop(journal);
        fixture.finish();
    }
}

#[test]
fn journal_callback_unwind_fences_and_preserves_original_stop() {
    let fixture = Fixture::new("journal-panic");
    let mut journal = fixture
        .activated()
        .finish_journal_activation(until())
        .unwrap();
    journal.ready(until()).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        journal.entrypoint(&run(false), until(), &mut |_| {
            panic!("fixture observer unwind")
        })
    }));
    assert!(result.is_err());
    assert!(journal.ready(until()).is_err());
    drop(journal);
    fixture.finish();
}

#[test]
fn journal_input_overflow_never_sends_application_input() {
    let fixture = Fixture::new("journal-input");
    let mut journal = fixture
        .activated()
        .finish_journal_activation(until())
        .unwrap();
    journal.ready(until()).unwrap();
    let request = GuestRequest::RunEntrypoint {
        stdin: vec![0; (64 << 10) + 1],
        timeout_secs: 2,
        env: vec![],
        stream_input: false,
    };
    assert!(
        journal
            .entrypoint(&request, until(), &mut |_| panic!("unexpected event"))
            .is_err()
    );
    assert!(journal.ready(until()).is_err());
    drop(journal);
    fixture.finish();
}

struct Fixture {
    vm: FcRunningVm,
    anchor: Arc<HostLifetimeAnchor>,
    identity: OriginalEntrypointIdentity,
    state: Arc<Mutex<OwnedFcState>>,
    events: UnixStream,
    _env: TestEnv,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new(mode: &str) -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let keys = mvm_core::config::mvm_keys_dir();
        mvm_core::config::create_private_dir(&keys).unwrap();
        let (_, host) = mvm_core::crypto::ed25519_keypair::load_or_init(
            &keys.join("host-signer.ed25519"),
            &keys.join("host-signer.pub"),
        )
        .unwrap();
        let socket = dir.path().join("mux.sock");
        let mut state = owned_fixture::state(dir.path());
        let lease = state.lease.as_ref().unwrap();
        let anchor = owned_fixture::kernel_anchor(lease, state.binding.clone());
        let (events, child_events) = UnixStream::pair().unwrap();
        events.set_read_timeout(Some(BUDGET)).unwrap();
        let mut command = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
        command
            .args(["--ignored", "--exact", PEER_TEST, "--nocapture"])
            .env("MVM_TEST_ORIGINAL_CONTROL_MODE", mode)
            .env("MVM_TEST_ORIGINAL_CONTROL_SOCKET", &socket)
            .env(
                "MVM_TEST_ORIGINAL_CONTROL_HOST",
                hex::encode(host.to_bytes()),
            )
            .stdin(Stdio::from(OwnedFd::from(child_events)));
        mvm_vmm::host::restore_image::inherit_descriptors(
            &mut command,
            vec![lease.holder().as_raw_fd()],
        );
        state.begin_spawn().unwrap();
        let mut child = command.spawn().unwrap();
        let process = OriginalProcess::observe(&mut child).unwrap();
        state.record_spawn(Ok((child, process))).unwrap();
        drop(command);
        let state = Arc::new(Mutex::new(state));
        let vm = FcRunningVm {
            owned: Some(state.clone()),
            original_report: None,
            id: mvm_core::vm_backend::VmId("w".into()),
            state_dir: dir.path().into(),
            pid_file: dir.path().join("unused.pid"),
            pid: None,
            vsock_uds: socket.to_str().unwrap().into(),
            flush_via_agent: false,
        };
        let mut fixture = Self {
            vm,
            anchor,
            identity: OriginalEntrypointIdentity {
                host: host.to_bytes(),
            },
            state,
            events,
            _env: env,
            _dir: dir,
        };
        assert_eq!(read_byte(&mut fixture.events), b'R');
        let config = UnixStream::connect(socket).unwrap();
        fixture
            .state
            .lock()
            .unwrap()
            .authenticate_config(&config)
            .unwrap();
        fixture
    }

    fn open(&self) -> anyhow::Result<Box<dyn OriginalEntrypointChannel>> {
        self.vm
            .open_owned_entrypoint(self.anchor.clone(), self.identity, until())
    }

    fn activated(&self) -> Box<dyn OriginalEntrypointChannel> {
        let mut channel = self.open().unwrap();
        assert!(matches!(
            channel.activate(&activation(), until()).unwrap(),
            GuestResponse::ActivateEnvironmentAck
        ));
        channel
    }

    fn finish(mut self) {
        self.events.write_all(b"F").unwrap();
        let mut state = self.state.lock().unwrap();
        assert_eq!(
            state.process().unwrap().wait_exit(until()).unwrap(),
            ProcessExitWait::Exited
        );
        state.collect_original(until()).unwrap();
        assert!(
            state
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .unwrap()
                .success()
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.retired && state.stop_original(until()).is_ok() {
            state.retired = true;
        }
    }
}

#[test]
fn original_control_runs_once_with_exact_events_and_terminal_sync() {
    let fixture = Fixture::new("complete");
    let mut channel = fixture.activated();
    assert!(fixture.open().is_err());
    let mut events = Vec::new();
    let terminal = channel
        .entrypoint(&run(false), until(), &mut |event| {
            events.push(event.clone())
        })
        .unwrap();
    assert_eq!(
        events,
        [EntrypointEvent::Stdout {
            chunk: OUTPUT.to_vec()
        }]
    );
    assert_eq!(terminal, EntrypointEvent::Exit { code: 42 });
    channel.sync_filesystems(until()).unwrap();
    assert!(channel.sync_filesystems(until()).is_err());
    drop(channel);
    fixture.finish();
}

#[test]
fn callback_unwind_closes_stream_and_consumes_the_original_operation() {
    let fixture = Fixture::new("panic");
    let mut channel = fixture.activated();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        channel.entrypoint(&run(false), until(), &mut |event| {
            assert_eq!(
                event,
                &EntrypointEvent::Stdout {
                    chunk: OUTPUT.to_vec()
                }
            );
            panic!("observer unwind");
        })
    }));
    assert_eq!(
        unwind.unwrap_err().downcast_ref::<&str>(),
        Some(&"observer unwind")
    );
    assert!(channel.sync_filesystems(until()).is_err());
    assert!(fixture.open().is_err());
    fixture.finish();
}

#[test]
fn stale_deadline_and_disallowed_verbs_write_no_operation() {
    for (mode, request) in [
        ("expired", GuestRequest::Ping),
        (
            "wrong-verb",
            GuestRequest::AgentPrompt {
                prompt: vec![],
                timeout_secs: 2,
                env: vec![],
            },
        ),
        ("streaming", run(true)),
    ] {
        let fixture = Fixture::new(mode);
        let mut channel = if mode == "expired" {
            fixture.open().unwrap()
        } else {
            fixture.activated()
        };
        if mode == "expired" {
            assert!(channel.activate(&activation(), Instant::now()).is_err());
        } else {
            assert!(
                channel
                    .entrypoint(&request, until(), &mut |_| panic!(
                        "refused verb emitted event"
                    ))
                    .is_err()
            );
        }
        assert!(
            channel
                .entrypoint(&run(false), until(), &mut |_| panic!(
                    "consumed channel emitted event"
                ))
                .is_err()
        );
        assert!(fixture.open().is_err());
        fixture.finish();
    }
}

#[test]
fn truncated_protected_terminal_never_permits_sync_or_resubmission() {
    let fixture = Fixture::new("partial");
    let mut channel = fixture.activated();
    assert!(
        channel
            .entrypoint(&run(false), until(), &mut |_| panic!("no complete event"))
            .is_err()
    );
    assert!(channel.sync_filesystems(until()).is_err());
    assert!(fixture.open().is_err());
    fixture.finish();
}

#[test]
fn changed_registered_host_identity_cannot_connect_or_reopen() {
    let fixture = Fixture::new("unopened");
    let mut identity = fixture.identity;
    identity.host[0] ^= 1;
    assert!(
        fixture
            .vm
            .open_owned_entrypoint(fixture.anchor.clone(), identity, until())
            .is_err()
    );
    assert!(fixture.open().is_err());
    fixture.finish();
}

#[test]
fn deadline_adapter_refuses_expired_io_even_when_the_data_is_ready() {
    let (mut client, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"x").unwrap();
    let mut byte = [0];
    let mut expired = super::DeadlineIo {
        stream: &mut client,
        until: Instant::now(),
    };
    assert_eq!(
        expired.read_exact(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        expired.write_all(b"y").unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(read_byte(&mut client), b'x');
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(peer.read(&mut byte).unwrap(), 0);
}
