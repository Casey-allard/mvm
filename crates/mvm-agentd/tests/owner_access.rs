use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use mvm_agentd::owner_access::AccessDesk;
use mvm_agentd::vsock::{GuestRequest, enforce_owner_access_grant};
use mvm_contract::{
    grants::owner_access::{
        AccessRefusal, ExecutionIdentity, OperationGrant, OwnerAccessBinding, OwnerAccessGrant,
        PolicyRevision,
    },
    plan::{Nonce, PlanId, VerbGrant},
    protocol::owner_access::{
        OwnerAccessReply, OwnerAccessRequest, OwnerAccessStatus, TypedRecord,
    },
};
use std::time::Instant;

#[cfg(feature = "owner-access-object")]
#[test]
fn object_core_uses_shared_decoder_and_refuses_expiry_or_foreign_context() {
    use mvm_agentd::owner_access_object::{AccessObjectScope, ObjectMode};
    use mvm_contract::{
        grants::owner_access::OwnerAccessObjectProfile,
        protocol::owner_access::OwnerAccessObjectDirection,
    };
    use std::time::Duration;
    let now = Utc::now();
    let binding = OwnerAccessBinding {
        policy: PolicyRevision {
            plan_id: PlanId("a".repeat(64)),
            plan_version: 1,
        },
        execution: ExecutionIdentity {
            instance_id: "object-fixture".into(),
            plan_nonce: Nonce::from_hex(&"b".repeat(32)).unwrap(),
            bundle_sha256: Some("c".repeat(64)),
        },
        tenant: "tenant-a".into(),
        grant: OwnerAccessGrant {
            operations: vec![OperationGrant {
                name: "state".into(),
                owners: vec!["owner-a".into()],
                request: vec![],
                reply: vec![],
                max_request_bytes: 16384,
                max_reply_bytes: 16384,
                max_in_flight: 1,
                max_calls_per_second: 32,
                max_deadline_ms: 3000,
            }],
            object_v1: Some(OwnerAccessObjectProfile {
                major: 1,
                codec_mask: 891,
                cache_reuse_within_execution: false,
            }),
        },
    };
    let request = OwnerAccessRequest {
        policy: binding.policy.clone(),
        execution: binding.execution.clone(),
        request_id: [17; 32],
        sequence: 1,
        operation: "state".into(),
        owner: "owner-a".into(),
        deadline_unix_ms: now.timestamp_millis() as u64 + 2500,
        payload: TypedRecord::default(),
    };
    let scope = AccessObjectScope::new(
        &binding,
        &request,
        "tenant-a",
        OwnerAccessObjectDirection::Input,
        mvm_agentd::entrypoint::CancellationToken::default(),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert!(scope.operation_charge().unwrap() <= 8 * 1024 * 1024);
    let root = tempfile::tempdir().unwrap();
    let mut receiver = scope.receiver(&root.path().join("objects")).unwrap();
    let bytes = vec![42; 4096];
    let artifact =
        spiralcore_transfer::schema::fit(&[b"{\"value\":0}\n", b"{\"value\":1}\n"]).unwrap();
    for (index, mode) in [
        ObjectMode::Raw,
        ObjectMode::Whole,
        ObjectMode::Warm,
        ObjectMode::Runtime,
        ObjectMode::Combined,
    ]
    .into_iter()
    .enumerate()
    {
        let prediction = matches!(mode, ObjectMode::Runtime | ObjectMode::Combined).then(|| {
            let checkpoint = spiralcore_transfer::shared_runtime::State::seeded(32)
                .unwrap()
                .encode()
                .unwrap();
            spiralcore_transfer::shared_transfer::PreparedPrediction::new_with_resource_profile(
                &checkpoint,
                &spiralcore_transfer::shared_runtime::Recipe {
                    steps: 4,
                    payload: 1.25,
                    output: spiralcore_transfer::shared_runtime::OutputKind::Trace,
                },
                spiralcore_transfer::resource_profile::ResourceProfile::SmallV1,
            )
            .unwrap()
        });
        let target = prediction.as_ref().map_or_else(
            || bytes.clone(),
            |prediction| prediction.prediction().to_vec(),
        );
        let mut sender = scope.sender(mode, Some(&artifact), prediction).unwrap();
        if matches!(mode, ObjectMode::Runtime | ObjectMode::Combined) {
            scope
                .seed_checkpoint(&mut sender, [50 + index as u8; 32], |frames| {
                    receiver.handle(frames)
                })
                .unwrap();
        }
        if matches!(mode, ObjectMode::Warm | ObjectMode::Combined) {
            scope
                .seed_schema(&mut sender, [60 + index as u8; 32], |frames| {
                    receiver.handle(frames)
                })
                .unwrap();
        }
        let id = [index as u8 + 1; 32];
        let receipt = scope
            .send(&mut sender, target.clone(), id, |frames| {
                receiver.handle(frames)
            })
            .unwrap();
        assert_eq!(
            receiver
                .read_object(receipt.transfer.object, target.len())
                .unwrap(),
            target
        );
        if mode == ObjectMode::Runtime {
            assert_eq!(
                receipt.transfer.mode,
                spiralcore_transfer::protocol::Mode::RuntimeV1
            );
        }
    }
    let token = mvm_agentd::entrypoint::CancellationToken::default();
    let cancelled = AccessObjectScope::new(
        &binding,
        &request,
        "tenant-a",
        OwnerAccessObjectDirection::Reply,
        token.clone(),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    token.request();
    assert!(cancelled.receiver(&root.path().join("cancelled")).is_err());
    assert!(!root.path().join("cancelled").exists());
}

#[test]
fn canonical_object_channel_has_one_mapping_and_no_uncompiled_advertisement() {
    use mvm_agentd::vsock::{GuestCapability, GuestResponse, supported_capabilities};
    use mvm_contract::protocol::owner_access::{
        OwnerAccessObjectCallFrame, OwnerAccessObjectReplyFrame, OwnerAccessObjectRequest,
        OwnerAccessObjectResponse,
    };
    let request = OwnerAccessObjectRequest::Commit {
        request_id: [8; 32],
        sequence: 3,
    };
    let canonical = GuestRequest::OwnerAccessObject(request.clone());
    assert_eq!(
        serde_json::to_vec(&canonical).unwrap(),
        serde_json::to_vec(&OwnerAccessObjectCallFrame { request }).unwrap()
    );
    assert_eq!(canonical.class(), mvm_agentd::vsock::RequestClass::ProdSafe);
    assert!(enforce_owner_access_grant(&canonical, None, Utc::now()).is_some());
    let reply = OwnerAccessObjectResponse::Completed {
        request_id: [8; 32],
        sequence: 3,
        status: OwnerAccessStatus::Ok,
        object: [4; 32],
        payload_bytes: 256,
    };
    assert_eq!(
        serde_json::to_vec(&GuestResponse::OwnerAccessObject(reply.clone())).unwrap(),
        serde_json::to_vec(&OwnerAccessObjectReplyFrame { reply }).unwrap()
    );
    assert_eq!(
        supported_capabilities().contains(&GuestCapability::OwnerAccessObjectV1),
        cfg!(feature = "owner-access-object")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_dev_exec_cancels_live_child_and_caps_blocked_stdin() {
    use mvm_agentd::{
        entrypoint::CancellationToken, exec_stream::stream_exec_bounded, vsock::ExecEvent,
    };
    use std::time::Duration;
    let legacy = GuestRequest::Exec {
        command: "exit 0".into(),
        stdin: None,
        timeout_secs: Some(1),
        deadline_unix_ms: None,
    };
    assert_eq!(
        serde_json::to_string(&legacy).unwrap(),
        r#"{"Exec":{"command":"exit 0","stdin":null,"timeout_secs":1}}"#
    );
    let token = CancellationToken::default();
    let started = Instant::now();
    let mut observed = Vec::new();
    let result = stream_exec_bounded(
        "printf READY; exec /bin/sleep 2",
        None,
        started + Duration::from_secs(1),
        &token,
        |event| {
            if let ExecEvent::Stdout { chunk } = event {
                observed.extend(chunk);
                if observed == b"READY" {
                    token.request();
                }
            }
        },
    );
    assert_eq!(observed, b"READY");
    assert_eq!(result, ExecEvent::Exit { code: -1 });
    assert!(started.elapsed() < Duration::from_millis(750));
    let input = "x".repeat(1024 * 1024);
    let started = Instant::now();
    let result = stream_exec_bounded(
        "exec /bin/sleep 2",
        Some(&input),
        started + Duration::from_millis(200),
        &CancellationToken::default(),
        |_| {},
    );
    assert_eq!(result, ExecEvent::TimedOut);
    assert!(started.elapsed() < Duration::from_millis(750));
}

#[cfg(target_os = "linux")]
#[test]
fn owned_control_hangup_cancels_and_joins_the_running_dev_child() {
    use mvm_agentd::{
        entrypoint::CancellationToken, owner_access::AccessDisconnect, vsock::ExecEvent,
    };
    use std::{os::unix::net::UnixStream, time::Duration};
    let (control, peer) = UnixStream::pair().unwrap();
    let token = CancellationToken::default();
    let start = Instant::now();
    let observer =
        AccessDisconnect::watch(&control, token.clone(), start + Duration::from_secs(1)).unwrap();
    let mut peer = Some(peer);
    let terminal = mvm_agentd::exec_stream::stream_exec_bounded(
        "printf READY; exec /bin/sleep 2",
        None,
        start + Duration::from_secs(1),
        &token,
        |event| {
            if let ExecEvent::Stdout { .. } = event {
                drop(peer.take());
            }
        },
    );
    drop(observer);
    assert!(token.is_requested());
    assert_eq!(terminal, ExecEvent::Exit { code: -1 });
    assert!(start.elapsed() < Duration::from_millis(750));
    let expired = mvm_agentd::exec_stream::stream_exec_bounded(
        "exit 0",
        None,
        Instant::now(),
        &CancellationToken::default(),
        |_| panic!("expired input emitted an event"),
    );
    assert_eq!(expired, ExecEvent::TimedOut);
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_canonical_writer_retains_partial_bytes_and_refuses_expired_reentry() {
    use mvm_agentd::owner_access::{AccessWriter, received_deadline};
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixStream},
        time::Duration,
    };
    struct Counted {
        socket: UnixStream,
        bytes: usize,
        calls: usize,
    }
    impl AsRawFd for Counted {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.socket.as_raw_fd()
        }
    }
    impl Write for Counted {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            let sent = self.socket.write(bytes)?;
            self.bytes += sent;
            Ok(sent)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.socket.flush()
        }
    }
    let (socket, _withholding_peer) = UnixStream::pair().unwrap();
    let size = 4096i32;
    // SAFETY: configure only the owned fixture socket, with a live i32 value.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const i32).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
    let mut counted = Counted {
        socket,
        bytes: 0,
        calls: 0,
    };
    let bytes = vec![42; 256 * 1024];
    let start = Instant::now();
    assert!(
        AccessWriter::new(&mut counted, start + Duration::from_millis(200))
            .write_all(&bytes)
            .is_err()
    );
    assert!(counted.bytes > 0 && counted.bytes < bytes.len());
    assert!(start.elapsed() < Duration::from_millis(750));
    let calls = counted.calls;
    let sent = counted.bytes;
    assert_eq!(
        AccessWriter::new(&mut counted, Instant::now())
            .write(&[1])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!((counted.calls, counted.bytes), (calls, sent));
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    assert_eq!(
        received_deadline(now.timestamp_millis() as u64, now, Instant::now()),
        Err(AccessRefusal::Expired)
    );
    assert_eq!(
        received_deadline(now.timestamp_millis() as u64 - 1, now, Instant::now()),
        Err(AccessRefusal::Expired)
    );
    assert_eq!(
        received_deadline(now.timestamp_millis() as u64 + 30_001, now, Instant::now()),
        Err(AccessRefusal::Expired)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn original_deadline_includes_owned_stdin_backpressure() {
    use mvm_agentd::entrypoint::{
        CallCaps, CancellationToken, EntrypointCall, EntrypointPolicy, RunOutcome,
    };
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    };
    let (_reader, writer) = std::io::pipe().unwrap();
    // SAFETY: inspect only this fresh test-owned pipe; no flags are changed.
    let capacity = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETPIPE_SZ) };
    assert!(capacity > 0);
    let input = vec![b'x'; capacity as usize * 2];
    let caps = CallCaps::v1();
    assert!(input.len() <= caps.stdin_max);
    let directory = tempfile::tempdir().unwrap();
    let program = directory.path().join("no-stdin");
    std::fs::write(&program, b"#!/bin/sh\nexec /bin/sleep 2\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o555)).unwrap();
    let marker = directory.path().join("entrypoint");
    std::fs::write(&marker, program.to_str().unwrap()).unwrap();
    let metadata = std::fs::metadata(&program).unwrap();
    let validated = EntrypointPolicy {
        marker_path: marker,
        allowed_prefix: directory.path().to_path_buf(),
        same_fs_as: None,
        required_mode: 0o555,
        required_uid: metadata.uid(),
        required_gid: metadata.gid(),
        allow_shell_shebang: true,
    }
    .validate()
    .unwrap();
    let token = CancellationToken::default();
    let cap = std::time::Duration::from_millis(200);
    let start = Instant::now();
    let call = EntrypointCall {
        entrypoint: &validated,
        cwd: directory.path(),
        stdin: &input,
        timeout: cap,
        caps,
        resource_limits: None,
        cancellation: Some(token),
        env: vec![],
        stream_input: false,
    };
    let result = mvm_agentd::entrypoint::execute_streaming_before(&call, start + cap, &mut |_| {});
    assert_eq!(
        result,
        RunOutcome::Timeout,
        "the original deadline must include blocked stdin"
    );
    assert!(start.elapsed() < std::time::Duration::from_millis(750));
}

#[test]
fn typed_capability_discovery_preserves_legacy_requested_service_set() {
    use mvm_agentd::vsock::{GuestCapability, GuestResponse, protocol_hello_response};
    assert!(matches!(
        protocol_hello_response(3, 3, "typed-client", &[]),
        GuestResponse::ProtocolHelloAck {
            agent_protocol_version: 3,
            ..
        }
    ));
    let legacy = protocol_hello_response(2, 2, "legacy-client", &[GuestCapability::Ping]);
    assert!(
        matches!(legacy,GuestResponse::ProtocolHelloAck {agent_protocol_version:3,ref capabilities,..} if capabilities==&[GuestCapability::Ping])
    );
    let typed = protocol_hello_response(3, 3, "typed-client", &[GuestCapability::OwnerAccessV1]);
    assert!(
        matches!(typed,GuestResponse::ProtocolHelloAck {ref capabilities,..} if capabilities==&[GuestCapability::OwnerAccessV1])
    );
}

#[test]
fn signed_access_desk_rejects_foreign_and_replayed_operation_without_executing() {
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let nonce = Nonce::from_bytes([4; 16]);
    let key = SigningKey::from_bytes(&[20; 32]);
    let binding = OwnerAccessBinding {
        policy: PolicyRevision {
            plan_id: PlanId(format!("sha256:{}", "a".repeat(64))),
            plan_version: 1,
        },
        execution: ExecutionIdentity {
            instance_id: "fixture-instance".into(),
            plan_nonce: nonce.clone(),
            bundle_sha256: Some("b".repeat(64)),
        },
        tenant: "tenant-a".into(),
        grant: OwnerAccessGrant {
            object_v1: None,
            operations: vec![OperationGrant {
                name: "status".into(),
                owners: vec!["local-owner".into()],
                request: vec![],
                reply: vec![],
                max_request_bytes: 1024,
                max_reply_bytes: 1024,
                max_in_flight: 1,
                max_calls_per_second: 4,
                max_deadline_ms: 1000,
            }],
        },
    };
    let mut grant = VerbGrant {
        session_id: "fixture-instance".into(),
        plan_nonce: nonce.clone(),
        not_after: now + chrono::Duration::seconds(30),
        verbs: vec![],
        drive: None,
        tool_mediation: None,
        application_terminal: None,
        owner_access: Some(binding.clone()),
        sig: vec![],
    };
    grant.sig = key.sign(&grant.signing_bytes()).to_bytes().to_vec();
    let mut desk = AccessDesk::default();
    desk.install_verified(
        &grant,
        &key.verifying_key(),
        "fixture-instance",
        &nonce,
        now,
    )
    .unwrap();
    let request = OwnerAccessRequest {
        policy: binding.policy.clone(),
        execution: binding.execution.clone(),
        request_id: [1; 32],
        sequence: 1,
        operation: "status".into(),
        owner: "local-owner".into(),
        deadline_unix_ms: now.timestamp_millis() as u64 + 1000,
        payload: TypedRecord::default(),
    };
    let mut foreign = request.clone();
    let wire = GuestRequest::DeliverDeclaredOperation(request.clone());
    let portable = mvm_contract::protocol::owner_access::OwnerAccessCallFrame::new(request.clone());
    assert_eq!(
        serde_json::to_vec(&wire).unwrap(),
        serde_json::to_vec(&portable).unwrap(),
        "portable clients use exactly the canonical guest payload mapping"
    );
    assert!(wire.allowed_in(mvm_contract::policy::security::AgentProfile::SealedProd));
    assert!(
        enforce_owner_access_grant(&wire, None, now).is_some(),
        "the old grant-less class gate cannot authorize typed access"
    );
    assert!(enforce_owner_access_grant(&wire, Some(&grant), now).is_none());
    foreign.execution.instance_id = "foreign".into();
    assert!(matches!(
        desk.admit(&foreign, now, Instant::now()),
        Err(AccessRefusal::Identity)
    ));
    let ticket = desk.admit(&request, now, Instant::now()).unwrap();
    assert!(matches!(
        desk.admit(&request, now, Instant::now()),
        Err(AccessRefusal::Replay)
    ));
    let reply = OwnerAccessReply {
        request_id: [1; 32],
        sequence: 1,
        status: OwnerAccessStatus::Ok,
        payload: TypedRecord::default(),
    };
    let canonical = mvm_agentd::vsock::GuestResponse::OwnerAccessReply(reply.clone());
    let portable = mvm_contract::protocol::owner_access::OwnerAccessReplyFrame::new(reply.clone());
    assert_eq!(
        serde_json::to_vec(&canonical).unwrap(),
        serde_json::to_vec(&portable).unwrap()
    );
    desk.finish(ticket, &reply, now, Instant::now()).unwrap();
    // This is an owned ordinary process fixture, not a guest/VM witness.
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = tempfile::tempdir().unwrap();
    let program = directory.path().join("operation-wrapper");
    std::fs::write(
        &program,
        b"#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"fields\":[]}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o555)).unwrap();
    let marker = directory.path().join("entrypoint");
    std::fs::write(&marker, program.to_str().unwrap()).unwrap();
    let policy = mvm_agentd::entrypoint::EntrypointPolicy {
        marker_path: marker,
        allowed_prefix: directory.path().to_path_buf(),
        same_fs_as: None,
        required_mode: 0o555,
        required_uid: std::fs::metadata(&program).unwrap().uid(),
        required_gid: std::fs::metadata(&program).unwrap().gid(),
        allow_shell_shebang: true,
    };
    let entrypoint = policy.validate().unwrap();
    let mut next = request.clone();
    next.request_id = [2; 32];
    next.sequence = 2;
    let ticket = desk.admit(&next, now, Instant::now()).unwrap();
    let executed = ticket.run(&entrypoint, directory.path());
    let reply = desk.complete_run(executed, now, Instant::now()).unwrap();
    assert_eq!(reply.status, OwnerAccessStatus::Ok);
    assert_eq!(reply.request_id, [2; 32]);
    assert!(matches!(
        desk.admit(&request, now, Instant::now()),
        Err(AccessRefusal::Replay)
    ));
    // Revocation must retain the running ticket until completion acknowledges
    // teardown; a newly signed binding cannot make that work disappear.
    let mut last = request.clone();
    last.request_id = [3; 32];
    last.sequence = 3;
    let active = desk.admit(&last, now, Instant::now()).unwrap();
    desk.close();
    assert!(active.cancellation().is_requested());
    let mut replacement = grant.clone();
    replacement
        .owner_access
        .as_mut()
        .unwrap()
        .policy
        .plan_version = 2;
    replacement.sig = key.sign(&replacement.signing_bytes()).to_bytes().to_vec();
    assert_eq!(
        desk.install_verified(
            &replacement,
            &key.verifying_key(),
            "fixture-instance",
            &nonce,
            now
        ),
        Err(AccessRefusal::Unavailable)
    );
    let cancelled = OwnerAccessReply {
        request_id: last.request_id,
        sequence: last.sequence,
        status: OwnerAccessStatus::Cancelled,
        payload: TypedRecord::default(),
    };
    assert_eq!(
        desk.finish(active, &cancelled, now, Instant::now()),
        Err(AccessRefusal::Unavailable)
    );
    desk.install_verified(
        &replacement,
        &key.verifying_key(),
        "fixture-instance",
        &nonce,
        now,
    )
    .unwrap();
    let mut expired = request.clone();
    expired.policy.plan_version = 2;
    assert!(
        matches!(
            desk.admit(
                &expired,
                now,
                Instant::now() + std::time::Duration::from_secs(31)
            ),
            Err(AccessRefusal::Expired)
        ),
        "frozen wall time cannot extend the installed signed grant"
    );
    #[cfg(feature = "owner-access-object")]
    {
        use mvm_contract::{
            grants::owner_access::OwnerAccessObjectProfile,
            protocol::owner_access::OwnerAccessObjectBegin,
        };
        let mut object_grant = grant.clone();
        object_grant.owner_access.as_mut().unwrap().grant.object_v1 =
            Some(OwnerAccessObjectProfile {
                major: 1,
                codec_mask: 891,
                cache_reuse_within_execution: false,
            });
        object_grant.sig = key.sign(&object_grant.signing_bytes()).to_bytes().to_vec();
        let mut object_desk = AccessDesk::default();
        object_desk
            .install_verified(
                &object_grant,
                &key.verifying_key(),
                "fixture-instance",
                &nonce,
                now,
            )
            .unwrap();
        let bytes = serde_json::to_vec(&TypedRecord::default()).unwrap();
        let begin = OwnerAccessObjectBegin {
            request: request.clone(),
            object: spiralcore_transfer::object_id(&bytes),
            payload_bytes: bytes.len() as u32,
            field: None,
        };
        let ticket = object_desk
            .admit_object(&begin, now, Instant::now())
            .unwrap();
        let ticket = object_desk
            .reconstruct_object(ticket, &bytes, now, Instant::now())
            .unwrap();
        let object_reply = OwnerAccessReply {
            request_id: begin.request.request_id,
            sequence: begin.request.sequence,
            status: OwnerAccessStatus::Ok,
            payload: TypedRecord::default(),
        };
        object_desk
            .finish(ticket, &object_reply, now, Instant::now())
            .unwrap();
        assert!(matches!(
            object_desk.admit_object(&begin, now, Instant::now()),
            Err(AccessRefusal::Replay)
        ));
    }
    let mut tampered = grant;
    tampered.owner_access.as_mut().unwrap().policy.plan_version = 2;
    assert!(
        desk.install_verified(
            &tampered,
            &key.verifying_key(),
            "fixture-instance",
            &nonce,
            now
        )
        .is_err()
    );
}
