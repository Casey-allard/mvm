//! Two real helper binaries and a fixture guest stream; no VMM or guest is booted.
use super::{
    OriginalJournalDestination,
    authorization::{JournalCredentials, PairedJournalAdmission},
};
use crate::mailbox_process::paired_incoming::{IncomingJournalAdmission, tests::setup};
use crate::plan_admission::MailboxLaunchPosture;
use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{MailboxGrant, MailboxJournalDirectionV1};
use mvm_core::mailbox::{
    frame::OutboxMessage, outbound::journal_capability_digest, reader::MailboxReaderBootBinding,
};
use mvm_core::plan::{ExecutionPlan, Variant, compute_plan_id, test_support::PlanFixture};
use mvm_runtime::backend::AnyBackend;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn original_plan(
    name: &str,
    grant: MailboxGrant,
) -> Result<(
    ExecutionPlan,
    MailboxReaderBootBinding,
    MailboxLaunchPosture,
    SigningKey,
)> {
    let mut plan = PlanFixture::new().build();
    plan.image.name = name.into();
    plan.mailbox = Some(grant);
    plan.plan_id = compute_plan_id(&plan);
    let state = mvm_core::config::vm_state_dir(name);
    mvm_core::private_fs::ensure_private_dir(&state)?;
    let guest = SigningKey::from_bytes(&rand::random()).verifying_key();
    let ack = SigningKey::from_bytes(&rand::random());
    let boot = MailboxReaderBootBinding::mint(&plan, guest, ack.verifying_key().to_bytes())?;
    boot.persist(&state)?;
    mvm_vmm::host::flowmux_identity::InheritableIdentity {
        session_id: name.into(),
        guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
            .encode(guest.to_bytes()),
    }
    .persist(&state)?;
    mvm_core::atomic_io::write_private(&state.join("plan.json"), &serde_json::to_vec(&plan)?)?;
    let posture = MailboxLaunchPosture::for_test(&plan, Variant::Prod);
    Ok((plan, boot, posture, ack))
}

fn guest_stream(listener: &UnixListener, until: Instant) -> Result<UnixStream> {
    let mut stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e.into()),
        }
    };
    // Darwin accepts a socket with its listener's O_NONBLOCK flag. The
    // fixture uses bounded blocking I/O on each individual guest stream.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(4)))?;
    let mut command = [0u8; 13];
    stream.read_exact(&mut command)?;
    ensure!(
        &command == b"CONNECT 5257\n",
        "unexpected fixture mux request"
    );
    stream.write_all(b"OK 5257\n")?;
    Ok(stream)
}

fn fixture_listener(state: &Path) -> Result<UnixListener> {
    let uds = mvm_agentd::vsock::vsock_uds_path(&state.to_string_lossy());
    let uds = Path::new(&uds);
    mvm_core::private_fs::ensure_private_dir(uds.parent().unwrap())?;
    let listener = UnixListener::bind(uds)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
struct Wire {
    stream: UnixStream,
    read: usize,
    written: usize,
}
impl Wire {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            read: 0,
            written: 0,
        }
    }
}
impl Read for Wire {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.stream.read(b)?;
        self.read += n;
        Ok(n)
    }
}
impl Write for Wire {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.stream.write(b)?;
        self.written += n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn read_and_ack(
    listener: &UnixListener,
    until: Instant,
    boot: &MailboxReaderBootBinding,
    grant: &MailboxGrant,
    key: &SigningKey,
    sent: &OutboxMessage,
    received: &mvm_contract::protocol::mailbox::SignedDestinationReceipt,
) -> Result<()> {
    use mvm_contract::protocol::mailbox::{
        DeliveryAckNonce, MailboxDeliveryAck, MailboxGuestReaderScope, ProtocolVersion,
        SignatureAlgorithm,
    };
    use mvm_core::mailbox::{
        reader::{
            sign_delivery_ack, sign_reader_possession, verify_delivery_lease_signature,
            verify_guest_reader_enrollment,
        },
        reader_wire::{ReaderRequest, ReaderResponse, read_response, write_request},
    };
    let authority = ed25519_dalek::VerifyingKey::from_bytes(&grant.authority_key)?;
    let now = super::authorization::now_ms;
    let mut s = Wire::new(guest_stream(listener, until)?);
    write_request(&mut s, &ReaderRequest::Receive)?;
    let ReaderResponse::Challenge {
        enrollment,
        capability,
        challenge,
    } = read_response(&mut s)?
    else {
        anyhow::bail!("missing real B reader challenge");
    };
    let scope = MailboxGuestReaderScope {
        plan: grant,
        plan_id: &boot.plan_id,
        plan_nonce: &boot.plan_nonce,
        receive: &capability.grant,
        current_boot: boot.boot,
        current_session: enrollment.enrollment.consumer_session,
        now_unix_ms: now()?,
    };
    verify_guest_reader_enrollment(&enrollment, &capability, &scope, &authority, &[])?;
    ensure!(enrollment.enrollment.ack_public_key == key.verifying_key().to_bytes());
    let sig = sign_reader_possession(&enrollment, &challenge, key)?;
    write_request(
        &mut s,
        &ReaderRequest::Possession {
            signature: sig.to_vec(),
        },
    )?;
    let ReaderResponse::Delivery { lease, payload, .. } = read_response(&mut s)? else {
        anyhow::bail!("B reader did not lease original record");
    };
    verify_delivery_lease_signature(&lease, &authority)?;
    ensure!(
        payload == sent.body
            && payload.len() == sent.body.len()
            && lease.lease.message_id == sent.message_id
            && lease.lease.address == received.receipt.address
            && lease.lease.delivery_id == received.receipt.delivery_id
            && lease.lease.ciphertext_commitment == received.receipt.ciphertext_commitment
            && lease.lease.consumer_session == enrollment.enrollment.consumer_session
    );
    let reader_counts = (s.written, s.read);
    drop(s);
    let signed = sign_delivery_ack(
        MailboxDeliveryAck {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            lease: *lease,
            ack_nonce: DeliveryAckNonce::from_bytes(rand::random()),
            acknowledged_at_unix_ms: now()?,
        },
        key,
    )?;
    let mut s = Wire::new(guest_stream(listener, until)?);
    write_request(
        &mut s,
        &ReaderRequest::Ack {
            signed: Box::new(signed.clone()),
        },
    )?;
    let ReaderResponse::Acknowledged { ack } = read_response(&mut s)? else {
        anyhow::bail!("B failed to acknowledge signed lease");
    };
    ensure!(*ack == signed);
    eprintln!(
        "ORIGINAL_PAIRED_B_READER exact_bytes={} receive_guest_to_helper={} receive_helper_to_guest={} ack_guest_to_helper={} ack_helper_to_guest={}",
        payload.len(),
        reader_counts.0,
        reader_counts.1,
        s.written,
        s.read
    );
    Ok(())
}

// The helper receives a real, originally observed process generation; this
// fixture process supplies only lifetime, never a VMM or a guest workload.
struct LifetimeFixture(std::process::Child);
impl std::ops::Deref for LifetimeFixture {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for LifetimeFixture {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for LifetimeFixture {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|s| s.is_none()) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn lifetime_fixture(name: &str) -> Result<LifetimeFixture> {
    let child = std::process::Command::new("sleep").arg("40").spawn()?;
    std::fs::write(
        mvm_core::config::vm_state_dir(name).join("fc.pid"),
        child.id().to_string(),
    )?;
    Ok(LifetimeFixture(child))
}

// Unlike a running guest agent, the stream fixture only calls accept when
// the test asks it for one exchange. Hold each original idle connection
// across its own child exit and check the terminal bytes before replay.
fn collect_with_idle_dial(
    listener: &UnixListener,
    child: &mut std::process::Child,
    until: Instant,
) -> Result<std::process::ExitStatus> {
    // Capture the connected original while its kernel peer identity is
    // available. Darwin clears LOCAL_PEERPID when a peer has exited.
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                ensure!(Instant::now() < until, "missing original idle dial");
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    };
    ensure!(
        mvm_vmm::host::uds_peer::connected_peer_pid(&stream)? as u32 == child.id()
            && child.try_wait()?.is_none(),
        "idle dial does not belong to the live original"
    );
    child.kill()?;
    let status = child.wait()?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(
        until
            .checked_duration_since(Instant::now())
            .context("idle dial deadline")?,
    ))?;
    let mut bytes = Vec::new();
    stream.take(14).read_to_end(&mut bytes)?;
    ensure!(
        b"CONNECT 5257\n".starts_with(&bytes),
        "application data on collected dial"
    );
    ensure!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "unexpected further dial after original collection"
    );
    Ok(status)
}

fn run(ordinal: bool, reconnect: bool) -> Result<()> {
    let keys = mvm_core::config::mvm_keys_dir();
    mvm_core::private_fs::ensure_private_dir(&keys)?;
    let (b_grant, incoming, _) = setup(&keys);
    IncomingJournalAdmission::install(&b_grant, &incoming)?;
    let backend = AnyBackend::from_hypervisor("firecracker");
    let (bp, boot_b, posture_b, ack_b) = original_plan("journal-b", b_grant)?;
    let b_guest = fixture_listener(&mvm_core::config::vm_state_dir("journal-b"))?;
    // An installed SDK B refuses before creating a helper when the original
    // VMM cannot be observed. Only this explicit test fixture may omit it.
    ensure!(
        OriginalJournalDestination::start_custodied(&bp, &backend, "journal-b", &posture_b)
            .is_err()
    );
    let mut b_vm = lifetime_fixture("journal-b")?;
    let b = OriginalJournalDestination::start_custodied(&bp, &backend, "journal-b", &posture_b)?;
    b.require_ready()?;
    let signed_recv = b.original_receive()?.clone();
    let grants = Arc::new(JournalCredentials {
        source_scope: incoming.source_scope.clone(),
        destination_send: incoming.destination_send.clone(),
        destination_receive: signed_recv,
    });
    let b = Arc::new(Mutex::new(b));
    let start = [
        &grants.source_scope,
        &grants.destination_send,
        &grants.destination_receive,
    ]
    .into_iter()
    .map(|c| c.grant.not_before_unix_ms)
    .max()
    .unwrap();
    let end = [
        &grants.source_scope,
        &grants.destination_send,
        &grants.destination_receive,
    ]
    .into_iter()
    .map(|c| c.grant.expires_at_unix_ms)
    .min()
    .unwrap();
    let direction = MailboxJournalDirectionV1 {
        sender_settlement: ordinal
            .then_some(mvm_contract::protocol::mailbox::SenderSettlementProfile::OrdinalV1),
        source: grants.destination_send.grant.subject,
        destination_plan_sha256: hex::decode(&bp.plan_id.0[7..])?.try_into().unwrap(),
        destination_plan_nonce: hex::decode(bp.nonce.as_hex())?.try_into().unwrap(),
        destination_boot: boot_b.boot,
        address: grants.destination_send.grant.address,
        execution_epoch: b_grant.epoch,
        policy_epoch: grants.destination_send.grant.policy_epoch,
        receipt_key: b_grant.authority_key,
        source_scope_grant_sha256: journal_capability_digest(&grants.source_scope)?,
        send_grant_sha256: journal_capability_digest(&grants.destination_send)?,
        receive_grant_sha256: journal_capability_digest(&grants.destination_receive)?,
        not_before_unix_ms: start,
        expires_at_unix_ms: end,
        max_payload_bytes: 313,
    };
    let a_grant = MailboxGrant {
        mailbox: incoming.source_mailbox,
        epoch: incoming.source_epoch,
        authority_key: crate::mailbox_launch::authority_key_for(
            &keys,
            &incoming.source_mailbox,
            incoming.source_epoch,
        )?
        .to_bytes(),
        retention: b_grant.retention,
        report: None,
        outbound_journal_v1: Some(direction),
        durable_object_pair_sha256_v1: None,
        incoming_journal_policy_sha256_v1: None,
    };
    let (ap, boot_a, posture_a, ack_a) = original_plan("journal-a", a_grant)?;
    let a_state = mvm_core::config::vm_state_dir("journal-a");
    let guest = fixture_listener(&a_state)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let admission = PairedJournalAdmission::new(b.clone(), grants, deadline);
    ensure!(
        admission
            .launch_custodied_source(&ap, &backend, "journal-a", &posture_a)
            .is_err()
    );
    let mut a_vm = lifetime_fixture("journal-a")?;
    let mut a = admission.launch_custodied_source(&ap, &backend, "journal-a", &posture_a)?;
    a.require_ready()?;
    if ordinal {
        ordinal_exchange(
            &guest, &b_guest, deadline, &mut a, &boot_a, &ack_a, &boot_b, &b_grant, &ack_b,
        )?;
    } else {
        let message =
            OutboxMessage::new(direction.address.recipient, (0..=255).chain([0]).collect());
        let mut receipt = None;
        let mut original_wire = None;
        let transaction = Instant::now();
        for turn in 0..3 {
            let mut socket = guest_stream(&guest, deadline)?;
            let encoded = message.encode();
            let send_start = Instant::now();
            socket.write_all(&u32::try_from(encoded.len())?.to_be_bytes())?;
            socket.write_all(&encoded)?;
            let mut socket = Some(socket);
            if turn == 0 && !reconnect {
                drop(socket.take());
            }
            let mut observed = None;
            let relay = loop {
                if let Some(value) = a.forward_once_observed(deadline, |envelope, reply| {
                    observed = Some((envelope.clone(), reply.to_vec()));
                })? {
                    break value;
                }
                ensure!(Instant::now() < deadline, "A helper did not request relay");
                std::thread::sleep(Duration::from_millis(2));
            };
            let wire = observed.context("missing original sealed turn")?;
            if let Some(prior) = &original_wire {
                ensure!(
                    prior == &wire,
                    "canonical envelope or raw signed B verdict changed"
                );
            } else {
                original_wire = Some(wire);
            }
            eprintln!(
                "ORIGINAL_PAIRED_RELAY turn={turn} sealed_to_b={} b_reply_to_a={}",
                relay.sealed_to_destination, relay.reply_to_source
            );
            if reconnect && turn == 0 {
                // The check discards the original reply only after A sent
                // the exact request to B, before the application reads it.
                drop(socket.take());
            }
            if let Some(socket) = socket {
                let mut raw = Vec::new();
                socket.take(4097).read_to_end(&mut raw)?;
                ensure!(raw.len() <= 4096, "oversized fixture guest verdict");
                let received = serde_json::from_slice::<
                    Result<
                        mvm_contract::protocol::mailbox::SignedDestinationReceipt,
                        mvm_core::mailbox::frame::Refusal,
                    >,
                >(&raw)??;
                mvm_core::mailbox::verify_receipt(
                    &received,
                    &ed25519_dalek::VerifyingKey::from_bytes(&direction.receipt_key)?,
                )?;
                ensure!(
                received.receipt.message_id == message.message_id
                    && received.receipt.address == direction.address
                    && received.receipt.execution_epoch == direction.execution_epoch
                    && received.receipt.outcome
                        == mvm_contract::protocol::mailbox::DeliveryOutcome::AcceptedLocalDurable,
                "wrong guest verdict"
            );
                if let Some(prior) = receipt.as_ref() {
                    ensure!(
                        *prior == received,
                        "duplicate returned different original receipt"
                    );
                }
                receipt = Some(received);
                eprintln!(
                    "ORIGINAL_ACCEPT turn={turn} guest_submit_to_verified_v2_ns={}",
                    send_start.elapsed().as_nanos()
                );
                eprintln!(
                    "ORIGINAL_PAIRED_HELPERS turn={turn} plaintext_bytes={} guest_submit_bytes={} guest_receipt_bytes={}",
                    message.body.len(),
                    encoded.len() + 4,
                    raw.len()
                );
            }
            if reconnect && turn == 1 {
                // Repeat an already-receipted immutable envelope after each
                // originally owned helper has exited, leaving both VMs alive.
                let which = super::JournalHelper::Source;
                ensure!(a.reconnect_helper(which, deadline).is_err());
                let old_a = collect_with_idle_dial(&guest, &mut a.source, deadline)
                    .context("collecting original A with idle dial")?;
                let old_b =
                    collect_with_idle_dial(&b_guest, &mut b.lock().unwrap().child, deadline)
                        .context("collecting original B with idle dial")?;
                eprintln!("COLLECTED_DIALS source=1 destination=1");
                let fresh = OriginalJournalDestination::start_custodied(
                    &bp,
                    &backend,
                    "journal-b",
                    &posture_b,
                );
                ensure!(
                    fresh.is_err_and(|e| e
                        .chain()
                        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                        .any(|cause| cause.kind() == std::io::ErrorKind::WouldBlock)),
                    "fresh launch unexpectedly bypassed the original ownership fence"
                );
                #[cfg(not(target_os = "linux"))]
                {
                    // This backend cannot pin a stale socket vnode. The
                    // fixture models a clean original release only after
                    // witnessing the conservative refusal on both paths.
                    ensure!(a.reconnect_helper(which, deadline).is_err());
                    ensure!(
                        a.reconnect_helper(super::JournalHelper::Destination, deadline)
                            .is_err()
                    );
                    std::fs::remove_file(mvm_core::config::vm_mailbox_socket_at(&a_state))?;
                    std::fs::remove_file(mvm_core::config::vm_mailbox_socket_at(
                        &mvm_core::config::vm_state_dir("journal-b"),
                    ))?;
                }
                let denied = crate::mailbox_process::reader::revocations_path(&a_state);
                mvm_core::atomic_io::write_private(
                    &denied,
                    &serde_json::to_vec(&[incoming.source_scope.grant.revocation_id])?,
                )?;
                ensure!(a.reconnect_helper(which, deadline).is_err());
                std::fs::remove_file(denied)?;
                let (anchor, original_pid) = {
                    let b = b.lock().unwrap();
                    let retained = crate::mailbox_custody::RetainedMailboxKeys::open_existing(
                        &keys,
                        &bp,
                        "journal-b",
                        &posture_b.handoff(Some(boot_b.boot)),
                        Some(boot_b.boot),
                        b.address(),
                    )?;
                    (retained.storage_paths(&keys)?.anchor, b.child.id())
                };
                let anchor_bytes = std::fs::read(&anchor)?;
                std::fs::write(&anchor, b"invalid test anchor")?;
                ensure!(
                    a.reconnect_helper(super::JournalHelper::Destination, deadline)
                        .is_err()
                );
                let failed_status = {
                    let mut b = b.lock().unwrap();
                    ensure!(b.child.id() != original_pid && b.require_ready().is_err());
                    b.marker.require_original()?;
                    b.child.wait()?
                };
                ensure!(!old_b.success() && !failed_status.success());
                std::fs::write(&anchor, &anchor_bytes)?;
                ensure!(
                    a.reconnect_helper(super::JournalHelper::Destination, deadline)?
                        == failed_status
                );
                ensure!(a.reconnect_helper(which, deadline)? == old_a);
                ensure!(a_vm.try_wait()?.is_none() && b_vm.try_wait()?.is_none());
                eprintln!(
                    "ORIGINAL_RECONNECT both_predecessors_collected=true both_original_vms_live=true current_revocation_refused=true"
                );
            }
        }
        read_and_ack(
            &b_guest,
            deadline,
            &boot_b,
            &b_grant,
            &ack_b,
            &message,
            receipt.as_ref().unwrap(),
        )?;
        eprintln!(
            "ORIGINAL_TRANSACTION first_connection_through_b_ack_ns={}",
            transaction.elapsed().as_nanos()
        );
    }
    // A holds a real mux connection waiting for the next guest frame. B has
    // no listener and may be in reconnect backoff. The SDK and both original
    // state directories stay alive throughout. Stop only A first.
    let _a_idle = guest_stream(&guest, deadline)?;
    drop(b_guest);
    let before = Instant::now();
    a_vm.kill()?;
    a_vm.wait()?;
    let until = Instant::now() + Duration::from_secs(2);
    let outcome = loop {
        if let Some(status) = a.try_collect()? {
            break status;
        }
        ensure!(
            Instant::now() < until,
            "original A did not retire with its VMM"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    ensure!(outcome.success() && b.lock().unwrap().try_collect()?.is_none());
    eprintln!(
        "ORIGINAL_A_UNASSISTED_EXIT_NS={}",
        before.elapsed().as_nanos()
    );
    ensure!(b_vm.try_wait()?.is_none());
    let before = Instant::now();
    b_vm.kill()?;
    b_vm.wait()?;
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = b.lock().unwrap().try_collect()? {
            ensure!(status.success());
            break;
        }
        ensure!(
            Instant::now() < until,
            "original B did not retire with its VMM"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!(
        "ORIGINAL_B_UNASSISTED_EXIT_NS={}",
        before.elapsed().as_nanos()
    );
    for name in ["journal-a", "journal-b"] {
        ensure!(mvm_core::config::vm_state_dir(name).is_dir());
        ensure!(
            mvm_core::config::vm_mailbox_original_owner_at(&keys, name)
                .join(super::MARKER)
                .exists()
        );
    }
    Ok(())
}

// Install this exact test binary in an owner-only directory, just as the
// production operator does. Cargo's group-writable target is a build output.
fn run_private_fixture(test_name: &str, guard_env: &str) {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap();
    let exe = std::env::current_exe().unwrap();
    let build = exe.parent().unwrap().parent().unwrap().join("mvm-mailbox");
    let helper = temp.path().join("mvm-mailbox");
    std::fs::copy(build, &helper).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let selector = format!("mailbox_process::original_journal::paired_process_tests::{test_name}");
    let status = std::process::Command::new(exe)
        .arg(selector)
        .args(["--exact", "--ignored", "--nocapture"])
        .env(guard_env, "1")
        .env("MVM_HOME", temp.path())
        .env("MVM_MAILBOX_PATH", helper)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "requires the separately compiled mvm-mailbox binary from this exact tree"]
fn original_a_and_b_helpers_relay_same_sealed_intent_after_lost_guest_reply() {
    const IDENT: &str = "MVM_ORIGINAL_JOURNAL_HOST_COMPONENT";
    if std::env::var_os(IDENT).is_some() {
        run(false, false).unwrap();
        return;
    }
    run_private_fixture(
        "original_a_and_b_helpers_relay_same_sealed_intent_after_lost_guest_reply",
        IDENT,
    );
}

#[allow(clippy::too_many_arguments)]
fn ordinal_exchange(
    a_guest: &UnixListener,
    b_guest: &UnixListener,
    deadline: Instant,
    original: &mut super::relay::OriginalJournalSourceHost,
    boot_a: &MailboxReaderBootBinding,
    key_a: &SigningKey,
    boot_b: &MailboxReaderBootBinding,
    grant_b: &MailboxGrant,
    key_b: &SigningKey,
) -> Result<()> {
    use mvm_core::mailbox::{
        frame::Refusal,
        outbound::journal_direction_commitment,
        reader_wire::{ReaderRequest, ReaderResponse, read_response, write_request},
        sender_ordinal::{SenderOrdinalV1, SenderRequestV1, SenderSettlementV1},
    };
    let handle = SenderOrdinalV1 {
        direction: journal_direction_commitment(boot_a)?,
        ordinal: 1,
    };
    let message = OutboxMessage {
        recipient: boot_a.outbound_journal_v1.unwrap().address.recipient,
        message_id: handle.message_id()?,
        body: (0..=255).chain([0]).collect(),
    };
    let submit = SenderRequestV1::Submit {
        handle,
        payload: message.body.clone(),
    };
    let request = |req: SenderRequestV1| -> Result<Wire> {
        let mut socket = Wire::new(guest_stream(a_guest, deadline)?);
        write_request(
            &mut socket,
            &ReaderRequest::SenderOrdinalV1 {
                request: Box::new(req),
            },
        )?;
        Ok(socket)
    };
    drop(request(submit.clone())?); // Original A cannot observe first receipt.
    let transfer = loop {
        if let Some(c) = original.forward_once_with_counts(deadline)? {
            break c;
        }
        ensure!(Instant::now() < deadline, "no original authorized relay");
        std::thread::sleep(Duration::from_millis(2));
    };
    let mut socket = request(submit.clone())?;
    let ReaderResponse::SenderAcceptedV1 {
        handle: seen,
        receipt,
    } = read_response(&mut socket)?
    else {
        anyhow::bail!("original receipt unavailable on exact retry")
    };
    ensure!(seen == handle);
    let statement = SenderSettlementV1::sign(boot_a, 1, &receipt, key_a)?;
    drop(socket);
    read_and_ack(
        b_guest, deadline, boot_b, grant_b, key_b, &message, &receipt,
    )?;
    let settle = SenderRequestV1::Settle { statement };
    drop(request(settle.clone())?); // Final settlement response lost too.
    let mut socket = request(settle)?;
    ensure!(
        matches!(read_response(&mut socket)?, ReaderResponse::SenderSettledV1{handle:seen,retired_through:1} if seen==handle)
    );
    drop(socket);
    let mut socket = request(submit)?;
    ensure!(matches!(
        read_response(&mut socket)?,
        ReaderResponse::Refused {
            reason: Refusal::SenderOrdinalRetired
        }
    ));
    eprintln!(
        "ORDINAL_ORIGINAL two_helpers=2 payload=257 original_relay_written={} original_relay_read={} contiguous_retired=1",
        transfer.sealed_to_destination, transfer.reply_to_source
    );
    Ok(())
}

#[test]
#[ignore = "requires the separately compiled mvm-mailbox binary from this exact tree"]
fn original_helpers_settle_ordinal_only_on_signed_receipt() {
    const IDENT: &str = "MVM_ORIGINAL_ORDINAL_COMPONENT";
    if std::env::var_os(IDENT).is_some() {
        run(true, false).unwrap();
        return;
    }
    run_private_fixture(
        "original_helpers_settle_ordinal_only_on_signed_receipt",
        IDENT,
    );
}

#[test]
#[ignore = "requires the separately compiled mvm-mailbox binary from this exact tree"]
fn original_helper_reconnect_preserves_receipt_under_both_live_vms() {
    const IDENT: &str = "MVM_ORIGINAL_HELPER_RECONNECT_COMPONENT";
    if std::env::var_os(IDENT).is_some() {
        run(false, true).unwrap();
        return;
    }
    run_private_fixture(
        "original_helper_reconnect_preserves_receipt_under_both_live_vms",
        IDENT,
    );
}
