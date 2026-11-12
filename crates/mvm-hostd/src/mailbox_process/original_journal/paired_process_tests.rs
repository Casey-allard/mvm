//! Two real helper binaries and a fixture guest stream; no VMM or guest is booted.
use super::{
    OriginalJournalDestination,
    authorization::{JournalCredentials, PairedJournalAdmission},
};
use crate::mailbox_process::paired_incoming::{IncomingJournalAdmission, tests::setup};
use crate::plan_admission::MailboxLaunchPosture;
use anyhow::{Result, ensure};
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
)> {
    let mut plan = PlanFixture::new().build();
    plan.image.name = name.into();
    plan.mailbox = Some(grant);
    plan.plan_id = compute_plan_id(&plan);
    let state = mvm_core::config::vm_state_dir(name);
    mvm_core::private_fs::ensure_private_dir(&state)?;
    let guest = SigningKey::from_bytes(&rand::random()).verifying_key();
    let ack = SigningKey::from_bytes(&rand::random()).verifying_key();
    let boot = MailboxReaderBootBinding::mint(&plan, guest, ack.to_bytes())?;
    boot.persist(&state)?;
    mvm_vmm::host::flowmux_identity::InheritableIdentity {
        session_id: name.into(),
        guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
            .encode(guest.to_bytes()),
    }
    .persist(&state)?;
    mvm_core::atomic_io::write_private(&state.join("plan.json"), &serde_json::to_vec(&plan)?)?;
    let posture = MailboxLaunchPosture::for_test(&plan, Variant::Prod);
    Ok((plan, boot, posture))
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

fn run() -> Result<()> {
    let keys = mvm_core::config::mvm_keys_dir();
    mvm_core::private_fs::ensure_private_dir(&keys)?;
    let (b_grant, incoming, _) = setup(&keys);
    IncomingJournalAdmission::install(&b_grant, &incoming)?;
    let backend = AnyBackend::from_hypervisor("firecracker");
    let (bp, boot_b, posture_b) = original_plan("journal-b", b_grant)?;
    let b = OriginalJournalDestination::start(&bp, &backend, "journal-b", &posture_b)?;
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
        incoming_journal_policy_sha256_v1: None,
    };
    let (ap, _, posture_a) = original_plan("journal-a", a_grant)?;
    let a_state = mvm_core::config::vm_state_dir("journal-a");
    let uds = mvm_agentd::vsock::vsock_uds_path(&a_state.to_string_lossy());
    let uds = Path::new(&uds);
    mvm_core::private_fs::ensure_private_dir(uds.parent().unwrap())?;
    let guest = UnixListener::bind(uds)?;
    guest.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let admission = PairedJournalAdmission::new(b.clone(), grants, deadline);
    let mut a = admission.launch_original_source(&ap, &backend, "journal-a", &posture_a)?;
    let message = OutboxMessage::new(direction.address.recipient, (0..=255).chain([0]).collect());
    let mut receipt = None;
    for turn in 0..3 {
        let mut socket = guest_stream(&guest, deadline)?;
        let encoded = message.encode();
        socket.write_all(&u32::try_from(encoded.len())?.to_be_bytes())?;
        socket.write_all(&encoded)?;
        let mut socket = Some(socket);
        if turn == 0 {
            drop(socket.take());
        }
        while !a.forward_once(deadline)? {
            ensure!(Instant::now() < deadline, "A helper did not request relay");
            std::thread::sleep(Duration::from_millis(2));
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
                "ORIGINAL_PAIRED_HELPERS turn={turn} plaintext_bytes={} guest_submit_bytes={} guest_receipt_bytes={}",
                message.body.len(),
                encoded.len() + 4,
                raw.len()
            );
        }
    }
    ensure!(receipt.is_some());
    // Withdraw only the synthetic runtime state from this fixture. The helpers
    // observe this normally and the caller waits on the real original handles.
    for name in ["journal-a", "journal-b"] {
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::rename(&state, state.with_file_name(format!("{name}-retired")))?;
    }
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let ea = a.try_collect()?;
        let eb = b.lock().unwrap().try_collect()?;
        if let (Some(a), Some(b)) = (ea, eb) {
            ensure!(a.success() && b.success());
            break;
        }
        ensure!(Instant::now() < until, "original helpers did not retire");
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
#[ignore = "requires the separately compiled mvm-mailbox binary from this exact tree"]
fn original_a_and_b_helpers_relay_same_sealed_intent_after_lost_guest_reply() {
    const IDENT: &str = "MVM_ORIGINAL_JOURNAL_HOST_COMPONENT";
    if std::env::var_os(IDENT).is_some() {
        run().unwrap();
        return;
    }
    let temp = tempfile::tempdir_in("/tmp").unwrap();
    let helper = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("mvm-mailbox");
    assert!(helper.is_file(), "build same-source mvm-mailbox first");
    let child=std::process::Command::new(std::env::current_exe().unwrap())
        .args(["mailbox_process::original_journal::paired_process_tests::original_a_and_b_helpers_relay_same_sealed_intent_after_lost_guest_reply","--exact","--ignored","--nocapture"])
        .env(IDENT,"1").env("MVM_HOME",temp.path()).env("MVM_MAILBOX_PATH",helper).status().unwrap();
    assert!(child.success());
}
