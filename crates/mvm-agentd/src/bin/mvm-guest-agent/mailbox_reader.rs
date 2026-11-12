//! Explicit guest-local Receive and ACK-after-processing over the existing
//! mailbox vsock port. The workload can read the socket, not the ACK key.

#[path = "mailbox_reader/object_submit.rs"]
pub(crate) mod object_submit;
#[path = "mailbox_reader/validity.rs"]
mod validity;
use mvm_core::mailbox::object_pair::role::SignedObjectRoleV1;

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    DeliveryAckNonce, MailboxDeliveryAck, MailboxGrant, MailboxGuestReaderScope, ProtocolVersion,
    SignatureAlgorithm, SignedMailboxDeliveryAck, SignedMailboxDeliveryLease,
};
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::reader::{
    MailboxReaderBootBinding, sign_delivery_ack, sign_reader_possession,
    verify_delivery_lease_signature, verify_guest_reader_enrollment,
};
use mvm_core::mailbox::reader_wire::{
    ApplicationReaderRequest, GUEST_READER_SOCKET_PATH, ReaderRequest, ReaderResponse,
    read_application_request, read_response, write_request, write_response,
};
use zeroize::Zeroizing;

const LOCAL_TIMEOUT: Duration = Duration::from_secs(12);

struct ActiveLease {
    object_call: bool,
    lease: SignedMailboxDeliveryLease,
    ack: Option<SignedMailboxDeliveryAck>,
}

struct GuestReader {
    role: Option<SignedObjectRoleV1>,
    settlement: object_submit::Settlement,
    outbox: std::path::PathBuf,
    boot: MailboxReaderBootBinding,
    ack_seed: &'static Zeroizing<[u8; 32]>,
    active: Mutex<Option<ActiveLease>>,
}

pub(crate) struct PendingReader {
    wait_until: Instant,
    request: ReaderRequest,
    reply: mpsc::SyncSender<ReaderResponse>,
    reader: Arc<GuestReader>,
}

pub(crate) fn now_unix_ms() -> Result<i64, Refusal> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Refusal::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Refusal::Unavailable)
}

/// Only start the local endpoint when the independently provisioned, root-only
/// boot key was captured by the agent. Send works without a reader.
pub(crate) fn start(
    boot: MailboxReaderBootBinding,
    ack_seed: &'static Zeroizing<[u8; 32]>,
    role: Option<SignedObjectRoleV1>,
) -> Option<mpsc::Receiver<PendingReader>> {
    let path = Path::new(GUEST_READER_SOCKET_PATH);
    let result = (|| {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
            Ok(_) => {
                return Err(std::io::Error::other(
                    "refusing to replace a non-socket guest reader path",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok::<_, std::io::Error>(listener)
    })();
    let listener = match result {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("mvm-guest-agent: mailbox reader socket unavailable: {error}");
            return None;
        }
    };
    let (tx, rx) = mpsc::sync_channel(1);
    let state = Arc::new(GuestReader {
        boot,
        role,
        settlement: Default::default(),
        outbox: Path::new(mvm_agentd::mailbox_outbox::LOCAL_OUTBOX_PATH)
            .parent()?
            .into(),
        ack_seed,
        active: Mutex::new(None),
    });
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(mut client) = client else { break };
            let _ = client.set_read_timeout(Some(LOCAL_TIMEOUT));
            let _ = client.set_write_timeout(Some(LOCAL_TIMEOUT));
            let response = application_request(&mut client, &tx, &state)
                .unwrap_or_else(|reason| ReaderResponse::Refused { reason });
            let _ = write_response(&mut client, &response);
        }
    });
    Some(rx)
}

fn application_request(
    stream: &mut UnixStream,
    tx: &mpsc::SyncSender<PendingReader>,
    reader: &Arc<GuestReader>,
) -> Result<ReaderResponse, Refusal> {
    let request = match read_application_request(stream)? {
        ApplicationReaderRequest::ObjectSubmissionStatusV1 { pair, message_id } => {
            match object_submit::status(reader, pair, message_id)? {
                object_submit::Status::Cached(result) => return Ok(result),
                object_submit::Status::Query(request) => request,
            }
        }
        ApplicationReaderRequest::StageObjectV1 { pair, submission } => {
            use mvm_core::mailbox::reader_wire::ObjectSubmissionV1;
            let message_id = submission.message_id();
            if reader.boot.durable_object_pair_sha256_v1 != Some(pair) {
                return Err(Refusal::NotAuthorized);
            }
            match &*submission {
                ObjectSubmissionV1::Call { correlation_id, .. }
                    if correlation_id.as_bytes() != &[0; 32] => {}
                ObjectSubmissionV1::Reply { original_call, .. } => {
                    let active = reader.active.lock().map_err(|_| Refusal::Unavailable)?;
                    let current = active.as_ref().ok_or(Refusal::NotAuthorized)?;
                    let now = now_unix_ms()?;
                    if !current.object_call
                        || current.ack.is_some()
                        || current.lease != **original_call
                        || message_id == current.lease.lease.message_id
                        || !(current.lease.lease.issued_at_unix_ms
                            ..current.lease.lease.expires_at_unix_ms)
                            .contains(&now)
                    {
                        return Err(Refusal::NotAuthorized);
                    }
                }
                _ => return Err(Refusal::NotAuthorized),
            }
            object_submit::stage(reader, pair, &submission)?;
            return Ok(ReaderResponse::ObjectStagedV1 { pair, message_id });
        }
        ApplicationReaderRequest::CheckOutboundJournalV1 {
            commitment,
            recipient,
            payload_bytes,
        } => {
            mvm_agentd::mailbox_outbox::journal_direction::check_available(
                &reader.boot,
                commitment,
                recipient,
                payload_bytes,
                now_unix_ms()?,
            )?;
            return Ok(ReaderResponse::OutboundJournalAvailableV1 { commitment });
        }
        ApplicationReaderRequest::Receive
            if reader.boot.durable_object_pair_sha256_v1.is_none() =>
        {
            ReaderRequest::Receive
        }
        ApplicationReaderRequest::ReceiveObjectPairV1 { pair }
            if reader.boot.durable_object_pair_sha256_v1 == Some(pair) =>
        {
            ReaderRequest::ReceiveObjectPairV1 { pair }
        }
        ApplicationReaderRequest::Receive
        | ApplicationReaderRequest::ReceiveObjectPairV1 { .. } => {
            return Err(Refusal::NotAuthorized);
        }
        ApplicationReaderRequest::Ack { lease } => {
            let mut active = reader.active.lock().expect("mailbox reader lock poisoned");
            let active = active.as_mut().ok_or(Refusal::NotAuthorized)?;
            if active.lease != *lease {
                return Err(Refusal::NotAuthorized);
            }
            if active.object_call {
                object_submit::allows_call_ack(reader, &active.lease)?;
            }
            let ack = if let Some(ack) = &active.ack {
                ack.clone()
            } else {
                verify_delivery_lease_signature(
                    &active.lease,
                    &VerifyingKey::from_bytes(&reader.boot.authority_key)
                        .map_err(|_| Refusal::NotAuthorized)?,
                )
                .map_err(|_| Refusal::NotAuthorized)?;
                let ack = sign_delivery_ack(
                    MailboxDeliveryAck {
                        protocol_version: ProtocolVersion::V1,
                        signature_algorithm: SignatureAlgorithm::ED25519,
                        lease: active.lease.clone(),
                        ack_nonce: DeliveryAckNonce::from_bytes(rand::random()),
                        acknowledged_at_unix_ms: now_unix_ms()?,
                    },
                    &SigningKey::from_bytes(reader.ack_seed),
                )
                .map_err(|_| Refusal::NotAuthorized)?;
                active.ack = Some(ack.clone());
                ack
            };
            ReaderRequest::Ack {
                signed: Box::new(ack),
            }
        }
    };
    let (reply, received) = mpsc::sync_channel(1);
    let pending_status = match &request {
        ReaderRequest::SubmitObjectV1 { pair, submission } => {
            Some(ReaderResponse::ObjectPendingV1 {
                pair: *pair,
                message_id: submission.message_id(),
            })
        }
        _ => None,
    };
    if let Err(error) = tx.try_send(PendingReader {
        wait_until: Instant::now() + validity::MAX_WINDOW_WAIT,
        request,
        reply,
        reader: reader.clone(),
    }) {
        if matches!(error, mpsc::TrySendError::Full(_)) {
            return pending_status.ok_or(Refusal::Unavailable);
        }
        return Err(Refusal::Unavailable);
    }
    match received.recv_timeout(LOCAL_TIMEOUT) {
        Ok(response) => Ok(response),
        Err(mpsc::RecvTimeoutError::Timeout) => pending_status.ok_or(Refusal::Unavailable),
        Err(_) => Err(Refusal::Unavailable),
    }
}

/// The mailbox listener calls this only when an application operation is
/// pending; idle host dials continue to carry Send without an extra handshake.
pub(crate) fn exchange(
    stream: &mut (impl Read + Write),
    pending: PendingReader,
) -> Result<(), Refusal> {
    let response = match perform_exchange(stream, &pending) {
        Ok(response) => response,
        Err(reason) => ReaderResponse::Refused { reason },
    };
    let _ = pending.reply.send(response);
    Ok(())
}

fn perform_exchange(
    stream: &mut (impl Read + Write),
    pending: &PendingReader,
) -> Result<ReaderResponse, Refusal> {
    if let ReaderRequest::SubmitObjectV1 { pair, submission } = &pending.request {
        object_submit::preflight(&pending.reader, *pair, submission)?;
        match write_request(stream, &pending.request) {
            Err(Refusal::Unavailable) => {
                return Ok(ReaderResponse::ObjectPendingV1 {
                    pair: *pair,
                    message_id: submission.message_id(),
                });
            }
            result => result?,
        }
    } else {
        write_request(stream, &pending.request)?;
    }
    match &pending.request {
        ReaderRequest::Receive | ReaderRequest::ReceiveObjectPairV1 { .. } => {
            let pair = match pending.request {
                ReaderRequest::ReceiveObjectPairV1 { pair } => Some(pair),
                _ => None,
            };
            if pair != pending.reader.boot.durable_object_pair_sha256_v1 {
                return Err(Refusal::NotAuthorized);
            }
            let ReaderResponse::Challenge {
                enrollment,
                capability,
                challenge,
            } = read_response(stream)?
            else {
                return Err(Refusal::NotAuthorized);
            };
            let boot = &pending.reader.boot;
            let grant = MailboxGrant {
                durable_object_pair_sha256_v1: boot.durable_object_pair_sha256_v1,
                incoming_journal_policy_sha256_v1: None,
                outbound_journal_v1: None,
                mailbox: boot.mailbox,
                authority_key: boot.authority_key,
                epoch: boot.execution_epoch,
                report: None,
                retention: None,
            };
            let authority = VerifyingKey::from_bytes(&boot.authority_key)
                .map_err(|_| Refusal::NotAuthorized)?;
            if enrollment.enrollment.ack_public_key != boot.ack_public_key {
                return Err(Refusal::NotAuthorized);
            }
            let current_session = enrollment.enrollment.consumer_session;
            validity::verify(
                enrollment.enrollment.issued_at_unix_ms,
                pending.wait_until,
                |now| {
                    let current_scope = MailboxGuestReaderScope {
                        plan: &grant,
                        plan_id: &boot.plan_id,
                        plan_nonce: &boot.plan_nonce,
                        receive: &capability.grant,
                        current_boot: boot.boot,
                        current_session,
                        now_unix_ms: now,
                    };
                    verify_guest_reader_enrollment(
                        &enrollment,
                        &capability,
                        &current_scope,
                        &authority,
                        &[],
                    )
                },
            )?;
            let possession = sign_reader_possession(
                &enrollment,
                &challenge,
                &SigningKey::from_bytes(pending.reader.ack_seed),
            )
            .map_err(|_| Refusal::NotAuthorized)?;
            write_request(
                stream,
                &ReaderRequest::Possession {
                    signature: possession.to_vec(),
                },
            )?;
            let response = read_response(stream)?;
            let (lease, content_type, payload) = match (&response, pair) {
                (
                    ReaderResponse::Delivery {
                        lease,
                        content_type,
                        payload,
                    },
                    None,
                ) if lease.lease.object_projection_v1.is_none() => {
                    verify_delivery_lease_signature(lease, &authority)
                        .map_err(|_| Refusal::NotAuthorized)?;
                    (lease, content_type, payload)
                }
                (
                    ReaderResponse::ObjectDeliveryV1 {
                        lease,
                        header,
                        payload,
                    },
                    Some(pair),
                ) => {
                    mvm_core::mailbox::reader::verify_object_delivery_projection(
                        &pair, header, payload, lease, &authority,
                    )
                    .map_err(|_| Refusal::NotAuthorized)?;
                    (lease, &header.content_type, payload)
                }
                (ReaderResponse::Empty | ReaderResponse::Refused { .. }, _) => return Ok(response),
                _ => return Err(Refusal::NotAuthorized),
            };
            validity::verify(lease.lease.issued_at_unix_ms, pending.wait_until, |now| {
                lease
                    .check_scope(&grant, &capability.grant, current_session, now)
                    .map_err(Into::into)
            })?;
            if payload.len() > capability.grant.max_payload_bytes as usize
                || !capability.grant.content_types.contains(content_type)
            {
                return Err(Refusal::NotAuthorized);
            }
            *pending
                .reader
                .active
                .lock()
                .expect("mailbox reader lock poisoned") = Some(ActiveLease {
                object_call: matches!(&response, ReaderResponse::ObjectDeliveryV1 {header,..} if header.kind==mvm_contract::protocol::mailbox::MailboxMessageKind::Call),
                lease: (**lease).clone(),
                ack: None,
            });
            Ok(response)
        }
        ReaderRequest::Ack { signed } => correlate_ack(read_response(stream)?, signed),
        ReaderRequest::SubmitObjectV1 { pair, submission } => {
            object_submit::settle(stream, &pending.reader, *pair, submission)
        }
        ReaderRequest::GetObjectRoleV1 { .. } | ReaderRequest::Possession { .. } => {
            Err(Refusal::NotAuthorized)
        }
    }
}

fn correlate_ack(
    response: ReaderResponse,
    signed: &SignedMailboxDeliveryAck,
) -> Result<ReaderResponse, Refusal> {
    match response {
        ReaderResponse::Acknowledged { ack } if *ack == *signed => {
            Ok(ReaderResponse::Acknowledged { ack })
        }
        refused @ ReaderResponse::Refused { .. } => Ok(refused),
        _ => Err(Refusal::NotAuthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::plan::{Nonce, PlanId};
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, BootId, CapabilityId, ConsumerSessionId, DeliveryId,
        DeliveryLeaseNonce, ExecutionEpoch, MailboxAddress, MailboxDeliveryLease, MailboxId,
        MessageId, PrincipalId, TenantId,
    };
    use mvm_core::mailbox::reader::sign_delivery_lease;
    use mvm_core::mailbox::reader_wire::write_application_request;
    use std::sync::OnceLock;

    static SEED: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

    #[test]
    fn local_receive_is_explicit_and_an_empty_reply_does_not_sign_an_ack() {
        let ack_seed = SEED.get_or_init(|| Zeroizing::new([7; 32]));
        let reader = Arc::new(GuestReader {
            role: None,
            settlement: Default::default(),
            outbox: Default::default(),
            boot: MailboxReaderBootBinding {
                durable_object_pair_sha256_v1: None,
                outbound_journal_v1: None,
                plan_id: PlanId("current".into()),
                plan_nonce: Nonce::from_bytes([1; 16]),
                mailbox: MailboxId::from_bytes([2; 32]),
                authority_key: [3; 32],
                execution_epoch: ExecutionEpoch::new(1).unwrap(),
                boot: BootId::from_bytes([4; 32]),
                guest_identity_key: [5; 32],
                ack_public_key: SigningKey::from_bytes(ack_seed).verifying_key().to_bytes(),
            },
            ack_seed,
            active: Mutex::new(None),
        });
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let (sender, pending) = mpsc::sync_channel(1);
        let state = reader.clone();
        let worker = std::thread::spawn(move || application_request(&mut server, &sender, &state));
        write_application_request(&mut client, &ApplicationReaderRequest::Receive).unwrap();
        let next = pending.recv_timeout(LOCAL_TIMEOUT).unwrap();
        assert_eq!(next.request, ReaderRequest::Receive);
        next.reply.send(ReaderResponse::Empty).unwrap();
        assert_eq!(worker.join().unwrap(), Ok(ReaderResponse::Empty));
        assert!(reader.active.lock().unwrap().is_none(), "no automatic ACK");
    }

    #[test]
    fn ack_confirmation_must_echo_the_exact_signed_operation() {
        let authority = SigningKey::from_bytes(&[9; 32]);
        let guest = SigningKey::from_bytes(&[10; 32]);
        let lease = sign_delivery_lease(
            MailboxDeliveryLease {
                object_projection_v1: None,
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                address: MailboxAddress {
                    tenant: TenantId::from_bytes([1; 32]),
                    authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
                    mailbox: MailboxId::from_bytes([3; 32]),
                    recipient: PrincipalId::from_bytes([4; 32]),
                },
                sender: PrincipalId::from_bytes([5; 32]),
                sender_boot: BootId::from_bytes([6; 32]),
                message_id: MessageId::from_bytes([7; 32]),
                delivery_id: DeliveryId::from_bytes([8; 32]),
                execution_epoch: ExecutionEpoch::new(1).unwrap(),
                consumer: PrincipalId::from_bytes([4; 32]),
                consumer_session: ConsumerSessionId::from_bytes([11; 32]),
                receive_capability_id: CapabilityId::from_bytes([12; 32]),
                policy_epoch: 1,
                ciphertext_commitment: [13; 32],
                issued_at_unix_ms: 100,
                expires_at_unix_ms: 200,
                lease_nonce: DeliveryLeaseNonce::from_bytes([14; 16]),
            },
            &authority,
        )
        .unwrap();
        let ack = sign_delivery_ack(
            MailboxDeliveryAck {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                lease,
                ack_nonce: DeliveryAckNonce::from_bytes([15; 16]),
                acknowledged_at_unix_ms: 150,
            },
            &guest,
        )
        .unwrap();
        let same = ReaderResponse::Acknowledged {
            ack: Box::new(ack.clone()),
        };
        let mut wire = Vec::new();
        write_response(&mut wire, &same).unwrap();
        assert_eq!(read_response(&mut wire.as_slice()), Ok(same.clone()));
        assert_eq!(correlate_ack(same.clone(), &ack), Ok(same));
        let mut changed = ack.ack.clone();
        changed.ack_nonce = DeliveryAckNonce::from_bytes([16; 16]);
        let changed = sign_delivery_ack(changed, &guest).unwrap();
        assert_eq!(
            correlate_ack(
                ReaderResponse::Acknowledged {
                    ack: Box::new(changed)
                },
                &ack,
            ),
            Err(Refusal::NotAuthorized),
            "a delayed success for a different signed ACK cannot confirm this one",
        );
        assert_eq!(
            correlate_ack(ReaderResponse::Empty, &ack),
            Err(Refusal::NotAuthorized)
        );
    }
}

#[cfg(test)]
#[path = "mailbox_reader/object_guest_tests.rs"]
mod object_guest_tests;
