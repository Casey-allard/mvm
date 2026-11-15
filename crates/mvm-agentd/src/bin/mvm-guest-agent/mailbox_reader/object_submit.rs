//! The destination alone attests local journal acceptance. The original host
//! separately binds delivery identity and ciphertext to its retained seal.
use super::*;
use mvm_contract::protocol::mailbox::{DeliveryOutcome, MessageId, SignedDestinationReceipt};
use mvm_core::mailbox::{
    object_pair::role::{ObjectParticipantRole, ObjectRoleV1, SignedObjectRoleV1},
    reader_wire::ObjectSubmissionV1,
};

#[derive(Default)]
pub(super) struct Settlement {
    // One original operation. Losing this cache requires another checked V2
    // exchange before the on-disk slot can be superseded.
    accepted: Mutex<Option<(ObjectSubmissionV1, SignedDestinationReceipt)>>,
}

pub(crate) fn fetch_role(
    stream: &mut (impl Read + Write),
    boot: &MailboxReaderBootBinding,
) -> Result<SignedObjectRoleV1, Refusal> {
    let pair = boot
        .durable_object_pair_sha256_v1
        .ok_or(Refusal::NotAuthorized)?;
    write_request(
        stream,
        &ReaderRequest::GetObjectRoleV1 {
            pair,
            boot: boot.boot,
        },
    )?;
    let ReaderResponse::ObjectRoleV1 { signed } = read_response(stream)? else {
        return Err(Refusal::NotAuthorized);
    };
    signed
        .verify(boot, now_unix_ms()?)
        .map_err(|_| Refusal::NotAuthorized)?;
    Ok(*signed)
}

fn current_role(reader: &GuestReader, pair: [u8; 32]) -> Result<&ObjectRoleV1, Refusal> {
    if reader.boot.durable_object_pair_sha256_v1 != Some(pair) {
        return Err(Refusal::NotAuthorized);
    }
    reader
        .role
        .as_ref()
        .ok_or(Refusal::NotAuthorized)?
        .verify(&reader.boot, now_unix_ms()?)
        .map_err(|_| Refusal::NotAuthorized)
}
fn check_submission(role: &ObjectRoleV1, submission: &ObjectSubmissionV1) -> Result<(), Refusal> {
    if submission.message_id().as_bytes() == &[0; 32] || submission.payload().is_empty() {
        return Err(Refusal::Malformed);
    }
    let max = role.outbound().grant.max_payload_bytes as usize;
    if submission.payload().len() > max {
        return Err(Refusal::Oversized(max));
    }
    match (role.role, submission) {
        (ObjectParticipantRole::Caller, ObjectSubmissionV1::Call { correlation_id, .. })
            if correlation_id.as_bytes() != &[0; 32] =>
        {
            Ok(())
        }
        (ObjectParticipantRole::Callee, ObjectSubmissionV1::Reply { .. }) => Ok(()),
        _ => Err(Refusal::NotAuthorized),
    }
}

fn check_receipt(
    role: &ObjectRoleV1,
    msg: MessageId,
    receipt: &SignedDestinationReceipt,
) -> Result<(), Refusal> {
    let key =
        VerifyingKey::from_bytes(&role.peer().authority_key).map_err(|_| Refusal::NotAuthorized)?;
    mvm_core::mailbox::verify_receipt(receipt, &key).map_err(|_| Refusal::NotAuthorized)?;
    let body = &receipt.receipt;
    if body.protocol_version != ProtocolVersion::V2
        || body.outcome != DeliveryOutcome::AcceptedLocalDurable
        || body.message_id != msg
        || body.address != role.outbound().grant.address
        || body.execution_epoch != role.peer().execution_epoch
        || !(role.not_before_unix_ms..role.expires_at_unix_ms).contains(&body.observed_at_unix_ms)
    {
        return Err(Refusal::NotAuthorized);
    }
    Ok(())
}
pub(super) fn stage(
    reader: &GuestReader,
    pair: [u8; 32],
    submission: &ObjectSubmissionV1,
) -> Result<(), Refusal> {
    check_submission(current_role(reader, pair)?, submission)?;
    let guard = reader
        .settlement
        .accepted
        .lock()
        .map_err(|_| Refusal::Unavailable)?;
    mvm_agentd::mailbox_outbox::object_pair::stage_after(
        &reader.outbox,
        &reader.boot,
        pair,
        submission,
        guard.as_ref().map(|v| &v.0),
    )
}

pub(super) enum Status {
    Cached(ReaderResponse),
    Query(ReaderRequest),
}
pub(super) fn status(
    reader: &GuestReader,
    pair: [u8; 32],
    msg: MessageId,
) -> Result<Status, Refusal> {
    let role = current_role(reader, pair)?;
    let original =
        mvm_agentd::mailbox_outbox::object_pair::load(&reader.outbox, &reader.boot, pair)?;
    if original.message_id() != msg {
        return Err(Refusal::NotAuthorized);
    }
    check_submission(role, &original)?;
    if let Some((settled, receipt)) = reader
        .settlement
        .accepted
        .lock()
        .map_err(|_| Refusal::Unavailable)?
        .as_ref()
        && settled == &original
    {
        check_receipt(role, msg, receipt)?;
        return Ok(Status::Cached(ReaderResponse::ObjectAcceptedV1 {
            receipt: Box::new(receipt.clone()),
        }));
    }
    Ok(Status::Query(ReaderRequest::SubmitObjectV1 {
        pair,
        submission: Box::new(original),
    }))
}
pub(super) fn allows_call_ack(
    reader: &GuestReader,
    lease: &SignedMailboxDeliveryLease,
) -> Result<(), Refusal> {
    let pair = reader
        .boot
        .durable_object_pair_sha256_v1
        .ok_or(Refusal::NotAuthorized)?;
    let role = current_role(reader, pair)?;
    let guard = reader
        .settlement
        .accepted
        .lock()
        .map_err(|_| Refusal::Unavailable)?;
    let Some((
        ObjectSubmissionV1::Reply {
            message_id,
            original_call,
            ..
        },
        receipt,
    )) = guard.as_ref()
    else {
        return Err(Refusal::NotAuthorized);
    };
    if **original_call != *lease {
        return Err(Refusal::NotAuthorized);
    }
    check_receipt(role, *message_id, receipt)
}

pub(super) fn preflight(
    reader: &GuestReader,
    pair: [u8; 32],
    submission: &ObjectSubmissionV1,
) -> Result<(), Refusal> {
    check_submission(current_role(reader, pair)?, submission)?;
    if mvm_agentd::mailbox_outbox::object_pair::load(&reader.outbox, &reader.boot, pair)?
        != *submission
    {
        return Err(Refusal::NotAuthorized);
    }
    Ok(())
}

pub(super) fn settle(
    stream: &mut (impl Read + Write),
    reader: &GuestReader,
    pair: [u8; 32],
    submission: &ObjectSubmissionV1,
) -> Result<ReaderResponse, Refusal> {
    let msg = submission.message_id();
    let response = match mvm_core::mailbox::reader_wire::read_submission_response(stream) {
        Err(Refusal::Unavailable) => {
            return Ok(ReaderResponse::ObjectPendingV1 {
                pair,
                message_id: msg,
            });
        }
        other => other?,
    };
    if matches!(response, ReaderResponse::Refused { .. }) {
        return Ok(response);
    }
    let ReaderResponse::ObjectSealAcceptedV1 { original, receipt } = &response else {
        return Err(Refusal::NotAuthorized);
    };
    if original.pair != pair
        || original.sender_boot != reader.boot.boot
        || original.intent_sha256
            != mvm_core::mailbox::reader_wire::original_object_intent_digest(submission)?
        || original.delivery_id != receipt.receipt.delivery_id
        || original.ciphertext_commitment != receipt.receipt.ciphertext_commitment
    {
        return Err(Refusal::NotAuthorized);
    }
    let role = current_role(reader, pair)?;
    check_submission(role, submission)?;
    check_receipt(role, msg, receipt)?;
    let mut guard = reader
        .settlement
        .accepted
        .lock()
        .map_err(|_| Refusal::Unavailable)?;
    if mvm_agentd::mailbox_outbox::object_pair::load(&reader.outbox, &reader.boot, pair)?
        != *submission
    {
        return Err(Refusal::NotAuthorized);
    }
    *guard = Some((submission.clone(), (**receipt).clone()));
    Ok(ReaderResponse::ObjectAcceptedV1 {
        receipt: receipt.clone(),
    })
}
