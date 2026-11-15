//! Original sender operations on the existing agent-owned guest reader socket.
use super::{GuestReader, ReaderResponse, Refusal, SigningKey, now_unix_ms};
use mvm_agentd::mailbox_outbox::ordinal::OrdinalOutbox;
use mvm_core::mailbox::reader_wire::read_submission_response;
use mvm_core::mailbox::sender_ordinal::{
    ApplicationSenderRequestV1, SenderOrdinalV1, SenderRequestV1,
};
use std::io::Read;
use std::sync::MutexGuard;

pub(super) enum Prepared {
    Staged(SenderOrdinalV1),
    Forward(Box<SenderRequestV1>),
}

fn store(reader: &GuestReader) -> Result<MutexGuard<'_, OrdinalOutbox>, Refusal> {
    reader
        .ordinal
        .as_ref()
        .ok_or(Refusal::NotAuthorized)?
        .lock()
        .map_err(|_| Refusal::Unavailable)
}

fn handle(request: &SenderRequestV1) -> SenderOrdinalV1 {
    match request {
        SenderRequestV1::Submit { handle, .. } => *handle,
        SenderRequestV1::Settle { statement } => statement.handle,
    }
}

pub(super) fn pending(request: &SenderRequestV1) -> ReaderResponse {
    ReaderResponse::SenderPendingV1 {
        handle: handle(request),
    }
}

pub(super) fn prepare(
    reader: &GuestReader,
    request: ApplicationSenderRequestV1,
) -> Result<Prepared, Refusal> {
    let mut store = store(reader)?;
    let now = now_unix_ms()?;
    let handle = match request {
        ApplicationSenderRequestV1::Stage { handle, payload } => {
            store.stage(handle, &payload, now)?;
            return Ok(Prepared::Staged(handle));
        }
        ApplicationSenderRequestV1::Status { handle } => handle,
        ApplicationSenderRequestV1::Settle {
            handle,
            receipt_digest,
        } => {
            let statement = store.begin_settle(
                handle,
                receipt_digest,
                &SigningKey::from_bytes(reader.ack_seed),
                now,
            )?;
            return Ok(Prepared::Forward(Box::new(SenderRequestV1::Settle {
                statement,
            })));
        }
    };
    Ok(Prepared::Forward(Box::new(store.request(handle, now)?)))
}

pub(super) fn preflight(reader: &GuestReader, request: &SenderRequestV1) -> Result<(), Refusal> {
    if store(reader)?.request(handle(request), now_unix_ms()?)? != *request {
        return Err(Refusal::NotAuthorized);
    }
    Ok(())
}

pub(super) fn complete(
    reader: &GuestReader,
    request: &SenderRequestV1,
    stream: &mut impl Read,
) -> Result<ReaderResponse, Refusal> {
    let response = match read_submission_response(stream) {
        Err(Refusal::Unavailable) => return Ok(pending(request)),
        result => result?,
    };
    let mut store = store(reader)?;
    let now = now_unix_ms()?;
    if store.request(handle(request), now)? != *request {
        return Err(Refusal::NotAuthorized);
    }
    match (request, &response) {
        (_, ReaderResponse::Refused { reason }) => return Err(reason.clone()),
        (
            SenderRequestV1::Submit { handle, .. },
            ReaderResponse::SenderAcceptedV1 {
                handle: returned,
                receipt,
            },
        ) if returned == handle => {
            store.record_receipt(receipt, now)?;
        }
        (
            SenderRequestV1::Settle { statement },
            ReaderResponse::SenderSettledV1 {
                handle,
                retired_through,
            },
        ) if *handle == statement.handle => {
            store.confirm(*handle, *retired_through, now)?;
        }
        _ => return Err(Refusal::NotAuthorized),
    }
    Ok(response)
}
