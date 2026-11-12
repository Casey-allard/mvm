//! Validation only. This does not grant admission, create slots, or collect children.
use super::broker_control::{self, ControlRequest, SignedControl};
use ed25519_dalek::VerifyingKey;
pub use mvm_contract::protocol::mailbox_worker::*;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum WorkerControlError {
    #[error("invalid worker control signature")]
    Signature(#[from] broker_control::ControlError),
    #[error("invalid worker control binding or bounded field")]
    Binding,
    #[error("expired or excessive worker operation deadline")]
    Deadline,
    #[error("invalid worker canonical encoding")]
    Encoding(#[from] serde_json::Error),
}

fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && s != "."
        && s != ".."
}
fn owner_valid(o: &MailboxWorkerOwner) -> bool {
    o.generation != 0
        && o.daemon_boot_nonce != [0; 32]
        && o.lease != [0; 32]
        && o.context_commitment != [0; 32]
}
/// Exact immutable admission context commitment. Nonces, operation and its
/// deadline are excluded so Query/Stop retain the original acquisition identity.
pub fn context_commitment(r: &MailboxWorkerRequest) -> Result<[u8; 32], WorkerControlError> {
    let bytes = serde_jcs::to_vec(&(
        &r.domain,
        r.version,
        &r.tenant,
        &r.vm_id,
        &r.workload_id,
        r.plan_commitment,
        &r.mailbox_grant,
        r.admission_expires_at_unix_ms,
        r.backend,
    ))?;
    let mut h = Sha256::new();
    h.update(b"mvm-mailbox-worker-context-v1\0");
    h.update(bytes);
    Ok(h.finalize().into())
}

/// Call after bounded frame decoding, before holding the canonical owner lock.
/// Caller must recheck current admission and exact live slot under that lock.
/// Wall time comes from the canonical host clock, not from a request field.
pub fn verify_request<'a>(
    signed: &'a SignedControl,
    root: &VerifyingKey,
    now_unix_ms: u64,
) -> Result<&'a MailboxWorkerRequest, WorkerControlError> {
    let r = verify_binding(signed, root)?;
    match r.deadline_unix_ms.checked_sub(now_unix_ms) {
        Some(1..=MAX_WORKER_OPERATION_MS) => (),
        _ => return Err(WorkerControlError::Deadline),
    }
    if !matches!(
        r.operation,
        MailboxWorkerOperation::LookupExistingV1
            | MailboxWorkerOperation::Stop { .. }
            | MailboxWorkerOperation::Query { .. }
            | MailboxWorkerOperation::ReleaseUnstartedV1 { .. }
    ) && r.admission_expires_at_unix_ms <= now_unix_ms
    {
        return Err(WorkerControlError::Deadline);
    }
    Ok(r)
}

/// Authenticate a persisted original Stop locator without authorizing a live
/// operation. Recovery sends a newly signed Query or Stop with a fresh deadline.
pub fn verify_stop_locator<'a>(
    signed: &'a SignedControl,
    root: &VerifyingKey,
    expected_vm: &str,
) -> Result<&'a MailboxWorkerRequest, WorkerControlError> {
    let r = verify_binding(signed, root)?;
    if r.deadline_unix_ms != 0
        || r.vm_id != expected_vm
        || !matches!(r.operation, MailboxWorkerOperation::Stop { .. })
    {
        return Err(WorkerControlError::Binding);
    }
    Ok(r)
}

/// A signed Pending acquisition is a lookup locator with no live operation deadline.
pub fn verify_pending_locator<'a>(
    signed: &'a SignedControl,
    root: &VerifyingKey,
    expected_vm: &str,
) -> Result<&'a MailboxWorkerRequest, WorkerControlError> {
    let r = verify_binding(signed, root)?;
    if r.vm_id != expected_vm || r.deadline_unix_ms != 0 || !matches!(r.operation, MailboxWorkerOperation::Acquire) {
        return Err(WorkerControlError::Binding);
    }
    Ok(r)
}

fn verify_binding<'a>(
    signed: &'a SignedControl,
    root: &VerifyingKey,
) -> Result<&'a MailboxWorkerRequest, WorkerControlError> {
    let ControlRequest::MailboxWorkerV1(r) = broker_control::verify(signed, root)? else {
        return Err(WorkerControlError::Binding);
    };
    if r.domain != MAILBOX_WORKER_DOMAIN
        || r.version != 1
        || r.request_nonce == [0; 32]
        || r.plan_commitment == [0; 32]
        || !label(&r.tenant)
        || !label(&r.vm_id)
        || !label(&r.workload_id)
        || serde_json::to_vec(signed)?.len() > MAX_WORKER_CONTROL_BYTES
    {
        return Err(WorkerControlError::Binding);
    }
    match &r.operation {
        MailboxWorkerOperation::Acquire | MailboxWorkerOperation::LookupExistingV1 => (),
        MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch } if *resource_epoch != 0 => {
            ()
        }
        MailboxWorkerOperation::ForwardCastV1 {
            owner,
            destination_vm,
            destination_owner,
            resource_epoch,
            projection,
        } if owner_valid(owner)
            && owner.context_commitment == context_commitment(r)?
            && owner_valid(destination_owner)
            && owner.lease != destination_owner.lease
            && owner.daemon_boot_nonce == destination_owner.daemon_boot_nonce
            && owner.context_commitment != destination_owner.context_commitment
            && label(destination_vm)
            && destination_vm != &r.vm_id
            && *resource_epoch != 0
            && !projection.is_empty()
            && projection.len() <= MAX_WORKER_CONTROL_BYTES => {}
        MailboxWorkerOperation::DelegateConfig { owner }
        | MailboxWorkerOperation::Query { owner }
        | MailboxWorkerOperation::Stop { owner }
        | MailboxWorkerOperation::ReleaseUnstartedV1 { owner }
            if owner_valid(owner) && owner.context_commitment == context_commitment(r)? => {}
        _ => return Err(WorkerControlError::Binding),
    }
    Ok(r)
}
/// An authenticated original daemon connection is required. Correlation alone
/// is not authentication. Acquire binds the exact canonical admission context;
/// subsequent operations must retain every byte of the originally returned owner.
pub fn verify_result(
    request: &MailboxWorkerRequest,
    result: &MailboxWorkerResult,
) -> Result<(), WorkerControlError> {
    if result.request_nonce != request.request_nonce || !owner_valid(&result.owner) {
        return Err(WorkerControlError::Binding);
    }
    if matches!(request.operation, MailboxWorkerOperation::LookupExistingV1) {
        return if result.owner.context_commitment == context_commitment(request)? && !result.delegates_config {
            Ok(())
        } else { Err(WorkerControlError::Binding) };
    }
    match &request.operation {
        MailboxWorkerOperation::Acquire | MailboxWorkerOperation::ProvisionAdmittedV1 { .. }
            if result.owner.context_commitment == context_commitment(request)?
                && matches!(result.state, MailboxWorkerState::Reserved)
                && !result.delegates_config => {}
        MailboxWorkerOperation::Acquire | MailboxWorkerOperation::ProvisionAdmittedV1 { .. } => return Err(WorkerControlError::Binding),
        MailboxWorkerOperation::ForwardCastV1 { owner, .. }
            if owner == &result.owner
                && result.state == MailboxWorkerState::Serving
                && !result.delegates_config => {}
        MailboxWorkerOperation::DelegateConfig { owner }
        | MailboxWorkerOperation::Query { owner }
        | MailboxWorkerOperation::Stop { owner }
        | MailboxWorkerOperation::ReleaseUnstartedV1 { owner }
            if owner == &result.owner => {}
        _ => return Err(WorkerControlError::Binding),
    }
    if matches!(
        request.operation,
        MailboxWorkerOperation::ReleaseUnstartedV1 { .. }
    ) != matches!(result.state, MailboxWorkerState::ReleasedBeforeSpawn)
    {
        return Err(WorkerControlError::Binding);
    }
    if result.delegates_config
        && !(matches!(
            request.operation,
            MailboxWorkerOperation::DelegateConfig { .. }
        ) && matches!(result.state, MailboxWorkerState::Starting))
    {
        return Err(WorkerControlError::Binding);
    }
    Ok(())
}
