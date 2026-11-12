//! Guest half of an already admitted host-dialed Submit stream. The caller
//! owns transport authentication, the original I/O deadline and the durable
//! outbox. A local acceptance identifies an ephemeral host admission.
use super::{Refusal, local::*};
use mvm_contract::protocol::mailbox::{
    CorrelationId, MailboxMessageKind,
    local::{
        LocalDirection, LocalDisposition, LocalFrame, LocalGreeting, LocalRole, LocalSubmitResult,
    },
    local_service::MailboxLocalLimits,
};
use std::io::{self, Read, Write};

/// Immutable bytes and their checked identity, prepared once for retries.
pub struct PreparedSubmit {
    bytes: Vec<u8>,
    limits: MailboxLocalLimits,
    binding: [u8; 32],
    request_id: u64,
    kind: MailboxMessageKind,
    correlation: CorrelationId,
    digest: [u8; 32],
}

impl PreparedSubmit {
    pub fn from_claim(bytes: Vec<u8>, limits: MailboxLocalLimits) -> Result<Self, Refusal> {
        let (request, digest) = decode_submit_with_digest(&bytes, &limits)?;
        Ok(Self {
            bytes,
            limits,
            binding: request.originating_binding,
            request_id: request.request_id,
            kind: request.kind,
            correlation: request.correlation,
            digest,
        })
    }

    /// Take both generations from the installed owner. The callback must
    /// durably publish the result before retiring the matching claim and be
    /// idempotent across interruption. If a result is already present, validate
    /// its original message ID, correlation, service generation and request
    /// identity before unlinking. A conflict or unlink error retains the claim.
    /// A retry may label the same admission DuplicateEphemeral. On any
    /// nonpositive disposition the callback is skipped.
    pub fn forward_on(
        &self,
        io: &mut (impl Read + Write),
        admitted: &LocalGreeting,
        service_generation: &[u8; 32],
        publish_and_retire: impl FnOnce(&[u8], &LocalSubmitResult) -> io::Result<()>,
    ) -> io::Result<LocalDisposition> {
        if admitted.role != LocalRole::Submit
            || admitted.binding != self.binding
            || *service_generation == [0; 32]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid installed Submit context",
            ));
        }
        let mut hello = [0; LOCAL_GREETING_BYTES];
        io.read_exact(&mut hello)?;
        verify_local_greeting_echo(admitted, &hello).map_err(invalid_data)?;
        io.write_all(&hello)?;
        io.write_all(&self.bytes)?;
        io.flush()?;

        let mut prefix = [0; 4];
        io.read_exact(&mut prefix)?;
        let size = checked_local_body_length(&prefix, LocalRole::Submit, &self.limits)
            .map_err(invalid_data)?;
        let mut bytes = vec![0; 4 + size];
        bytes[..4].copy_from_slice(&prefix);
        io.read_exact(&mut bytes[4..])?;
        let LocalFrame::SubmitResult(result) = decode_local_frame(
            &bytes,
            LocalRole::Submit,
            LocalDirection::HostToGuest,
            &self.limits,
        )
        .map_err(invalid_data)?
        else {
            return Err(invalid_data("expected SubmitResult"));
        };
        if result.request_id != self.request_id
            || result.semantic_digest != self.digest
            || result.service_generation != *service_generation
        {
            return Err(invalid_data(
                "SubmitResult does not identify this claim and service",
            ));
        }
        if matches!(
            result.disposition,
            LocalDisposition::AcceptedEphemeral | LocalDisposition::DuplicateEphemeral
        ) {
            let valid = match self.kind {
                MailboxMessageKind::Call => result.correlation.as_bytes() != &[0; 32],
                MailboxMessageKind::Cast => result.correlation.as_bytes() == &[0; 32],
                MailboxMessageKind::Reply => result.correlation == self.correlation,
            };
            if !valid {
                return Err(invalid_data("unexpected SubmitResult correlation"));
            }
            publish_and_retire(&self.bytes, &result)?;
        }
        Ok(result.disposition)
    }
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Compare validated local verdicts when an interrupted unlink leaves a
/// published result beside its claim. Keep the first stored encoding intact.
pub fn reconciles_published_submit(first: &LocalSubmitResult, retry: &LocalSubmitResult) -> bool {
    use LocalDisposition::{AcceptedEphemeral, DuplicateEphemeral};
    match (first.disposition, retry.disposition) {
        (AcceptedEphemeral, DuplicateEphemeral) => {
            let mut original_form = retry.clone();
            original_form.disposition = AcceptedEphemeral;
            *first == original_form
        }
        (AcceptedEphemeral, AcceptedEphemeral) | (DuplicateEphemeral, DuplicateEphemeral) => {
            first == retry
        }
        _ => false,
    }
}
