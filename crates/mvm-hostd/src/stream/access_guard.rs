//! Narrow access-service facade over the existing canonical stream seam.
use super::{
    redact::{StreamRedaction, StreamRedactor},
    secret_scan::SecretScanner,
};
use mvm_contract::stream::secret_fingerprint::SecretFingerprint;
use mvm_core::plan::ExecutionPlan;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccessGuardError {
    #[error("access payload guard closed")]
    Closed,
    #[error("access payload resource limit")]
    Limit,
    #[error("access known-secret fingerprint matched")]
    SecretMatch,
    #[error("access policy transform refused")]
    Redaction,
    #[error("access secret profile unavailable")]
    Profile,
}
pub struct AccessPayloadGuard {
    scanner: SecretScanner,
    redaction: StreamRedaction,
    closed: bool,
}
impl AccessPayloadGuard {
    /// The host supplies the admitted plan and its already resolved secret
    /// profile, never data from a caller/guest payload. Empty profiles refuse
    /// when the admitted plan actually carries host secret bindings.
    pub fn from_admitted(
        plan: &ExecutionPlan,
        fingerprints: Arc<Vec<SecretFingerprint>>,
    ) -> Result<Self, AccessGuardError> {
        if fingerprints.len() > 128
            || fingerprints
                .iter()
                .any(|fp| fp.is_empty() || fp.len() > 4096)
            || (!plan.secrets.is_empty() && fingerprints.is_empty())
        {
            return Err(AccessGuardError::Profile);
        }
        Ok(Self {
            scanner: SecretScanner::new(fingerprints),
            redaction: StreamRedaction::curated(&plan.redaction),
            closed: false,
        })
    }
    /// Production materialization uses the profile reported by the canonical
    /// substitution endpoint for this exact admitted runtime instance.
    pub fn for_instance(plan: &ExecutionPlan, instance: &str) -> Result<Self, AccessGuardError> {
        Self::from_admitted(
            plan,
            Arc::new(mvm_vmm::host::network_endpoint_spawn::recorded_secret_fingerprints(instance)),
        )
    }
    fn transform(&mut self, bytes: &[u8]) -> Result<Vec<u8>, AccessGuardError> {
        self.redaction
            .redact(bytes)
            .map(|cleared| cleared.body)
            .map_err(|_| {
                self.closed = true;
                AccessGuardError::Redaction
            })
    }
    pub fn admit(&mut self, bytes: &[u8]) -> Result<Vec<u8>, AccessGuardError> {
        if self.closed {
            return Err(AccessGuardError::Closed);
        }
        if bytes.len() > 65536 {
            self.closed = true;
            return Err(AccessGuardError::Limit);
        }
        let cleared = self.scanner.admit(bytes).map_err(|_| {
            self.closed = true;
            AccessGuardError::SecretMatch
        })?;
        self.transform(&cleared)
    }
    pub fn flush(&mut self) -> Result<Vec<u8>, AccessGuardError> {
        if self.closed {
            return Err(AccessGuardError::Closed);
        }
        let tail = self.scanner.flush();
        self.transform(&tail)
    }
    /// Only for a complete bounded semantic message. Streaming callers use
    /// admit/flush across their whole stream so split secrets stay withheld.
    pub fn clear_message(&mut self, bytes: &[u8]) -> Result<Vec<u8>, AccessGuardError> {
        if self.closed {
            return Err(AccessGuardError::Closed);
        }
        if bytes.len() > 65536 {
            self.closed = true;
            return Err(AccessGuardError::Limit);
        }
        if self.scanner.contains_bound_secret(bytes) {
            self.closed = true;
            return Err(AccessGuardError::SecretMatch);
        }
        self.transform(bytes)
    }
}
