//! Original installed/registered guards around the canonical signer client.
use anyhow::{Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};
use mvm_core::signer_helper::DEFAULT_HELPER_MAX_FRAME_BYTES;
use mvm_core::{
    net::telemetry::{TelemetryError, handshake_signing_bytes},
    protocol::{
        audit_signer::{SignerHelperRequest, SignerHelperResponse, SignerHelperSignHost},
        host_signer::{SignRequest, TelemetryHandshake},
    },
    security::{SessionHello, SessionHelloAck},
};
use std::ops::Deref;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct OwnedSignerClient {
    canonical: mvm_core::signer_helper::SignerHelperClient,
    uds_path: PathBuf,
    max_frame_bytes: usize,
    original_child: Option<u32>,
}
impl Deref for OwnedSignerClient {
    type Target = mvm_core::signer_helper::SignerHelperClient;
    fn deref(&self) -> &Self::Target {
        &self.canonical
    }
}
impl OwnedSignerClient {
    pub(crate) fn new(uds_path: impl Into<PathBuf>) -> Self {
        let uds_path = uds_path.into();
        Self {
            canonical: mvm_core::signer_helper::SignerHelperClient::new(uds_path.clone()),
            uds_path,
            max_frame_bytes: DEFAULT_HELPER_MAX_FRAME_BYTES,
            original_child: None,
        }
    }
    pub(crate) fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.canonical = self.canonical.with_max_frame_bytes(max_frame_bytes);
        self.max_frame_bytes = max_frame_bytes;
        self
    }
    pub(crate) fn with_original_child(mut self, child: u32) -> Self {
        self.original_child = Some(child);
        self
    }

    /// Same canonical exchange with one deadline across connection and all bytes.
    pub(crate) fn send_until(
        &self,
        req: &SignerHelperRequest,
        deadline: std::time::Instant,
    ) -> Result<SignerHelperResponse> {
        self.send_until_inner(req, deadline, None, None)
    }

    pub(crate) fn send_until_current(
        &self,
        req: &SignerHelperRequest,
        deadline: std::time::Instant,
        admission: &crate::owned_resources::registered::RegistrationAdmission,
    ) -> Result<SignerHelperResponse> {
        self.send_until_inner(req, deadline, Some(admission), None)
    }

    /// The actual installed endpoint's original kernel observations accompany
    /// every trust-boundary step; metadata alone cannot construct this guard.
    pub(crate) fn send_until_endpoint(
        &self,
        req: &SignerHelperRequest,
        deadline: std::time::Instant,
        audit: &mvm_vmm::host::network_endpoint_spawn::InstalledEndpointAudit,
    ) -> Result<SignerHelperResponse> {
        let result = (|| {
            let SignerHelperRequest::AppendEntry(entry) = req else {
                bail!("installed endpoint only appends audit entries")
            };
            anyhow::ensure!(
                self.uds_path == audit.socket()
                    && self.original_child == Some(audit.signer_pid())
                    && self.max_frame_bytes <= DEFAULT_HELPER_MAX_FRAME_BYTES
                    && entry.vm_id == audit.vm()
                    && entry.workload_id == audit.vm()
                    && entry.tenant_id == audit.tenant(),
                "installed audit original target differs"
            );
            self.send_until_inner(req, deadline, None, Some(audit))
        })();
        if result.is_err() {
            audit.fence();
        }
        result
    }

    fn send_until_inner(
        &self,
        req: &SignerHelperRequest,
        deadline: std::time::Instant,
        admission: Option<&crate::owned_resources::registered::RegistrationAdmission>,
        endpoint: Option<&mvm_vmm::host::network_endpoint_spawn::InstalledEndpointAudit>,
    ) -> Result<SignerHelperResponse> {
        if let Some(endpoint) = endpoint {
            endpoint.check_current()?;
        }
        if let Some(admission) = admission {
            admission.check()?;
        }
        anyhow::ensure!(
            self.max_frame_bytes > 0 && u32::try_from(self.max_frame_bytes).is_ok(),
            "invalid signer frame cap"
        );
        let mut stream =
            mvm_vmm::host::hvf_control_transport::connect_path(&self.uds_path, deadline)?;
        if let Some(child) = self.original_child {
            anyhow::ensure!(
                u32::try_from(mvm_vmm::host::uds_peer::connected_peer_pid(&stream)?)? == child,
                "signer peer is not the original child"
            );
        }
        if let Some(admission) = admission {
            admission.check()?;
        }
        if let Some(endpoint) = endpoint {
            endpoint.check_current()?;
        }
        mvm_vmm::host::hvf_control_transport::write_frame_with_limit(
            &mut stream,
            req,
            deadline,
            self.max_frame_bytes,
        )?;
        let response: SignerHelperResponse =
            mvm_vmm::host::hvf_control_transport::read_frame_with_limit(
                &mut stream,
                deadline,
                self.max_frame_bytes,
            )?;
        anyhow::ensure!(
            response.request_id() == req.request_id(),
            "signer response request identity mismatch"
        );
        if let Some(endpoint) = endpoint {
            endpoint.check_current()?;
        }
        Ok(response)
    }

    pub(crate) fn sign_owned_telemetry_handshake(
        &self,
        audit: &mvm_vmm::host::network_endpoint_spawn::InstalledEndpointAudit,
        hello: &SessionHello,
        ack: &SessionHelloAck,
        host_key: &VerifyingKey,
        deadline: std::time::Instant,
    ) -> Result<Signature, TelemetryError> {
        if self.uds_path != audit.socket()
            || self.original_child != Some(audit.signer_pid())
            || self.max_frame_bytes > DEFAULT_HELPER_MAX_FRAME_BYTES
        {
            audit.fence();
            return Err(TelemetryError::Authentication);
        }
        let transcript = handshake_signing_bytes(hello, ack, host_key)?;
        let response = self
            .send_until_inner(&telemetry_request(hello, ack), deadline, None, Some(audit))
            .map_err(|_| TelemetryError::Authentication)?;
        mvm_core::signer_helper::verify_telemetry_signature(
            response,
            &hello.session_id,
            &transcript,
            host_key,
        )
    }
}
fn telemetry_request(hello: &SessionHello, ack: &SessionHelloAck) -> SignerHelperRequest {
    SignerHelperRequest::SignHost(SignerHelperSignHost {
        request_id: hello.session_id.clone(),
        request: SignRequest::SignTelemetryHandshake {
            request_id: hello.session_id.clone(),
            handshake: Box::new(TelemetryHandshake {
                hello: hello.clone(),
                ack: ack.clone(),
            }),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn owned_signer_deadline_refuses_expired_request_before_connect() {
        let root = tempdir().unwrap();
        let path = root.path().join("signer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = OwnedSignerClient::new(path);
        assert!(
            client
                .send_until(
                    &SignerHelperRequest::Probe {
                        request_id: "expired".into()
                    },
                    std::time::Instant::now()
                )
                .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
