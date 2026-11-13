//! UDS client to `mvm-audit-signer` for the `host.audit.v1` handler.
//!
//! Each `append` opens a fresh UDS connection. Pooling lives at the
//! supervisor's `AuditSignerProxy`; the broker is a
//! direct client because the audit-signer's UDS path is part of the
//! broker's `SubprocessConfig`, and going through the supervisor would
//! add a hop per workload-emitted entry.
//!
//! Wire format mirrors `mvm-audit-signer::server`: 4-byte big-endian
//! length prefix + JSON `AppendEntryRequest`; response is the same
//! shape. Frame cap matches the audit-signer's
//! `DEFAULT_MAX_FRAME_BYTES` (64 KiB).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mvm_core::protocol::audit_signer::{
    AppendEntryRequest, AppendEntryResponse, SignerHelperAppendEntry, SignerHelperRequest,
    SignerHelperResponse,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const FRAME_LEN_BYTES: usize = 4;
const DEFAULT_MAX_FRAME_BYTES: usize = 65_536;

/// Errors the client can surface beyond a typed [`AppendEntryResponse::Err`].
#[derive(Debug, Error)]
pub enum AuditClientError {
    #[error("connect to {path} failed: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("UDS I/O on {path} failed: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("response from {path} too large: {size} > {cap}")]
    ResponseTooLarge {
        path: PathBuf,
        size: usize,
        cap: usize,
    },
    #[error("response envelope parse failed from {path}: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("request envelope encode failed: {source}")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
    #[error("protocol violation from {path}: {message}")]
    Protocol { path: PathBuf, message: String },
}

/// One-call-per-connection UDS client.
///
/// Cheap to construct: holds only the path. Each `append` re-opens
/// the socket and shuts it down after the response — there's no
/// connection state to retain.
#[derive(Debug, Clone)]
pub struct AuditClient {
    target: AuditClientTarget,
    max_frame_bytes: usize,
}

#[derive(Debug, Clone)]
enum AuditClientTarget {
    PerVmSigner {
        uds_path: PathBuf,
    },
    SignerHelper {
        uds_path: PathBuf,
        vm_id: String,
    },
    OwnedSignerHelper {
        uds_path: PathBuf,
        vm_id: String,
        original_child: u32,
        admission: OwnedAuditAdmission,
    },
}
#[derive(Clone)]
struct OwnedAuditAdmission(Arc<crate::owned_resources::registered::RegistrationAdmission>);
impl std::fmt::Debug for OwnedAuditAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RegistrationAdmission(..)")
    }
}

impl AuditClient {
    /// New client targeting the audit-signer UDS at `uds_path`.
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            target: AuditClientTarget::PerVmSigner {
                uds_path: uds_path.into(),
            },
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// New client targeting the resident signer helper for one server-derived
    /// `vm_id`.
    pub fn new_signer_helper(uds_path: impl Into<PathBuf>, vm_id: impl Into<String>) -> Self {
        Self {
            target: AuditClientTarget::SignerHelper {
                uds_path: uds_path.into(),
                vm_id: vm_id.into(),
            },
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    pub(crate) fn new_owned_signer_helper(
        uds_path: PathBuf,
        vm_id: String,
        original_child: u32,
        admission: Arc<crate::owned_resources::registered::RegistrationAdmission>,
    ) -> Self {
        Self {
            target: AuditClientTarget::OwnedSignerHelper {
                uds_path,
                vm_id,
                original_child,
                admission: OwnedAuditAdmission(admission),
            },
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Set the max bytes the client will read on a response. Defaults
    /// to 64 KiB.
    pub fn with_max_frame_bytes(mut self, max: usize) -> Self {
        self.max_frame_bytes = max;
        self
    }

    /// Send one [`AppendEntryRequest`] and return the typed response.
    /// Errors are split between transport ([`AuditClientError`]) and
    /// protocol-level (`AppendEntryResponse::Err`); callers handle both.
    pub async fn append(
        &self,
        req: &AppendEntryRequest,
    ) -> Result<AppendEntryResponse, AuditClientError> {
        match &self.target {
            AuditClientTarget::PerVmSigner { uds_path } => {
                let mut stream = connect(uds_path).await?;
                write_frame(&mut stream, uds_path, req).await?;
                let resp =
                    read_frame::<AppendEntryResponse>(&mut stream, uds_path, self.max_frame_bytes)
                        .await?;
                let _ = stream.shutdown().await;
                Ok(resp)
            }
            AuditClientTarget::SignerHelper { uds_path, vm_id } => {
                let helper_req = helper_request_from_append(req, vm_id);
                let mut stream = connect(uds_path).await?;
                write_frame(&mut stream, uds_path, &helper_req).await?;
                let resp =
                    read_frame::<SignerHelperResponse>(&mut stream, uds_path, self.max_frame_bytes)
                        .await?;
                let _ = stream.shutdown().await;
                helper_response_to_append_response(resp, uds_path)
            }
            AuditClientTarget::OwnedSignerHelper { uds_path, .. } => {
                let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
                    AuditClientError::Protocol {
                        path: uds_path.clone(),
                        message: "owned audit runtime absent".into(),
                    }
                })?;
                if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
                    return Err(AuditClientError::Protocol {
                        path: uds_path.clone(),
                        message: "owned audit requires multi-thread runtime".into(),
                    });
                }
                let single_append = Instant::now()
                    .checked_add(Duration::from_secs(5))
                    .ok_or_else(|| AuditClientError::Protocol {
                        path: uds_path.clone(),
                        message: "owned deadline overflow".into(),
                    })?;
                let deadline = crate::broker::registry::owned_call_deadline()
                    .map_or(single_append, |original| original.min(single_append));
                // No detached blocking job: the current handler and workspace
                // remain live until this bounded closure actually returns.
                tokio::task::block_in_place(|| self.append_owned_until(req, deadline))
            }
        }
    }

    fn append_owned_until(
        &self,
        req: &AppendEntryRequest,
        deadline: Instant,
    ) -> Result<AppendEntryResponse, AuditClientError> {
        let AuditClientTarget::OwnedSignerHelper {
            uds_path,
            vm_id,
            original_child,
            admission,
        } = &self.target
        else {
            return Err(AuditClientError::Protocol {
                path: PathBuf::new(),
                message: "not an owned signer target".into(),
            });
        };
        admission.0.check().map_err(|source| AuditClientError::Io {
            path: uds_path.clone(),
            source,
        })?;
        if Instant::now() >= deadline {
            return Err(AuditClientError::Io {
                path: uds_path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned append deadline elapsed",
                ),
            });
        }
        if self.max_frame_bytes == 0 || self.max_frame_bytes > DEFAULT_MAX_FRAME_BYTES {
            return Err(AuditClientError::Protocol {
                path: uds_path.clone(),
                message: "owned frame cap".into(),
            });
        }
        if let AppendEntryRequest::AppendEntry { fields, .. } = req {
            crate::owned_resources::validate_value(fields)
                .map_err(|source| AuditClientError::Encode { source })?;
        }
        crate::owned_resources::encoded_len(req, DEFAULT_MAX_FRAME_BYTES)
            .map_err(|source| AuditClientError::Encode { source })?;
        let helper_req = helper_request_from_append(req, vm_id);
        let client = crate::audit_signer::helper_client::SignerHelperClient::new(uds_path)
            .with_max_frame_bytes(self.max_frame_bytes)
            .with_original_child(*original_child);
        let response = client
            .send_until_current(&helper_req, deadline, &admission.0)
            .map_err(|error| {
                admission.0.fence();
                match error.downcast::<std::io::Error>() {
                    Ok(source) => AuditClientError::Io {
                        path: uds_path.clone(),
                        source,
                    },
                    Err(error) => match error.downcast::<serde_json::Error>() {
                        Ok(source) => AuditClientError::Decode {
                            path: uds_path.clone(),
                            source,
                        },
                        Err(_) => AuditClientError::Protocol {
                            path: uds_path.clone(),
                            message: "owned signer response rejected".into(),
                        },
                    },
                }
            })?;
        admission.0.check().map_err(|source| AuditClientError::Io {
            path: uds_path.clone(),
            source,
        })?;
        let response = helper_response_to_append_response(response, uds_path);
        if response.is_err() {
            admission.0.fence();
        }
        response
    }
}

fn helper_request_from_append(req: &AppendEntryRequest, vm_id: &str) -> SignerHelperRequest {
    match req {
        AppendEntryRequest::AppendEntry {
            request_id,
            category,
            ts,
            workload_id,
            tenant_id,
            session_id,
            correlation_id,
            fields,
        } => SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
            request_id: request_id.clone(),
            vm_id: vm_id.to_string(),
            category: category.clone(),
            ts: ts.clone(),
            workload_id: workload_id.clone(),
            tenant_id: tenant_id.clone(),
            session_id: session_id.clone(),
            correlation_id: correlation_id.clone(),
            fields: fields.clone(),
        }),
        AppendEntryRequest::Probe { request_id } => SignerHelperRequest::Probe {
            request_id: request_id.clone(),
        },
    }
}

fn helper_response_to_append_response(
    resp: SignerHelperResponse,
    path: &Path,
) -> Result<AppendEntryResponse, AuditClientError> {
    match resp {
        SignerHelperResponse::Ok {
            request_id,
            chain_head,
            entry_hash,
            sig_alg,
        } => Ok(AppendEntryResponse::Ok {
            request_id,
            chain_head,
            entry_hash,
            sig_alg,
        }),
        SignerHelperResponse::Pong { request_id } => Ok(AppendEntryResponse::Pong { request_id }),
        SignerHelperResponse::Err {
            request_id,
            code,
            message,
        } => Ok(AppendEntryResponse::Err {
            request_id,
            code,
            message,
        }),
        SignerHelperResponse::FundedInventory { .. }
        | SignerHelperResponse::Registered { .. }
        | SignerHelperResponse::Deregistered { .. }
        | SignerHelperResponse::HostSigned { .. } => Err(AuditClientError::Protocol {
            path: path.to_path_buf(),
            message: "signer helper returned a non-append response to append".into(),
        }),
    }
}

async fn connect(path: &Path) -> Result<UnixStream, AuditClientError> {
    UnixStream::connect(path)
        .await
        .map_err(|source| AuditClientError::Connect {
            path: path.to_path_buf(),
            source,
        })
}

async fn write_frame<T: serde::Serialize>(
    stream: &mut UnixStream,
    path: &Path,
    value: &T,
) -> Result<(), AuditClientError> {
    let body = serde_json::to_vec(value).map_err(|source| AuditClientError::Encode { source })?;
    let len: u32 = body.len().try_into().map_err(|_| AuditClientError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other("frame body too large for u32 prefix"),
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    stream
        .write_all(&body)
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    path: &Path,
    max_frame_bytes: usize,
) -> Result<T, AuditClientError> {
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        return Err(AuditClientError::ResponseTooLarge {
            path: path.to_path_buf(),
            size: len,
            cap: max_frame_bytes,
        });
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    serde_json::from_slice(&body).map_err(|source| AuditClientError::Decode {
        path: path.to_path_buf(),
        source,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_core::protocol::audit_signer::AuditSignerErrorCode;
    use mvm_core::security::SIG_ALG_ED25519;
    use tempfile::tempdir;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use super::*;

    /// Spin up a one-shot mock UDS server that records the request it
    /// sees + replies with a canned response.
    async fn spawn_mock(
        path: PathBuf,
        response: AppendEntryResponse,
        captured: Arc<Mutex<Option<AppendEntryRequest>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let req: AppendEntryRequest = serde_json::from_slice(&body).unwrap();
            *captured.lock().await = Some(req);

            let resp_bytes = serde_json::to_vec(&response).unwrap();
            let resp_len: u32 = resp_bytes.len().try_into().unwrap();
            stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
            stream.write_all(&resp_bytes).await.unwrap();
            let _ = stream.shutdown().await;
        })
    }

    fn sample_req() -> AppendEntryRequest {
        AppendEntryRequest::AppendEntry {
            request_id: "req-1".into(),
            category: "workload_audit".into(),
            ts: "2026-05-28T00:00:00Z".into(),
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            session_id: "sess-001".into(),
            correlation_id: "01HCORR0000000000000000".into(),
            fields: serde_json::json!({"foo": "bar"}),
        }
    }

    #[tokio::test]
    async fn append_round_trips_an_ok_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");
        let response = AppendEntryResponse::Ok {
            request_id: "req-1".into(),
            chain_head: "head1".into(),
            entry_hash: "head1".into(),
            sig_alg: SIG_ALG_ED25519,
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response.clone(), captured.clone()).await;
        tokio::task::yield_now().await;

        let client = AuditClient::new(&path);
        let resp = client.append(&sample_req()).await.unwrap();
        assert_eq!(resp, response);

        let captured_req = captured.lock().await.clone().unwrap();
        assert_eq!(captured_req.request_id(), "req-1");
        mock.abort();
    }

    #[tokio::test]
    async fn surfaces_typed_subprocess_err_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");
        let err_resp = AppendEntryResponse::Err {
            request_id: "req-1".into(),
            code: AuditSignerErrorCode::InvalidRequest,
            message: "category not in allow-list".into(),
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), err_resp.clone(), captured).await;
        tokio::task::yield_now().await;

        let client = AuditClient::new(&path);
        let resp = client.append(&sample_req()).await.unwrap();
        assert_eq!(resp, err_resp);
        mock.abort();
    }

    #[tokio::test]
    async fn returns_connect_error_when_socket_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.sock");
        let client = AuditClient::new(&path);
        let err = client.append(&sample_req()).await.unwrap_err();
        assert!(matches!(err, AuditClientError::Connect { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_std_exchange_preserves_exact_canonical_request_and_response() {
        use std::io::Read;
        let directory = tempdir().unwrap();
        let path = directory.path().join("owned.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let request = sample_req();
        let expected =
            serde_json::to_vec(&helper_request_from_append(&request, "vm-owned")).unwrap();
        let request_id = request.request_id().to_owned();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, expected);
            let response = SignerHelperResponse::Ok {
                request_id,
                chain_head: "head".into(),
                entry_hash: "entry".into(),
                sig_alg: SIG_ALG_ED25519,
            };
            mvm_vmm::host::hvf_control_transport::write_frame_with_limit(
                &mut stream,
                &response,
                std::time::Instant::now() + std::time::Duration::from_secs(3),
                65536,
            )
            .unwrap();
        });
        let admission = Arc::new(crate::owned_resources::registered::RegistrationAdmission::new());
        // Transport fixture corroborates this process; actual original Child
        // authority is exercised by the separate process tests, not this mock.
        let client = AuditClient::new_owned_signer_helper(
            path,
            "vm-owned".into(),
            std::process::id(),
            admission,
        );
        let response = client.append(&request).await.unwrap();
        assert!(
            matches!(response, AppendEntryResponse::Ok { chain_head, entry_hash, .. }
            if chain_head == "head" && entry_hash == "entry")
        );
        server.join().unwrap();
    }

    #[test]
    fn two_blocked_owned_calls_retain_workspaces_and_leave_control_schedulable() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .max_blocking_threads(2)
            .max_io_events_per_tick(16)
            .thread_stack_size(2 * 1024 * 1024)
            .build()
            .unwrap()
            .block_on(async {
                use std::io::Read;
                struct Release(Vec<std::sync::mpsc::Sender<()>>);
                impl Drop for Release {
                    fn drop(&mut self) {
                        for sender in &self.0 {
                            let _ = sender.send(());
                        }
                    }
                }
                let directory = tempdir().unwrap();
                let pool = crate::owned_resources::WorkspacePool::new(2).unwrap();
                let admission =
                    Arc::new(crate::owned_resources::registered::RegistrationAdmission::new());
                let (entered, received) = std::sync::mpsc::channel();
                let mut release = Release(Vec::new());
                let mut servers = Vec::new();
                let mut calls = Vec::new();
                for index in 0..2 {
                    let path = directory.path().join(format!("blocked-{index}.sock"));
                    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
                    let (finish, wait) = std::sync::mpsc::channel();
                    release.0.push(finish);
                    let entered = entered.clone();
                    servers.push(std::thread::spawn(move || {
                        let (mut stream, _) = listener.accept().unwrap();
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                            .unwrap();
                        let mut header = [0; 4];
                        stream.read_exact(&mut header).unwrap();
                        let mut body = vec![0; u32::from_be_bytes(header) as usize];
                        stream.read_exact(&mut body).unwrap();
                        let request: SignerHelperRequest = serde_json::from_slice(&body).unwrap();
                        entered.send(()).unwrap();
                        wait.recv_timeout(std::time::Duration::from_secs(3))
                            .unwrap();
                        mvm_vmm::host::hvf_control_transport::write_frame_with_limit(
                            &mut stream,
                            &SignerHelperResponse::Pong {
                                request_id: request.request_id().into(),
                            },
                            std::time::Instant::now() + std::time::Duration::from_secs(1),
                            65536,
                        )
                        .unwrap();
                    }));
                    let client = AuditClient::new_owned_signer_helper(
                        path,
                        "vm-owned".into(),
                        std::process::id(),
                        admission.clone(),
                    );
                    let held = pool.try_acquire().unwrap();
                    calls.push(tokio::spawn(async move {
                        let _held = held;
                        client
                            .append(&AppendEntryRequest::Probe {
                                request_id: "held".into(),
                            })
                            .await
                    }));
                }
                for _ in 0..2 {
                    received
                        .recv_timeout(std::time::Duration::from_secs(3))
                        .unwrap();
                }
                for call in &calls {
                    call.abort();
                }
                for call in &mut calls {
                    assert!(
                        tokio::time::timeout(std::time::Duration::from_millis(50), call)
                            .await
                            .is_err()
                    );
                }
                assert!(
                    pool.try_acquire().is_err(),
                    "running STD exchanges still own both workspaces"
                );
                let (mut first, mut second) = tokio::net::UnixStream::pair().unwrap();
                let control = tokio::spawn(async move {
                    let value: serde_json::Value =
                        crate::framing::read_json_frame(&mut second, 65536)
                            .await
                            .unwrap();
                    crate::framing::write_json_frame(&mut second, &value)
                        .await
                        .unwrap();
                });
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    let expected = serde_json::json!({"control":"still-schedulable"});
                    crate::framing::write_json_frame(&mut first, &expected)
                        .await
                        .unwrap();
                    let actual: serde_json::Value =
                        crate::framing::read_json_frame(&mut first, 65536)
                            .await
                            .unwrap();
                    assert_eq!(actual, expected);
                })
                .await
                .unwrap();
                control.await.unwrap();
                drop(release);
                for call in calls {
                    match call.await {
                        Ok(response) => assert!(matches!(
                            response.unwrap(),
                            AppendEntryResponse::Pong { .. }
                        )),
                        Err(error) => assert!(error.is_cancelled()),
                    }
                }
                for server in servers {
                    server.join().unwrap();
                }
                let first = pool.try_acquire().unwrap();
                let second = pool.try_acquire().unwrap();
                drop((first, second));
            });
    }

    #[test]
    fn owned_wrong_reply_identity_fences_following_connections() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wrong-id.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            let _: SignerHelperRequest =
                mvm_vmm::host::hvf_control_transport::read_frame_with_limit(
                    &mut stream,
                    deadline,
                    65536,
                )
                .unwrap();
            mvm_vmm::host::hvf_control_transport::write_frame_with_limit(
                &mut stream,
                &SignerHelperResponse::Pong {
                    request_id: "different-request".into(),
                },
                deadline,
                65536,
            )
            .unwrap();
            listener
        });
        let admission = Arc::new(crate::owned_resources::registered::RegistrationAdmission::new());
        let client = AuditClient::new_owned_signer_helper(
            path,
            "vm-owned".into(),
            std::process::id(),
            admission.clone(),
        );
        assert!(matches!(
            client.append_owned_until(&sample_req(), Instant::now() + Duration::from_secs(3)),
            Err(AuditClientError::Protocol { .. })
        ));
        assert!(admission.check().is_err());
        let listener = server.join().unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(
            client
                .append_owned_until(&sample_req(), Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn owned_partial_reply_uses_original_deadline_and_fences() {
        use std::io::Write;
        let directory = tempdir().unwrap();
        let path = directory.path().join("partial.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _: SignerHelperRequest =
                mvm_vmm::host::hvf_control_transport::read_frame_with_limit(
                    &mut stream,
                    Instant::now() + Duration::from_secs(3),
                    65536,
                )
                .unwrap();
            stream.write_all(&[0, 0]).unwrap();
            // Keep the original connection alive until the caller observes its
            // deadline. EOF must not substitute for the partial-prefix proof.
            wait.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        let admission = Arc::new(crate::owned_resources::registered::RegistrationAdmission::new());
        let client = AuditClient::new_owned_signer_helper(
            path,
            "vm-owned".into(),
            std::process::id(),
            admission.clone(),
        );
        let deadline = Instant::now() + Duration::from_millis(150);
        let result = client.append_owned_until(&sample_req(), deadline);
        release.send(()).unwrap();
        server.join().unwrap();
        assert!(Instant::now() >= deadline);
        // The canonical framer preserves the socket's native timeout class:
        // Linux SO_RCVTIMEO commonly reports EAGAIN/WouldBlock. Require the
        // original deadline as well; an early WouldBlock cannot pass.
        assert!(
            matches!(&result, Err(AuditClientError::Io { source, .. })
            if matches!(source.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)),
            "{result:?}"
        );
        assert!(admission.check().is_err());
    }

    #[test]
    fn owned_closed_or_expired_exchange_refuses_before_connection() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("owned.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let admission = Arc::new(crate::owned_resources::registered::RegistrationAdmission::new());
        let client = AuditClient::new_owned_signer_helper(
            path,
            "vm-owned".into(),
            std::process::id(),
            admission.clone(),
        );
        assert!(
            client
                .append_owned_until(&sample_req(), std::time::Instant::now())
                .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        admission.fence();
        assert!(
            client
                .append_owned_until(
                    &sample_req(),
                    std::time::Instant::now() + std::time::Duration::from_secs(1)
                )
                .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
