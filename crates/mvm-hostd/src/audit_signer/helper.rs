//! Resident per-tenant signer helper.
//!
//! The helper owns a `vm_id -> Chain` map: `RegisterVm` opens a VM's workload
//! chain, `AppendEntry` routes through the server-derived `vm_id`, and
//! `DeregisterVm` drops the chain handle so the file is closed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mvm_core::protocol::audit_signer::{
    AuditSignerErrorCode, SignerHelperAppendEntry, SignerHelperDeregisterVm,
    SignerHelperRegisterVm, SignerHelperRequest, SignerHelperResponse, SignerHelperSignHost,
};
use mvm_core::protocol::host_signer::{HostSignerErrorCode, SignRequest, SignResponse};
use mvm_core::security::SIG_ALG_ED25519;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::audit_signer::canonical::CanonicalEntry;
use crate::audit_signer::chain::Chain;
use crate::audit_signer::server::format_code_message;
use crate::host_signer::keystore::Keystore;

const WORKLOAD_AUDIT_CATEGORY: &str = "workload_audit";

/// Shared helper state for the async UDS server.
pub type SharedSignerHelper = Arc<Mutex<SignerHelper>>;

struct VmChain {
    generation: Option<[u8; 32]>,
    workload_id: String,
    chain: Chain,
}

/// The one key-holding signer helper for a tenant.
pub struct SignerHelper {
    tenant_id: String,
    software_chain_key_path: Option<PathBuf>,
    chains: HashMap<String, VmChain>,
    owned: bool,
    chain_bytes: Option<std::num::NonZeroU64>,
}

impl SignerHelper {
    /// Create an empty helper for one tenant. Chains are opened by
    /// `RegisterVm`, not at helper boot.
    pub fn new(tenant_id: impl Into<String>, software_chain_key_path: Option<PathBuf>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            software_chain_key_path,
            chains: HashMap::new(),
            owned: false,
            chain_bytes: None,
        }
    }

    pub fn with_owned_resource_limits(mut self) -> Self {
        self.owned = true;
        self
    }

    pub fn with_audit_chain_bytes(mut self, limit: Option<std::num::NonZeroU64>) -> Self {
        self.chain_bytes = limit;
        self
    }

    /// Number of currently registered VM chains.
    pub fn registration_count(&self) -> usize {
        self.chains.len()
    }

    /// Current chain head for a registered VM.
    pub fn chain_head(&self, vm_id: &str) -> Option<&str> {
        self.chains.get(vm_id).map(|vm| vm.chain.head())
    }

    /// Apply one helper request.
    pub fn dispatch(&mut self, req: SignerHelperRequest) -> SignerHelperResponse {
        match req {
            SignerHelperRequest::RegisterVm(req) => self.register(req),
            SignerHelperRequest::DeregisterVm(req) => self.deregister(req),
            SignerHelperRequest::AppendEntry(req) => self.append(req),
            SignerHelperRequest::SignHost(req) => self.sign_host(req),
            SignerHelperRequest::Probe { request_id } => SignerHelperResponse::Pong { request_id },
        }
    }

    fn register(&mut self, req: SignerHelperRegisterVm) -> SignerHelperResponse {
        let request_id = req.request_id.clone();
        if self.owned
            && (req.tenant_id != self.tenant_id
                || validate_vm_id(&req.vm_id).is_err()
                || self.chains.contains_key(&req.vm_id))
        {
            return SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message: "owned signer registration identity/conflict".into(),
            };
        }
        // Drop any chain already registered under this vm_id before opening
        // the replacement: the open takes the file's sole-writer lock, and the
        // old handle still holds it. Re-registering is a supervisor restart,
        // and the head is recovered from the file, so releasing early costs
        // nothing.
        self.chains.remove(&req.vm_id);
        match self.open_chain(&req) {
            Ok(chain) => {
                let chain_head = chain.head().to_string();
                let generation = self.chain_bytes.map(|_| rand::random::<[u8; 32]>());
                let inventory = match generation
                    .map(|generation| {
                        chain.inventory(
                            mvm_core::protocol::audit_signer::AuditInventoryPhase::Registered,
                            generation,
                            &self.tenant_id,
                            &req.vm_id,
                            &req.workload_id,
                        )
                    })
                    .transpose()
                {
                    Ok(value) => value,
                    Err(e) => {
                        return SignerHelperResponse::Err {
                            request_id,
                            code: AuditSignerErrorCode::InternalError,
                            message: e.to_string(),
                        };
                    }
                };
                self.chains.insert(
                    req.vm_id.clone(),
                    VmChain {
                        generation,
                        workload_id: req.workload_id,
                        chain,
                    },
                );
                if let Some(value) = inventory {
                    return SignerHelperResponse::FundedInventory {
                        request_id,
                        inventory: Box::new(value),
                    };
                }
                SignerHelperResponse::Registered {
                    request_id,
                    vm_id: req.vm_id,
                    chain_head,
                }
            }
            Err(e) => SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message: e.to_string(),
            },
        }
    }

    fn open_chain(&mut self, req: &SignerHelperRegisterVm) -> Result<Chain> {
        if req.tenant_id != self.tenant_id {
            bail!(
                "register for tenant {:?} on signer helper for tenant {:?}",
                req.tenant_id,
                self.tenant_id
            );
        }
        validate_vm_id(&req.vm_id)?;
        if self.owned {
            anyhow::ensure!(
                self.chains.len() < 2
                    && req.workload_id.len() <= 128
                    && req.workload_chain_path.len() <= 4096
                    && req.chain_head_secondary_path.len() <= 4096,
                "owned signer registration resource limit"
            );
        }
        let workload_chain_path = Path::new(&req.workload_chain_path);
        let chain_head_secondary_path = Path::new(&req.chain_head_secondary_path);
        if self.chain_bytes.is_some() {
            let audit = mvm_core::config::workload_audit_path(&self.tenant_id, &req.vm_id);
            let state = mvm_core::config::vm_state_dir(&req.vm_id);
            let head = state.join(mvm_vmm::host::broker_services_spawn::AUDIT_SIGNER_HEAD_FILE);
            anyhow::ensure!(
                workload_chain_path == audit && chain_head_secondary_path == head,
                "funded audit paths differ from original registration"
            );
            mvm_core::private_fs::create_owned_private_dir(&mvm_core::config::mvm_audit_dir())?;
            mvm_vmm::host::restore_image::open_trusted_dir(&state)?;
        } else {
            ensure_parent(workload_chain_path)?;
            ensure_parent(chain_head_secondary_path)?;
        }
        if let Some(limit) = self.chain_bytes {
            anyhow::ensure!(
                self.owned,
                "funded audit chain requires original owned signer"
            );
            return Chain::open_owned_bounded(
                workload_chain_path,
                chain_head_secondary_path,
                self.software_chain_key_path.as_deref(),
                limit,
            );
        }
        let open = if self.owned {
            Chain::open_owned
        } else {
            Chain::open
        };
        open(
            workload_chain_path,
            chain_head_secondary_path,
            self.software_chain_key_path.as_deref(),
        )
    }

    fn deregister(&mut self, req: SignerHelperDeregisterVm) -> SignerHelperResponse {
        if let Some(vm) = self.chains.get(&req.vm_id)
            && let Some(generation) = vm.generation
        {
            match vm.chain.inventory(
                mvm_core::protocol::audit_signer::AuditInventoryPhase::Deregistered,
                generation,
                &self.tenant_id,
                &req.vm_id,
                &vm.workload_id,
            ) {
                Ok(value) => {
                    self.chains.remove(&req.vm_id);
                    return SignerHelperResponse::FundedInventory {
                        request_id: req.request_id,
                        inventory: Box::new(value),
                    };
                }
                Err(e) => {
                    return SignerHelperResponse::Err {
                        request_id: req.request_id,
                        code: AuditSignerErrorCode::InternalError,
                        message: e.to_string(),
                    };
                }
            }
        }
        self.chains.remove(&req.vm_id);
        SignerHelperResponse::Deregistered {
            request_id: req.request_id,
            vm_id: req.vm_id,
        }
    }

    fn append(&mut self, req: SignerHelperAppendEntry) -> SignerHelperResponse {
        let request_id = req.request_id.clone();
        if req.tenant_id != self.tenant_id {
            return SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message: "append tenant does not match signer helper tenant".into(),
            };
        }
        let Some(vm) = self.chains.get_mut(&req.vm_id) else {
            return SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::NotReady,
                message: "vm is not registered with signer helper".into(),
            };
        };
        if req.workload_id != vm.workload_id {
            return SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message: "append workload does not match registered signer helper workload".into(),
            };
        }
        // Category is host-set on every append path: the workload-facing
        // `host.audit.v1` broker forces `workload_audit`, and the daemon's own
        // health watcher sets `host` — the guest never supplies it. Honor the
        // caller's category (falling back to the workload default when unset)
        // so host-asserted health entries stay distinguishable from
        // workload-asserted ones; the chain re-validates it against the
        // allow-list, so an unknown category still fails closed here.
        let category = if req.category.is_empty() {
            WORKLOAD_AUDIT_CATEGORY.to_string()
        } else {
            req.category
        };
        if !crate::audit_signer::category::is_allowed(&category) {
            return SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message: "append category not in allow-list".into(),
            };
        }
        debug!(
            vm_id = %req.vm_id,
            workload_id = %vm.workload_id,
            request_id = %request_id,
            category = %category,
            "signer helper appending entry"
        );
        let entry = CanonicalEntry {
            category,
            correlation_id: req.correlation_id,
            fields: req.fields,
            prev_hash: vm.chain.head().to_string(),
            session_id: req.session_id,
            tenant_id: req.tenant_id,
            ts: req.ts,
            workload_id: req.workload_id,
        };
        match vm.chain.append(entry) {
            Ok(new_head) => SignerHelperResponse::Ok {
                request_id,
                chain_head: new_head.clone(),
                entry_hash: new_head,
                sig_alg: SIG_ALG_ED25519,
            },
            Err(code) => SignerHelperResponse::Err {
                request_id,
                code,
                message: format_code_message(code),
            },
        }
    }

    fn sign_host(&self, req: SignerHelperSignHost) -> SignerHelperResponse {
        let request_id = req.request_id;
        let response = match self.sign_host_inner(&req.request) {
            Ok(resp) => resp,
            Err(message) => SignResponse::Err {
                request_id: request_id.clone(),
                code: HostSignerErrorCode::KeyUnavailable,
                message,
            },
        };
        SignerHelperResponse::HostSigned {
            request_id,
            response,
        }
    }

    fn sign_host_inner(&self, req: &SignRequest) -> std::result::Result<SignResponse, String> {
        let Some(path) = self.software_chain_key_path.as_deref() else {
            return Err("signer helper has no host signing key path".into());
        };
        if self.owned && !matches!(req, SignRequest::SignTelemetryHandshake { .. }) {
            return Err("owned host-signing operation resource profile unqualified".into());
        }
        let load = if self.owned {
            Keystore::load_from_file_bounded
        } else {
            Keystore::load_from_file
        };
        let keystore = load(path).map_err(|e| e.to_string())?;
        Ok(crate::host_signer::server::dispatch_local(req, &keystore))
    }
}

/// Accept loop for the resident helper UDS.
pub async fn serve(
    listener: UnixListener,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
) -> Result<()> {
    info!(max_frame_bytes, "mvm-signer-helper accept loop started");
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("mvm-signer-helper UDS accept failed")?;
        let helper = helper.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, helper, max_frame_bytes).await {
                warn!(error = %e, "mvm-signer-helper connection terminated with error");
            }
        });
    }
}

pub async fn serve_on_listener(
    listener: UnixListener,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
) -> Result<()> {
    serve(listener, helper, max_frame_bytes).await
}

/// Installed profile: at most two bounded broker queues feed this helper.
pub async fn serve_owned_on_listener(
    listener: crate::owned_resources::registered::RegisteredListener,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
    admission: Arc<crate::owned_resources::registered::RegistrationAdmission>,
) -> Result<()> {
    anyhow::ensure!(
        (1..=65536).contains(&max_frame_bytes),
        "owned signer frame limit"
    );
    anyhow::ensure!(
        helper.lock().await.owned,
        "owned signer resource profile absent"
    );
    let mut requests = tokio::task::JoinSet::new();
    let workspaces =
        crate::owned_resources::WorkspacePool::new(crate::owned_resources::SIGNER_WORKSPACES)?;
    let outcome: Result<()> = loop {
        tokio::select! {
            _ = admission.closed() => break Err(anyhow::anyhow!("owned signer I/O fenced")),
            Some(result) = requests.join_next(), if !requests.is_empty() => {
                if let Err(error) = result { break Err(error).context("owned signer request task failed"); }
            }
            accepted = listener.accept(), if requests.len() < 64 => {
                let stream = match accepted { Ok(stream) => stream,
                    Err(error) => break Err(error).context("owned signer accept") };
                let helper = helper.clone();
                let workspaces = workspaces.clone();
                let future = async move {
                    if let Err(error) = handle_owned_connection(stream, helper, max_frame_bytes, workspaces).await {
                        warn!(error = %error, "owned signer request terminated");
                    }
                };
                if let Err(error) = crate::owned_resources::task_size(&future) { break Err(error); }
                requests.spawn(future);
            }
        }
    };
    drop(listener);
    requests.abort_all();
    let mut joined = Ok(());
    while let Some(result) = requests.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            joined = Err(error).context("join owned signer request");
        }
    }
    outcome
        .and(joined)
        .and(admission.check().map_err(anyhow::Error::from))
}

async fn handle_owned_connection(
    mut stream: crate::owned_resources::registered::RegisteredStream,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
    workspaces: crate::owned_resources::WorkspacePool,
) -> Result<()> {
    let _workspace = workspaces.acquire().await?;
    let request = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        crate::framing::read_json_frame_checked::<_, SignerHelperRequest>(
            &mut stream,
            max_frame_bytes,
            crate::owned_resources::validate_shape,
        ),
    )
    .await
    .context("owned signer parse deadline")??;
    anyhow::ensure!(
        request.request_id().len() <= 256,
        "owned signer request identity limit"
    );
    let response = helper.lock().await.dispatch(request);
    crate::framing::write_json_frame_bounded(&mut stream, &response, max_frame_bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
) -> Result<()> {
    let req = read_frame::<SignerHelperRequest>(&mut stream, max_frame_bytes).await?;
    let response = {
        let mut helper = helper.lock().await;
        helper.dispatch(req)
    };
    write_frame(&mut stream, &response).await?;
    stream
        .shutdown()
        .await
        .context("mvm-signer-helper UDS shutdown failed")?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<T> {
    crate::framing::read_json_frame(stream, max_frame_bytes)
        .await
        .context("mvm-signer-helper frame read failed")
}

async fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    crate::framing::write_json_frame(stream, value)
        .await
        .context("mvm-signer-helper frame write failed")
}

fn validate_vm_id(vm_id: &str) -> Result<()> {
    if vm_id.is_empty() || vm_id.len() > 63 {
        bail!("vm_id must be 1..=63 chars, got {}", vm_id.len());
    }
    if !vm_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("vm_id {:?} has characters outside [A-Za-z0-9_-]", vm_id);
    }
    Ok(())
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use tempfile::tempdir;

    fn key_path(dir: &Path) -> PathBuf {
        let path = dir.join("tenant-key.ed25519");
        std::fs::write(&path, [9u8; 32]).unwrap();
        path
    }

    fn register_req(dir: &Path, vm_id: &str, tenant_id: &str) -> SignerHelperRequest {
        SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
            request_id: format!("reg-{vm_id}"),
            vm_id: vm_id.into(),
            tenant_id: tenant_id.into(),
            workload_id: format!("wl-{vm_id}"),
            workload_chain_path: dir
                .join(format!("{tenant_id}.{vm_id}.workload.jsonl"))
                .to_string_lossy()
                .into_owned(),
            chain_head_secondary_path: dir
                .join(format!("{tenant_id}.{vm_id}.head"))
                .to_string_lossy()
                .into_owned(),
        })
    }

    fn append_req(vm_id: &str, request_id: &str) -> SignerHelperRequest {
        SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
            request_id: request_id.into(),
            vm_id: vm_id.into(),
            category: "workload_audit".into(),
            ts: "2026-06-17T00:00:00Z".into(),
            workload_id: format!("wl-{vm_id}"),
            tenant_id: "local".into(),
            session_id: "sess-1".into(),
            correlation_id: format!("brk-{request_id}"),
            fields: serde_json::json!({"event": request_id}),
        })
    }

    #[test]
    fn funded_original_signer_seals_genesis_and_exact_terminal_head() {
        use mvm_core::protocol::audit_signer::AuditInventoryPhase;
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let state = mvm_core::config::vm_state_dir("vm-1");
        mvm_core::config::create_private_dir(&state).unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())))
            .with_owned_resource_limits()
            .with_audit_chain_bytes(std::num::NonZeroU64::new(65536));
        let SignerHelperRequest::RegisterVm(mut req) = register_req(dir.path(), "vm-1", "local")
        else {
            unreachable!()
        };
        assert!(matches!(
            helper.dispatch(SignerHelperRequest::RegisterVm(req.clone())),
            SignerHelperResponse::Err { .. }
        ));
        req.workload_chain_path = mvm_core::config::workload_audit_path("local", "vm-1")
            .to_string_lossy()
            .into_owned();
        req.chain_head_secondary_path = state
            .join(mvm_vmm::host::broker_services_spawn::AUDIT_SIGNER_HEAD_FILE)
            .to_string_lossy()
            .into_owned();
        let original = match helper.dispatch(SignerHelperRequest::RegisterVm(req)) {
            SignerHelperResponse::FundedInventory { inventory, .. } => inventory,
            other => panic!("missing original inventory: {other:?}"),
        };
        let start = mvm_core::protocol::audit_inventory::verify(&original, &original.key).unwrap();
        assert_eq!(start.phase, AuditInventoryPhase::Registered);
        assert_eq!(start.length, 0);
        let accepted = helper.dispatch(append_req("vm-1", "held"));
        let SignerHelperResponse::Ok { chain_head, .. } = accepted else {
            panic!("append refused")
        };
        let close = || {
            SignerHelperRequest::DeregisterVm(SignerHelperDeregisterVm {
                vm_id: "vm-1".into(),
                request_id: "end-1".into(),
            })
        };
        let end = match helper.dispatch(close()) {
            SignerHelperResponse::FundedInventory { inventory, .. } => inventory,
            other => panic!("missing terminal inventory: {other:?}"),
        };
        let terminal = mvm_core::protocol::audit_inventory::verify(&end, &original.key).unwrap();
        assert!(start.same_registration(&terminal));
        assert_eq!(terminal.head, chain_head);
        assert_eq!(terminal.phase, AuditInventoryPhase::Deregistered);
        assert!(terminal.length > 0);
        assert!(mvm_core::protocol::audit_inventory::verify(&end, &[2; 32]).is_err());
        assert!(matches!(
            helper.dispatch(close()),
            SignerHelperResponse::Deregistered { .. }
        ));
    }

    fn append_req_with_category(
        vm_id: &str,
        request_id: &str,
        category: &str,
    ) -> SignerHelperRequest {
        SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
            request_id: request_id.into(),
            vm_id: vm_id.into(),
            category: category.into(),
            ts: "2026-06-17T00:00:00Z".into(),
            workload_id: format!("wl-{vm_id}"),
            tenant_id: "local".into(),
            session_id: "sess-1".into(),
            correlation_id: format!("brk-{request_id}"),
            fields: serde_json::json!({"event": request_id}),
        })
    }

    /// Read a per-VM chain file and return its entries' decoded JCS bytes as one
    /// string. Each on-disk line stores the entry base64-encoded in `canonical`,
    /// so category assertions must decode it rather than grep the raw line.
    fn chain_lines(dir: &Path, vm_id: &str) -> String {
        use base64::Engine;
        let raw =
            std::fs::read_to_string(dir.join(format!("local.{vm_id}.workload.jsonl"))).unwrap();
        raw.lines()
            .map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(v["canonical"].as_str().unwrap())
                    .unwrap();
                String::from_utf8(bytes).unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn append_honors_allowlisted_host_category() {
        // A host-asserted health entry (category "host") must be recorded as
        // "host" — not silently reclassified as a workload emission.
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        helper.dispatch(register_req(dir.path(), "vm-h", "local"));

        let resp = helper.dispatch(append_req_with_category("vm-h", "a1", "host"));
        assert!(
            matches!(resp, SignerHelperResponse::Ok { .. }),
            "got {resp:?}"
        );

        let chain = chain_lines(dir.path(), "vm-h");
        assert!(
            chain.contains("\"category\":\"host\""),
            "host category must be recorded, got: {chain}"
        );
        assert!(
            !chain.contains("workload_audit"),
            "host entry must not be reclassified as workload_audit"
        );
    }

    #[test]
    fn append_defaults_empty_category_to_workload_audit() {
        // An older caller that leaves the category unset still lands on the
        // workload default (backward-safe fallback).
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        helper.dispatch(register_req(dir.path(), "vm-e", "local"));

        let resp = helper.dispatch(append_req_with_category("vm-e", "a1", ""));
        assert!(
            matches!(resp, SignerHelperResponse::Ok { .. }),
            "got {resp:?}"
        );

        let chain = chain_lines(dir.path(), "vm-e");
        assert!(
            chain.contains("\"category\":\"workload_audit\""),
            "empty category must default to workload_audit, got: {chain}"
        );
    }

    #[test]
    fn append_rejects_category_outside_allow_list() {
        // A category not in the allow-list fails closed rather than seeding the
        // chain with something downstream tooling won't recognise.
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        helper.dispatch(register_req(dir.path(), "vm-x", "local"));

        let resp = helper.dispatch(append_req_with_category("vm-x", "a1", "totally-bogus"));
        assert!(
            matches!(
                resp,
                SignerHelperResponse::Err {
                    code: AuditSignerErrorCode::InvalidRequest,
                    ..
                }
            ),
            "unlisted category must be refused, got {resp:?}"
        );
    }

    #[test]
    fn register_opens_per_vm_chain_and_deregister_closes_it() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));

        let registered = helper.dispatch(register_req(dir.path(), "vm-1", "local"));
        match registered {
            SignerHelperResponse::Registered {
                vm_id, chain_head, ..
            } => {
                assert_eq!(vm_id, "vm-1");
                assert_eq!(Some(chain_head.as_str()), helper.chain_head("vm-1"));
            }
            other => panic!("expected Registered, got {other:?}"),
        }
        assert_eq!(helper.registration_count(), 1);

        let deregistered = helper.dispatch(SignerHelperRequest::DeregisterVm(
            SignerHelperDeregisterVm {
                request_id: "dereg-1".into(),
                vm_id: "vm-1".into(),
            },
        ));
        assert!(matches!(
            deregistered,
            SignerHelperResponse::Deregistered { .. }
        ));
        assert_eq!(helper.registration_count(), 0);

        let append_after_drop = helper.dispatch(append_req("vm-1", "append-after-drop"));
        assert!(matches!(
            append_after_drop,
            SignerHelperResponse::Err {
                code: AuditSignerErrorCode::NotReady,
                ..
            }
        ));
    }

    #[test]
    fn append_routes_to_the_selected_vm_chain() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        helper.dispatch(register_req(dir.path(), "vm-a", "local"));
        helper.dispatch(register_req(dir.path(), "vm-b", "local"));

        let a_head = match helper.dispatch(append_req("vm-a", "append-a")) {
            SignerHelperResponse::Ok { chain_head, .. } => chain_head,
            other => panic!("expected vm-a append Ok, got {other:?}"),
        };
        let b_head = match helper.dispatch(append_req("vm-b", "append-b")) {
            SignerHelperResponse::Ok { chain_head, .. } => chain_head,
            other => panic!("expected vm-b append Ok, got {other:?}"),
        };

        assert_eq!(Some(a_head.as_str()), helper.chain_head("vm-a"));
        assert_eq!(Some(b_head.as_str()), helper.chain_head("vm-b"));
        assert_ne!(a_head, b_head);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("local.vm-a.workload.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("local.vm-b.workload.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    #[test]
    fn register_rejects_cross_tenant_and_unsafe_vm_id() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));

        let cross_tenant = helper.dispatch(register_req(dir.path(), "vm-1", "other"));
        assert!(matches!(
            cross_tenant,
            SignerHelperResponse::Err {
                code: AuditSignerErrorCode::InvalidRequest,
                ..
            }
        ));

        let unsafe_id = helper.dispatch(register_req(dir.path(), "../escape", "local"));
        assert!(matches!(
            unsafe_id,
            SignerHelperResponse::Err {
                code: AuditSignerErrorCode::InvalidRequest,
                ..
            }
        ));
        assert_eq!(helper.registration_count(), 0);
    }

    #[test]
    fn append_rejects_workload_mismatch_for_registered_vm() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        helper.dispatch(register_req(dir.path(), "vm-a", "local"));

        let mut req = append_req("vm-a", "append-a");
        let SignerHelperRequest::AppendEntry(append) = &mut req else {
            panic!("expected append request");
        };
        append.workload_id = "wl-other".into();

        assert!(matches!(
            helper.dispatch(req),
            SignerHelperResponse::Err {
                code: AuditSignerErrorCode::InvalidRequest,
                ..
            }
        ));
    }

    #[test]
    fn sign_host_signs_plan_bytes_with_helper_key() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let plan_bytes = mvm_core::plan::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[23; 32]),
            "plan-fixture",
        )
        .0
        .payload;

        let before = Keystore::test_signing_calls();
        let response = helper.dispatch(SignerHelperRequest::SignHost(SignerHelperSignHost {
            request_id: "sign-1".into(),
            request: SignRequest::SignPlan {
                bytes: plan_bytes.clone(),
                request_id: "sign-1".into(),
            },
        }));
        assert_eq!(Keystore::test_signing_calls(), before + 1);

        match response {
            SignerHelperResponse::HostSigned {
                request_id,
                response:
                    SignResponse::Ok {
                        signer_pubkey,
                        signature,
                        ..
                    },
            } => {
                assert_eq!(request_id, "sign-1");
                let pk_arr: [u8; 32] = signer_pubkey.try_into().unwrap();
                let vk = VerifyingKey::from_bytes(&pk_arr).unwrap();
                let sig_arr: [u8; 64] = signature.try_into().unwrap();
                let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                vk.verify(&plan_bytes, &sig).expect("signature must verify");
            }
            other => panic!("expected host sign response, got {other:?}"),
        }
    }

    #[test]
    fn sign_host_without_key_path_returns_typed_error() {
        let mut helper = SignerHelper::new("local", None);
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let plan_bytes = mvm_core::plan::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[23; 32]),
            "plan-fixture",
        )
        .0
        .payload;

        let response = helper.dispatch(SignerHelperRequest::SignHost(SignerHelperSignHost {
            request_id: "sign-missing".into(),
            request: SignRequest::SignPlan {
                bytes: plan_bytes,
                request_id: "sign-missing".into(),
            },
        }));

        match response {
            SignerHelperResponse::HostSigned {
                response: SignResponse::Err { code, .. },
                ..
            } => assert_eq!(code, HostSignerErrorCode::KeyUnavailable),
            other => panic!("expected host sign error response, got {other:?}"),
        }
    }

    #[test]
    fn sign_plan_payload_rejects_cross_purpose_bytes_in_real_helper() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        let before = Keystore::test_signing_calls();
        let response = helper.dispatch(SignerHelperRequest::SignHost(SignerHelperSignHost {
            request_id: "invalid-plan-fixture".into(),
            request: SignRequest::SignPlan {
                bytes: b"mvm.prebirth.grant.v1\0{}".to_vec(),
                request_id: "invalid-plan-fixture".into(),
            },
        }));
        assert_eq!(
            Keystore::test_signing_calls(),
            before,
            "helper refusal must precede the signing primitive"
        );
        match response {
            SignerHelperResponse::HostSigned {
                request_id,
                response:
                    SignResponse::Err {
                        request_id: inner_id,
                        code,
                        message,
                    },
            } => {
                assert_eq!(request_id, "invalid-plan-fixture");
                assert_eq!(inner_id, "invalid-plan-fixture");
                assert_eq!(code, HostSignerErrorCode::InvalidRequest);
                assert_eq!(message, "invalid execution plan payload");
            }
            other => panic!("expected static invalid-plan refusal, got {other:?}"),
        }
    }
}
