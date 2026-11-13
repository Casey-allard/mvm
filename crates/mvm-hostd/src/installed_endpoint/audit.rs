//! Canonical Recorder -> original installed signer, without a key-file fallback.
use super::*;
use crate::{
    audit_signer::{category, helper_client::SignerHelperClient},
    owned_resources::{
        FRAME_BYTES, WORKSPACE_BYTES, WorkspacePermit, WorkspacePool, encoded_len, validate_value,
    },
    supervisor::{
        audit::{AuditError, AuditSigner, PlanAuditEntry},
        audit_recorder::{LABEL_VM_NAME, Recorder},
    },
};
use async_trait::async_trait;
use mvm_core::{
    plan::TenantId,
    protocol::audit_signer::{SignerHelperAppendEntry, SignerHelperRequest, SignerHelperResponse},
};
use mvm_vmm::host::network_endpoint_spawn::InstalledEndpointAudit;
use std::{sync::atomic::AtomicU64, time::Duration};

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;

const ENTRY_BYTES: usize = 16 * 1024;
const LABELS: usize = 32;

impl InstalledEndpointResources {
    /// Build only from the original child resources and original process
    /// observations. No public path/PID or quota projection is a substitute.
    pub fn build_owned_audit_recorder(&self) -> io::Result<Recorder> {
        let audit = self.lease.audit().map_err(invalid)?;
        let InstalledEndpointProgram::Network(config) = &self.program else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "collector has no network audit recorder",
            ));
        };
        if audit.vm() != config.instance_id || audit.tenant() != config.tenant_id {
            return Err(invalid("original audit config identity differs"));
        }
        // SAME parent auxiliary ledger, before every owned constructor/copy.
        let permit = self.claim_component(Component::Audit, 0, WORKSPACE_BYTES)?;
        let workspaces = WorkspacePool::new(1).map_err(invalid)?;
        let tenant = TenantId(audit.tenant().to_owned());
        let vm = audit.vm().to_owned();
        let session = hex::encode(audit.session());
        let signer = Arc::new(InstalledSigner {
            audit,
            workspaces,
            permit,
            session,
            next: AtomicU64::new(0),
        });
        let origin = InstalledAuditOrigin {
            signer: signer.clone(),
            lease: self.lease.clone(),
        };
        Ok(Recorder::new(signer, tenant)
            .with_vm_name(&vm)
            .with_installed_origin(origin))
    }
}

/// Private provenance for the actual concrete signer, not copied metadata.
/// Only the original Resources factory above can construct this value.
#[derive(Clone)]
pub(crate) struct InstalledAuditOrigin {
    signer: Arc<InstalledSigner>,
    lease: InstalledEndpointLease,
}
impl InstalledAuditOrigin {
    pub(crate) fn matches(&self, audit: &InstalledEndpointAudit) -> bool {
        audit.same_endpoint(&self.lease)
    }
    pub(crate) fn same_signer(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.signer, &other.signer)
    }
    pub(crate) fn acquire(&self) -> std::result::Result<WorkspacePermit, AuditError> {
        let result = (|| {
            self.signer.permit.check_current()?;
            self.signer.audit.check_current()?;
            self.signer.workspaces.try_acquire()
        })();
        result.map_err(|_| self.fenced_error())
    }
    pub(crate) fn preflight(&self, entry: &PlanAuditEntry) -> std::result::Result<(), AuditError> {
        let result = (|| {
            self.signer.permit.check_current()?;
            self.signer.audit.check_current()?;
            // Maximum serial width covers the later actual request without
            // consuming a serial or sending any audit record before connect.
            project_entry(
                entry,
                self.signer.audit.vm(),
                self.signer.audit.tenant(),
                &self.signer.session,
                u64::MAX,
            )?;
            Ok(())
        })();
        result.map_err(|_: anyhow::Error| self.fenced_error())
    }
    pub(crate) fn emit_held(
        &self,
        entry: &PlanAuditEntry,
        _workspace: &WorkspacePermit,
        deadline: Instant,
    ) -> std::result::Result<(), AuditError> {
        self.signer
            .append_held(entry, Some(deadline))
            .map_err(|_| self.fenced_error())
    }
    fn fenced_error(&self) -> AuditError {
        // Preserve an actual signing/projection failure independently of a
        // later normal parent stop; cancellation cannot erase this cause.
        self.signer.permit.fence();
        AuditError::Io("installed audit admission fenced".into())
    }
}

struct InstalledSigner {
    audit: InstalledEndpointAudit,
    workspaces: WorkspacePool,
    permit: InstalledEndpointComponentPermit,
    session: String,
    next: AtomicU64,
}
impl InstalledSigner {
    fn append(&self, entry: &PlanAuditEntry) -> Result<()> {
        let _workspace = self.workspaces.try_acquire()?;
        self.append_held(entry, None)
    }
    fn append_held(&self, entry: &PlanAuditEntry, original: Option<Instant>) -> Result<()> {
        let cap = Instant::now()
            .checked_add(Duration::from_secs(5))
            .context("audit deadline overflow")?;
        let deadline = crate::broker::registry::owned_call_deadline()
            .map_or(cap, |original| cap.min(original));
        let deadline = original.map_or(deadline, |original| deadline.min(original));
        self.permit.check_current()?;
        self.audit.check_current()?;
        ensure!(Instant::now() < deadline, "installed audit deadline");
        let serial = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("audit serial exhausted"))?;
        let request = project_entry(
            entry,
            self.audit.vm(),
            self.audit.tenant(),
            &self.session,
            serial,
        )?;
        self.permit.check_current()?;
        let response = SignerHelperClient::new(self.audit.socket())
            .with_original_child(self.audit.signer_pid())
            .send_until_endpoint(&request, deadline, &self.audit)?;
        let SignerHelperResponse::Ok {
            chain_head,
            entry_hash,
            sig_alg,
            ..
        } = response
        else {
            anyhow::bail!("original audit append refused")
        };
        ensure!(
            chain_head.len() == 64
                && chain_head.bytes().all(|byte| byte.is_ascii_hexdigit())
                && chain_head == entry_hash
                && sig_alg == mvm_core::security::SIG_ALG_ED25519,
            "original audit append result differs"
        );
        self.permit.check_current()?;
        self.audit.check_current()?;
        ensure!(Instant::now() < deadline, "audit deadline elapsed");
        Ok(())
    }
}

/// Pure canonical serialization only. These borrowed attribution values are
/// not authority; append calls it only after the actual guards/workspace.
fn project_entry(
    entry: &PlanAuditEntry,
    vm: &str,
    tenant: &str,
    session: &str,
    serial: u64,
) -> Result<SignerHelperRequest> {
    ensure!(
        !vm.is_empty()
            && vm.len() <= 64
            && !tenant.is_empty()
            && tenant.len() <= 128
            && !session.is_empty()
            && session.len() <= 64,
        "audit projection identity bound"
    );
    ensure!(entry.labels.len() <= LABELS, "installed audit label bound");
    encoded_len(entry, ENTRY_BYTES)?;
    let category = entry
        .labels
        .get("category")
        .context("canonical audit category absent")?;
    ensure!(
        category::is_allowed(category)
            && entry
                .event
                .strip_prefix(category)
                .is_some_and(|suffix| suffix.starts_with('.'))
            && entry
                .labels
                .get(LABEL_VM_NAME)
                .is_some_and(|value| value == vm)
            && entry.tenant.0 == tenant,
        "canonical audit attribution differs"
    );
    // Exact canonical Serialize, with every original field retained.
    let fields = serde_json::to_value(entry)?;
    validate_value(&fields)?;
    let request_id = format!("endpoint-{serial}");
    let request = SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
        request_id: request_id.clone(),
        vm_id: vm.to_owned(),
        category: category.clone(),
        ts: entry.timestamp.to_rfc3339(),
        workload_id: vm.to_owned(),
        tenant_id: tenant.to_owned(),
        session_id: session.to_owned(),
        correlation_id: request_id,
        fields,
    });
    encoded_len(&request, FRAME_BYTES)?;
    Ok(request)
}
#[async_trait]
impl AuditSigner for InstalledSigner {
    async fn sign_and_emit(&self, entry: &PlanAuditEntry) -> std::result::Result<(), AuditError> {
        if self.append(entry).is_err() {
            self.audit.fence();
            // The encoded entry and helper error can contain private fields.
            // Only this fixed payload-free error crosses the diagnostic seam.
            return Err(AuditError::Io("installed audit admission fenced".into()));
        }
        Ok(())
    }
}
