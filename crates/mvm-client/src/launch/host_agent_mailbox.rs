//! Opt-in local mailbox provisioning on the installed host-agent worker.
//! The installation manager supplies the Child it started in worker mode with
//! `--owned-mailbox-v1`. It must retain this controller through VM cleanup.
use super::mailbox_owner::InstalledMailboxProvisioner;
use anyhow::{Result, ensure};
use mvm_core::protocol::{
    broker_control::{ControlRequest, SignedControl},
    mailbox_worker_control::{
        MAX_WORKER_OPERATION_MS, MailboxWorkerOperation, MailboxWorkerRequest,
    },
};
use mvm_hostd::{
    mailbox_process::owned_client::{InstalledMailboxClient, InstalledMailboxPeer},
    plan_admission::AdmittedPlan,
};
use mvm_runtime::AnyBackend;
use std::{
    fs::File,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Child,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// One original installed local worker. The kernel exit observer and the
/// connected control socket's peer credentials must match on every exchange.
pub struct HostAgentMailboxProvisioner {
    home: File,
    original: Arc<Mutex<Child>>,
    peer: Arc<InstalledMailboxPeer>,
    boot: Mutex<Option<[u8; 32]>>,
}

fn open_home(home: &Path) -> Result<File> {
    let dir = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(home)?;
    let meta = dir.metadata()?;
    mvm_core::private_fs::require_current_owner(&meta)?;
    ensure!(
        meta.is_dir() && meta.mode() & 0o022 == 0,
        "unsafe installed mailbox home"
    );
    Ok(dir)
}

impl HostAgentMailboxProvisioner {
    /// Use the original worker which owns the tenant control listener. A
    /// supervisor Child that launched a separate worker cannot authenticate.
    pub fn from_original_worker(home: &Path, original: Arc<Mutex<Child>>) -> Result<Self> {
        let value = Self {
            home: open_home(home)?,
            peer: Arc::new(InstalledMailboxPeer::from_original(original.clone())?),
            original,
            boot: Mutex::new(None),
        };
        value.check_installation()?;
        Ok(value)
    }

    fn check_installation(&self) -> Result<()> {
        let current = open_home(&mvm_core::config::mvm_home_strict()?)?.metadata()?;
        let original = self.home.metadata()?;
        ensure!(
            (original.dev(), original.ino()) == (current.dev(), current.ino()),
            "mailbox installation changed"
        );
        let mut child = self
            .original
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original mailbox worker unavailable"))?;
        ensure!(
            child.try_wait()?.is_none(),
            "original mailbox worker exited"
        );
        Ok(())
    }

    fn admitted_client(
        &self,
        plan: &AdmittedPlan,
        backend: &AnyBackend,
        request: &MailboxWorkerRequest,
    ) -> Result<InstalledMailboxClient> {
        self.check_installation()?;
        ensure!(
            request.tenant == "local",
            "installed mailbox requires local SDK admission"
        );
        let client = InstalledMailboxClient::reconnect(
            plan,
            backend,
            &request.vm_id,
            request.request_nonce,
            None,
        )?;
        ensure!(
            client.acquire_request() == request,
            "mailbox reservation differs from admission"
        );
        Ok(client)
    }
}

impl InstalledMailboxProvisioner for HostAgentMailboxProvisioner {
    fn original_peer(
        &self,
        plan: &AdmittedPlan,
        backend: &AnyBackend,
        request: &MailboxWorkerRequest,
    ) -> Result<Arc<InstalledMailboxPeer>> {
        self.admitted_client(plan, backend, request)?;
        Ok(self.peer.clone())
    }

    fn provision(
        &self,
        plan: &AdmittedPlan,
        backend: &AnyBackend,
        request: &MailboxWorkerRequest,
    ) -> Result<Arc<InstalledMailboxPeer>> {
        let mut client = self.admitted_client(plan, backend, request)?;
        client.bind_peer(self.peer.clone())?;
        let owner = client.provision_admitted_slot(
            Instant::now() + Duration::from_millis(MAX_WORKER_OPERATION_MS),
        )?;
        let mut boot = self
            .boot
            .lock()
            .map_err(|_| anyhow::anyhow!("mailbox installation unavailable"))?;
        ensure!(
            *boot.get_or_insert(owner.daemon_boot_nonce) == owner.daemon_boot_nonce,
            "mailbox daemon generation changed"
        );
        Ok(self.peer.clone())
    }

    fn resolve_original(&self, signed: &SignedControl) -> Result<Arc<InstalledMailboxPeer>> {
        self.check_installation()?;
        let ControlRequest::MailboxWorkerV1(request) = &signed.request else {
            anyhow::bail!("expected original mailbox locator");
        };
        let mut client = match request.operation {
            MailboxWorkerOperation::Acquire => {
                InstalledMailboxClient::from_pending_locator(&request.vm_id, signed)?
            }
            MailboxWorkerOperation::Stop { .. } => {
                InstalledMailboxClient::from_stop_locator(&request.vm_id, signed)?
            }
            _ => anyhow::bail!("expected stored mailbox acquisition or stop"),
        };
        ensure!(
            client.acquire_request().tenant == "local"
                && self.peer.issued_nonce(&request.request_nonce),
            "locator belongs to another installed mailbox worker"
        );
        client.bind_peer(self.peer.clone())?;
        if let Some(owner) = client.owner() {
            let boot = self
                .boot
                .lock()
                .map_err(|_| anyhow::anyhow!("mailbox installation unavailable"))?;
            // A lost Provision reply can leave this unset. The signed original
            // issuer and the live original Child still authenticate recovery.
            ensure!(
                boot.is_none_or(|saved| saved == owner.daemon_boot_nonce),
                "mailbox locator belongs to another daemon generation"
            );
        }
        Ok(self.peer.clone())
    }
}
