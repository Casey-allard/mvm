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
use mvm_hostd::mailbox_process::installed_profile::MailboxPair;
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
    peers: InstallationPeers,
    boot: Mutex<Option<[u8; 32]>>,
}

enum InstallationPeers {
    Single(Arc<InstalledMailboxPeer>),
    Pair {
        names: MailboxPair,
        peers: [Arc<InstalledMailboxPeer>; 2],
    },
}

impl InstallationPeers {
    fn select(&self, vm: &str) -> Result<Arc<InstalledMailboxPeer>> {
        match self {
            Self::Single(peer) => Ok(peer.clone()),
            Self::Pair { names, peers } => Ok(peers[names.index(vm)?].clone()),
        }
    }
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
        let peer = Arc::new(InstalledMailboxPeer::from_original(original.clone())?);
        Self::with_peers(home, original, InstallationPeers::Single(peer))
    }

    /// Pin two independent acquisition issuers and original-cleanup lanes to
    /// the same daemon Child. The daemon must carry the identical name allowlist.
    pub fn from_original_worker_pair(
        home: &Path,
        original: Arc<Mutex<Child>>,
        names: [&str; 2],
    ) -> Result<Self> {
        let names = MailboxPair::new(names)?;
        let first = Arc::new(InstalledMailboxPeer::from_original(original.clone())?);
        let second = Arc::new(InstalledMailboxPeer::from_original(original.clone())?);
        Self::with_peers(
            home,
            original,
            InstallationPeers::Pair {
                names,
                peers: [first, second],
            },
        )
    }

    fn with_peers(
        home: &Path,
        original: Arc<Mutex<Child>>,
        peers: InstallationPeers,
    ) -> Result<Self> {
        let value = Self {
            home: open_home(home)?,
            peers,
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
        self.peers.select(&request.vm_id)
    }

    fn provision(
        &self,
        plan: &AdmittedPlan,
        backend: &AnyBackend,
        request: &MailboxWorkerRequest,
    ) -> Result<Arc<InstalledMailboxPeer>> {
        let mut client = self.admitted_client(plan, backend, request)?;
        let peer = self.peers.select(&request.vm_id)?;
        client.bind_peer(peer.clone())?;
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
        Ok(peer)
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
        let peer = self.peers.select(&request.vm_id)?;
        ensure!(
            client.acquire_request().tenant == "local" && peer.issued_nonce(&request.request_nonce),
            "locator belongs to another installed mailbox worker"
        );
        client.bind_peer(peer.clone())?;
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
        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn paired_installed_sdk_selects_stable_distinct_original_lanes() -> Result<()> {
        let mut child = Command::new("sleep").arg("20").spawn()?;
        let result = (|| -> Result<()> {
            let a = Arc::new(InstalledMailboxPeer::from_child(&mut child)?);
            let b = Arc::new(InstalledMailboxPeer::from_child(&mut child)?);
            let peers = InstallationPeers::Pair {
                names: MailboxPair::new(["alpha", "beta"])?,
                peers: [a.clone(), b.clone()],
            };
            assert!(Arc::ptr_eq(&peers.select("alpha")?, &a));
            assert!(Arc::ptr_eq(&peers.select("beta")?, &b));
            assert!(!Arc::ptr_eq(&a, &b));
            assert!(peers.select("other").is_err());
            Ok(())
        })();
        let _ = child.kill();
        child.wait()?;
        result
    }
}
