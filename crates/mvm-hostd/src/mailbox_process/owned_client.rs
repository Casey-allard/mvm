//! Launcher control of one mailbox under an existing verified MVM admission.
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use mvm_contract::protocol::mailbox::MAILBOX_PORT;
use mvm_core::protocol::{
    broker_control::{self, ControlRequest},
    mailbox_worker_control::*,
};
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::host::mailbox_worker_transport::{recv_response, send_request};
use mvm_vmm::host::process_exit::{ProcessExitObserver, ProcessExitWait};

use super::{build_config, write_delegated_config};
use crate::audit::host_keypair::{PUBLIC_FILENAME, SECRET_FILENAME};
use crate::plan_admission::AdmittedPlan;

mod native_start;
mod terminal_acceptance;

/// Kernel identity anchored while the installation controller holds its original Child.
pub struct InstalledMailboxPeer {
    observer: Mutex<Option<ProcessExitObserver>>,
    pid: u32,
    issuer: [u8; 16],
    admitted_vm: Option<String>,
    native_start: native_start::NativeStartCustody,
    terminal_acceptance: terminal_acceptance::TerminalAcceptance,
}

impl InstalledMailboxPeer {
    pub fn from_original(original: Arc<Mutex<Child>>) -> Result<Self> {
        let mut child = original
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original daemon unavailable"))?;
        Self::from_child(&mut child)
    }

    /// Pin an issuer to one VM lane even if its trusted Arc is passed to
    /// another client. Signed plan and peer credential checks still apply.
    pub fn from_original_for_vm(original: Arc<Mutex<Child>>, vm: &str) -> Result<Self> {
        mvm_core::naming::validate_vm_name(vm)?;
        let mut peer = Self::from_original(original)?;
        peer.admitted_vm = Some(vm.to_owned());
        Ok(peer)
    }

    fn require_vm(&self, vm: &str) -> Result<()> {
        ensure!(self.admitted_vm.as_deref().is_none_or(|named| named == vm),
                "VM differs from original mailbox issuer lane");
        Ok(())
    }

    pub fn from_child(child: &mut Child) -> Result<Self> {
        mvm_vmm::host::process_exit::require_owned_child_custody()?;
        ensure!(
            child.try_wait()?.is_none(),
            "original mailbox daemon already exited"
        );
        let pid = child.id();
        let observer = ProcessExitObserver::arm(i32::try_from(pid)?)?;
        ensure!(
            child.try_wait()?.is_none(),
            "original mailbox daemon exited during binding"
        );
        Ok(Self {
            observer: Mutex::new(Some(observer)),
            pid,
            issuer: rand::random(),
            admitted_vm: None,
            native_start: Default::default(),
            terminal_acceptance: Default::default(),
        })
    }

    /// Match the issuer embedded in this installation's host-signed locator.
    pub fn issued_nonce(&self, nonce: &[u8; 32]) -> bool {
        nonce[..16] == self.issuer
    }

    fn authenticate(&self, stream: &UnixStream) -> Result<()> {
        let peer = u32::try_from(mvm_vmm::host::uds_peer::connected_peer_pid(stream)?)?;
        ensure!(
            peer == self.pid,
            "mailbox control socket differs from original daemon"
        );
        self.check_original_alive()
    }

    fn check_original_alive(&self) -> Result<()> {
        let mut original = self
            .observer
            .lock()
            .map_err(|_| anyhow::anyhow!("original daemon unavailable"))?;
        // On Darwin the queued exit event is consumed once; permanently disarm
        // on an exit or observer error. A new process reusing this PID cannot pass.
        match original
            .as_ref()
            .context("original mailbox daemon exited")?
            .wait_event(Instant::now())
        {
            Ok(ProcessExitWait::TimedOut) => Ok(()),
            other => {
                *original = None;
                other?;
                bail!("original mailbox daemon exited");
            }
        }
    }
}

impl mvm_core::vm_backend::InstalledBrokerPeer for InstalledMailboxPeer {
    fn authenticate(&self, stream: &UnixStream) -> Result<()> {
        InstalledMailboxPeer::authenticate(self, stream)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Authority {
    Fresh,
    Admitted,
    PendingLookup,
    Stop,
}

/// A prepared original acquisition. Retain its nonce through uncertain replies;
/// the daemon rejects a second acquisition for the same VM under another nonce.
pub struct InstalledMailboxClient {
    acquire: MailboxWorkerRequest,
    owner: Option<MailboxWorkerOwner>,
    authority: Authority,
    peer: Option<Arc<InstalledMailboxPeer>>,
}

fn worker_deadline() -> Instant {
    Instant::now() + Duration::from_millis(MAX_WORKER_OPERATION_MS)
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn host_key() -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey)> {
    let keys = mvm_core::config::mvm_keys_dir();
    mvm_core::crypto::ed25519_keypair::load_existing(
        &keys.join(SECRET_FILENAME),
        &keys.join(PUBLIC_FILENAME),
    )
}

fn kind(backend: &AnyBackend) -> Result<MailboxWorkerBackend> {
    use mvm_runtime::catalog::BackendKind;
    match backend.kind() {
        BackendKind::Firecracker => Ok(MailboxWorkerBackend::Firecracker),
        BackendKind::Hvf => Ok(MailboxWorkerBackend::Hvf),
        _ => bail!("backend has no installed mailbox worker binding"),
    }
}

impl InstalledMailboxClient {
    pub fn prepare(admitted: &AdmittedPlan, backend: &AnyBackend, vm_name: &str) -> Result<Self> {
        let mut client = Self::with_nonce(admitted, backend, vm_name, rand::random())?;
        client.authority = Authority::Fresh;
        Ok(client)
    }

    fn with_nonce(
        admitted: &AdmittedPlan,
        backend: &AnyBackend,
        vm_name: &str,
        nonce: [u8; 32],
    ) -> Result<Self> {
        mvm_core::naming::validate_vm_name(vm_name)?;
        let plan = admitted.plan();
        ensure!(
            plan.workload.0 == vm_name,
            "mailbox VM differs from admitted workload"
        );
        let grant = plan
            .mailbox
            .context("admitted plan requires a mailbox grant")?;
        grant.require_implemented_local_service()?;
        let mut commitment = [0u8; 32];
        let digest = admitted
            .plan_id()
            .0
            .strip_prefix("sha256:")
            .context("invalid admitted plan id")?;
        hex::decode_to_slice(digest, &mut commitment)?;
        ensure!(
            nonce != [0; 32],
            "invalid original mailbox acquisition nonce"
        );
        let acquire = MailboxWorkerRequest {
            domain: MAILBOX_WORKER_DOMAIN.to_owned(),
            version: 1,
            request_nonce: nonce,
            tenant: plan.tenant.0.clone(),
            vm_id: vm_name.to_owned(),
            workload_id: plan.workload.0.clone(),
            plan_commitment: commitment,
            mailbox_grant: grant,
            admission_expires_at_unix_ms: plan.valid_until.timestamp_millis().try_into()?,
            deadline_unix_ms: 0,
            backend: kind(backend)?,
            operation: MailboxWorkerOperation::Acquire,
        };
        Ok(Self {
            acquire,
            owner: None,
            authority: Authority::Admitted,
            peer: None,
        })
    }

    /// Re-open the original reservation under the same verified plan and
    /// original nonce. With a recorded owner, Query/Stop can proceed directly.
    pub fn reconnect(
        admitted: &AdmittedPlan,
        backend: &AnyBackend,
        vm_name: &str,
        original_nonce: [u8; 32],
        original_owner: Option<MailboxWorkerOwner>,
    ) -> Result<Self> {
        let mut client = Self::with_nonce(admitted, backend, vm_name, original_nonce)?;
        if let Some(owner) = original_owner {
            let proof = MailboxWorkerResult {
                owner: owner.clone(),
                request_nonce: original_nonce,
                state: MailboxWorkerState::Reserved,
                delegates_config: false,
            };
            verify_result(&client.acquire, &proof)
                .context("stored mailbox owner differs from admission")?;
            client.owner = Some(owner);
        }
        Ok(client)
    }

    /// Bind the original process identity before persisting an initial reservation.
    /// Half the nonce uniquely identifies this original issuer; half is random
    /// for this transfer. Both halves remain covered by the host signature.
    pub fn bind_acquire_peer(&mut self, peer: Arc<InstalledMailboxPeer>) -> Result<()> {
        ensure!(
            self.authority == Authority::Fresh && self.peer.is_none(),
            "initial acquisition already bound"
        );
        peer.require_vm(&self.acquire.vm_id)?;
        peer.terminal_acceptance.while_vacant(|| Ok(()))?;
        self.acquire.request_nonce[..16].copy_from_slice(&peer.issuer);
        self.authority = Authority::Admitted;
        self.bind_peer(peer)
    }

    pub fn signed_pending_locator(&self) -> Result<broker_control::SignedControl> {
        ensure!(
            self.authority == Authority::Admitted && self.peer.is_some() && self.owner.is_none(),
            "pending locator requires the original bound acquisition"
        );
        let (secret, _) = host_key()?;
        Ok(broker_control::sign(
            ControlRequest::MailboxWorkerV1(Box::new(self.acquire.clone())),
            secret.as_bytes(),
        )?)
    }

    pub fn from_pending_locator(
        vm_name: &str,
        signed: &broker_control::SignedControl,
    ) -> Result<Self> {
        let (_, public) = host_key()?;
        let request = verify_pending_locator(signed, &public, vm_name)?;
        Ok(Self {
            acquire: request.clone(),
            owner: None,
            authority: Authority::PendingLookup,
            peer: None,
        })
    }

    /// Lookup on a Pending locator must never reserve, publish or spawn.
    pub fn recover_owner(&mut self, deadline: Instant) -> Result<&MailboxWorkerOwner> {
        ensure!(
            self.authority == Authority::PendingLookup,
            "signed pending reservation required"
        );
        if self.owner.is_none() {
            let (receipt, writer) =
                self.call(MailboxWorkerOperation::LookupExistingV1, deadline)?;
            ensure!(writer.is_none(), "lookup returned a delegated descriptor");
            self.owner = Some(receipt.owner);
        }
        self.owner.as_ref().context("original reservation missing")
    }

    pub fn signed_stop_locator(&self) -> Result<broker_control::SignedControl> {
        let mut stop = self.acquire.clone();
        stop.operation = MailboxWorkerOperation::Stop {
            owner: self.original()?,
        };
        // Zero cannot be a valid live deadline. The saved acquisition nonce
        // permits the original retry to be identified after reopening.
        stop.deadline_unix_ms = 0;
        let (secret, _) = host_key()?;
        Ok(broker_control::sign(
            ControlRequest::MailboxWorkerV1(Box::new(stop)),
            secret.as_bytes(),
        )?)
    }

    pub fn from_stop_locator(
        vm_name: &str,
        signed: &broker_control::SignedControl,
    ) -> Result<Self> {
        let (_, public) = host_key()?;
        let request = verify_stop_locator(signed, &public, vm_name)?;
        ensure!(
            request.deadline_unix_ms == 0,
            "expected a stored mailbox locator"
        );
        let MailboxWorkerOperation::Stop { owner } = &request.operation else {
            bail!("expected original mailbox Stop locator");
        };
        let mut acquire = request.clone();
        acquire.operation = MailboxWorkerOperation::Acquire;
        Ok(Self {
            acquire,
            owner: Some(owner.clone()),
            authority: Authority::Stop,
            peer: None,
        })
    }

    /// Bind once, using the installed controller that owns the original daemon.
    pub fn bind_peer(&mut self, peer: Arc<InstalledMailboxPeer>) -> Result<()> {
        peer.require_vm(&self.acquire.vm_id)?;
        ensure!(
            self.authority != Authority::Fresh,
            "initial acquisition must bind its issuer"
        );
        if self.authority != Authority::Stop {
            ensure!(
                self.acquire.request_nonce[..16] == peer.issuer,
                "original mailbox issuer differs"
            );
        }
        if let Some(original) = &self.peer {
            ensure!(
                Arc::ptr_eq(original, &peer),
                "cannot replace installed daemon binding"
            );
        } else {
            self.peer = Some(peer);
        }
        Ok(())
    }

    pub fn acquire_request(&self) -> &MailboxWorkerRequest {
        &self.acquire
    }
    pub fn owner(&self) -> Option<&MailboxWorkerOwner> {
        self.owner.as_ref()
    }

    /// Set the operation's original deadline before connecting. A retry of
    /// Acquire retains its nonce. Each later signed operation has a fresh one.
    fn call(
        &self,
        operation: MailboxWorkerOperation,
        until: Instant,
    ) -> Result<(MailboxWorkerResult, Option<OwnedFd>)> {
        let deadline = until.min(Instant::now() + Duration::from_millis(MAX_WORKER_OPERATION_MS));
        let mut request = self.acquire.clone();
        let now = now_ms()?;
        let left = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )?;
        ensure!(left > 0, "mailbox operation deadline elapsed");
        request.deadline_unix_ms = now.checked_add(left).context("mailbox deadline overflow")?;
        if !matches!(
            operation,
            MailboxWorkerOperation::Acquire
                | MailboxWorkerOperation::ProvisionAdmittedV1 { .. }
                | MailboxWorkerOperation::LookupExistingV1
        ) {
            request.request_nonce = rand::random();
        }
        request.operation = operation;
        let (secret, public) = host_key()?;
        let signed = broker_control::sign(
            ControlRequest::MailboxWorkerV1(Box::new(request.clone())),
            secret.as_bytes(),
        )?;
        verify_request(&signed, &public, now_ms()?)?;
        let mut stream = self.connect_original(deadline)?;
        send_request(&stream, &signed, deadline)?;
        Ok(recv_response(&mut stream, &request, deadline)?)
    }

    fn connect_original(&self, deadline: Instant) -> Result<UnixStream> {
        let peer = self
            .peer
            .as_ref()
            .context("installed mailbox daemon binding required")?;
        let stream = mvm_agentd::vsock::connect_unix_before(
            &mvm_core::config::host_agent_control_socket(&self.acquire.tenant),
            deadline,
        )?;
        peer.authenticate(&stream)?;
        Ok(stream)
    }

    /// Confirm removal of separately registered companion services under
    /// the same original owner before removing persistent machine state.
    pub fn remove_companion_services(&self, until: Instant) -> Result<()> {
        let deadline = until.min(Instant::now() + Duration::from_millis(MAX_WORKER_OPERATION_MS));
        let request = broker_control::DeregisterVm {
            vm_id: self.acquire.vm_id.clone(),
            mailbox_owner_v1: Some(self.original()?),
        };
        let (key, _) = host_key()?;
        let signed = broker_control::sign(ControlRequest::Deregister(request), key.as_bytes())?;
        let stream = self.connect_original(deadline)?;
        Ok(
            mvm_vmm::host::mailbox_worker_transport::deregister_companion(
                &stream, &signed, deadline,
            )?,
        )
    }

    /// Attest this original admitted context and reserve its acquisition nonce.
    pub fn provision_admitted_slot(&self, deadline: Instant) -> Result<MailboxWorkerOwner> {
        ensure!(
            self.authority == Authority::Admitted,
            "stop locator cannot provision a worker"
        );
        let gate = mvm_core::tenant_lifecycle::TenantLifecycleGate::new(
            mvm_core::config::mvm_home_strict()?,
            &self.acquire.tenant,
        )?;
        let resource_epoch = gate.active_resource_epoch(deadline)?;
        Ok(self
            .call(
                MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch },
                deadline,
            )?
            .0
            .owner)
    }
    pub fn acquire(&mut self, deadline: Instant) -> Result<&MailboxWorkerOwner> {
        ensure!(
            self.authority == Authority::Admitted,
            "stop locator cannot acquire a worker"
        );
        if self.owner.is_none() {
            let (receipt, _) = self.call(MailboxWorkerOperation::Acquire, deadline)?;
            self.owner = Some(receipt.owner);
        }
        self.owner.as_ref().context("missing mailbox owner")
    }

    /// Enter the native backend under the exact same owner as the durable
    /// mailbox locator. Capture the original typed error for stop/recovery.
    pub fn start_native<T>(&self, start: impl FnOnce() -> Result<T>) -> Result<T> {
        ensure!(self.authority == Authority::Admitted, "cleanup locator cannot start a VM");
        let peer = self.peer.as_ref().context("missing original mailbox peer")?;
        peer.terminal_acceptance.while_vacant(|| peer.native_start.run(&self.original()?, start))
    }

    /// Resolve any retained *native* start before allowing mailbox/VM cleanup.
    pub fn settle_native_start(&self) -> Result<()> {
        self.peer.as_ref().context("missing original mailbox peer")?
            .native_start.settle(&self.original()?)
    }

    /// Recover the same terminal helper and paired broker while the original
    /// installed controller survives. Retain one fixed-size acceptance token
    /// until the caller durably commits its local cleanup under the VM claim.
    pub fn finish_installed_cleanup(&self, retiring: bool, cleanup: impl FnOnce() -> Result<()>, acknowledge: impl FnOnce() -> Result<()>) -> Result<()> {
        let peer = self.peer.as_ref().context("missing original mailbox peer")?;
        ensure!(peer.issued_nonce(&self.acquire.request_nonce), "original cleanup issuer differs");
        peer.terminal_acceptance.finish(
            self.original()?, self.acquire.request_nonce, retiring,
            || {
                peer.check_original_alive()?;
                self.settle_native_start()
            },
            || {
                self.collect_worker_terminal(worker_deadline())?;
                self.remove_companion_services(worker_deadline())
            },
            cleanup,
            acknowledge,
        )
    }

    pub fn collect_original_worker(&self) -> Result<()> {
        self.settle_native_start()?;
        self.collect_worker_terminal(worker_deadline())
    }

    fn collect_worker_terminal(&self, until: Instant) -> Result<()> {
        match self.stop(until)? {
            MailboxWorkerState::Collected { .. } => Ok(()),
            MailboxWorkerState::Reserved | MailboxWorkerState::Unresolved => {
                ensure!(self.release_unstarted(until)? == MailboxWorkerState::ReleasedBeforeSpawn,
                    "original mailbox reservation release is unresolved");
                Ok(())
            }
            _ => bail!("original mailbox worker collection is unresolved"),
        }
    }

    fn original(&self) -> Result<MailboxWorkerOwner> {
        self.owner
            .clone()
            .context("mailbox worker has not been acquired")
    }
    pub fn query(&self, deadline: Instant) -> Result<MailboxWorkerState> {
        Ok(self
            .call(
                MailboxWorkerOperation::Query {
                    owner: self.original()?,
                },
                deadline,
            )?
            .0
            .state)
    }
    pub fn stop(&self, deadline: Instant) -> Result<MailboxWorkerState> {
        Ok(self
            .call(
                MailboxWorkerOperation::Stop {
                    owner: self.original()?,
                },
                deadline,
            )?
            .0
            .state)
    }

    /// Discard a reservation only if the original daemon certifies that it never spawned.
    pub fn release_unstarted(&self, deadline: Instant) -> Result<MailboxWorkerState> {
        Ok(self
            .call(
                MailboxWorkerOperation::ReleaseUnstartedV1 {
                    owner: self.original()?,
                },
                deadline,
            )?
            .0
            .state)
    }

    /// Only the original, once-delegated FD may receive configuration. A retry
    /// that finds the helper starting just queries its state, keeping all
    /// derived bytes and epoch state out of the host-agent control connection.
    pub fn configure_and_wait(&self, backend: &AnyBackend, deadline: Instant) -> Result<()> {
        ensure!(
            self.authority == Authority::Admitted,
            "stop locator cannot delegate configuration"
        );
        ensure!(
            kind(backend)? == self.acquire.backend,
            "backend differs from original acquisition"
        );
        let dir = mvm_core::config::vm_state_dir(&self.acquire.vm_id);
        let route = backend
            .host_dial_route(&dir, MAILBOX_PORT)
            .context("backend exposes no mailbox route")?;
        let (result, writer) = self.call(
            MailboxWorkerOperation::DelegateConfig {
                owner: self.original()?,
            },
            deadline,
        )?;
        if let Some(fd) = writer {
            let config = build_config(
                &mvm_core::config::mvm_keys_dir(),
                &self.acquire.mailbox_grant,
                &dir,
                route,
            )?;
            write_delegated_config(fd, &config, deadline)?;
        }
        let mut state = result.state;
        while state == MailboxWorkerState::Starting {
            let left = deadline
                .checked_duration_since(Instant::now())
                .context("mailbox readiness timed out")?;
            std::thread::sleep(left.min(Duration::from_millis(5)));
            state = self.query(deadline)?;
        }
        ensure!(
            state == MailboxWorkerState::Serving,
            "mailbox worker did not reach Serving"
        );
        Ok(())
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::{Command, Stdio};

    const CHILD_SOCKET: &str = "MVM_TEST_INSTALLED_ORIGINAL_PEER_SOCKET";

    #[test]
    fn original_peer_fixture() {
        let Some(path) = std::env::var_os(CHILD_SOCKET) else {
            return;
        };
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => panic!("fixture failed to accept: {e}"),
            }
        };
        // Darwin accepts children with the listener's nonblocking mode.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"1").unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [1]);
    }

    #[test]
    fn paired_installed_original_issuer_cannot_cross_vm_lanes() -> Result<()> {
        let child = Arc::new(Mutex::new(Command::new("sleep").arg("20").spawn()?));
        let check = (|| -> Result<()> {
            let first = InstalledMailboxPeer::from_original_for_vm(child.clone(), "alpha")?;
            let second = InstalledMailboxPeer::from_original_for_vm(child.clone(), "beta")?;
            first.require_vm("alpha")?;
            second.require_vm("beta")?;
            assert!(first.require_vm("beta").is_err());
            assert!(second.require_vm("alpha").is_err());
            let mut nonce = [4; 32];
            nonce[..16].copy_from_slice(&first.issuer);
            assert!(first.issued_nonce(&nonce));
            assert!(!second.issued_nonce(&nonce));
            Ok(())
        })();
        let mut original = child.lock().unwrap();
        let _ = original.kill();
        original.wait()?;
        check
    }

    fn connect_child(path: &Path) -> Result<UnixStream> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match UnixStream::connect(path) {
                Ok(stream) => return Ok(stream),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    #[test]
    fn daemon_socket_requires_original_live_child_after_path_replacement() -> Result<()> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let path = dir.path().join("control.sock");
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "mailbox_process::owned_client::tests::original_peer_fixture",
                "--exact",
            ])
            .env(CHILD_SOCKET, &path)
            .stdin(Stdio::null())
            .spawn()?;
        let result = (|| -> Result<()> {
            let peer = InstalledMailboxPeer::from_child(&mut child)?;
            let mut original = connect_child(&path)?;
            original.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut ack = [0];
            original.read_exact(&mut ack)?;
            ensure!(ack == *b"1");
            peer.authenticate(&original)?;
            std::fs::remove_file(&path)?;
            let replacement = UnixListener::bind(&path)?;
            let impostor = UnixStream::connect(&path)?;
            let (_same_uid_peer, _) = replacement.accept()?;
            assert!(peer.authenticate(&impostor).is_err());
            peer.authenticate(&original)?;
            original.write_all(&[1])?;
            ensure!(child.wait()?.success());
            assert!(peer.authenticate(&original).is_err());
            assert!(peer.authenticate(&original).is_err());
            assert!(InstalledMailboxPeer::from_child(&mut child).is_err());
            Ok(())
        })();
        if child.try_wait()?.is_none() {
            child.kill()?;
            child.wait()?;
        }
        result
    }
}
