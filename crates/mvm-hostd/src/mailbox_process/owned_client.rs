//! Launcher control of one mailbox under an existing verified MVM admission.
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use mvm_contract::protocol::mailbox::MAILBOX_PORT;
use mvm_core::protocol::{
    broker_control::{self, ControlRequest},
    mailbox_worker_control::*,
};
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::host::mailbox_worker_transport::{recv_response, send_request};

use super::{build_config, write_delegated_config};
use crate::audit::host_keypair::{PUBLIC_FILENAME, SECRET_FILENAME};
use crate::plan_admission::AdmittedPlan;

/// A prepared original acquisition. Retain its nonce through uncertain replies;
/// the daemon rejects a second acquisition for the same VM under another nonce.
pub struct InstalledMailboxClient {
    acquire: MailboxWorkerRequest,
    owner: Option<MailboxWorkerOwner>,
    stop_only: bool,
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
        Self::with_nonce(admitted, backend, vm_name, rand::random())
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
            stop_only: false,
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
            stop_only: true,
        })
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
        if !matches!(operation, MailboxWorkerOperation::Acquire) {
            request.request_nonce = rand::random();
        }
        request.operation = operation;
        let (secret, public) = host_key()?;
        let signed = broker_control::sign(
            ControlRequest::MailboxWorkerV1(Box::new(request.clone())),
            secret.as_bytes(),
        )?;
        verify_request(&signed, &public, now_ms()?)?;
        let mut stream = mvm_agentd::vsock::connect_unix_before(
            &mvm_core::config::host_agent_control_socket(&request.tenant),
            deadline,
        )?;
        send_request(&stream, &signed, deadline)?;
        Ok(recv_response(&mut stream, &request, deadline)?)
    }

    pub fn acquire(&mut self, deadline: Instant) -> Result<&MailboxWorkerOwner> {
        ensure!(!self.stop_only, "stop locator cannot acquire a worker");
        if self.owner.is_none() {
            let (receipt, _) = self.call(MailboxWorkerOperation::Acquire, deadline)?;
            self.owner = Some(receipt.owner);
        }
        self.owner.as_ref().context("missing mailbox owner")
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

    /// Only the original, once-delegated FD may receive configuration. A retry
    /// that finds the helper starting just queries its state, keeping all
    /// derived bytes and epoch state out of the host-agent control connection.
    pub fn configure_and_wait(&self, backend: &AnyBackend, deadline: Instant) -> Result<()> {
        ensure!(
            !self.stop_only,
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
