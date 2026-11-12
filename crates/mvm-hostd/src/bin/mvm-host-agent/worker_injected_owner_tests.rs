//! Private mvm-host-agent binary regression. No new wire ABI; actual original
//! pipe child, canonical WorkerControl and actual installed collect_originals.
#![cfg(target_os = "linux")]

use super::*;
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
use mvm_core::protocol::broker_control::{self, ControlRequest};
use mvm_core::protocol::mailbox_worker_control::*;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::host_keypair;
use mvm_hostd::broker::daemon::HostAgentDaemon;
use mvm_hostd::broker::mailbox_workers::{
    MailboxWorkerBudget, MailboxWorkerFactory, MailboxWorkers, SpawnedMailboxWorker, WorkerLimits,
};
use mvm_vmm::host::host_agent_installation::create_new_home_and_provision;
use mvm_vmm::host::mailbox_worker_transport::recv_response;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct FixtureHelper;
impl MailboxWorkerFactory for FixtureHelper {
    fn spawn(
        &self,
        _request: &MailboxWorkerRequest,
        owner: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker> {
        let (control, child_control) = UnixStream::pair()?;
        let ready = serde_json::to_string(owner)?;
        // This fixed fixture consumes config without exposing it to the daemon,
        // reports its exact owner, then waits for owner EOF. No test waits Child.
        let script =
            format!("/bin/cat >/dev/null; printf '%s\\n' '{ready}'; /bin/cat <&1 >/dev/null");
        let child = Command::new("/bin/sh")
            .env_clear()
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(child_control)))
            .stderr(Stdio::null())
            .spawn()?;
        Ok(SpawnedMailboxWorker { child, control, parent_lease: None })
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn request(tenant: &str, vm: &str) -> MailboxWorkerRequest {
    MailboxWorkerRequest {
        domain: MAILBOX_WORKER_DOMAIN.into(),
        version: 1,
        request_nonce: [1; 32],
        tenant: tenant.into(),
        vm_id: vm.into(),
        workload_id: vm.into(),
        plan_commitment: [2; 32],
        mailbox_grant: MailboxGrant {
            mailbox: MailboxId::from_bytes([3; 32]),
            authority_key: [4; 32],
            epoch: ExecutionEpoch::new(1).unwrap(),
            local_service: None,
        },
        admission_expires_at_unix_ms: now() + 60_000,
        deadline_unix_ms: now() + 4_000,
        backend: MailboxWorkerBackend::Firecracker,
        operation: MailboxWorkerOperation::Acquire,
    }
}
fn call(
    key: &[u8; 32],
    path: &Path,
    request: &MailboxWorkerRequest,
) -> io::Result<(MailboxWorkerResult, Option<std::os::fd::OwnedFd>)> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let signed = broker_control::sign(
        ControlRequest::MailboxWorkerV1(Box::new(request.clone())),
        key,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&signed)?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    recv_response(
        &mut stream,
        request,
        Instant::now() + Duration::from_secs(5),
    )
}

struct ObservedFactory(Arc<std::sync::Mutex<Option<u32>>>, Arc<dyn MailboxWorkerFactory>);
impl MailboxWorkerFactory for ObservedFactory {
    fn requires_signed_provision(&self) -> bool { self.1.requires_signed_provision() }
    fn admit(&self, request: &MailboxWorkerRequest) -> io::Result<()> { self.1.admit(request) }
    fn spawn(
        &self,
        r: &MailboxWorkerRequest,
        owner: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker> {
        // Acquire every fallible observation resource BEFORE the actual spawn.
        // Once Child exists, return that original owner without a new Err path.
        let mut observed = self
            .0
            .lock()
            .map_err(|_| io::Error::other("fixture observer poisoned"))?;
        let spawned = self.1.spawn(r, owner)?;
        *observed = Some(spawned.child.id());
        Ok(spawned)
    }
}

#[test]
fn installed_retirement_collects_injected_original_mailbox_child() -> Result<()> {
    run_installed(None)
}
#[test]
#[ignore = "requires the built mvm-mailbox executable beside this Cargo profile's deps directory"]
fn installed_owned_helper_signed_stop() -> Result<()> {
    run_installed(Some(true))
}
#[test]
#[ignore = "requires the built mvm-mailbox executable beside this Cargo profile's deps directory"]
fn installed_owned_helper_coordinator_shutdown() -> Result<()> {
    run_installed(Some(false))
}
fn run_installed(signed_stop: Option<bool>) -> Result<()> {
    let mut env = TestEnv::new();
    let base = tempfile::tempdir()?;
    std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700))?;
    let home = base.path().join("mvm-home");
    create_new_home_and_provision(&home, "local")?.verify()?;
    env.set("MVM_HOME", &home);
    let signer = host_keypair::load_or_init_at(&home.join("keys"))?;
    let cfg = HostAgentConfig {
        tenant_id: "local".into(),
        control_socket: mvm_core::config::host_agent_control_socket("local"),
        registration_journal_path: Some(
            mvm_core::config::host_agent_dir("local").join("registrations.json"),
        ),
        host_signer_public_key_path: signer.public_path,
        signer_helper_uds_path: mvm_core::config::host_agent_signer_helper_socket("local"),
        software_chain_key_path: signer.secret_path,
        max_frame_bytes: 65_536,
    };
    let mut worker = WorkerCoordinator::open(cfg)?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let budget = MailboxWorkerBudget::new(WorkerLimits {
                host_workers: 1,
                tenant_workers: 1,
                host_bytes: 1_048_576,
                tenant_bytes: 1_048_576,
                bytes_per_worker: 65_536,
            })?;
            let initial_budget = budget.usage()?;
            let child_pid = Arc::new(std::sync::Mutex::new(None));
            let mut admitted = request("local", "installed-child");
            let (factory, config): (Arc<dyn MailboxWorkerFactory>, _) = if signed_stop.is_some() {
                use mvm_hostd::broker::mailbox_workers::InstalledMailboxWorkerFactory;
                use mvm_hostd::{mailbox_launch, mailbox_process};
                let profile = std::env::current_exe()?.parent().and_then(Path::parent).context("Cargo profile directory")?.to_owned();
                let state = mvm_core::config::vm_state_dir_at(&home, &admitted.vm_id);
                std::fs::create_dir_all(&state)?;
                mvm_core::config::secure_fallback_socket_dir_at(&state)?;
                let keys = home.join("keys");
                let grant = &mut admitted.mailbox_grant;
                grant.authority_key = mailbox_launch::authority_key_for(&keys, &grant.mailbox, grant.epoch)?.to_bytes();
                let factory = InstalledMailboxWorkerFactory::new(&profile.join("mvm-mailbox"), worker.resources.binding.clone(), &home)?;
                let route = mvm_runtime::AnyBackend::from_hypervisor("firecracker")
                    .host_dial_route(&state, mvm_contract::protocol::mailbox::MAILBOX_PORT)
                    .context("canonical Firecracker mailbox route")?;
                let config = mailbox_process::build_config(&keys, &admitted.mailbox_grant, &state, route)?;
                (Arc::new(factory), Some(config))
            } else { (Arc::new(FixtureHelper), None) };
            let workers = Arc::new(MailboxWorkers::new(
                "local",
                budget.clone(),
                Arc::new(ObservedFactory(child_pid.clone(), factory)),
            )?);
            let daemon = HostAgentDaemon::new("local", signer.verifying, 65_536)
                .with_resource_binding(worker.resources.binding.clone())
                .with_lifecycle_coordination(&home, worker.generation.clone())?
                .with_mailbox_workers(workers.clone())?;
            // Replace only the no-effect initial fixture daemon, BEFORE any task.
            // Keep its actual installed coordinator fields attached to this SAME
            // daemon/custody/accepted ledger throughout the regression.
            worker.accepted = daemon.accepted_work_drain()?;
            worker.drain_controller = daemon.drain_controller()?;
            worker.custody = daemon.custody_owner();
            worker.daemon = Arc::new(Mutex::new(daemon));
            worker.lifecycle.activate_after_reconciliation(
                &worker.generation,
                Instant::now() + Duration::from_secs(2),
            )?;
            worker
                .daemon
                .lock()
                .await
                .open_local_admission(&worker.generation)?;
            let listener = tokio::net::UnixListener::bind(&worker.cfg.control_socket)?;
            worker.control = Some(ControlLoopHandle::spawn(worker.daemon.clone(), listener));
            let socket = worker.cfg.control_socket.clone();
            let key = signer.signing.to_bytes();
            let resource_epoch = worker.generation.resource_epoch();
            let (mut current, owner) = tokio::task::spawn_blocking(move || -> io::Result<_> {
                let mut current = admitted;
                if config.is_some() {
                    if call(&key, &socket, &current).is_ok() {
                        return Err(io::Error::other("Acquire minted an unprovisioned worker"));
                    }
                    let mut probe = current.clone();
                    probe.operation = MailboxWorkerOperation::LookupExistingV1;
                    if call(&key, &socket, &probe).is_ok() {
                        return Err(io::Error::other("lookup minted an unprovisioned worker"));
                    }
                    probe.operation = MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch: resource_epoch + 1 };
                    if call(&key, &socket, &probe).is_ok() {
                        return Err(io::Error::other("foreign installation epoch provisioned a worker"));
                    }
                    probe.operation = MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch };
                    let reserved = call(&key, &socket, &probe)?.0;
                    probe.operation = MailboxWorkerOperation::LookupExistingV1;
                    let (lookup, fd) = call(&key, &socket, &probe)?;
                    if lookup != reserved || fd.is_some() {
                        return Err(io::Error::other("lookup lost original reservation"));
                    }
                    let mut foreign = current.clone();
                    foreign.plan_commitment = [99; 32];
                    if call(&key, &socket, &foreign).is_ok() {
                        return Err(io::Error::other("unadmitted VM context acquired a worker"));
                    }
                    foreign = current.clone();
                    foreign.vm_id = "second-active".into();
                    foreign.workload_id = foreign.vm_id.clone();
                    foreign.operation = MailboxWorkerOperation::ProvisionAdmittedV1 { resource_epoch };
                    if call(&key, &socket, &foreign).is_ok() {
                        return Err(io::Error::other("second live VM exceeded installed host budget"));
                    }
                }
                let acquired = call(&key, &socket, &current)?.0;
                current.request_nonce = [2; 32];
                current.operation = MailboxWorkerOperation::DelegateConfig {
                    owner: acquired.owner.clone(),
                };
                let (_, fd) = call(&key, &socket, &current)?;
                let fd = fd.ok_or_else(|| io::Error::other("original writer absent"))?;
                if let Some(config) = &config {
                    mvm_hostd::mailbox_process::write_delegated_config(fd, config, Instant::now()+Duration::from_secs(2))?;
                } else {
                    let mut pipe = std::fs::File::from(fd);
                    pipe.write_all(b"private-fixture-config")?;
                }
                current.operation = MailboxWorkerOperation::Query {
                    owner: acquired.owner.clone(),
                };
                current.request_nonce = [3; 32];
                let until = Instant::now() + Duration::from_secs(2);
                loop {
                    if call(&key, &socket, &current)?.0.state == MailboxWorkerState::Serving {
                        break;
                    }
                    if Instant::now() >= until {
                        return Err(io::Error::other("actual pipe child never became Serving"));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                if let Some(config) = &config {
                    if mvm_hostd::mailbox_service::recv(&config.socket)?.message.is_some() {
                        return Err(io::Error::other("expected newly bound empty mailbox"));
                    }
                }
                if signed_stop == Some(true) {
                    current.request_nonce = [44; 32];
                    current.operation = MailboxWorkerOperation::Stop { owner: acquired.owner.clone() };
                    let status = call(&key, &socket, &current)?.0.state;
                    current.request_nonce = [45; 32];
                    current.operation = MailboxWorkerOperation::Query { owner: acquired.owner.clone() };
                    if !matches!(status, MailboxWorkerState::Collected { exit: MailboxWorkerExit::Code { code: 0 } }) || call(&key, &socket, &current)?.0.state != status {
                        return Err(io::Error::other("signed stop/query did not collect the original helper"));
                    }
                }
                Ok((current, acquired.owner))
            })
            .await??;
            worker
                .begin_drain(false)?
                .context("original installed fence refused")?;
            let retirement =
                tokio::time::timeout(Duration::from_secs(2), worker.collect_originals()).await;
            let original_usage = budget.usage()?;
            let original_result = retirement.as_ref().ok().is_some_and(|r| r.is_ok());
            let expected_current_refusal = matches!(&retirement,
                Ok(Err(error)) if error.to_string() == "injected mailbox worker owner requires its original collection receipt");
            // Success requires original child disappearance plus released credit,
            // not merely pidfd readiness. On current refusal, canonical typed
            // Stop collects the original ONLY as fixture cleanup before RED.
            let socket = worker.cfg.control_socket.clone();
            let key = signer.signing.to_bytes();
            let requested_owner = owner.clone();
            let (collected_by_retirement, cleanup_collected) = if original_result {
                let pid = child_pid.lock().map_err(|_| anyhow::anyhow!("observer poisoned"))?.context("actual child never spawned")?;
                (matches!(std::fs::symlink_metadata(format!("/proc/{pid}")), Err(error) if error.kind()==io::ErrorKind::NotFound), false)
            } else { tokio::task::spawn_blocking(move || -> io::Result<_> {
                    current.request_nonce = [4; 32];
                    current.deadline_unix_ms = now() + 4_000;
                    current.operation = MailboxWorkerOperation::Query {
                        owner: owner.clone(),
                    };
                    let observed = call(&key, &socket, &current)?.0;
                    let collected = matches!(observed.state, MailboxWorkerState::Collected { .. });
                    if collected {
                        return Ok((true, false));
                    }
                    current.request_nonce = [5; 32];
                    current.operation = MailboxWorkerOperation::Stop { owner };
                    let cleaned = call(&key, &socket, &current)?.0;
                    // SAME canonical owner Query must preserve the actual Stop
                    // receipt/status; cleanup still cannot satisfy retirement.
                    current.request_nonce = [6; 32];
                    current.operation = MailboxWorkerOperation::Query { owner: cleaned.owner.clone() };
                    let queried = call(&key, &socket, &current)?.0;
                    if queried.state != cleaned.state || queried.owner != cleaned.owner {
                        return Err(io::Error::other("original collected receipt changed on Query"));
                    }
                    Ok((
                        false,
                        matches!(cleaned.state, MailboxWorkerState::Collected { .. }),
                    ))
                })
                .await?? };
            if original_result {
                let Some(MailboxRetirement::Collected(receipt)) = &worker.mailbox_retirement else {
                    anyhow::bail!("installed retirement did not retain its original collection receipt");
                };
                workers.validate_retirement(receipt)?;
                anyhow::ensure!(
                    matches!(receipt.original_exit(&requested_owner), Some(MailboxWorkerExit::Code { code: 0 })),
                    "original helper exit status was not preserved"
                );
                anyhow::ensure!(original_usage.workers == initial_budget.workers && original_usage.bytes == initial_budget.bytes + receipt.retained_bytes() && receipt.retained_bytes() > 0, "original worker reservation or control workspace remains charged");
                // GREEN must come from the REAL collector joining this loop.
                // No fixture cancellation may manufacture that completion.
                anyhow::ensure!(worker.control.as_ref().is_some_and(|control|
                    control.completed && !control.failed && control.task.is_none()),
                    "successful retirement did not join its original control loop");
            } else {
                // Baseline deliberately cannot retire an injected provider.
                // Its listener stop predicate also rejects injected providers,
                // even after their original child has been collected. Only
                // AFTER typed Stop+Query and released original worker credit,
                // cancel this fixture-owned loop; this is NOT a drain receipt.
                anyhow::ensure!(cleanup_collected || collected_by_retirement,
                    "fixture cannot cancel listener before original collection");
                anyhow::ensure!(budget.usage()?.workers == 0,
                    "fixture cannot cancel listener while original child credit is live");
                let control = worker.control.as_mut().context("original fixture control absent")?;
                control.stop.send_replace(true);
                if let Some(task) = control.task.take() {
                    task.abort();
                    let joined = tokio::time::timeout(Duration::from_secs(2), task)
                        .await.context("fixture listener cancellation did not join")?;
                    anyhow::ensure!(matches!(joined, Err(error) if error.is_cancelled()),
                        "fixture listener did not report its distinct cancellation");
                }
                // completed remains false: fixture cancellation cannot count
                // as production control collection or turn this RED into GREEN.
                anyhow::ensure!(!control.completed, "fixture cancellation became collection");
            }
            anyhow::ensure!(
                collected_by_retirement || cleanup_collected,
                "fixture original child uncollected"
            );
            anyhow::ensure!(original_result || expected_current_refusal,
                "unexpected retirement error/timeout; not the intended injected-owner refusal: {retirement:?}");
            anyhow::ensure!(original_result,
                "expected RED: installed retirement refuses injected owner without its original collection receipt");
            anyhow::ensure!(
                collected_by_retirement,
                "manual fixture Stop must not satisfy installed collection"
            );
            anyhow::ensure!(
                original_usage.workers == 0,
                "retirement refunded before actual collection or retained live credit"
            );
            Ok(())
        })
}
