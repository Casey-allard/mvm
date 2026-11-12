#![cfg(target_os = "linux")]

use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
use mvm_core::protocol::broker_control::{self, ControlRequest};
use mvm_core::protocol::mailbox_worker_control::*;
use mvm_hostd::broker::daemon::HostAgentDaemon;
use mvm_hostd::broker::mailbox_workers::{
    MailboxWorkerBudget, MailboxWorkerFactory, MailboxWorkers, SpawnedMailboxWorker, WorkerLimits,
};
use mvm_vmm::host::mailbox_worker_transport::recv_response;
use std::io::{self, Write};
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
        Ok(SpawnedMailboxWorker {
            child,
            control,
            parent_lease: None,
        })
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
    path: &Path,
    request: &MailboxWorkerRequest,
) -> io::Result<(MailboxWorkerResult, Option<std::os::fd::OwnedFd>)> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let signed = broker_control::sign(
        ControlRequest::MailboxWorkerV1(Box::new(request.clone())),
        &[7; 32],
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

async fn serve(
    tenant: &str,
    budget: Arc<MailboxWorkerBudget>,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    serve_with(tenant, budget, Arc::new(FixtureHelper)).await
}
async fn serve_with(
    tenant: &str,
    budget: Arc<MailboxWorkerBudget>,
    factory: Arc<dyn MailboxWorkerFactory>,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let workers = Arc::new(MailboxWorkers::new(tenant, budget, factory).unwrap());
    let daemon = HostAgentDaemon::new(
        tenant,
        SigningKey::from_bytes(&[7; 32]).verifying_key(),
        65_536,
    )
    .with_mailbox_workers(workers)
    .unwrap();
    let server_path = path.clone();
    let task = tokio::spawn(async move { daemon.run(&server_path).await });
    for _ in 0..100 {
        if path.exists() {
            return (dir, path, task);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("test daemon never bound");
}

#[tokio::test]
async fn shared_original_budget_prevents_duplicate_owner_minting_for_one_vm() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 2,
        host_bytes: 1_048_576,
        tenant_bytes: 1_048_576,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let (_first_dir, first, first_task) = serve("tenant", budget.clone()).await;
    let (_second_dir, second, second_task) = serve("tenant", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        let r = request("tenant", "same-vm");
        assert_eq!(
            call(&first, &r).unwrap().0.state,
            MailboxWorkerState::Reserved
        );
        assert!(
            call(&second, &r).is_err(),
            "a second owner must not mint a new lease for the same registered VM"
        );
        assert_eq!(budget.usage().unwrap().workers, 1);
    })
    .await
    .unwrap();
    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn two_tenant_owners_share_host_worker_and_byte_limits() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let (_a_dir, a, a_task) = serve("tenant-a", budget.clone()).await;
    let (_b_dir, b, b_task) = serve("tenant-b", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        call(&a, &request("tenant-a", "a-one")).unwrap();
        call(&b, &request("tenant-b", "b-one")).unwrap();
        assert_eq!(budget.usage().unwrap().workers, 2);
        assert!(call(&a, &request("tenant-a", "a-two")).is_err());
        assert_eq!(budget.usage().unwrap().workers, 2);
    })
    .await
    .unwrap();
    a_task.abort();
    b_task.abort();
}

// A real separate launcher process. Without the explicit fixture variables this
// entrypoint is a no-op, not another independent lifecycle qualification.
#[test]
fn detached_launch_client_fixture() {
    let Some(path) = std::env::var_os("MVM_OWNER_TEST_CONTROL") else {
        return;
    };
    let record = std::env::var_os("MVM_OWNER_TEST_RECORD").unwrap();
    let mut r = request("tenant", "detached-vm");
    let (acquired, _) = call(Path::new(&path), &r).unwrap();
    r.operation = MailboxWorkerOperation::DelegateConfig {
        owner: acquired.owner.clone(),
    };
    r.request_nonce = [2; 32];
    let (_, fd) = call(Path::new(&path), &r).unwrap();
    let mut writer = std::fs::File::from(fd.unwrap());
    writer.write_all(b"private-fixture-config").unwrap();
    drop(writer);
    use std::os::unix::fs::OpenOptionsExt;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(record)
        .unwrap();
    serde_json::to_writer(&mut output, &(r, acquired.owner)).unwrap();
}

#[tokio::test]
async fn detached_launcher_exits_then_independent_client_collects_original_worker() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let (dir, path, server) = serve("tenant", budget.clone()).await;
    let record = dir.path().join("owner.json");
    tokio::task::spawn_blocking(move || {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "detached_launch_client_fixture",
                "--test-threads=1",
            ])
            .env("MVM_OWNER_TEST_CONTROL", &path)
            .env("MVM_OWNER_TEST_RECORD", &record)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success()); // Waits only launcher, never the worker Child.
        let (mut r, owner): (MailboxWorkerRequest, MailboxWorkerOwner) =
            serde_json::from_slice(&std::fs::read(record).unwrap()).unwrap();
        assert_eq!(
            budget.usage().unwrap().workers,
            1,
            "launcher exit must not surrender worker custody"
        );
        r.operation = MailboxWorkerOperation::Stop { owner };
        r.request_nonce = [4; 32];
        r.deadline_unix_ms = now() + 4_000;
        let result = call(&path, &r).unwrap().0;
        assert!(matches!(result.state, MailboxWorkerState::Collected { .. }));
        assert_eq!(budget.usage().unwrap().workers, 0);
    })
    .await
    .unwrap();
    server.abort();
}

struct ExitBeforeConfig;
impl MailboxWorkerFactory for ExitBeforeConfig {
    fn spawn(
        &self,
        _request: &MailboxWorkerRequest,
        _owner: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker> {
        let (control, child_control) = UnixStream::pair()?;
        let child = Command::new("/bin/true")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(child_control)))
            .spawn()?;
        // Observe, but never reap the fixture child. The daemon must collect it.
        let observer =
            mvm_vmm::host::process_exit::ProcessExitObserver::arm(child.id().try_into().unwrap())
                .unwrap();
        assert_eq!(
            observer
                .wait_event(Instant::now() + Duration::from_secs(2))
                .unwrap(),
            mvm_vmm::host::process_exit::ProcessExitWait::Exited
        );
        Ok(SpawnedMailboxWorker {
            child,
            control,
            parent_lease: None,
        })
    }
}

#[tokio::test]
async fn already_exited_original_child_is_collected_without_delegating_dead_stdin() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let (_dir, path, server) =
        serve_with("tenant", budget.clone(), Arc::new(ExitBeforeConfig)).await;
    tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "early-exit");
        let (acquired, _) = call(&path, &r).unwrap();
        r.request_nonce = [2; 32];
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: acquired.owner,
        };
        let (result, fd) =
            call(&path, &r).expect("must return exact collected original-child result");
        assert!(matches!(result.state, MailboxWorkerState::Collected { .. }));
        assert!(fd.is_none());
        assert_eq!(budget.usage().unwrap().workers, 0);
    })
    .await
    .unwrap();
    server.abort();
}

struct IgnoreLifetimeUntilReleased(std::sync::Mutex<Option<UnixStream>>);
impl MailboxWorkerFactory for IgnoreLifetimeUntilReleased {
    fn spawn(
        &self,
        _request: &MailboxWorkerRequest,
        owner: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker> {
        let (control, child_control) = UnixStream::pair()?;
        let (release, child_release) = UnixStream::pair()?;
        *self.0.lock().unwrap() = Some(release);
        let ready = serde_json::to_string(owner)?;
        let child = Command::new("/bin/sh")
            .env_clear()
            .arg("-c")
            .arg(format!(
                "/bin/cat >/dev/null; printf '%s\\n' '{ready}'; /bin/cat <&2 >/dev/null"
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(child_control)))
            .stderr(Stdio::from(std::os::fd::OwnedFd::from(child_release)))
            .spawn()?;
        Ok(SpawnedMailboxWorker {
            child,
            control,
            parent_lease: None,
        })
    }
}

#[tokio::test]
async fn stop_timeout_retains_original_owner_and_credit_until_later_collection() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let factory = Arc::new(IgnoreLifetimeUntilReleased(std::sync::Mutex::new(None)));
    let (_dir, path, server) = serve_with("tenant", budget.clone(), factory.clone()).await;
    tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "held-worker");
        let owner = call(&path, &r).unwrap().0.owner;
        r.request_nonce = [2; 32];
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        };
        let fd = call(&path, &r).unwrap().1.unwrap();
        drop(std::fs::File::from(fd));
        r.operation = MailboxWorkerOperation::Query {
            owner: owner.clone(),
        };
        let mut ready = false;
        for _ in 0..100 {
            if call(&path, &r).unwrap().0.state == MailboxWorkerState::Serving {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ready,
            "fault fixture must finish readiness before Stop closes lifetime"
        );
        r.request_nonce = [3; 32];
        r.operation = MailboxWorkerOperation::Stop {
            owner: owner.clone(),
        };
        r.deadline_unix_ms = now() + 100;
        assert!(call(&path, &r).is_err());
        r.request_nonce = [4; 32];
        r.operation = MailboxWorkerOperation::Query { owner };
        r.deadline_unix_ms = now() + 4_000;
        assert_eq!(
            call(&path, &r).unwrap().0.state,
            MailboxWorkerState::Unresolved
        );
        assert_eq!(budget.usage().unwrap().workers, 1);
        assert!(budget.usage().unwrap().bytes >= 65_536);
        // Release only the fixture's injected fault; the daemon remains the
        // sole process reaper. No external kill/waitpid/Child wait is used.
        drop(factory.0.lock().unwrap().take());
        let mut collected = false;
        for _ in 0..100 {
            if matches!(
                call(&path, &r).unwrap().0.state,
                MailboxWorkerState::Collected { .. }
            ) {
                collected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(collected);
        assert_eq!(budget.usage().unwrap().workers, 0);
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn stopping_unspawned_admission_cannot_later_delegate_or_create_a_child() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let (_dir, path, server) = serve("tenant", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "stopped-before-spawn");
        let owner = call(&path, &r).unwrap().0.owner;
        r.request_nonce = [2; 32];
        r.operation = MailboxWorkerOperation::Stop {
            owner: owner.clone(),
        };
        let stopped = call(&path, &r).unwrap().0;
        assert!(
            !matches!(stopped.state, MailboxWorkerState::Collected { .. }),
            "no child must not fabricate collected exit"
        );
        r.request_nonce = [3; 32];
        r.operation = MailboxWorkerOperation::DelegateConfig { owner };
        assert!(
            call(&path, &r).is_err(),
            "a stopped admission cannot authorize a later worker spawn"
        );
        assert_eq!(
            budget.usage().unwrap().workers,
            1,
            "unresolved admission remains bounded/charged"
        );
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn signed_stale_context_and_duplicate_delegation_cannot_mint_more_work() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let (_dir, path, server) = serve("tenant", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "exact-owner");
        let owner = call(&path, &r).unwrap().0.owner;
        let mut stale = owner.clone();
        stale.lease[0] ^= 1;
        r.operation = MailboxWorkerOperation::Query { owner: stale };
        assert!(call(&path, &r).is_err());
        r.operation = MailboxWorkerOperation::Query {
            owner: owner.clone(),
        };
        r.plan_commitment[0] ^= 1;
        assert!(call(&path, &r).is_err());
        r.plan_commitment[0] ^= 1;
        assert!(call(&path, &request("foreign-tenant", "exact-owner")).is_err());
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        };
        r.request_nonce = [2; 32];
        let fd = call(&path, &r).unwrap().1.unwrap();
        let (duplicate, again) = call(&path, &r).unwrap();
        assert!(!duplicate.delegates_config);
        assert!(again.is_none());
        assert_eq!(budget.usage().unwrap().workers, 1);
        drop(std::fs::File::from(fd));
        r.operation = MailboxWorkerOperation::Stop { owner };
        r.request_nonce = [3; 32];
        r.deadline_unix_ms = now() + 4_000;
        assert!(matches!(
            call(&path, &r).unwrap().0.state,
            MailboxWorkerState::Collected { .. }
        ));
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn workspace_and_terminal_bytes_exhaust_before_unlimited_worker_count() {
    // Original one-actor stack/cells/wakeup reserve + one slot + one bounded
    // control workspace; a second slot must still fail before count capacity.
    let limit = 536_576;
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 8,
        tenant_workers: 8,
        host_bytes: limit,
        tenant_bytes: limit,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let (_dir, path, server) = serve("tenant", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        call(&path, &request("tenant", "first-slot")).unwrap();
        assert!(call(&path, &request("tenant", "second-slot")).is_err());
        let usage = budget.usage().unwrap();
        assert_eq!(
            usage.workers, 1,
            "byte budget must refuse while count budget has headroom"
        );
        assert!(usage.bytes <= limit);
    })
    .await
    .unwrap();
    server.abort();
}

struct RecordWorkerPid(std::sync::atomic::AtomicU32);
impl MailboxWorkerFactory for RecordWorkerPid {
    fn spawn(
        &self,
        request: &MailboxWorkerRequest,
        owner: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker> {
        let worker = FixtureHelper.spawn(request, owner)?;
        self.0
            .store(worker.child.id(), std::sync::atomic::Ordering::SeqCst);
        Ok(worker)
    }
}

#[tokio::test]
async fn daemon_destruction_preserves_original_child_until_it_is_collected() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let factory = Arc::new(RecordWorkerPid(std::sync::atomic::AtomicU32::new(0)));
    let (_dir, path, server) = serve_with("tenant", budget.clone(), factory.clone()).await;
    let observer = tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "owner-drop");
        let owner = call(&path, &r).unwrap().0.owner;
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        };
        r.request_nonce = [2; 32];
        drop(std::fs::File::from(call(&path, &r).unwrap().1.unwrap()));
        r.operation = MailboxWorkerOperation::Query { owner };
        r.request_nonce = [3; 32];
        let mut ready = false;
        for _ in 0..100 {
            if call(&path, &r).unwrap().0.state == MailboxWorkerState::Serving {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(ready);
        let pid = factory.0.load(std::sync::atomic::Ordering::SeqCst);
        let observer =
            mvm_vmm::host::process_exit::ProcessExitObserver::arm(pid.try_into().unwrap()).unwrap();
        (pid, observer)
    })
    .await
    .unwrap();
    server.abort();
    let _ = server.await;
    tokio::task::spawn_blocking(move || {
        let (pid,observer)=observer;
        assert_eq!(observer.wait_event(Instant::now()+Duration::from_secs(2)).unwrap(),mvm_vmm::host::process_exit::ProcessExitWait::Exited);
        for _ in 0..100 {
            if budget.usage().unwrap().workers==0 && !std::path::PathBuf::from(format!("/proc/{pid}/stat")).exists() {return;}
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("destroying the daemon lost original Child collection authority; retained live credit or zombie remains");
    }).await.unwrap();
}

#[tokio::test]
async fn canonical_daemon_owns_real_child_and_collects_before_stop_reply() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let workers =
        Arc::new(MailboxWorkers::new("tenant", budget.clone(), Arc::new(FixtureHelper)).unwrap());
    let daemon = HostAgentDaemon::new(
        "tenant",
        SigningKey::from_bytes(&[7; 32]).verifying_key(),
        65_536,
    )
    .with_mailbox_workers(workers)
    .unwrap();
    let server_path = path.clone();
    let server = tokio::spawn(async move { daemon.run(&server_path).await });
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (exit, duplicate, usage) = tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "vm-one");
        let (acquired, fd) = call(&path, &r).unwrap();
        assert!(fd.is_none());
        assert_eq!(acquired.state, MailboxWorkerState::Reserved);
        assert_eq!(budget.usage().unwrap().workers, 1);
        // New independent control connections, like detached launcher then Stop.
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: acquired.owner.clone(),
        };
        r.request_nonce = [2; 32];
        let (started, fd) = call(&path, &r).unwrap();
        assert!(started.delegates_config);
        let mut writer = std::fs::File::from(fd.unwrap());
        writer.write_all(b"fixture-secret-config").unwrap();
        drop(writer);
        r.operation = MailboxWorkerOperation::Query {
            owner: acquired.owner.clone(),
        };
        r.request_nonce = [3; 32];
        let mut ready = false;
        for _ in 0..100 {
            if call(&path, &r).unwrap().0.state == MailboxWorkerState::Serving {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(ready, "actual helper must report matching readiness");
        r.operation = MailboxWorkerOperation::Stop {
            owner: acquired.owner,
        };
        r.request_nonce = [4; 32];
        r.deadline_unix_ms = now() + 4_000;
        let exit = call(&path, &r).unwrap().0;
        let duplicate = call(&path, &r).unwrap().0;
        (exit, duplicate, budget.usage().unwrap())
    })
    .await
    .unwrap();
    assert!(
        matches!(exit.state, MailboxWorkerState::Collected { .. }),
        "typed Stop must contain original Child's collected status"
    );
    assert_eq!(exit, duplicate);
    assert_eq!(
        usage.workers, 0,
        "credit releases only after original collection"
    );
    server.abort();
}

#[tokio::test]
async fn final_provider_disconnect_drains_original_child_without_a_sender_cycle() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let weak = Arc::downgrade(&budget);
    let factory = Arc::new(RecordWorkerPid(std::sync::atomic::AtomicU32::new(0)));
    let (_dir, path, server) = serve_with("tenant", budget.clone(), factory.clone()).await;
    let captured = tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "last-provider");
        let owner = call(&path, &r).unwrap().0.owner;
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        };
        r.request_nonce = [2; 32];
        drop(std::fs::File::from(call(&path, &r).unwrap().1.unwrap()));
        r.operation = MailboxWorkerOperation::Query { owner };
        r.request_nonce = [3; 32];
        let mut ready = false;
        for _ in 0..100 {
            if call(&path, &r).unwrap().0.state == MailboxWorkerState::Serving {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(ready);
        let pid = factory.0.load(std::sync::atomic::Ordering::SeqCst);
        (
            pid,
            mvm_vmm::host::process_exit::ProcessExitObserver::arm(pid.try_into().unwrap()).unwrap(),
        )
    })
    .await
    .unwrap();
    server.abort();
    let _ = server.await;
    drop(budget);
    tokio::task::spawn_blocking(move || {
        let (pid, observer) = captured;
        assert_eq!(
            observer
                .wait_event(Instant::now() + Duration::from_secs(2))
                .unwrap(),
            mvm_vmm::host::process_exit::ProcessExitWait::Exited
        );
        for _ in 0..100 {
            if weak.upgrade().is_none()
                && !std::path::PathBuf::from(format!("/proc/{pid}/stat")).exists()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("provider/Sender cycle or original child was not collected after final disconnect");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn all_reserved_handoff_cells_drain_across_two_tenants_without_new_budgets() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let fa = Arc::new(RecordWorkerPid(std::sync::atomic::AtomicU32::new(0)));
    let fb = Arc::new(RecordWorkerPid(std::sync::atomic::AtomicU32::new(0)));
    let (_da, a, sa) = serve_with("tenant-a", budget.clone(), fa.clone()).await;
    let (_db, b, sb) = serve_with("tenant-b", budget.clone(), fb.clone()).await;
    let captured = tokio::task::spawn_blocking(move || {
        let mut captured = Vec::new();
        for (tenant, path, factory) in [("tenant-a", a, fa), ("tenant-b", b, fb)] {
            let mut r = request(tenant, "bounded-vm");
            let owner = call(&path, &r).unwrap().0.owner;
            r.operation = MailboxWorkerOperation::DelegateConfig {
                owner: owner.clone(),
            };
            r.request_nonce = [2; 32];
            drop(std::fs::File::from(call(&path, &r).unwrap().1.unwrap()));
            r.operation = MailboxWorkerOperation::Query { owner };
            r.request_nonce = [3; 32];
            let mut ready = false;
            for _ in 0..100 {
                if call(&path, &r).unwrap().0.state == MailboxWorkerState::Serving {
                    ready = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(ready);
            let pid = factory.0.load(std::sync::atomic::Ordering::SeqCst);
            captured.push((
                pid,
                mvm_vmm::host::process_exit::ProcessExitObserver::arm(pid.try_into().unwrap())
                    .unwrap(),
            ));
        }
        captured
    })
    .await
    .unwrap();
    assert_eq!(budget.usage().unwrap().workers, 2);
    sa.abort();
    sb.abort();
    let _ = sa.await;
    let _ = sb.await;
    let checked_budget = budget.clone();
    tokio::task::spawn_blocking(move || {
        for (_, observer) in &captured {
            assert_eq!(
                observer
                    .wait_event(Instant::now() + Duration::from_secs(2))
                    .unwrap(),
                mvm_vmm::host::process_exit::ProcessExitWait::Exited
            );
        }
        for _ in 0..100 {
            if checked_budget.usage().unwrap().workers == 0
                && captured
                    .iter()
                    .all(|(pid, _)| !std::path::PathBuf::from(format!("/proc/{pid}/stat")).exists())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("shared actor did not collect every original child from its reserved cells");
    })
    .await
    .unwrap();
    let (_dir, path, server) = serve("tenant-a", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        call(&path, &request("tenant-a", "after-collected-drop")).unwrap();
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn signed_release_unstarted_requires_original_owner_and_replays_without_refunding_twice() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2,
        tenant_workers: 1,
        host_bytes: 1_048_576,
        tenant_bytes: 524_288,
        bytes_per_worker: 65_536,
    })
    .unwrap();
    let slot_bytes = budget.usage().unwrap().bytes + 65_536;
    let (_dir, path, task) = serve("tenant", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "never-launched");
        let original = call(&path, &r).unwrap().0.owner;
        let settled_usage = || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let usage = budget.usage().unwrap();
                if usage.bytes == slot_bytes {
                    return usage;
                }
                assert!(Instant::now() < deadline, "signed reply workspace retained");
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        let reserved = settled_usage();
        // Decode the explicit wire tag; older peers must refuse this request.
        let release = |owner| {
            serde_json::from_value(serde_json::json!({
                "operation":"release_unstarted_v1","owner":owner
            }))
            .unwrap()
        };
        let mut foreign = original.clone();
        foreign.lease[0] ^= 1;
        r.operation = release(foreign);
        assert!(call(&path, &r).is_err());
        assert_eq!(settled_usage(), reserved);
        r.operation = release(original.clone());
        for nonce in [2, 3] {
            r.request_nonce = [nonce; 32];
            let (result, fd) = call(&path, &r).unwrap();
            assert!(fd.is_none());
            assert_eq!(
                serde_json::to_value(result.state).unwrap(),
                serde_json::json!({"state":"released_before_spawn"})
            );
            assert_eq!(budget.usage().unwrap().workers, 0);
            assert_eq!(settled_usage().bytes, reserved.bytes);
        }
        r.operation = MailboxWorkerOperation::Query {
            owner: original.clone(),
        };
        assert_eq!(
            call(&path, &r).unwrap().0.state,
            MailboxWorkerState::Unresolved
        );
        r.operation = MailboxWorkerOperation::DelegateConfig { owner: original };
        assert!(call(&path, &r).is_err());
        // A different VM immediately reuses the single live worker credit.
        let mut r = request("tenant", "spawned");
        let owner = call(&path, &r).unwrap().0.owner;
        r.operation = MailboxWorkerOperation::DelegateConfig {
            owner: owner.clone(),
        };
        let (_, writer) = call(&path, &r).unwrap();
        r.operation = release(owner.clone());
        assert!(call(&path, &r).is_err());
        assert_eq!(budget.usage().unwrap().workers, 1);
        drop(writer);
        r.operation = MailboxWorkerOperation::Stop { owner };
        assert!(matches!(
            call(&path, &r).unwrap().0.state,
            MailboxWorkerState::Collected { .. }
        ));
    })
    .await
    .unwrap();
    task.abort();
}

#[tokio::test]
async fn signed_lookup_is_read_only_and_recovers_original_after_expiry() {
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 1, tenant_workers: 1, host_bytes: 1_048_576,
        tenant_bytes: 1_048_576, bytes_per_worker: 65_536,
    }).unwrap();
    let (_dir, path, task) = serve("tenant", budget.clone()).await;
    tokio::task::spawn_blocking(move || {
        let mut r = request("tenant", "recover");
        r.admission_expires_at_unix_ms = now() + 250;
        let lookup = serde_json::from_value::<MailboxWorkerOperation>(serde_json::json!({"operation": "lookup_existing_v1"})).unwrap();
        r.operation = lookup.clone();
        assert!(call(&path, &r).is_err());
        assert_eq!(budget.usage().unwrap().workers, 0);
        r.operation = MailboxWorkerOperation::Acquire;
        let receipt = call(&path, &r).unwrap().0;
        std::thread::sleep(Duration::from_millis(260));
        r.operation = lookup.clone();
        let mut other = r.clone();
        other.request_nonce = [88; 32];
        assert!(call(&path, &other).is_err());
        other = r.clone();
        other.plan_commitment = [88; 32];
        assert!(call(&path, &other).is_err());
        let (found, fd) = call(&path, &r).unwrap();
        assert_eq!(found, receipt);
        assert!(fd.is_none());
        r.operation = MailboxWorkerOperation::DelegateConfig { owner: receipt.owner.clone() };
        assert!(call(&path, &r).is_err());
        r.operation = MailboxWorkerOperation::ReleaseUnstartedV1 { owner: receipt.owner };
        assert_eq!(call(&path, &r).unwrap().0.state, MailboxWorkerState::ReleasedBeforeSpawn);
        r.operation = lookup;
        assert_eq!(call(&path, &r).unwrap().0.state, MailboxWorkerState::ReleasedBeforeSpawn);
        assert_eq!(budget.usage().unwrap().workers, 0);
    }).await.unwrap();
    task.abort();
}

/// Run a real signed request through the daemon while its canonical mutation
/// lane is held. Query must remain usable without acquiring that lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_initial_worker_waits_for_held_mutation_lane_and_rechecks_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let budget = MailboxWorkerBudget::new(WorkerLimits {
        host_workers: 2, tenant_workers: 2,
        host_bytes: 1_048_576, tenant_bytes: 1_048_576, bytes_per_worker: 65_536,
    }).unwrap();
    let workers = Arc::new(MailboxWorkers::new("tenant", budget.clone(), Arc::new(FixtureHelper)).unwrap());
    let daemon = HostAgentDaemon::new("tenant", SigningKey::from_bytes(&[7;32]).verifying_key(),65_536)
        .with_mailbox_workers(workers).unwrap();
    let lane = daemon.mutation_lane();
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server=tokio::spawn(HostAgentDaemon::run_shared_on_listener(Arc::new(tokio::sync::Mutex::new(daemon)),listener));
    let invoke=|r:MailboxWorkerRequest| {
        let socket=path.clone();
        tokio::task::spawn_blocking(move || call(&socket,&r).map(|p|p.0))
    };
    let first=request("tenant","alpha");
    let owner=invoke(first.clone()).await.unwrap().unwrap().owner;
    let held=lane.clone().acquire_owned().await.unwrap();
    let mut second=request("tenant","beta");
    second.request_nonce=[6;32];
    let mut pending=invoke(second.clone());
    let early=tokio::time::timeout(Duration::from_millis(100), &mut pending).await;
    assert!(early.is_err(),"contended signed Acquire returned before its deadline: {early:?}");
    let mut query=first;
    query.operation=MailboxWorkerOperation::Query {owner};
    assert_eq!(invoke(query).await.unwrap().unwrap().state,MailboxWorkerState::Reserved);
    assert_eq!(budget.usage().unwrap().workers,1);
    drop(held);
    assert_eq!(pending.await.unwrap().unwrap().state,MailboxWorkerState::Reserved);
    assert_eq!(budget.usage().unwrap().workers,2);
    let held=lane.acquire_owned().await.unwrap();
    let mut expired=request("tenant","never-admitted");
    expired.admission_expires_at_unix_ms=now()+300;
    let mut denied=invoke(expired);
    let early=tokio::time::timeout(Duration::from_millis(60), &mut denied).await;
    assert!(early.is_err(),"request did not enter bounded wait: {early:?}");
    tokio::time::sleep(Duration::from_millis(325)).await;
    drop(held);
    assert!(denied.await.unwrap().is_err());
    assert_eq!(budget.usage().unwrap().workers,2);
    server.abort();
}
