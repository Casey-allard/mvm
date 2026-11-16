//! Native owned-helper qualification, not booted-VM or installed-Ready evidence.
use super::*;
use anyhow::Context;
use mvm_vmm::host::host_agent_spawn::{
    OWNED_ASYNC_WORKERS_PER_PROCESS, OWNED_BLOCKING_WORKERS_PER_PROCESS, OWNED_TENANT_MAX_THREADS,
    RegisteredAuditFile, RegisteredEndpointOwner,
};
use std::sync::{Mutex, atomic::AtomicUsize};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn require_pair_budget() -> Result<()> {
    let endpoint = mvm_hostd::installed_endpoint::owned_network_runtime_requirements()?;
    ensure!(endpoint.required_workers == 7, "endpoint quote changed");
    ensure!(
        OWNED_TENANT_MAX_THREADS + 2 + 2 * usize::try_from(endpoint.required_workers)? <= 24,
        "two endpoints exceed the original 24-worker ceiling: helpers={}, observers=2, endpoints={}",
        OWNED_TENANT_MAX_THREADS,
        2 * endpoint.required_workers
    );
    Ok(())
}

#[test]
fn owned_runtime_preserves_progress_with_both_blocking_slots_occupied() -> Result<()> {
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(OWNED_ASYNC_WORKERS_PER_PROCESS)
        .max_blocking_threads(OWNED_BLOCKING_WORKERS_PER_PROCESS)
        .thread_stack_size(2 * 1024 * 1024)
        .max_io_events_per_tick(16)
        .on_thread_start({
            let live = live.clone();
            let peak = peak.clone();
            move || {
                peak.fetch_max(live.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            }
        })
        .on_thread_stop({
            let live = live.clone();
            move || {
                live.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .build()?;
    let release = Arc::new(AtomicBool::new(false));
    let (started, waiting) = std::sync::mpsc::channel();
    let started_at = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let release = release.clone();
        let started = started.clone();
        tasks.push(runtime.spawn(async move {
            tokio::task::block_in_place(|| -> Result<()> {
                started.send(())?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while !release.load(Ordering::Acquire) {
                    ensure!(Instant::now() < deadline, "blocking fixture deadline");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(())
            })
        }));
    }
    // Always release and join BOTH original callbacks, including on a failed pulse.
    let progress = (|| -> Result<()> {
        for _ in 0..2 {
            waiting.recv_timeout(Duration::from_secs(2))?;
        }
        runtime.block_on(async {
            let pulse = tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
            });
            tokio::time::timeout(Duration::from_secs(1), pulse).await??;
            Ok::<_, anyhow::Error>(())
        })
    })();
    release.store(true, Ordering::Release);
    let outcomes = runtime.block_on(async {
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await);
        }
        results
    });
    drop(runtime);
    ensure!(live.load(Ordering::SeqCst) == 0, "runtime threads remain");
    let failures: Vec<_> = outcomes
        .into_iter()
        .filter_map(|result| match result {
            Ok(Ok(())) => None,
            other => Some(format!("{other:?}")),
        })
        .collect();
    ensure!(
        failures.is_empty(),
        "independent blocking failures: {failures:?}; progress={progress:?}"
    );
    progress?;
    let peak = peak.load(Ordering::SeqCst);
    ensure!(peak <= OWNED_ASYNC_WORKERS_PER_PROCESS + OWNED_BLOCKING_WORKERS_PER_PROCESS);
    eprintln!(
        "worker_pressure runtime_peak={peak} main_threads=1 elapsed_ns={}",
        started_at.elapsed().as_nanos()
    );
    require_pair_budget()
}

const EMITS: usize = 32;
#[derive(Default)]
struct Archives(Mutex<Vec<serde_json::Value>>);
impl RegisteredEndpointOwner for Archives {
    fn bind_registration(
        &self,
        _: &OwnedHostAgentRegistrar,
        _: &OwnedVmRegistration,
        _: &HostAgentServicesParams<'_>,
    ) -> Result<()> {
        Ok(())
    }
    fn retired_audit(&self, _: &OwnedVmRegistration, file: &RegisteredAuditFile) -> Result<()> {
        use base64::Engine;
        use std::os::unix::fs::FileExt;
        let key = file.verifying_key();
        let opening = mvm_core::protocol::audit_inventory::verify(file.signed_registered(), &key)?;
        let closing = mvm_core::protocol::audit_inventory::verify(
            file.signed_terminal().context("missing terminal")?,
            &key,
        )?;
        ensure!(&opening == file.registered() && Some(&closing) == file.terminal());
        ensure!(opening.same_registration(&closing));
        let verified = mvm_hostd::audit_signer::verify::verify_original_workload_chain(
            file.file(),
            &ed25519_dalek::VerifyingKey::from_bytes(&key)?,
            &mvm_hostd::audit_signer::verify::WorkloadChainExpectation {
                tenant: &closing.tenant,
                workload: &closing.workload,
                head: &closing.head,
                length: closing.length,
                cap: 256 << 10,
                device: closing.dev,
                inode: closing.ino,
            },
        )?;
        ensure!(verified.entries == EMITS);
        let mut original = vec![0; usize::try_from(verified.length)?];
        file.file().read_exact_at(&mut original, 0)?;
        for (seq, line) in std::str::from_utf8(&original)?.lines().enumerate() {
            let entry: mvm_hostd::audit_signer::chain::OnDiskEntry = serde_json::from_str(line)?;
            let bytes = base64::engine::general_purpose::STANDARD.decode(entry.canonical)?;
            let entry: mvm_hostd::audit_signer::canonical::CanonicalEntry =
                serde_json::from_slice(&bytes)?;
            ensure!(entry.fields == serde_json::json!({"event":"worker_budget_probe", "seq":seq}));
        }
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("archive lock poisoned"))?
            .push(serde_json::json!({
                "workload": closing.workload, "entries":verified.entries, "bytes": verified.length,
                "sha256":hex::encode(Sha256::digest(&original)),
            }));
        Ok(())
    }
}

fn process_sample(pid: u32) -> Result<serde_json::Value> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("process stat")?
        .1
        .split_whitespace()
        .collect();
    Ok(serde_json::json!({
        "pid":pid, "start_ticks":fields[19].parse::<u64>()?,
        "user_ticks":fields[11].parse::<u64>()?, "system_ticks":fields[12].parse::<u64>()?,
        "threads":std::fs::read_dir(format!("/proc/{pid}/task"))?.count(),
    }))
}

struct Sampler {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<Result<[usize; 2]>>>,
}
impl Sampler {
    fn start(pids: [u32; 2]) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let join = std::thread::spawn(move || {
            let mut peaks = [0; 2];
            while !done.load(Ordering::Acquire) {
                for (i, pid) in pids.into_iter().enumerate() {
                    peaks[i] =
                        peaks[i].max(std::fs::read_dir(format!("/proc/{pid}/task"))?.count());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(peaks)
        });
        Self {
            stop,
            join: Some(join),
        }
    }
    fn finish(mut self) -> Result<[usize; 2]> {
        self.stop.store(true, Ordering::Release);
        self.join
            .take()
            .context("missing sampler")?
            .join()
            .map_err(|_| anyhow::anyhow!("sampler panicked"))?
    }
}
impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

async fn emit_batch(socket: &Path) -> Result<(usize, usize)> {
    use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceResponse};
    let mut sent = 0;
    let mut received = 0;
    for seq in 0..EMITS {
        // Stay below the canonical per-workload audit rate; do not enlarge it
        // to turn this concurrency fixture into a successful flood.
        if seq != 0 {
            tokio::time::sleep(Duration::from_millis(75)).await;
        }
        let mut conn = tokio::net::UnixStream::connect(socket).await?;
        let call = ServiceCall {
            service: ServiceId::parse("host.audit.v1")?,
            verb: "emit".into(),
            correlation_id: CorrelationId::new("guest-supplied-ignored"),
            capability: None,
            payload: serde_json::json!({"ts":"2026-06-17T00:00:00Z", "fields":{"event":"worker_budget_probe", "seq":seq}}),
        };
        let body = serde_json::to_vec(&call)?;
        conn.write_u32(u32::try_from(body.len())?).await?;
        conn.write_all(&body).await?;
        sent += 4 + body.len();
        let n = usize::try_from(conn.read_u32().await?)?;
        ensure!(n <= 65536, "fixture response bound");
        let mut body = vec![0; n];
        conn.read_exact(&mut body).await?;
        received += 4 + n;
        let response = serde_json::from_slice::<ServiceResponse>(&body)?;
        ensure!(
            matches!(response, ServiceResponse::Ok { .. }),
            "audit refused: {response:?}"
        );
    }
    Ok((sent, received))
}

#[test]
fn native_owned_pair_signs_both_registered_chains_within_worker_budget() -> Result<()> {
    let started = Instant::now();
    let f = Fixture::new();
    let mut agent = OwnedHostAgent::spawn(f.inputs())?;
    let archives = Arc::new(Archives::default());
    let registrar = agent
        .registrar()
        .with_registration_owner(archives.clone())?;
    let (state1, socket1) = f.vm("vm-1");
    let (state2, socket2) = f.vm("vm-2");
    let mut first = register(&registrar, "vm-1", &state1, &socket1)?;
    let mut second = register(&registrar, "vm-2", &state2, &socket2)?;
    let audit = first.prepare_endpoint_audit(
        &registrar,
        &HostAgentServicesParams {
            workload_id: "vm-1",
            tenant_id: Some("local"),
            vm_name: "vm-1",
            state_dir: &state1,
            broker_listen_socket: &socket1,
            services: &[ServiceId::parse("host.audit.v1")?],
            capability_bindings: &[],
            service_proxies: &[],
        },
    )?;
    let pids = [agent.child_id()?, audit.signer_pid()];
    let before = [process_sample(pids[0])?, process_sample(pids[1])?];
    let executable_hashes: Vec<_> = pids
        .iter()
        .map(|pid| -> Result<String> {
            Ok(hex::encode(Sha256::digest(std::fs::read(format!(
                "/proc/{pid}/exe"
            ))?)))
        })
        .collect::<Result<_>>()?;
    let sampler = Sampler::start(pids);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let signing_started = Instant::now();
    let (left, right, stalled) = runtime.block_on(async {
        // Offer a partial frame alongside valid requests. Runtime pressure above
        // separately establishes deterministic overlap of both blocking slots.
        let mut partial = tokio::net::UnixStream::connect(audit.socket()).await?;
        partial.write_u32(1024).await?;
        partial.write_all(b"{").await?;
        let stalled = async {
            let mut byte = [0];
            let n = tokio::time::timeout(Duration::from_secs(2), partial.read(&mut byte)).await??;
            ensure!(n == 0, "partial signer frame was accepted");
            Ok::<_, anyhow::Error>(())
        };
        Ok::<_, anyhow::Error>(tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), emit_batch(&socket1)),
            tokio::time::timeout(Duration::from_secs(5), emit_batch(&socket2)),
            stalled
        ))
    })?;
    let signing_ns = signing_started.elapsed().as_nanos();
    let observations = (|| -> Result<_> {
        let after = [process_sample(pids[0])?, process_sample(pids[1])?];
        let peaks = sampler.finish()?;
        for i in 0..2 {
            ensure!(
                before[i]["start_ticks"] == after[i]["start_ticks"],
                "helper identity changed"
            );
            ensure!(
                executable_hashes[i]
                    == hex::encode(Sha256::digest(std::fs::read(format!(
                        "/proc/{}/exe",
                        pids[i]
                    ))?)),
                "helper executable changed"
            );
        }
        Ok((after, peaks))
    })();
    let current = audit.check_current();
    drop(audit);
    // Attempt every original retirement; retain every independent error.
    let retirement = [first.shutdown(), second.shutdown(), agent.shutdown()];
    drop(runtime);
    ensure!(
        matches!(&left, Ok(Ok(_)))
            && matches!(&right, Ok(Ok(_)))
            && stalled.is_ok()
            && observations.is_ok()
            && current.is_ok()
            && retirement.iter().all(Result::is_ok),
        "left={left:?}; right={right:?}; partial={stalled:?}; observations={observations:?}; current={current:?}; retirements={retirement:?}"
    );
    let (after, peaks) = observations?;
    let archives = archives
        .0
        .lock()
        .map_err(|_| anyhow::anyhow!("archive lock poisoned"))?;
    ensure!(archives.len() == 2);
    let mut workloads: Vec<_> = archives
        .iter()
        .map(|row| row["workload"].as_str().unwrap_or_default())
        .collect();
    workloads.sort_unstable();
    ensure!(
        workloads == ["vm-1", "vm-2"],
        "original workload archives differ"
    );
    eprintln!(
        "native_worker_budget {}",
        serde_json::json!({
            "scope":"native owned helpers, two registrations, no booted VM or installed Ready endpoint",
            "before":before, "after":after, "sampled_peak_threads":peaks, "sample_interval_ms":1,
            "executable_sha256":executable_hashes, "broker_framed_bytes_vm1":left??, "broker_framed_bytes_vm2":right??,
            "partial_signer_sent_bytes":5, "partial_signer_received_bytes":0,
            "cpu_scope":"helper /proc ticks post-registration through post-signing, excluding retirement; orchestration unit CPU reported separately",
            "signing_with_partial_frame_ns":signing_ns, "setup_to_verified_retirement_ns":started.elapsed().as_nanos(),
            "original_archives":*archives,
        })
    );
    ensure!(
        peaks
            .into_iter()
            .all(|n| n <= 1 + OWNED_ASYNC_WORKERS_PER_PROCESS + OWNED_BLOCKING_WORKERS_PER_PROCESS)
    );
    require_pair_budget()
}
