//! Original installed collector thread custody. No quota or VM authority is
//! minted by the requirement query or by physical worker completion.

use crate::installed_endpoint::InstalledEndpointComponentPermit;
use std::{
    io,
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub(super) const OWNED_COLLECTOR_STACK_BYTES: usize = 2_097_152;

/// Known requested allocations of the canonical collector, not a reservation.
/// Curated-regex construction/cache is queried and charged separately; native
/// pthread/TLS/allocator usable size and process RSS are separate domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedCollectorRequirements {
    pub threads: u8,
    pub explicit_stack_bytes: u64,
    pub known_rust_stack_bytes: u64,
    pub queued_record_bytes: u64,
    pub transient_record_bytes: u64,
    pub known_metadata_bytes: u64,
}

pub fn owned_collector_requirements() -> anyhow::Result<OwnedCollectorRequirements> {
    use mvm_core::protocol::telemetry::{
        Attribute, MAX_ATTRIBUTES, MAX_LINKS, MAX_RECORD_BYTES, TelemetryRecord,
    };
    // These supplement the source field/cardinality audit: decoded records
    // have closed nonrecursive bodies, <=16 attributes, <=8 links and bounded
    // text. Actual receiver admission additionally caps their encoded32KiB.
    anyhow::ensure!(
        usize::BITS == 64 && MAX_RECORD_BYTES == 32_768 && MAX_ATTRIBUTES == 16 && MAX_LINKS == 8,
        "unqualified owned telemetry model"
    );
    anyhow::ensure!(
        std::mem::size_of::<TelemetryRecord>() <= 512 && std::mem::size_of::<Attribute>() <= 256,
        "owned telemetry descriptor model changed"
    );
    let stack =
        mvm_core::host_lifetime::native_thread_stack_terms(OWNED_COLLECTOR_STACK_BYTES as u64)?;
    // Source Text/BoundedList ceilings plus wire-bound text leave <=64KiB
    // requested pointees per queued validated record; channel's inline value
    // and bookkeeping get an additional512B per slot. Clone length is bounded
    // independently of arbitrary caller Vec capacity by canonical containers.
    let queued_record_bytes = u64::try_from(super::WRITE_QUEUE_RECORDS)?
        .checked_mul(65_536 + 512)
        .ok_or_else(|| anyhow::anyhow!("collector queue model overflow"))?;
    // Tagged Content/JSON growth workspace (256*32KiB) plus overlapping
    // plaintext/crypto/record/scrub/held/status/path storage (2MiB).
    let transient_record_bytes = 10 * 1024 * 1024;
    Ok(OwnedCollectorRequirements {
        threads: 3,
        explicit_stack_bytes: 3 * OWNED_COLLECTOR_STACK_BYTES as u64,
        known_rust_stack_bytes: stack
            .known_rust_bytes
            .checked_mul(3)
            .ok_or_else(|| anyhow::anyhow!("collector stack model overflow"))?,
        queued_record_bytes,
        transient_record_bytes,
        known_metadata_bytes: queued_record_bytes
            .checked_add(transient_record_bytes)
            .ok_or_else(|| anyhow::anyhow!("collector metadata model overflow"))?,
    })
}

/// Maximum encoded bytes in either installed collector status generation.
/// This is a producer bound within the prepaid transient/sidecar terms, not
/// a reservation or a bound on arbitrary caller-owned Snapshot strings.
pub const OWNED_COLLECTOR_STATUS_BYTES: usize = 4096;

const OWNED_STATUS_FILE: &str =
    mvm_vmm::host::telemetry_provisioning::TELEMETRY_COLLECTOR_STATUS_FILE;
const OWNED_STATUS_SCRATCH: &str = "telemetry-collector-status.json.tmp";

fn write_owned_status(
    directory: &std::fs::File,
    snapshot: &super::CollectorStatusSnapshot,
) -> io::Result<()> {
    let mut bytes = [0u8; OWNED_COLLECTOR_STATUS_BYTES];
    let length = {
        let mut cursor = io::Cursor::new(&mut bytes[..]);
        serde_json::to_writer_pretty(&mut cursor, snapshot).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "owned telemetry status encoding refused",
            )
        })?;
        usize::try_from(cursor.position())
            .map_err(|_| io::Error::other("owned telemetry status encoding refused"))?
    };
    // No path/tmp/file effect precedes complete bounded serialization.
    crate::installed_endpoint::publish_runtime_sidecar(
        directory,
        OWNED_STATUS_FILE,
        OWNED_STATUS_SCRATCH,
        &bytes[..length],
    )
    .map_err(|_| io::Error::other("owned telemetry status write refused"))
}

fn stop_transport(stop: &AtomicBool, active: &Mutex<Option<UnixStream>>, failed: &AtomicBool) {
    stop.store(true, Ordering::Release);
    // Serialized with the reader's original cancellation-socket publication.
    // No socket operation is performed while holding that state mutex.
    let stream = match active.lock() {
        Ok(mut active) => active.take(),
        Err(poison) => {
            failed.store(true, Ordering::Release);
            poison.into_inner().take()
        }
    };
    if let Some(stream) = stream {
        // Darwin can report NotConnected on Both after one FIN while the
        // reverse half remains writable. Preserve the canonical fallback.
        if stream.shutdown(Shutdown::Both).is_err() {
            let _ = stream.shutdown(Shutdown::Write);
            let _ = stream.shutdown(Shutdown::Read);
        }
    }
}

fn fail_status(stop: &AtomicBool, active: &Mutex<Option<UnixStream>>, failed: &AtomicBool) {
    failed.store(true, Ordering::Release);
    stop_transport(stop, active, failed);
}

/// Retains the three original collector threads and actual cancellation socket.
/// An unfinished/error Drop cannot release its original component permit.
pub struct OwnedEmbeddedCollector {
    custody: Option<Custody>,
}

struct Custody {
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Option<UnixStream>>>,
    threads: [Option<JoinHandle<()>>; 3],
    permit: Option<Arc<InstalledEndpointComponentPermit>>,
    failed: Arc<AtomicBool>,
}

impl Custody {
    fn request_stop(&mut self) {
        stop_transport(&self.stop, &self.active, &self.failed);
        for thread in self.threads.iter().flatten() {
            thread.thread().unpark();
        }
    }

    fn collect_finished(&mut self) -> bool {
        for thread in &mut self.threads {
            if thread.as_ref().is_some_and(JoinHandle::is_finished) {
                // The original std handle is consumed only after positive
                // completion; no join holds a ledger or cancellation mutex.
                if thread
                    .take()
                    .expect("checked original handle")
                    .join()
                    .is_err()
                {
                    self.failed.store(true, Ordering::Release);
                }
            }
        }
        self.threads.iter().all(Option::is_none)
    }
}

impl OwnedEmbeddedCollector {
    pub fn close_and_join(&mut self, deadline: Instant) -> io::Result<()> {
        let Some(custody) = &mut self.custody else {
            return Ok(());
        };
        custody.request_stop();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "owned collector cleanup deadline")
                })?;
            if custody.collect_finished() {
                if custody.failed.load(Ordering::Acquire) {
                    return Err(io::Error::other("owned collector cleanup failed"));
                }
                // A completed component never replenishes the monotonic Aux
                // subdivision; the parent partition remains separately held.
                custody.permit.take();
                self.custody.take();
                return Ok(());
            }
            std::thread::park_timeout(remaining.min(Duration::from_millis(1)));
        }
    }
}

impl Drop for OwnedEmbeddedCollector {
    fn drop(&mut self) {
        if let Some(mut custody) = self.custody.take() {
            custody.request_stop();
            let complete = custody.collect_finished();
            if !complete || custody.failed.load(Ordering::Acquire) {
                // At most ONE collector claim per original Resources. This
                // bounded quarantine retains actual permit/handles until
                // process exit, without detaching/refunding or a reaper.
                std::mem::forget(custody);
            }
        }
    }
}

/// Provisional logical requested-workspace model for the fixed canonical scanner.
/// Engine controls alone are not a whole heap bound. The pinned-source and
/// requested-allocator witness gate is recorded separately before activation.
/// This read-only quote grants no quota or admission; the embedding must retain
/// an actual same-pool reservation before constructing the collector.
pub fn owned_scanner_requested_bytes(
    policy: &mvm_core::policy::RedactionPolicy,
) -> anyhow::Result<u64> {
    let facts = crate::stream::redact::StreamRedaction::owned_pii_requirements(policy)?;
    checked_owned_scanner_facts(facts)
}

fn checked_owned_scanner_facts(facts: mvm_core::pii::OwnedPiiRequirements) -> anyhow::Result<u64> {
    anyhow::ensure!(
        (1..=5).contains(&facts.rule_count)
            && facts.rule_count.checked_add(1) == Some(facts.regex_objects)
            && facts.nfa_size_limit_bytes == 524_288
            && facts.rule_nfa_size_limit_bytes == 131_072
            && facts.dfa_cache_limit_bytes == 262_144
            && facts.nest_limit == 64
            && facts.max_concurrent_searches == 1,
        "unqualified owned collector scanner controls"
    );
    let set_nfa = u64::try_from(facts.nfa_size_limit_bytes)?;
    let rule_nfa = u64::try_from(facts.rule_nfa_size_limit_bytes)?;
    let cache = u64::try_from(facts.dfa_cache_limit_bytes)?;
    let rules = u64::try_from(facts.rule_count)?;
    let overflow = || anyhow::anyhow!("owned scanner working envelope overflow");
    let engine = |nfa: u64| {
        nfa.checked_mul(8)
            .and_then(|bytes| cache.checked_mul(2).and_then(|d| bytes.checked_add(d)))
            .and_then(|bytes| bytes.checked_add(1_048_576 + 40_960))
    };
    let set = engine(set_nfa).ok_or_else(overflow)?;
    let all_rules = engine(rule_nfa)
        .and_then(|bytes| bytes.checked_mul(rules))
        .ok_or_else(overflow)?;
    let compiler = set_nfa
        .max(rule_nfa)
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(1_048_576))
        .ok_or_else(overflow)?;
    set.checked_add(all_rules)
        .and_then(|bytes| bytes.checked_add(compiler))
        .ok_or_else(overflow)
}

pub(crate) struct OwnedCollectorStart<'a> {
    pub vm: &'a str,
    pub config: &'a super::TelemetryEmbedConfig,
    pub redaction: &'a mvm_core::policy::RedactionPolicy,
    pub fingerprints: Vec<mvm_contract::stream::secret_fingerprint::SecretFingerprint>,
    pub permit: InstalledEndpointComponentPermit,
    pub records: mvm_vmm::host::network_endpoint_spawn::InstalledTelemetryRecords,
    pub anchor: std::fs::File,
    pub state_directory: Arc<std::fs::File>,
    pub audit: mvm_vmm::host::network_endpoint_spawn::InstalledEndpointAudit,
    pub deadline: Instant,
}

pub(crate) fn start_owned(
    input: OwnedCollectorStart<'_>,
) -> anyhow::Result<OwnedEmbeddedCollector> {
    use super::*;
    use anyhow::Context as _;
    use std::{io::Read, sync::mpsc};
    anyhow::ensure!(
        Instant::now() < input.deadline,
        "owned collector startup expired"
    );
    input.permit.check_current()?;
    input.audit.check_current()?;
    anyhow::ensure!(
        input.permit.has_original_audit(&input.audit)
            && input.audit.socket() == input.config.signer_sock
            && input.audit.vm() == input.vm,
        "owned collector original audit target differs"
    );
    anyhow::ensure!(
        input.vm.len() <= 256
            && input.config.records_key_b64.len() <= 64
            && [
                &input.config.state_dir,
                &input.config.telemetry_sock,
                &input.config.signer_sock,
                &input.config.host_anchor_path
            ]
            .into_iter()
            .all(|path| path.as_os_str().len() <= 4096),
        "owned collector configuration exceeds bound"
    );
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None));
    let failed = Arc::new(AtomicBool::new(false));
    let permit = Arc::new(input.permit);
    // Install actual permit custody BEFORE any file effect or thread spawn.
    let mut owned = OwnedEmbeddedCollector {
        custody: Some(Custody {
            stop: stop.clone(),
            active: active.clone(),
            threads: [None, None, None],
            permit: Some(permit.clone()),
            failed: failed.clone(),
        }),
    };
    let mut anchor_file = input.anchor;
    anyhow::ensure!(
        anchor_file.metadata()?.is_file() && anchor_file.metadata()?.len() == 32,
        "owned collector anchor differs"
    );
    let mut anchor_bytes = [0; 32];
    anchor_file
        .read_exact(&mut anchor_bytes)
        .context("reading owned collector anchor")?;
    anyhow::ensure!(
        anchor_file.read(&mut [0; 1])? == 0,
        "owned collector anchor grew"
    );
    let host_anchor =
        VerifyingKey::from_bytes(&anchor_bytes).context("invalid owned collector anchor")?;
    let records = CappedJsonlSink::over(
        input.records,
        input.config.records_byte_cap,
        input.config.records_key()?,
    )
    .context("binding original owned encrypted telemetry records")?;
    let losses = Arc::new(LossCounters::default());
    let status = Arc::new(Mutex::new(CoverageStatus::Connecting));
    let state_directory = input.state_directory;
    if let Err(error) = write_owned_status(
        &state_directory,
        &super::status_snapshot(input.vm, &CoverageStatus::Connecting, HostLosses::default()),
    ) {
        permit.fence();
        fail_status(&stop, &active, &failed);
        return Err(error.into());
    }
    let (queue, writer) = QueuedSink::spawn_owned(input.vm, records, losses.clone())?;
    owned.custody.as_mut().expect("original custody").threads[1] = Some(writer);
    let audit = input.audit;
    let config = input.config.clone();
    let vm = input.vm.to_owned();
    let policy = input.redaction.clone();
    let fingerprints = input.fingerprints;
    let status_active = active.clone();
    let worker_status = status.clone();
    let worker_losses = losses.clone();
    let worker_stop = stop.clone();
    let (started, started_rx) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name(format!("mvm-telemetry-collector-{vm}"))
        .stack_size(OWNED_COLLECTOR_STACK_BYTES)
        .spawn(move || {
            // Construct AND search on this SAME original worker. No scanner
            // clone or thread migration can multiply retained search caches.
            let redaction = match crate::stream::redact::StreamRedaction::curated_owned(&policy) {
                Ok(redaction) => redaction,
                Err(_) => {
                    let _ = started.send(false);
                    return;
                }
            };
            let sink = ScrubbingSink::new(fingerprints, redaction, queue, worker_losses.clone());
            let telemetry_sock = config.telemetry_sock.clone();
            let mux = PathBuf::from(mvm_agentd::vsock::vsock_uds_path(
                &config.state_dir.to_string_lossy(),
            ));
            let connector_stop = worker_stop.clone();
            let connector = move || {
                connect_owned(
                    &telemetry_sock,
                    &mux,
                    connector_stop.clone(),
                    active.clone(),
                )
            };
            let signer_sock = config.signer_sock.clone();
            let signer =
                move |hello: &SessionHello,
                      ack: &SessionHelloAck|
                      -> Result<Signature, mvm_core::net::session::SessionError> {
                    let refused = || {
                        mvm_core::net::session::SessionError::InvalidHandshake(
                            "owned telemetry signer refused".into(),
                        )
                    };
                    let client =
                        crate::audit_signer::helper_client::SignerHelperClient::new(&signer_sock)
                            .with_original_child(audit.signer_pid());
                    client
                        .sign_owned_telemetry_handshake(
                            &audit,
                            hello,
                            ack,
                            &host_anchor,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .map_err(|_| refused())
                };
            let shared = WorkerShared {
                status: worker_status,
                losses: worker_losses,
                stop: worker_stop,
            };
            let config = CollectorConfig::new(config.state_dir, vm, host_anchor, connector, signer);
            if started.send(true).is_ok() {
                run_worker(config, sink, &shared);
            }
        })?;
    owned.custody.as_mut().expect("original custody").threads[0] = Some(worker);
    let left = input
        .deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .context("owned collector startup expired")?;
    anyhow::ensure!(
        started_rx
            .recv_timeout(left)
            .context("owned collector startup incomplete")?,
        "owned collector scanner refused startup"
    );
    anyhow::ensure!(
        Instant::now() < input.deadline,
        "owned collector startup expired"
    );
    let vm = input.vm.to_owned();
    let status_thread = std::thread::Builder::new()
        .name(format!("mvm-telemetry-status-{vm}"))
        .stack_size(OWNED_COLLECTOR_STACK_BYTES)
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                std::thread::park_timeout(Duration::from_secs(1));
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let current = status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                if write_owned_status(
                    &state_directory,
                    &super::status_snapshot(&vm, &current, losses.snapshot()),
                )
                .is_err()
                {
                    permit.fence();
                    fail_status(&stop, &status_active, &failed);
                    break;
                }
            }
        })?;
    owned.custody.as_mut().expect("original custody").threads[2] = Some(status_thread);
    Ok(owned)
}

struct OwnedTelemetryStream {
    stream: UnixStream,
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Option<UnixStream>>>,
    handshake_deadline: Option<Instant>,
}
impl OwnedTelemetryStream {
    fn remaining(&self) -> io::Result<Option<Duration>> {
        if self.stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned collector stopped",
            ));
        }
        self.handshake_deadline
            .map(|deadline| {
                deadline
                    .checked_duration_since(Instant::now())
                    .filter(|left| !left.is_zero())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::TimedOut, "owned telemetry connect deadline")
                    })
            })
            .transpose()
    }
}
impl io::Read for OwnedTelemetryStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(self.remaining()?)?;
        io::Read::read(&mut self.stream, bytes)
    }
}
impl io::Write for OwnedTelemetryStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(self.remaining()?)?;
        io::Write::write(&mut self.stream, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.stream)
    }
}
impl Drop for OwnedTelemetryStream {
    fn drop(&mut self) {
        match self.active.lock() {
            Ok(mut active) => {
                active.take();
            }
            Err(poison) => {
                poison.into_inner().take();
            }
        }
    }
}

fn connect_owned(
    per_port: &std::path::Path,
    mux: &std::path::Path,
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Option<UnixStream>>>,
) -> io::Result<OwnedTelemetryStream> {
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "owned collector stopped",
        ));
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| io::Error::other("owned telemetry deadline overflow"))?;
    let (stream, needs_mux) = match mvm_agentd::vsock::connect_unix_before(per_port, deadline) {
        Ok(stream) => (stream, false),
        Err(_) if mux.exists() => (
            mvm_agentd::vsock::connect_unix_before(mux, deadline)
                .map_err(|_| io::Error::other("owned telemetry mux unavailable"))?,
            true,
        ),
        Err(_) => return Err(io::Error::other("owned telemetry peer unavailable")),
    };
    let cancel = stream.try_clone()?;
    {
        let mut registered = active
            .lock()
            .map_err(|_| io::Error::other("owned collector cancellation state poisoned"))?;
        // Serialized with request_stop's take: a late connection either
        // refuses here or is present when stop takes/shuts the exact socket.
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned collector stopped",
            ));
        }
        *registered = Some(cancel);
    }
    let mut owned = OwnedTelemetryStream {
        stream,
        stop,
        active,
        handshake_deadline: Some(deadline),
    };
    if needs_mux {
        mvm_agentd::vsock::complete_connect_handshake(
            &mut owned,
            mvm_core::protocol::telemetry::TELEMETRY_PORT,
        )
        .map_err(|_| io::Error::other("owned telemetry mux handshake refused"))?;
    }
    owned.remaining()?;
    owned.handshake_deadline = None;
    owned.stream.set_read_timeout(None)?;
    owned.stream.set_write_timeout(None)?;
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::unix::net::UnixStream,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    fn status_snapshot(vm: String) -> super::super::CollectorStatusSnapshot {
        super::super::CollectorStatusSnapshot {
            vm_name: vm,
            status: "collecting".into(),
            generation: Some(u64::MAX),
            shed: u64::MAX,
            losses: mvm_core::protocol::telemetry::served::HostLosses::default(),
        }
    }

    #[test]
    fn owned_status_caps_before_tmp_or_current_file_effects_without_echoing_input() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(OWNED_STATUS_FILE);
        let directory = std::fs::File::open(root.path()).unwrap();
        std::fs::write(&path, b"original status").unwrap();
        let snapshot = status_snapshot(format!("SYNTHETIC_PRIVATE_STATUS{}", "x".repeat(4096)));
        let error = write_owned_status(&directory, &snapshot).unwrap_err();
        assert!(!error.to_string().contains("SYNTHETIC_PRIVATE_STATUS"));
        assert_eq!(std::fs::read(&path).unwrap(), b"original status");
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn owned_status_exact_4096_boundary_preserves_canonical_pretty_bytes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(OWNED_STATUS_FILE);
        let directory = std::fs::File::open(root.path()).unwrap();
        let mut snapshot = status_snapshot(String::new());
        let base = serde_json::to_vec_pretty(&snapshot).unwrap().len();
        snapshot.vm_name = "x".repeat(4096 - base);
        let expected = serde_json::to_vec_pretty(&snapshot).unwrap();
        assert_eq!(expected.len(), 4096);
        write_owned_status(&directory, &snapshot).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        snapshot.vm_name.push('x');
        assert!(write_owned_status(&directory, &snapshot).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn owned_status_supported_fields_and_maximum_loss_counters_fit_the_cap() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(OWNED_STATUS_FILE);
        let directory = std::fs::File::open(root.path()).unwrap();
        // Conservative compatibility case: every byte of the already capped
        // VM name needs six encoded bytes, all counters have maximum width,
        // and the status text exceeds the canonical static coverage codes.
        let mut snapshot = status_snapshot("\0".repeat(256));
        snapshot.status = format!("degraded:{}", "x".repeat(256));
        let mut losses = serde_json::to_value(snapshot.losses).unwrap();
        let counters = losses.as_object_mut().unwrap();
        assert!(!counters.is_empty());
        for value in counters.values_mut() {
            assert!(value.is_u64());
            *value = u64::MAX.into();
        }
        snapshot.losses = serde_json::from_value(losses).unwrap();
        let expected = serde_json::to_vec_pretty(&snapshot).unwrap();
        assert!(expected.len() < OWNED_COLLECTOR_STATUS_BYTES);
        write_owned_status(&directory, &snapshot).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), expected);
    }

    #[test]
    fn owned_status_serialization_escape_growth_is_counted_and_io_errors_are_static() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(OWNED_STATUS_FILE);
        let directory = std::fs::File::open(root.path()).unwrap();
        let snapshot = status_snapshot("\n".repeat(2048));
        assert!(write_owned_status(&directory, &snapshot).is_err());
        assert!(!path.exists());
        assert!(!path.with_extension("json.tmp").exists());
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        let error = write_owned_status(&directory, &status_snapshot("vm-1".into())).unwrap_err();
        assert!(
            !error
                .to_string()
                .contains(&root.path().display().to_string())
        );
        assert!(!path.exists());
    }

    #[test]
    fn owned_status_failure_wakes_original_reader_and_successful_joins_keep_failure() {
        let (mut collector, _release) = fixture(false, false);
        let custody = collector.custody.as_ref().unwrap();
        fail_status(&custody.stop, &custody.active, &custody.failed);
        assert!(custody.stop.load(Ordering::Acquire));
        assert!(custody.active.lock().unwrap().is_none());
        assert!(
            collector
                .close_and_join(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        assert!(
            collector
                .custody
                .as_ref()
                .unwrap()
                .threads
                .iter()
                .all(Option::is_none)
        );
        assert!(
            collector
                .close_and_join(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        // Controlled fixture has no quota permit. Retain neither actual
        // threads nor test-only empty custody after the negative assertions.
        collector.custody.take();
    }

    #[test]
    fn owned_collector_has_actual_original_context_start_entry() {
        let _ = crate::installed_endpoint::InstalledEndpointResources::start_owned_collector;
        let _ = mvm_vmm::host::network_endpoint_spawn::InstalledEndpointChild::startup_deadline;
    }

    #[test]
    fn stopped_collector_refuses_before_opening_another_actual_socket() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("peer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(true));
        let active = Arc::new(Mutex::new(None));
        assert!(
            matches!(connect_owned(&path, &root.path().join("mux.sock"), stop, active.clone()), Err(error) if error.kind() == io::ErrorKind::Interrupted)
        );
        assert!(active.lock().unwrap().is_none());
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }

    fn fixture(
        block_writer: bool,
        panic_writer: bool,
    ) -> (OwnedEmbeddedCollector, mpsc::Sender<()>) {
        let stop = Arc::new(AtomicBool::new(false));
        let (mut reader, peer) = UnixStream::pair().unwrap();
        let active = Arc::new(Mutex::new(Some(reader.try_clone().unwrap())));
        let reader = thread::spawn(move || {
            let mut byte = [0];
            let _peer = peer;
            let _ = reader.read(&mut byte);
        });
        let (release, wait) = mpsc::channel();
        let writer_stop = stop.clone();
        let writer = thread::spawn(move || {
            assert!(!panic_writer, "controlled writer panic");
            if block_writer {
                let _ = wait.recv();
            }
            while !writer_stop.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(1));
            }
        });
        let status_stop = stop.clone();
        let status = thread::spawn(move || {
            while !status_stop.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(1));
            }
        });
        // Physical thread-custody fixture only. It does not construct a parent
        // permit or establish actual installed resource admission.
        (
            OwnedEmbeddedCollector {
                custody: Some(Custody {
                    stop,
                    active,
                    threads: [Some(reader), Some(writer), Some(status)],
                    permit: None,
                    failed: Arc::new(AtomicBool::new(false)),
                }),
            },
            release,
        )
    }

    #[test]
    fn owned_collector_query_counts_all_three_stacks_and_decoded_queue() {
        let facts = owned_collector_requirements().unwrap();
        assert_eq!(facts.threads, 3);
        assert_eq!(facts.explicit_stack_bytes, 3 * 2_097_152);
        assert!(facts.known_rust_stack_bytes > facts.explicit_stack_bytes);
        assert_eq!(facts.queued_record_bytes, 256 * (65_536 + 512));
        assert!(facts.transient_record_bytes >= 8 * 1024 * 1024);
    }

    #[test]
    fn owned_collector_closes_actual_quiet_reader_and_collects_all_original_threads() {
        let (mut collector, _release) = fixture(false, false);
        collector
            .close_and_join(Instant::now() + Duration::from_secs(1))
            .unwrap();
        collector.close_and_join(Instant::now()).unwrap();
        assert!(collector.custody.is_none());
        collector
            .close_and_join(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn blocked_writer_retains_original_handle_after_deadline_then_collects_same_handle() {
        let (mut collector, release) = fixture(true, false);
        assert_eq!(
            collector
                .close_and_join(Instant::now() + Duration::from_millis(5))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(collector.custody.as_ref().unwrap().threads[1].is_some());
        release.send(()).unwrap();
        collector
            .close_and_join(Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert!(collector.custody.is_none());
    }

    #[test]
    fn panic_is_failed_cleanup_and_expired_cap_never_proves_completion() {
        let (mut collector, _release) = fixture(false, true);
        assert!(
            collector
                .close_and_join(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        assert!(
            collector
                .close_and_join(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        let (mut collector, _release) = fixture(false, false);
        assert_eq!(
            collector.close_and_join(Instant::now()).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        collector
            .close_and_join(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }
}

#[cfg(test)]
#[path = "owned_dual_model_tests.rs"]
mod dual_model_tests;
