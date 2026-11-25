//! Ledger, session stop and plan-bound audit composition in a local fixture.

use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Instant;

use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::audit_sink::AuditContext;
use mvm_core::host_interface::{HostInterfaceError, error::Denial, workload::WorkloadChange};
use mvm_core::plan::{sign_plan, test_support::PlanFixture, verify_plan, verify_plan_id};

use super::audit_boundary_tests::verify_tcp_exchange;
use super::tests::{
    fresh_keys, gate_allowing_addr, local_test_ip, read_flowmux_frame, write_frame,
};
use super::*;
use crate::policy_generation::workload_store::OwnedWorkloadStore;
use crate::supervisor::audit::{
    audit_file::{FileAuditSigner, verify_audit_chain_entries},
    audit_recorder::Recorder,
    bound_sink::BoundRecorder,
    signer::{AuditError, AuditSigner, PlanAuditEntry},
};
use crate::supervisor::endpoint::epoch_admission::{
    EndpointEpochGate, REVOKED_EVENT, UNREADABLE_LEDGER_GRACE,
};

const WORKLOAD: &str = "epoch-closure-unit";
const FIXTURE_POLL: Duration = Duration::from_millis(5);
const CLOSURE_BOUND: Duration = Duration::from_secs(1);
const EARLIER_AUDIT_EVENT: &str = "host.flow.fixture_pending";

struct HeldAuditSigner {
    file: FileAuditSigner,
    entered: mpsc::SyncSender<String>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[async_trait::async_trait]
impl AuditSigner for HeldAuditSigner {
    async fn sign_and_emit(&self, entry: &PlanAuditEntry) -> Result<(), AuditError> {
        if matches!(entry.event.as_str(), EARLIER_AUDIT_EVENT | REVOKED_EVENT) {
            self.entered
                .try_send(entry.event.clone())
                .map_err(|error| AuditError::Io(error.to_string()))?;
            // Test-only fault injection before the existing signer appends.
            // BoundRecorder still owns the original plan and this call.
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| AuditError::Io(error.to_string()))?;
        }
        self.file.sign_and_emit(entry).await
    }
}

struct OpenFlow {
    guest: UnixStream,
    session: Session,
    upstream: TcpStream,
    stop: UnixStream,
    host: JoinHandle<Result<(), FlowMuxError>>,
}

fn open_flow(epoch: &EndpointEpochGate, sink: Arc<dyn AuditSink>) -> OpenFlow {
    let listener = TcpListener::bind((local_test_ip(), 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = listener.local_addr().unwrap();
    let gate = gate_allowing_addr(target.ip(), target.port(), None)
        .with_admission(epoch.clone().into_check());
    let (host_key, host_verify) = fresh_keys();
    let (guest_key, guest_verify) = fresh_keys();
    let (transport, mut guest) = UnixStream::pair().unwrap();
    let stop = transport.try_clone().unwrap();
    let host = std::thread::spawn(move || {
        FlowMuxSession::accept_with(
            transport,
            FlowMuxAccept::new(
                "epoch-closure",
                host_key,
                guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .with_audit_sink(sink),
        )?
        .serve()
    });
    let timeout = Some(Duration::from_secs(2));
    guest.set_read_timeout(timeout).unwrap();
    guest.set_write_timeout(timeout).unwrap();
    let (mut session, _) = Session::guest(&mut guest, guest_key, &host_verify).unwrap();
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Hello,
        0,
        &Handshake::local("epoch-closure").encode(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::HelloAck
    );
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        1,
        target.to_string().as_bytes(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Opened
    );
    let (upstream, _) = listener.accept().unwrap();
    upstream.set_nonblocking(false).unwrap();
    upstream.set_read_timeout(timeout).unwrap();
    upstream.set_write_timeout(timeout).unwrap();
    OpenFlow {
        guest,
        session,
        upstream,
        stop,
        host,
    }
}

fn ledger_closes_flow_and_preserves_audit(change: WorkloadChange, expected: Denial) {
    let setup_start = Instant::now();
    let home = tempfile::tempdir().unwrap();
    let owner = OwnedWorkloadStore::open(home.path()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let handle = runtime.handle().clone();
    let plan = PlanFixture::new().workload(WORKLOAD).build();
    let (plan_key, plan_verify) = fresh_keys();
    let signed = sign_plan(&plan, &plan_key, "epoch-fixture");
    let plan = verify_plan(&signed, &[("epoch-fixture", &plan_verify)]).unwrap();
    verify_plan_id(&plan).unwrap();
    let epoch = ExecutionEpoch::new(plan.execution_epoch).unwrap();
    assert_eq!(epoch, ExecutionEpoch::FIRST);
    let gate = EndpointEpochGate::new(home.path().to_path_buf(), plan.workload.0.clone(), epoch);
    gate.admit().unwrap();

    let (audit_key, audit_verify) = fresh_keys();
    let path = home.path().join("audit.jsonl");
    let (entered, pending) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let recorder = Arc::new(Recorder::new(
        Arc::new(HeldAuditSigner {
            file: FileAuditSigner::open_file(audit_key, &path).unwrap(),
            entered,
            release: Mutex::new(resume),
        }),
        plan.tenant.clone(),
    ));
    let context = AuditContext::Workload {
        plan: Box::new(plan.clone()),
    };
    let health_path = BoundRecorder::health_path(home.path(), &context).unwrap();
    let sink: Arc<dyn AuditSink> = Arc::new(
        BoundRecorder::builder(Arc::clone(&recorder), handle.clone(), context)
            .health_file(health_path)
            .build()
            .unwrap(),
    );
    recorder.bind_audit_sink(&sink).unwrap();
    let mut flow = open_flow(&gate, Arc::clone(&sink));
    let setup_time = setup_start.elapsed();
    let transfer_start = Instant::now();
    let traffic = verify_tcp_exchange(&mut flow.guest, &mut flow.session, &mut flow.upstream);
    let transfer_time = transfer_start.elapsed();
    let before_bytes = std::fs::read(&path).unwrap();
    let before = verify_audit_chain_entries(&path, &audit_verify).unwrap();
    assert!(
        before
            .iter()
            .any(|entry| entry.event == "host.flow.allowed")
    );
    assert!(before.iter().all(|entry| entry.event != REVOKED_EVENT));

    // Hold another plan-bound audit call before committing the ledger change.
    // This occupies the real BoundRecorder, as well as the underlying signer.
    let busy_sink = Arc::clone(&sink);
    let earlier_write =
        std::thread::spawn(move || busy_sink.record(EARLIER_AUDIT_EVENT, BTreeMap::new()));
    assert_eq!(
        pending.recv_timeout(Duration::from_secs(2)).unwrap(),
        EARLIER_AUDIT_EVENT
    );
    let stop = flow.stop;
    let (detected, refusal) = mpsc::sync_channel(1);
    let watch = gate
        .watch(FIXTURE_POLL, UNREADABLE_LEDGER_GRACE, move |gate, error| {
            // The watcher holds the original carrier and stops it before
            // entering the audit path. The test thread only observes closure.
            let stopped = stop.shutdown(Shutdown::Both);
            let _ = detected.send((error.to_string(), stopped));
            gate.record_revocation(Some(&recorder), &handle, &error);
        })
        .unwrap();
    // On a failing assertion release the sender before joining the watch.
    let release = release;
    let change_start = Instant::now();
    let deadline = change_start + CLOSURE_BOUND;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .expect("closure deadline expired")
    };
    owner.commit(&change).unwrap();
    let expected = HostInterfaceError::Denied(expected).to_string();
    let (received, stopped) = refusal.recv_timeout(remaining()).unwrap();
    assert_eq!(received, expected);
    stopped.unwrap();
    flow.guest.set_read_timeout(Some(remaining())).unwrap();
    assert_eq!(flow.guest.read(&mut [0]).unwrap(), 0);
    flow.upstream.set_read_timeout(Some(remaining())).unwrap();
    assert_eq!(flow.upstream.read(&mut [0]).unwrap(), 0);
    let closure_time = change_start.elapsed();
    assert!(Instant::now() <= deadline);
    assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
    assert!(!earlier_write.is_finished());
    assert!(!flow.host.is_finished());

    // Complete the already-held record, then observe the watcher handing its
    // revocation to the same signer. Its record remains held at this stage.
    release.send(()).unwrap();
    earlier_write.join().unwrap().unwrap();
    assert_eq!(
        pending.recv_timeout(Duration::from_secs(2)).unwrap(),
        REVOKED_EVENT
    );
    let prior_bytes = std::fs::read(&path).unwrap();
    assert!(prior_bytes.starts_with(&before_bytes));
    let prior = verify_audit_chain_entries(&path, &audit_verify).unwrap();
    let (earlier, history) = prior.split_last().unwrap();
    assert_eq!(history, before);
    assert_eq!(earlier.event, EARLIER_AUDIT_EVENT);
    assert_eq!(earlier.plan_id, plan.plan_id);
    assert_eq!(earlier.tenant, plan.tenant);
    release.send(()).unwrap();
    drop(watch);
    flow.host.join().unwrap().unwrap();

    let after = verify_audit_chain_entries(&path, &audit_verify).unwrap();
    let (revocation, history) = after.split_last().unwrap();
    assert_eq!(history, prior);
    assert_eq!(revocation.event, REVOKED_EVENT);
    assert_eq!(revocation.plan_id, plan.plan_id);
    assert_eq!(revocation.tenant, plan.tenant);
    assert_eq!(revocation.labels["workload"], plan.workload.0);
    assert_eq!(
        revocation.labels["execution_epoch"],
        epoch.get().to_string()
    );
    assert_eq!(revocation.labels["reason"], "execution_not_admitted");
    assert_eq!(revocation.labels["detail"], expected);
    let final_bytes = std::fs::read(&path).unwrap();
    assert!(final_bytes.starts_with(&prior_bytes));
    let earlier_signed_bytes = prior_bytes.len() - before_bytes.len();
    let signed_bytes = final_bytes.len() - prior_bytes.len();
    eprintln!(
        "payload_out={} payload_in={} carrier_out={} carrier_in={} setup_us={} transfer_us={} closure_us={} lifecycle_us={} earlier_signed_bytes={earlier_signed_bytes} signed_bytes={signed_bytes}",
        traffic.payload_out,
        traffic.payload_in,
        traffic.carrier_out,
        traffic.carrier_in,
        setup_time.as_micros(),
        transfer_time.as_micros(),
        closure_time.as_micros(),
        setup_start.elapsed().as_micros(),
    );
}

#[test]
fn replacement_watcher_closes_tcp_while_signed_audit_is_stalled() {
    ledger_closes_flow_and_preserves_audit(
        WorkloadChange::Replace {
            workload: WORKLOAD.into(),
            from_epoch: ExecutionEpoch::FIRST,
        },
        Denial::StaleEpoch { got: 1, current: 2 },
    );
}

#[test]
fn quarantine_watcher_closes_tcp_while_signed_audit_is_stalled() {
    ledger_closes_flow_and_preserves_audit(
        WorkloadChange::Quarantine {
            workload: WORKLOAD.into(),
        },
        Denial::WorkloadQuarantined(WORKLOAD.into()),
    );
}
