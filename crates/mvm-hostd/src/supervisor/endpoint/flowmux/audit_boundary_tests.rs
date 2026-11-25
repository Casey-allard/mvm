//! Additional refusal and cleanup witnesses through authenticated sessions.

use std::io::Write;
use std::net::Shutdown;
use std::sync::mpsc;
use std::time::Instant;

use super::audit_tests::CapturingSink;
use super::tests::{
    build_dns_query, fresh_keys, gate_allowing_addr, gate_pinning_name, local_test_ip,
    read_flowmux_frame, run_session_from, write_frame,
};
use super::*;

struct FailedFlush(CapturingSink);

impl AuditSink for FailedFlush {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> std::io::Result<()> {
        self.0.record(event, labels)
    }

    fn suppress_denial(&self) {
        self.0.suppress_denial();
    }

    fn flush_health(&self) -> std::io::Result<()> {
        Err(std::io::Error::other("injected health flush failure"))
    }
}

struct CleanupWitness {
    sink: CapturingSink,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl AuditSink for CleanupWitness {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> std::io::Result<()> {
        self.sink.record(event, labels)
    }

    fn suppress_denial(&self) {
        self.sink.suppress_denial();
    }

    fn flush_health(&self) -> std::io::Result<()> {
        self.entered.send(()).map_err(std::io::Error::other)?;
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .map_err(std::io::Error::other)?;
        self.sink.flush_health()
    }
}

struct MeteredCarrier<'a> {
    stream: &'a mut UnixStream,
    written: usize,
    read: usize,
}

impl Read for MeteredCarrier<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let received = self.stream.read(bytes)?;
        self.read += received;
        Ok(received)
    }
}

impl Write for MeteredCarrier<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.stream.write(bytes)?;
        self.written += written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

pub(super) struct VerifiedExchange {
    pub(super) payload_out: usize,
    pub(super) payload_in: usize,
    pub(super) carrier_out: usize,
    pub(super) carrier_in: usize,
}

pub(super) fn verify_tcp_exchange(
    guest: &mut UnixStream,
    session: &mut Session,
    upstream: &mut std::net::TcpStream,
) -> VerifiedExchange {
    const REQUEST: &[u8] = b"close-check\0\0";
    let reply = b"reply\0\0";
    let mut carrier = MeteredCarrier {
        stream: guest,
        written: 0,
        read: 0,
    };
    write_frame(&mut carrier, session, Opcode::Data, 1, REQUEST);
    let mut received = [0; REQUEST.len()];
    upstream.read_exact(&mut received).unwrap();
    assert_eq!(&received, REQUEST);
    let (opcode, stream, _) = read_flowmux_frame(&mut carrier, session);
    assert_eq!((opcode, stream), (Opcode::WindowUpdate, 1));
    upstream.write_all(reply).unwrap();
    let mut returned = Vec::with_capacity(reply.len());
    while returned.len() < reply.len() {
        let (opcode, stream, data) = read_flowmux_frame(&mut carrier, session);
        assert_eq!((opcode, stream), (Opcode::Data, 1));
        assert!(!data.is_empty());
        returned.extend_from_slice(&data);
    }
    assert_eq!(&returned, reply);
    VerifiedExchange {
        payload_out: received.len(),
        payload_in: returned.len(),
        carrier_out: carrier.written,
        carrier_in: carrier.read,
    }
}

#[test]
fn session_completion_closes_tcp_before_flushing_health() {
    let setup_start = Instant::now();
    let listener = std::net::TcpListener::bind((local_test_ip(), 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = listener.local_addr().unwrap();
    let gate = gate_allowing_addr(target.ip(), target.port(), None);
    let (entered, flushing) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(Arc::new(
                CleanupWitness {
                    sink: CapturingSink::default(),
                    entered,
                    release: Mutex::new(resume),
                },
            ))
        });
    let io_timeout = Some(Duration::from_secs(2));
    guest.set_read_timeout(io_timeout).unwrap();
    guest.set_write_timeout(io_timeout).unwrap();
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
    let (mut upstream, _) = listener.accept().unwrap();
    upstream.set_nonblocking(false).unwrap();
    upstream.set_read_timeout(io_timeout).unwrap();
    upstream.set_write_timeout(io_timeout).unwrap();
    let setup_time = setup_start.elapsed();

    let transfer_start = Instant::now();
    let traffic = verify_tcp_exchange(&mut guest, &mut session, &mut upstream);
    let transfer_time = transfer_start.elapsed();

    // Trigger normal session completion while retaining the guest's read half.
    // The same deadline covers both EOFs and entry into the held flush.
    let stop_start = Instant::now();
    let deadline = stop_start + Duration::from_secs(1);
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .expect("session closure deadline expired")
    };
    guest.shutdown(Shutdown::Write).unwrap();
    flushing.recv_timeout(remaining()).unwrap();
    upstream.set_read_timeout(Some(remaining())).unwrap();
    assert_eq!(
        upstream.read(&mut [0; 1]).unwrap(),
        0,
        "upstream must close before health flush completes"
    );
    guest.set_read_timeout(Some(remaining())).unwrap();
    assert_eq!(guest.read(&mut [0; 1]).unwrap(), 0, "carrier must close");
    let closure_time = stop_start.elapsed();
    assert!(Instant::now() <= deadline);
    assert!(!host.is_finished(), "audit flush must still be held");
    release.send(()).unwrap();
    host.join().unwrap().unwrap();
    eprintln!(
        "payload_out={} payload_in={} carrier_out={} carrier_in={} setup_us={} transfer_us={} closure_us={} lifecycle_us={}",
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
fn a_failed_completion_flush_is_not_reported_as_a_clean_session() {
    let (guest, _, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
                .with_audit_sink(Arc::new(FailedFlush(CapturingSink::default())))
        });
    drop(guest);
    assert!(matches!(host.join().unwrap(), Err(FlowMuxError::Audit(_))));
}

#[test]
fn a_failed_dns_allow_returns_no_answer() {
    let sink = Arc::new(CapturingSink::default());
    sink.fail.store(true, Ordering::SeqCst);
    let supplied = Arc::clone(&sink);
    let gate = gate_pinning_name("dns.test", "93.184.216.34".parse().unwrap(), 443);
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(supplied)
        });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Resolve,
        1,
        &build_dns_query("dns.test", 1, 123),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::ResolveRefused
    );
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert_eq!(sink.records.lock().unwrap()[0].0, "dns.resolved");
    drop(guest);
    host.join().unwrap().unwrap();
}

#[test]
fn a_failed_ingress_allow_releases_resources_without_opening_the_guest() {
    let sink = Arc::new(CapturingSink::default());
    sink.fail.store(true, Ordering::SeqCst);
    let supplied = Arc::clone(&sink);
    let (host_key, host_verify) = fresh_keys();
    let (guest_key, guest_verify) = fresh_keys();
    let (host_stream, mut guest) = UnixStream::pair().unwrap();
    let (send_ingress, ingress) = std::sync::mpsc::channel();
    let host = std::thread::spawn(move || {
        let mut host = FlowMuxSession::accept_with(
            host_stream,
            FlowMuxAccept::new(
                "failed-ingress",
                host_key,
                guest_verify,
                RegistryLimits::default(),
                EgressGate::default_deny(),
            )
            .with_audit_sink(supplied)
            .with_ingress_mappings([17]),
        )
        .unwrap();
        send_ingress.send(host.ingress_handle()).unwrap();
        host.serve()
    });
    let (mut session, _) = Session::guest(&mut guest, guest_key, &host_verify).unwrap();
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Hello,
        0,
        &Handshake::local("audit-test").encode(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::HelloAck
    );
    let ingress = ingress.recv().unwrap();
    let listener = std::net::TcpListener::bind((local_test_ip(), 0)).unwrap();
    let mut external = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    assert!(matches!(
        ingress.open_tcp(17, accepted),
        Err(FlowMuxError::Audit(_))
    ));
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert!(lock_pending_ingress(&ingress.pending).is_empty());
    assert!(lock_tcp_streams(&ingress.streams).is_empty());
    assert!(lock_registry(&ingress.registry).get(2).is_none());
    external
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(external.read(&mut [0; 1]).unwrap(), 0);
    guest
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(guest.read(&mut [0; 1]).is_err_and(|e| matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )));
    drop(guest);
    host.join().unwrap().unwrap();
    let (accepted, _) = {
        let _external = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        listener.accept().unwrap()
    };
    assert!(
        ingress.open_tcp(17, accepted).is_err(),
        "completed sessions cannot reopen ingress"
    );
}
