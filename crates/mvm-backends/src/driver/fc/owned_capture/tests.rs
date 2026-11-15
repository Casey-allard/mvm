use super::*;
use mvm_core::exit_capture::{capture_stream, read_captured};
use std::time::Duration;
use tempfile::tempdir;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

#[test]
fn owned_capture_persists_guest_report_before_ack_and_joins() {
    let state = tempdir().unwrap();
    let socket = state.path().join("exit.sock");
    let mut worker = CaptureWorker::spawn(&socket, state.path()).unwrap();
    let mut guest = UnixStream::connect(&socket).unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    guest.write_all(&(-23_i32).to_le_bytes()).unwrap();
    let mut ack = [0u8; 1];
    guest.read_exact(&mut ack).unwrap();
    assert_eq!(ack, [1]);
    assert_eq!(read_captured(state.path()), Some(-23));
    worker.stop(deadline()).unwrap();
    worker.stop(deadline()).unwrap();
}

#[test]
fn owned_capture_cancels_before_any_guest_connects() {
    let state = tempdir().unwrap();
    let socket = state.path().join("exit.sock");
    let mut worker = CaptureWorker::spawn(&socket, state.path()).unwrap();
    worker.stop(deadline()).unwrap();
    assert!(UnixStream::connect(socket).is_err());
    assert_eq!(read_captured(state.path()), None);
}

#[test]
fn owned_capture_preserves_occupied_socket_and_regular_file() {
    let state = tempdir().unwrap();
    let socket = state.path().join("existing");
    let original = UnixListener::bind(&socket).unwrap();
    assert!(CaptureWorker::spawn(&socket, state.path()).is_err());
    let _guest = UnixStream::connect(&socket).unwrap();
    original.accept().unwrap();
    let file = state.path().join("file");
    std::fs::write(&file, b"original").unwrap();
    assert!(CaptureWorker::spawn(&file, state.path()).is_err());
    assert_eq!(std::fs::read(file).unwrap(), b"original");
}

struct Progress<'a> {
    stream: CancelStream<'a>,
    first_read: Option<mpsc::Sender<usize>>,
}
impl Read for Progress<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.stream.read(bytes)?;
        if let Some(sender) = self.first_read.take() {
            sender.send(count).unwrap();
        }
        Ok(count)
    }
}
impl Write for Progress<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[test]
fn owned_capture_cancels_after_consuming_partial_report_without_exit_code() {
    let state = tempdir().unwrap();
    let socket = state.path().join("exit.sock");
    let (tx, rx) = mpsc::channel();
    let path = state.path().to_owned();
    let mut worker = CaptureWorker::start(&socket, move |stream| {
        let progress = Progress {
            stream,
            first_read: Some(tx),
        };
        capture_stream(progress, &path)
    })
    .unwrap();
    let mut guest = UnixStream::connect(&socket).unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    guest.write_all(&[4, 0]).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), 2);
    worker.stop(deadline()).unwrap();
    assert_eq!(
        worker.report().wait(deadline()).unwrap(),
        VmExitStatus::UNKNOWN
    );
    assert_eq!(guest.read(&mut [0]).unwrap(), 0);
    assert_eq!(read_captured(state.path()), None);
}

#[test]
fn owned_capture_deadline_keeps_the_original_join_for_retry() {
    let state = tempdir().unwrap();
    let socket = state.path().join("exit.sock");
    let (started, ready) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let mut worker = CaptureWorker::start(&socket, move |_| {
        started.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(3)).unwrap();
        Ok(0)
    })
    .unwrap();
    let _guest = UnixStream::connect(&socket).unwrap();
    ready.recv_timeout(Duration::from_secs(3)).unwrap();
    let err = worker.stop(Instant::now()).unwrap_err();
    assert_eq!(
        err.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::TimedOut
    );
    release.send(()).unwrap();
    worker.stop(deadline()).unwrap();
}

#[test]
fn owned_capture_collects_malformed_report_without_inventing_a_workload_exit() {
    let state = tempdir().unwrap();
    let socket = state.path().join("exit.sock");
    let mut worker = CaptureWorker::spawn(&socket, state.path()).unwrap();
    let mut guest = UnixStream::connect(&socket).unwrap();
    guest.write_all(&[0, 1]).unwrap();
    guest.shutdown(std::net::Shutdown::Write).unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert_eq!(guest.read(&mut [0]).unwrap(), 0);
    worker.stop(deadline()).unwrap();
    worker.stop(deadline()).unwrap();
    assert_eq!(read_captured(state.path()), None);
}

#[test]
fn owned_capture_panic_is_not_a_positive_retirement() {
    let state = tempdir().unwrap();
    let socket = state.path().join("exit.sock");
    let (entered, observed) = mpsc::channel();
    let mut worker = CaptureWorker::start(&socket, move |_| {
        entered.send(()).unwrap();
        panic!("fixture capture panic");
    })
    .unwrap();
    let _guest = UnixStream::connect(&socket).unwrap();
    observed.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(worker.stop(deadline()).is_err());
    assert_eq!(
        worker.report().wait(deadline()).unwrap(),
        VmExitStatus::UNKNOWN
    );
    assert!(worker.stop(deadline()).is_err());
}

#[test]
fn owned_report_uses_only_its_original_guest_even_with_a_stale_file() {
    let state = tempdir().unwrap();
    std::fs::write(mvm_core::exit_capture::exit_file_path(state.path()), "0").unwrap();
    let socket = state.path().join("exit.sock");
    let mut worker = CaptureWorker::spawn(&socket, state.path()).unwrap();
    let report = worker.report();
    assert_eq!(report.wait(Instant::now()).unwrap().code, None);

    let mut guest = UnixStream::connect(&socket).unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    guest.write_all(&42_i32.to_le_bytes()).unwrap();
    let mut ack = [0u8; 1];
    guest.read_exact(&mut ack).unwrap();
    assert_eq!(ack, [1]);
    worker.stop(deadline()).unwrap();
    std::fs::write(mvm_core::exit_capture::exit_file_path(state.path()), "0").unwrap();
    let captured = report.wait(deadline()).unwrap();
    assert_eq!(captured.code, Some(42));
    assert!(!captured.success);
}

#[test]
fn owned_report_cancellation_releases_waiters_with_unknown() {
    let state = tempdir().unwrap();
    let socket = state.path().join("exit.sock");
    let mut worker = CaptureWorker::spawn(&socket, state.path()).unwrap();
    let report = worker.report();
    let (ready, entered) = mpsc::channel();
    let (output, received) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            ready.send(()).unwrap();
            output
                .send(
                    report
                        .wait(Instant::now() + Duration::from_secs(8))
                        .unwrap(),
                )
                .unwrap();
        });
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        worker.stop(deadline()).unwrap();
        let result = received
            .recv_timeout(Duration::from_secs(2))
            .expect("stop must wake original report waiters");
        assert_eq!(result.code, None);
        assert!(!result.success);
    });
}
