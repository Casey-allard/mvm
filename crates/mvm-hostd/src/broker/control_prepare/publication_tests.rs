use super::{BoundHandlers, StartLatch};
use crate::assurance_session::{hold_original_global_writer_for_test, host_assurance_plane};
use crate::broker::handlers::host_assurance_v1::HostAssuranceV1Handler;
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::sync::oneshot;

fn isolated_case(name: &str) -> bool {
    const CHILD: &str = "MVM_TEST_ORIGINAL_ASSURANCE_LATCH";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .status()
        .unwrap();
    assert!(status.success(), "isolated original-latch witness failed");
    true
}

#[test]
fn busy_publication_refuses_before_original_latch_dispatch() {
    const NAME: &str = "broker::control_prepare::publication_tests::busy_publication_refuses_before_original_latch_dispatch";
    if isolated_case(NAME) {
        return;
    }
    assert!(host_assurance_plane().is_none());
    let writer = hold_original_global_writer_for_test().unwrap();
    let original = Arc::new(HostAssuranceV1Handler::new());
    let (start, mut dispatch) = oneshot::channel();
    let latch = StartLatch {
        start: Some(start),
        bound: BoundHandlers {
            assurance: Some(Arc::clone(&original)),
        },
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        sender.send(latch.release().is_err()).unwrap();
    });
    let observed = receiver.recv_timeout(Duration::from_secs(5));
    // Collect the original thread even if the old release body waited.
    drop(writer);
    worker.join().unwrap();
    assert!(observed.unwrap(), "publication must refuse while busy");
    assert!(dispatch.try_recv().is_err(), "busy must not dispatch");
    assert!(host_assurance_plane().is_none(), "busy must not publish");
}

#[test]
fn receiver_loss_drops_reservation_and_success_publishes_original_arc() {
    const NAME: &str = "broker::control_prepare::publication_tests::receiver_loss_drops_reservation_and_success_publishes_original_arc";
    if isolated_case(NAME) {
        return;
    }
    assert!(host_assurance_plane().is_none());
    let original = Arc::new(HostAssuranceV1Handler::new());
    let (start, dispatch) = oneshot::channel();
    drop(dispatch);
    let refused = StartLatch {
        start: Some(start),
        bound: BoundHandlers {
            assurance: Some(Arc::clone(&original)),
        },
    };
    assert!(refused.release().is_err());
    assert!(host_assurance_plane().is_none());
    let (start, mut dispatch) = oneshot::channel();
    let accepted = StartLatch {
        start: Some(start),
        bound: BoundHandlers {
            assurance: Some(Arc::clone(&original)),
        },
    };
    accepted.release().unwrap();
    assert_eq!(dispatch.try_recv(), Ok(()));
    assert!(Arc::ptr_eq(&host_assurance_plane().unwrap(), &original));
}
