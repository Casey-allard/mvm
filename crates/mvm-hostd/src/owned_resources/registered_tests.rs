use super::registered::RegistrationAdmission;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[tokio::test]
async fn retirement_error_fences_before_bind_and_wakes_an_armed_waiter() {
    let root = tempfile::tempdir().unwrap();
    let admission = Arc::new(RegistrationAdmission::new());
    let listener = admission
        .listener(|| UnixListener::bind(root.path().join("first.sock")))
        .unwrap();
    let wake_admission = admission.clone();
    let (armed, ready) = tokio::sync::oneshot::channel();
    let waiter = tokio::spawn(async move {
        let closed = wake_admission.closed();
        tokio::pin!(closed);
        let mut armed = Some(armed);
        std::future::poll_fn(|cx| {
            let result = closed.as_mut().poll(cx);
            if result.is_pending()
                && let Some(armed) = armed.take()
            {
                armed.send(()).unwrap();
            }
            result
        })
        .await;
    });
    tokio::time::timeout(Duration::from_secs(5), ready)
        .await
        .expect("waiter must arm before the retirement fault")
        .unwrap();
    admission.fail_next_retirement();
    drop(listener);
    tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("fatal admission must wake its waiter")
        .unwrap();

    let calls = AtomicUsize::new(0);
    let error = admission.listener(|| {
        calls.fetch_add(1, Ordering::SeqCst);
        UnixListener::bind(root.path().join("forbidden.sock"))
    });
    assert_eq!(error.err().unwrap().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!root.path().join("forbidden.sock").exists());
    assert!(admission.check().is_err(), "fatal admission is monotonic");
}

#[tokio::test]
async fn guarded_stream_preserves_bytes_and_drop_error_refuses_the_next_accept() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("paired.sock");
        let admission = Arc::new(RegistrationAdmission::new());
        let listener = admission.listener(|| UnixListener::bind(&path)).unwrap();
        let mut peer = UnixStream::connect(&path).await.unwrap();
        let mut accepted = listener.accept().await.unwrap();
        let request = [0, 0, 0, 1, b'7'];
        peer.write_all(&request).await.unwrap();
        let mut observed = [0; 5];
        accepted.read_exact(&mut observed).await.unwrap();
        assert_eq!(observed, request);
        accepted.write_all(&request).await.unwrap();
        peer.read_exact(&mut observed).await.unwrap();
        assert_eq!(observed, request);
        admission.fail_next_retirement();
        drop(accepted);
        let error = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("fenced accept must not wait for another connection")
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    })
    .await
    .expect("paired guarded I/O must finish within its test watchdog");
}

#[tokio::test]
async fn normal_retirement_remains_open_but_a_racing_bind_never_escapes_fatal() {
    let root = tempfile::tempdir().unwrap();
    let admission = Arc::new(RegistrationAdmission::new());
    let listener = admission
        .listener(|| UnixListener::bind(root.path().join("normal.sock")))
        .unwrap();
    listener.retire().unwrap();
    admission.check().unwrap();

    let calls = AtomicUsize::new(0);
    let error = admission.listener(|| {
        calls.fetch_add(1, Ordering::SeqCst);
        let listener = UnixListener::bind(root.path().join("inflight.sock"))?;
        admission.fence();
        Ok(listener)
    });
    assert_eq!(error.err().unwrap().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(admission.check().is_err());
}
