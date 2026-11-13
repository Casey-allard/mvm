use super::*;
use std::future::Future;
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::time::Duration;

async fn pair() -> (
    Arc<RegistrationAdmission>,
    RegisteredStream,
    std::os::unix::net::UnixStream,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sideband");
    let admission = Arc::new(RegistrationAdmission::new());
    let listener = admission.listener(|| UnixListener::bind(&path)).unwrap();
    let peer = std::os::unix::net::UnixStream::connect(path).unwrap();
    peer.set_nonblocking(true).unwrap();
    let stream = listener.accept().await.unwrap();
    (admission, stream, peer, directory)
}

#[tokio::test]
async fn sideband_sends_exactly_one_byte_and_same_original_file() {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
    let (_admission, stream, peer, _directory) = pair().await;
    let original = tempfile::tempfile().unwrap();
    stream
        .send_one_fd_until(
            0xa1,
            original.as_fd(),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    let mut byte = [0; 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        &peer,
        &mut [IoSliceMut::new(&mut byte)],
        &mut ancillary,
        RecvFlags::DONTWAIT,
    )
    .unwrap();
    assert_eq!(received.bytes, 1);
    assert!(received.flags.is_empty());
    assert_eq!(byte, [0xa1]);
    let mut descriptors = Vec::new();
    for control in ancillary.drain() {
        match control {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => panic!("only one SCM_RIGHTS record is admitted"),
        }
    }
    assert_eq!(descriptors.len(), 1);
    let actual = rustix::fs::fstat(&descriptors[0]).unwrap();
    let expected = rustix::fs::fstat(&original).unwrap();
    assert_eq!(
        (actual.st_dev, actual.st_ino),
        (expected.st_dev, expected.st_ino)
    );
}

#[tokio::test]
async fn expired_or_fenced_sideband_sends_no_byte_or_descriptor() {
    let (admission, stream, peer, _directory) = pair().await;
    let original = tempfile::tempfile().unwrap();
    assert_eq!(
        stream
            .send_one_fd_until(0xa1, original.as_fd(), tokio::time::Instant::now())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    admission.fence();
    assert_eq!(
        stream
            .send_one_fd_until(
                0xa1,
                original.as_fd(),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    let mut byte = [0; 1];
    assert_eq!(
        rustix::io::read(&peer, &mut byte).unwrap_err(),
        rustix::io::Errno::AGAIN
    );
}

#[tokio::test]
async fn full_sideband_wait_is_woken_by_the_same_admission_fence() {
    let (admission, stream, _peer, _directory) = pair().await;
    let socket = stream.inner.as_ref().unwrap();
    socket.writable().await.unwrap();
    let fill = [0u8; 4096];
    loop {
        match socket.try_write(&fill) {
            Ok(0) => panic!("original socket stopped accepting data"),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("original socket fill failed: {error}"),
        }
    }
    let original = tempfile::tempfile().unwrap();
    let mut sending = Box::pin(stream.send_one_fd_until(
        0xa1,
        original.as_fd(),
        tokio::time::Instant::now() + Duration::from_secs(2),
    ));
    std::future::poll_fn(|cx| {
        assert!(
            sending.as_mut().poll(cx).is_pending(),
            "full original socket waits"
        );
        Poll::Ready(())
    })
    .await;
    admission.fence();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), sending)
            .await
            .expect("the original fence must wake the blocked ancillary send")
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}
