use super::*;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
use std::{
    io::{IoSlice, Read, Write},
    mem::MaybeUninit,
    os::{fd::AsFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

fn send(stream: &UnixStream, byte: u8, fds: &[std::os::fd::BorrowedFd<'_>]) {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(16))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() {
        assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
    }
    assert_eq!(
        sendmsg(
            stream,
            &[IoSlice::new(&[byte])],
            &mut control,
            SendFlags::empty()
        )
        .unwrap(),
        1
    );
}

#[test]
fn one_original_descriptor_arrives_cloexec_with_unchanged_stream_framing() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    let (mut witness, transferred) = UnixStream::pair().unwrap();
    writer.write_all(b"ok").unwrap();
    send(&writer, 0xA1, &[transferred.as_fd()]);
    drop(transferred);
    let mut header = [0; 2];
    reader.read_exact(&mut header).unwrap();
    assert_eq!(header, *b"ok");
    let received = receive_signer_event(&reader, Instant::now() + Duration::from_secs(1)).unwrap();
    assert!(
        rustix::io::fcntl_getfd(&received)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    drop(received);
    assert_eq!(witness.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn wrong_byte_and_extra_or_truncated_rights_close_every_received_copy() {
    for (byte, count) in [(0xA0, 1), (0xA1, 2), (0xA1, 16)] {
        let (writer, reader) = UnixStream::pair().unwrap();
        let (mut witness, transferred) = UnixStream::pair().unwrap();
        witness.set_nonblocking(true).unwrap();
        let fds = vec![transferred.as_fd(); count];
        send(&writer, byte, &fds);
        drop(fds);
        drop(transferred);
        assert!(receive_signer_event(&reader, Instant::now() + Duration::from_secs(1)).is_err());
        assert_eq!(
            witness.read(&mut [0; 1]).unwrap(),
            0,
            "all rejected rights close"
        );
    }
}

#[test]
fn missing_rights_eof_and_original_expired_deadline_refuse() {
    let (writer, reader) = UnixStream::pair().unwrap();
    send(&writer, 0xA1, &[]);
    assert!(receive_signer_event(&reader, Instant::now() + Duration::from_secs(1)).is_err());
    drop(writer);
    assert!(receive_signer_event(&reader, Instant::now() + Duration::from_secs(1)).is_err());
    let (writer, reader) = UnixStream::pair().unwrap();
    let transferred = std::fs::File::open("/dev/null").unwrap();
    send(&writer, 0xA1, &[transferred.as_fd()]);
    assert_eq!(
        receive_signer_event(&reader, Instant::now())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
}
