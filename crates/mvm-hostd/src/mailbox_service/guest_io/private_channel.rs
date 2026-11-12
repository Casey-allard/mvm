//! Linux qualification channel for an individual original helper.
//! The trusted coordinator transfers the reader before spawn. Only the helper
//! receives the writer. Later tenant activity cannot write to this socketpair.
use super::{MailboxWorkerOwner, UnixDatagram, invalid, original_tag};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;

pub const ISOLATED_HELPER_MODE: &str = "2";

pub(crate) fn prepare_writer(
    control: &UnixDatagram,
    owner: &MailboxWorkerOwner,
) -> io::Result<UnixDatagram> {
    let (reader, writer) = UnixDatagram::pair()?;
    let fds = [reader.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(invalid("private helper channel descriptor unavailable"));
    }
    let tag = original_tag(owner);
    let size = sendmsg(
        control,
        &[IoSlice::new(&tag)],
        &mut ancillary,
        SendFlags::DONTWAIT,
    )?;
    if size != tag.len() {
        return Err(invalid("incomplete private helper channel offer"));
    }
    Ok(writer)
}

/// The signed helper verdict and original exit are checked separately by the
/// caller. This offer binds the private report reader to that original grant.
pub fn take_reader(control: &UnixDatagram, owner: &MailboxWorkerOwner) -> io::Result<UnixDatagram> {
    let mut tag = [0u8; 32];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = recvmsg(
        control,
        &mut [IoSliceMut::new(&mut tag)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    )?;
    if message.bytes != tag.len()
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || tag != original_tag(owner)
    {
        return Err(invalid("invalid or truncated private helper channel offer"));
    }
    let mut reader = None;
    for entry in ancillary.drain() {
        let RecvAncillaryMessage::ScmRights(fds) = entry else {
            return Err(invalid("unexpected private helper channel metadata"));
        };
        for fd in fds {
            if reader.replace(fd).is_some() {
                return Err(invalid("multiple private helper channel descriptors"));
            }
        }
    }
    let fd = reader.ok_or_else(|| invalid("missing private helper channel descriptor"))?;
    super::anonymous_datagram(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_service::guest_io::{GuestStreamCounts, receive_original, send_original};

    #[test]
    fn signed_owner_channels_remain_isolated_while_original_coordinator_stays_open() {
        let (coordinator, collector) = UnixDatagram::pair().unwrap();
        let a = super::super::tests::owner(7);
        let b = super::super::tests::owner(8);
        let first = prepare_writer(&coordinator, &a).unwrap();
        let second = prepare_writer(&coordinator, &b).unwrap();
        let first_rx = take_reader(&collector, &a).unwrap();
        let second_rx = take_reader(&collector, &b).unwrap();
        let counts = GuestStreamCounts {
            guest_to_host_read_bytes: 21,
            ..Default::default()
        };
        // Even a valid-looking first-owner report on the sibling channel must
        // not reach the first owner's reader.
        send_original(&second, &a, GuestStreamCounts::default()).unwrap();
        send_original(&first, &a, counts.clone()).unwrap();
        drop(first);
        assert_eq!(receive_original(&first_rx, &a).unwrap(), counts);
        assert!(receive_original(&second_rx, &b).is_err());
        assert!(
            prepare_writer(&coordinator, &b).is_ok(),
            "coordinator still serves"
        );
    }

    #[test]
    fn private_channel_rejects_missing_fd_foreign_owner_and_wrong_type() {
        let (coordinator, collector) = UnixDatagram::pair().unwrap();
        let a = super::super::tests::owner(4);
        let b = super::super::tests::owner(5);
        coordinator.send(&original_tag(&a)).unwrap();
        assert!(take_reader(&collector, &a).is_err());
        let _writer = prepare_writer(&coordinator, &a).unwrap();
        assert!(take_reader(&collector, &b).is_err());
        let (fd, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let fds = [fd.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
        sendmsg(
            &coordinator,
            &[IoSlice::new(&original_tag(&a))],
            &mut ancillary,
            SendFlags::DONTWAIT,
        )
        .unwrap();
        assert!(take_reader(&collector, &a).is_err());
    }
}
