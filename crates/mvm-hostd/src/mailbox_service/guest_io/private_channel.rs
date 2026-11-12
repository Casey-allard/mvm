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
    let (tag, reader) = take_offer(control)?;
    if tag != original_tag(owner) {
        return Err(invalid("private helper offer names another owner"));
    }
    Ok(reader)
}

/// Collect the two distinct private readers after concurrent original launches.
/// Their descriptor order is independent of SDK role order.
pub fn take_pair_readers(
    control: &UnixDatagram,
    owners: [&MailboxWorkerOwner; 2],
) -> io::Result<[UnixDatagram; 2]> {
    let expected = owners.map(original_tag);
    if expected[0] == expected[1] {
        return Err(invalid("two different original helper owners required"));
    }
    let (first, r1) = take_offer(control)?;
    let (second, r2) = take_offer(control)?;
    match [first, second] {
        pair if pair == expected => Ok([r1, r2]),
        [b, a] if [a, b] == expected => Ok([r2, r1]),
        _ => Err(invalid("duplicate or foreign private helper channel offer")),
    }
}

fn take_offer(control: &UnixDatagram) -> io::Result<([u8; 32], UnixDatagram)> {
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
    Ok((tag, super::anonymous_datagram(fd)?))
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
    fn paired_reader_collection_binds_reversed_originals_and_refuses_duplicates() {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        let a = super::super::tests::owner(4);
        let b = super::super::tests::owner(5);
        let wb = prepare_writer(&tx, &b).unwrap();
        let wa = prepare_writer(&tx, &a).unwrap();
        let [ra, rb] = take_pair_readers(&rx, [&a, &b]).unwrap();
        let counts = GuestStreamCounts::default();
        send_original(&wa, &a, counts.clone()).unwrap();
        send_original(&wb, &b, counts.clone()).unwrap();
        drop((wa, wb));
        assert_eq!(receive_original(&ra, &a).unwrap(), counts);
        assert_eq!(receive_original(&rb, &b).unwrap(), counts);
        let _a = prepare_writer(&tx, &a).unwrap();
        let _duplicate = prepare_writer(&tx, &a).unwrap();
        assert!(take_pair_readers(&rx, [&a, &b]).is_err());
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
