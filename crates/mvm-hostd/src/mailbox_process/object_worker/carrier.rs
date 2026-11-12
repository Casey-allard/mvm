//! The trusted launcher supplies one connected socket per data direction. Each
//! canonical request and its signed verdict have a separate bounded length.
use super::*;
use crate::mailbox_launch::{LAUNCH_LIMITS, object_pair::SealedObjectTurn};
use crate::mailbox_service::{durable::GuestDeadline, read_frame};
use mvm_contract::protocol::mailbox::SignedDestinationReceipt;
use mvm_core::mailbox::frame::{MAX_VERDICT_BYTES, Refusal, encode_frame};
use std::{io::Write, net::Shutdown};

pub(super) type Verdict = std::result::Result<SignedDestinationReceipt, Refusal>;

pub(super) fn write_record(io: &mut impl Write, data: &[u8], max: usize) -> Result<()> {
    ensure!(
        !data.is_empty() && data.len() <= max,
        "invalid sealed link record size"
    );
    io.write_all(&u32::try_from(data.len())?.to_be_bytes())?;
    io.write_all(data)?;
    Ok(())
}

pub(super) fn submit(
    stream: &UnixStream,
    turn: &SealedObjectTurn,
    until: Instant,
) -> Result<SignedDestinationReceipt> {
    let body = encode_frame(turn.capability(), turn.envelope())?;
    let mut io = GuestDeadline::new(stream.try_clone()?, until)?;
    let result = (|| -> Result<Verdict> {
        write_record(&mut io, &body, LAUNCH_LIMITS.max_frame_bytes)?;
        let reply = read_frame(MAX_VERDICT_BYTES as usize, &mut io)?;
        Ok(serde_json::from_slice(&reply)?)
    })();
    // After a partial frame or ambiguous read the next verdict cannot be
    // correlated on this stream. Recovery reuses the original persisted seal.
    match result {
        Ok(verdict) => Ok(verdict?),
        Err(_) => {
            let _ = stream.shutdown(Shutdown::Both);
            Err(Refusal::Unavailable.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consecutive_frames_bound_each_request_and_verdict_without_socket_eof() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_record(&mut a, b"first", 5).unwrap();
        write_record(&mut a, b"second", 6).unwrap();
        assert_eq!(read_frame(5, &mut b).unwrap(), b"first");
        assert_eq!(read_frame(6, &mut b).unwrap(), b"second");
        assert!(write_record(&mut a, b"excess", 3).is_err());
        a.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert_eq!(read_frame(4096, &mut b), Err(Refusal::Oversized(4096)));
    }
}
