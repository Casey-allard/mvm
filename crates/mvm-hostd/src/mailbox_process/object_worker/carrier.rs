//! The trusted launcher supplies one connected socket per data direction. Each
//! canonical request and its signed verdict have a separate bounded length.
use super::*;
use crate::mailbox_launch::{LAUNCH_LIMITS, object_pair::SealedObjectTurn};
use crate::mailbox_service::{durable::GuestDeadline, read_frame};
use mvm_contract::protocol::mailbox::SignedDestinationReceipt;
use mvm_core::mailbox::frame::{MAX_VERDICT_BYTES, Refusal, encode_frame};
use std::{
    io::{Read, Write},
    net::Shutdown,
    path::Path,
};

pub(super) type Verdict = std::result::Result<SignedDestinationReceipt, Refusal>;

pub(super) trait Duplex: Read + Write {}
impl<T: Read + Write> Duplex for T {}

pub(super) struct Link {
    pub(super) socket: UnixStream,
    #[cfg(feature = "durable-guest-io-witness")]
    meter: crate::mailbox_service::durable::witness_io::Recorder,
}
impl Link {
    pub(super) fn new(socket: UnixStream, _state: &Path, _outbound: bool) -> Result<Self> {
        #[cfg(feature = "durable-guest-io-witness")]
        let meter = {
            let name = if _outbound {
                "object-sealed-out-v1.counts"
            } else {
                "object-sealed-in-v1.counts"
            };
            crate::mailbox_service::durable::witness_io::Recorder::create_scoped(
                &_state.join(name),
                b"mvm/owned-mailbox/selected-object/sealed-stream/read-write/v1\n",
            )?
        };
        Ok(Self {
            socket,
            #[cfg(feature = "durable-guest-io-witness")]
            meter,
        })
    }
    pub(super) fn record<T>(
        &self,
        until: Instant,
        op: impl FnOnce(&mut dyn Duplex) -> Result<T>,
    ) -> Result<T> {
        let mut io = GuestDeadline::new(self.socket.try_clone()?, until)?;
        #[cfg(feature = "durable-guest-io-witness")]
        {
            self.meter.observe(&mut io, |measured, _| op(measured))
        }
        #[cfg(not(feature = "durable-guest-io-witness"))]
        {
            op(&mut io)
        }
    }
}

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
    link: &Link,
    turn: &SealedObjectTurn,
    until: Instant,
) -> Result<SignedDestinationReceipt> {
    let body = encode_frame(turn.capability(), turn.envelope())?;
    let result = link.record(until, |mut io| -> Result<Verdict> {
        write_record(&mut io, &body, LAUNCH_LIMITS.max_frame_bytes)?;
        let reply = read_frame(MAX_VERDICT_BYTES as usize, &mut io)?;
        Ok(serde_json::from_slice(&reply)?)
    });
    // After a partial frame or ambiguous read the next verdict cannot be
    // correlated on this stream. Recovery reuses the original persisted seal.
    match result {
        Ok(verdict) => Ok(verdict?),
        Err(_) => {
            let _ = link.socket.shutdown(Shutdown::Both);
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

#[cfg(all(test, feature = "durable-guest-io-witness"))]
#[test]
fn sealed_direction_meters_count_accepted_io_at_each_end() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    let a = Link::new(a, dir.path(), true).unwrap();
    let b = Link::new(b, dir.path(), false).unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    std::thread::scope(|scope| {
        let incoming = scope.spawn(|| {
            b.record(until, |mut io| {
                assert_eq!(read_frame(8, &mut io)?, b"sealed");
                write_record(&mut io, b"receipt", 8)
            })
        });
        a.record(until, |mut io| {
            write_record(&mut io, b"sealed", 8)?;
            assert_eq!(read_frame(8, &mut io)?, b"receipt");
            Ok(())
        })
        .unwrap();
        incoming.join().unwrap().unwrap();
    });
    drop((a, b));
    for (file, end) in [
        ("object-sealed-out-v1.counts", "end 1 11 10 0 0 false"),
        ("object-sealed-in-v1.counts", "end 1 10 11 0 0 false"),
    ] {
        let rows = std::fs::read_to_string(dir.path().join(file)).unwrap();
        assert_eq!(
            rows.lines().collect::<Vec<_>>(),
            vec![
                "mvm/owned-mailbox/selected-object/sealed-stream/read-write/v1",
                "begin 1",
                end,
                "finish 1"
            ]
        );
    }
}
