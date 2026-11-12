use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub(crate) struct GuestDeadline<'a> {
    pub(crate) stream: &'a mut UnixStream,
    pub(crate) until: Instant,
}

impl GuestDeadline<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        let remaining = self.until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "mailbox guest exchange deadline",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl Read for GuestDeadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for GuestDeadline<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_reply_and_eof_survive_peer_exit() {
        let (mut local, mut peer) = UnixStream::pair().unwrap();
        let expected: Vec<_> = (0..=255).cycle().take(1197).collect();
        peer.write_all(&expected).unwrap();
        drop(peer);
        let mut stream = GuestDeadline {
            stream: &mut local,
            until: Instant::now() + Duration::from_secs(2),
        };
        let mut reply = Vec::new();
        Read::by_ref(&mut stream)
            .take(4097)
            .read_to_end(&mut reply)
            .unwrap();
        assert_eq!(reply, expected);
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn empty_peer_close_stays_eof_and_write_remains_an_error() {
        let (mut local, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut stream = GuestDeadline {
            stream: &mut local,
            until: Instant::now() + Duration::from_secs(2),
        };
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        assert!(stream.write(b"x").is_err());
    }

    #[test]
    fn partial_reads_do_not_extend_the_original_deadline() {
        let (mut local, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"x").unwrap();
        let until = Instant::now() + Duration::from_millis(50);
        let mut stream = GuestDeadline {
            stream: &mut local,
            until,
        };
        let mut bytes = [0; 2];
        assert_eq!(
            stream.read_exact(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(bytes[0], b'x');
        assert!(Instant::now() >= until);
    }

    #[test]
    fn a_full_open_socket_obeys_the_absolute_write_deadline() {
        let (mut local, _peer) = UnixStream::pair().unwrap();
        let until = Instant::now() + Duration::from_millis(50);
        let mut stream = GuestDeadline {
            stream: &mut local,
            until,
        };
        let block = [1; 16 * 1024];
        loop {
            match stream.write(&block) {
                Ok(n) => assert!(n > 0),
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
                    break;
                }
            }
        }
        assert!(Instant::now() >= until);
    }
}
