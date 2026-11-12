use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub(crate) struct GuestDeadline {
    stream: UnixStream,
    until: Instant,
}

impl GuestDeadline {
    /// This private exchange consumes the connected socket. No other handler
    /// reads it or relies on its former blocking mode.
    pub(crate) fn new(stream: UnixStream, until: Instant) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self { stream, until })
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mailbox guest exchange deadline",
            ))
        } else {
            Ok(remaining)
        }
    }

    // Darwin can refuse SO_RCVTIMEO after the peer closes even when a signed
    // response is buffered. A nonblocking read drains those bytes and then EOF.
    fn transfer(
        &self,
        events: PollFlags,
        mut operation: impl FnMut(&UnixStream) -> io::Result<usize>,
    ) -> io::Result<usize> {
        loop {
            self.remaining()?;
            match operation(&self.stream) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
            let timeout = Timespec::try_from(self.remaining()?).map_err(io::Error::other)?;
            let mut wait = [PollFd::new(&self.stream, events)];
            match poll(&mut wait, Some(&timeout)) {
                // Read/write again for buffered data, EOF, and the actual socket error.
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Read for GuestDeadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.transfer(PollFlags::IN, |mut socket| socket.read(buf))
    }
}

impl Write for GuestDeadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.transfer(PollFlags::OUT, |mut socket| socket.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_reply_and_eof_survive_peer_exit() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        let expected: Vec<_> = (0..=255).cycle().take(1197).collect();
        peer.write_all(&expected).unwrap();
        drop(peer);
        let mut stream =
            GuestDeadline::new(local, Instant::now() + Duration::from_secs(2)).unwrap();
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
        let (local, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut stream =
            GuestDeadline::new(local, Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        assert!(stream.write(b"x").is_err());
    }

    #[test]
    fn partial_reads_do_not_extend_the_original_deadline() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"x").unwrap();
        let until = Instant::now() + Duration::from_millis(50);
        let mut stream = GuestDeadline::new(local, until).unwrap();
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
        let (local, _peer) = UnixStream::pair().unwrap();
        let until = Instant::now() + Duration::from_millis(50);
        let mut stream = GuestDeadline::new(local, until).unwrap();
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
