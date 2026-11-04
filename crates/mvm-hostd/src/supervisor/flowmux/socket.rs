//! The host-side socket sitting behind one FlowMux TCP flow.
//!
//! An opaque flow is backed by the real upstream TCP connection: the relay
//! thread reads the destination's bytes and frames them back to the guest.
//! A terminated flow is backed by one half of a local socket pair whose other
//! half a host-side terminator drives, so the guest keeps writing `Data`
//! frames and keeps receiving framed bytes without knowing that its peer is a
//! process on this host rather than the destination.
//!
//! There are two physical backings. An explicitly authenticated payload mapping
//! decorates the admitted TCP connection; it does not add a third network route.

use std::io::{Read, Result, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;

/// One flow's host-side socket.
#[derive(Debug)]
pub(super) enum FlowSocket {
    /// The admitted upstream connection an opaque flow relays to.
    Upstream(UpstreamPayload),
    /// The endpoint's half of the pair a terminated flow is driven over.
    Terminated(UnixStream),
}

#[derive(Debug)]
pub(super) enum UpstreamPayload {
    Plain(TcpStream),
    Mapped(Box<dyn super::AuthenticatedTcpPayloadIo>),
}

impl FlowSocket {
    /// A second handle on the same socket, so the relay thread can read while
    /// the session thread writes.
    pub(super) fn try_clone(&self) -> Result<Self> {
        match self {
            Self::Upstream(UpstreamPayload::Plain(stream)) => stream.try_clone().map(Self::from),
            Self::Upstream(UpstreamPayload::Mapped(stream)) => stream.try_clone().map(Self::mapped),
            Self::Terminated(stream) => stream.try_clone().map(Self::Terminated),
        }
    }

    /// Shut one or both directions down. Half-closing the write side is what
    /// makes a blocked peer read unwind, on either backing.
    pub(super) fn shutdown(&self, how: Shutdown) -> Result<()> {
        match self {
            Self::Upstream(UpstreamPayload::Plain(stream)) => stream.shutdown(how),
            Self::Upstream(UpstreamPayload::Mapped(stream)) => stream.shutdown(how),
            Self::Terminated(stream) => stream.shutdown(how),
        }
    }
    pub(super) fn mapped(stream: Box<dyn super::AuthenticatedTcpPayloadIo>) -> Self {
        Self::Upstream(UpstreamPayload::Mapped(stream))
    }
    pub(super) fn mapped_clone(&self) -> Result<Option<Self>> {
        match self {
            Self::Upstream(UpstreamPayload::Mapped(stream)) => {
                stream.try_clone().map(|stream| Some(Self::mapped(stream)))
            }
            Self::Upstream(UpstreamPayload::Plain(_)) | Self::Terminated(_) => Ok(None),
        }
    }
    pub(super) fn is_mapped(&self) -> bool {
        matches!(self, Self::Upstream(UpstreamPayload::Mapped(_)))
    }
}

impl From<TcpStream> for FlowSocket {
    fn from(stream: TcpStream) -> Self {
        Self::Upstream(UpstreamPayload::Plain(stream))
    }
}

impl From<UnixStream> for FlowSocket {
    fn from(stream: UnixStream) -> Self {
        Self::Terminated(stream)
    }
}

impl Read for FlowSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Upstream(UpstreamPayload::Plain(stream)) => stream.read(buf),
            Self::Upstream(UpstreamPayload::Mapped(stream)) => stream.read(buf),
            Self::Terminated(stream) => stream.read(buf),
        }
    }
}

impl Write for FlowSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            Self::Upstream(UpstreamPayload::Plain(stream)) => stream.write(buf),
            Self::Upstream(UpstreamPayload::Mapped(stream)) => stream.write(buf),
            Self::Terminated(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            Self::Upstream(UpstreamPayload::Plain(stream)) => stream.flush(),
            Self::Upstream(UpstreamPayload::Mapped(stream)) => stream.flush(),
            Self::Terminated(stream) => stream.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_backed_socket_relays_in_both_directions() {
        let (host, peer) = UnixStream::pair().expect("socket pair");
        let mut host = FlowSocket::from(host);
        let mut clone = host.try_clone().expect("clone a pair-backed socket");
        let mut peer = peer;

        host.write_all(b"to-peer").expect("write to the peer half");
        host.flush().expect("flush the pair-backed socket");
        let mut got = [0u8; 7];
        peer.read_exact(&mut got).expect("peer reads what we wrote");
        assert_eq!(&got, b"to-peer");

        peer.write_all(b"back").expect("peer writes back");
        peer.flush().expect("peer flush");
        let mut back = [0u8; 4];
        clone
            .read_exact(&mut back)
            .expect("the clone reads the peer's bytes");
        assert_eq!(&back, b"back");
    }

    #[test]
    fn half_closing_a_pair_backed_socket_ends_the_peer_read() {
        let (host, mut peer) = UnixStream::pair().expect("socket pair");
        let host = FlowSocket::from(host);
        host.shutdown(Shutdown::Write).expect("half close");
        let mut sink = Vec::new();
        peer.read_to_end(&mut sink).expect("peer read unwinds");
        assert!(sink.is_empty(), "no bytes were written before the shutdown");
    }

    #[test]
    fn an_upstream_backed_socket_keeps_the_tcp_behaviour() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let accept = std::thread::spawn(move || listener.accept().expect("accept"));
        let mut socket =
            FlowSocket::from(TcpStream::connect(addr).expect("connect to the test listener"));
        let (mut served, _) = accept.join().expect("accept thread");

        socket.write_all(b"hi").expect("write upstream");
        socket.flush().expect("flush upstream");
        let mut got = [0u8; 2];
        served.read_exact(&mut got).expect("listener reads");
        assert_eq!(&got, b"hi");
        assert!(matches!(socket, FlowSocket::Upstream(_)));
    }
}
