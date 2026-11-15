//! Streaming digest and byte accounting for bundle I/O.
use super::*;

/// A writer that hashes and counts what passes through it.
pub(crate) struct HashingWriter<W> {
    pub(super) inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    pub(crate) fn finish(self) -> (u64, String) {
        (self.written, hex::encode(self.hasher.finalize()))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A reader that hashes and counts what is read through it.
#[cfg(feature = "host-state")]
pub(super) struct HashingReader<R> {
    pub(super) inner: R,
    pub(super) hasher: Sha256,
    pub(super) read: u64,
}

#[cfg(feature = "host-state")]
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.read += n as u64;
        Ok(n)
    }
}
