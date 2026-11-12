//! Optional host-side counters for exchanges on the original guest mailbox stream.
//! Each begin/end pair accounts for one post-mux exchange. An unmatched begin
//! marks an interrupted observation. Counts exclude dialing, idle polls and the
//! helper's separate host-side Unix journal API.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

const MAX_EXCHANGES: usize = 64;
pub(crate) const FILE_NAME: &str = "mailbox-guest-stream-v1.counts";

#[derive(Default)]
struct GuestStreamCounts {
    guest_to_host_read_bytes: u64,
    host_to_guest_write_accepted_bytes: u64,
    read_errors: u64,
    write_errors: u64,
    overflow: bool,
}
fn add(value: &mut u64, n: u64, overflow: &mut bool) {
    match value.checked_add(n) {
        Some(next) => *value = next,
        None => {
            *value = u64::MAX;
            *overflow = true;
        }
    }
}

pub(crate) struct Measured<'a, S> {
    stream: S,
    counts: &'a mut GuestStreamCounts,
}
impl<'a, S> Measured<'a, S> {
    fn new(stream: S, counts: &'a mut GuestStreamCounts) -> Self {
        Self { stream, counts }
    }
}
impl<S: Read> Read for Measured<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.stream.read(buf);
        match &result {
            Ok(n) if *n > 0 => {
                add(
                    &mut self.counts.guest_to_host_read_bytes,
                    *n as u64,
                    &mut self.counts.overflow,
                );
            }
            Err(e) if e.kind() != io::ErrorKind::Interrupted => {
                add(&mut self.counts.read_errors, 1, &mut self.counts.overflow)
            }
            _ => {}
        }
        result
    }
}
impl<S: Write> Write for Measured<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = self.stream.write(buf);
        match &result {
            Ok(n) if *n > 0 => {
                add(
                    &mut self.counts.host_to_guest_write_accepted_bytes,
                    *n as u64,
                    &mut self.counts.overflow,
                );
            }
            Ok(0) if !buf.is_empty() => {
                add(&mut self.counts.write_errors, 1, &mut self.counts.overflow)
            }
            Err(e) if e.kind() != io::ErrorKind::Interrupted => {
                add(&mut self.counts.write_errors, 1, &mut self.counts.overflow)
            }
            _ => {}
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

struct Sink {
    file: File,
    exchanges: usize,
    max_exchanges: usize,
}
pub(crate) struct Recorder(Mutex<Option<Sink>>);

impl Recorder {
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        Self::create_scoped(
            path,
            b"mvm/owned-mailbox/guest-5257/post-mux-host-stream/v1\n",
        )
    }

    pub(crate) fn selected_guest(path: &Path) -> io::Result<Self> {
        Self::with_limit(
            path,
            b"mvm/owned-mailbox/selected-object/guest-5257/post-mux-host-stream/v1\n",
            512,
        )
    }

    pub(crate) fn create_scoped(path: &Path, header: &[u8]) -> io::Result<Self> {
        Self::with_limit(path, header, MAX_EXCHANGES)
    }

    fn with_limit(path: &Path, header: &[u8], max_exchanges: usize) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(header)?;
        Ok(Self(Mutex::new(Some(Sink {
            file,
            exchanges: 0,
            max_exchanges,
        }))))
    }

    // Measurements must never change the protocol result. If measurement
    // storage fails, stop emitting rows. Consumers must require the expected
    // complete exchanges and reject truncated, missing and overflow rows.
    pub(crate) fn observe<S, T>(
        &self,
        stream: S,
        exchange: impl FnOnce(&mut Measured<'_, S>, &mut dyn FnMut(&'static str)) -> T,
    ) -> T {
        let mut counts = GuestStreamCounts::default();
        let mut output = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sink) = output.as_mut() {
            if sink.exchanges == sink.max_exchanges {
                let _ = sink.file.write_all(b"overflow\n");
                *output = None;
            } else {
                sink.exchanges += 1;
                if writeln!(sink.file, "begin {}", sink.exchanges).is_err() {
                    *output = None;
                }
            }
        }
        let mut mark = |phase: &'static str| {
            if let Some(sink) = output.as_mut()
                && writeln!(sink.file, "phase {} {}", sink.exchanges, phase).is_err()
            {
                *output = None;
            }
        };
        let result = exchange(&mut Measured::new(stream, &mut counts), &mut mark);
        if let Some(sink) = output.as_mut()
            && writeln!(
                sink.file,
                "end {} {} {} {} {} {}",
                sink.exchanges,
                counts.guest_to_host_read_bytes,
                counts.host_to_guest_write_accepted_bytes,
                counts.read_errors,
                counts.write_errors,
                counts.overflow
            )
            .is_err()
        {
            *output = None;
        }
        result
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        // A crash, write error, overflow or interrupted exchange must leave
        // the observer unable to claim a full-session total.
        if let Ok(Some(sink)) = self.0.get_mut()
            && writeln!(sink.file, "finish {}", sink.exchanges).is_ok()
        {
            let _ = sink.file.flush();
        }
    }
}

#[cfg(test)]
#[path = "witness_io_tests.rs"]
mod tests;
