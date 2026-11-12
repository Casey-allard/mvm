//! A constant-size observation over a single original durable-guest socket
//! service lifetime. Only a clean finish publishes the cumulative counters.
use super::{GuestStreamCounts, Measured, add};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Mutex,
};
const FILE: &str = "ordinal-guest-total-v1.counts";
const HEADER: &[u8] = b"mvm/owned-mailbox/guest-5257/ordinal-total/v1\n";
pub(crate) struct Aggregate {
    file: File,
    state: Mutex<(u64, GuestStreamCounts)>,
}
impl Aggregate {
    pub(crate) fn create(dir: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(dir.join(FILE))?;
        file.write_all(HEADER)?;
        Ok(Self {
            file,
            state: Mutex::default(),
        })
    }
    pub(crate) fn observe<S, T>(
        &self,
        stream: S,
        exchange: impl FnOnce(&mut Measured<'_, S>) -> T,
    ) -> T {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (turns, counts) = &mut *state;
        let result = exchange(&mut Measured::new(stream, counts));
        add(turns, 1, &mut counts.overflow);
        result
    }
}
impl Drop for Aggregate {
    fn drop(&mut self) {
        if !std::thread::panicking()
            && let Ok((turns, c)) = self.state.get_mut()
        {
            let _ = writeln!(
                self.file,
                "finish {turns} {} {} {} {} {}",
                c.guest_to_host_read_bytes,
                c.host_to_guest_write_accepted_bytes,
                c.read_errors,
                c.write_errors,
                c.overflow
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    #[test]
    fn counts_all_completed_original_turns_in_constant_space() {
        let d = tempfile::tempdir().unwrap();
        let m = Aggregate::create(d.path()).unwrap();
        for _ in 0..2050 {
            let mut io = Cursor::new(vec![0; 3]);
            m.observe(&mut io, |s| {
                let mut buf = [0; 3];
                s.read_exact(&mut buf).unwrap();
                s.write_all(b"fixed").unwrap()
            });
        }
        assert!(Aggregate::create(d.path()).is_err());
        assert_eq!(std::fs::read(d.path().join(FILE)).unwrap(), HEADER);
        drop(m);
        let result = std::fs::read_to_string(d.path().join(FILE)).unwrap();
        assert_eq!(
            result.lines().last(),
            Some("finish 2050 6150 10250 0 0 false")
        );
        assert_eq!(result.lines().count(), 2);
    }
    #[test]
    fn torn_turn_preserves_protocol_error_and_cannot_close_observation() {
        let d = tempfile::tempdir().unwrap();
        let m = Aggregate::create(d.path()).unwrap();
        let panic =
            std::panic::catch_unwind(|| m.observe(Cursor::new(vec![]), |_| panic!("interrupted")));
        assert!(panic.is_err());
        drop(m);
        assert_eq!(std::fs::read(d.path().join(FILE)).unwrap(), HEADER);
    }
}
