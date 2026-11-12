//! Crash-consistent custody for a single, explicitly selected original sender.
//! The prefix and remaining consecutive entries share one atomic snapshot.
//! At most one additional snapshot exists during replacement.
use super::{MAX_SOURCE_ATTEMPTS, MAX_SOURCE_INTENT_BYTES, MAX_SOURCE_INTENTS, Refusal};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::SignedDestinationReceipt;
use mvm_core::{
    mailbox::sender_ordinal::{SenderOrdinalV1, SenderSettlementV1},
    util::atomic_io::{FileLock, atomic_write_new, sync_dir},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const NAME: &str = "ordinal-state-v1";
const MAX_STATE: usize = MAX_SOURCE_INTENTS * (2 * MAX_SOURCE_INTENT_BYTES + 8192) + 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    direction: [u8; 32],
    retired: u64,
    entries: VecDeque<Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    intent: [u8; 32],
    seal: String,
    attempts: u8,
    receipt: Option<SignedDestinationReceipt>,
    settled: bool,
}
pub(super) enum Original {
    Send(Vec<u8>),
    Accepted(Vec<u8>, SignedDestinationReceipt),
}
pub(crate) struct SenderWindow {
    path: PathBuf,
    direction: [u8; 32],
}
impl SenderWindow {
    fn at(root: &Path, direction: [u8; 32]) -> Self {
        Self {
            path: root.join(NAME),
            direction,
        }
    }
    /// Only the original launcher creates a generation. A surviving generation
    /// directory with a missing snapshot cannot be initialized again.
    pub(crate) fn provision(root: &Path, direction: [u8; 32]) -> Result<(), Refusal> {
        let w = Self::at(root, direction);
        // The launcher's generation fence outlives loss of the state directory.
        // Only a pristine original may publish the fence; any torn preparation
        // thereafter requires reconciliation, never a new sequence starting at one.
        let fence = root.join("ordinal-generation-v1");
        if fs::symlink_metadata(&fence).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            if !fs::symlink_metadata(&w.path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                return Err(Refusal::Unavailable);
            }
            atomic_write_new(&fence, &direction).map_err(|_| Refusal::Unavailable)?;
            sync_dir(root).map_err(|_| Refusal::Unavailable)?;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&w.path)
                .map_err(|_| Refusal::Unavailable)?;
            let _guard = w.lock()?;
            let zero = State {
                version: 1,
                direction,
                retired: 0,
                entries: VecDeque::new(),
            };
            atomic_write_new(
                &w.path.join("state"),
                &serde_json::to_vec(&zero).map_err(|_| Refusal::Malformed)?,
            )
            .map_err(|_| Refusal::Unavailable)?;
            sync_dir(root).map_err(|_| Refusal::Unavailable)?;
        }
        Self::reopen(root, direction)?;
        Ok(())
    }
    pub(super) fn reopen(root: &Path, direction: [u8; 32]) -> Result<Self, Refusal> {
        let w = Self::at(root, direction);
        let fence = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join("ordinal-generation-v1"))
            .map_err(|_| Refusal::Unavailable)?;
        let m = fence.metadata().map_err(|_| Refusal::Unavailable)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o077 != 0
            || m.len() != 32
        {
            return Err(Refusal::NotAuthorized);
        }
        let mut original = Vec::with_capacity(33);
        fence
            .take(33)
            .read_to_end(&mut original)
            .map_err(|_| Refusal::Unavailable)?;
        if original != direction {
            return Err(Refusal::NotAuthorized);
        }
        let _guard = w.lock()?;
        w.load()?;
        Ok(w)
    }
    fn lock(&self) -> Result<FileLock, Refusal> {
        let m = fs::symlink_metadata(&self.path).map_err(|_| Refusal::Unavailable)?;
        if !m.is_dir() || m.mode() & 0o077 != 0 || m.uid() != rustix::process::geteuid().as_raw() {
            return Err(Refusal::NotAuthorized);
        }
        FileLock::acquire_until(
            &self.path.join("custody"),
            std::time::Instant::now() + std::time::Duration::from_millis(10),
        )
        .map_err(|_| Refusal::Unavailable)
    }
    fn load(&self) -> Result<State, Refusal> {
        sync_dir(&self.path).map_err(|_| Refusal::Unavailable)?;
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.path.join("state"))
            .map_err(|_| Refusal::Unavailable)?;
        let m = f.metadata().map_err(|_| Refusal::Unavailable)?;
        if m.nlink() != 1
            || !m.is_file()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o077 != 0
            || m.len() > MAX_STATE as u64
        {
            return Err(Refusal::Malformed);
        }
        let mut raw = Vec::new();
        f.take(MAX_STATE as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| Refusal::Unavailable)?;
        if raw.len() > MAX_STATE {
            return Err(Refusal::Malformed);
        }
        let s: State = serde_json::from_slice(&raw).map_err(|_| Refusal::Malformed)?;
        if s.version != 1
            || s.direction != self.direction
            || s.entries.len() > MAX_SOURCE_INTENTS
            || s.retired.checked_add(s.entries.len() as u64).is_none()
            || s.entries.iter().any(|e| {
                e.seal.len() > 2 * MAX_SOURCE_INTENT_BYTES
                    || e.seal.is_empty()
                    || !(1..=MAX_SOURCE_ATTEMPTS).contains(&e.attempts)
                    || e.settled && e.receipt.is_none()
            })
        {
            return Err(Refusal::Malformed);
        }
        Ok(s)
    }
    fn persist(&self, s: &State) -> Result<(), Refusal> {
        let bytes = serde_json::to_vec(s).map_err(|_| Refusal::Malformed)?;
        if bytes.len() > MAX_STATE {
            return Err(Refusal::StorageFull);
        }
        // One fixed temporary name bounds orphaned bytes even when the process
        // crashes before rename. Reopen the old state until rename is durable.
        let stage = self.path.join("next");
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&stage)
            .map_err(|_| Refusal::Unavailable)?;
        let m = file.metadata().map_err(|_| Refusal::Unavailable)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o077 != 0
        {
            return Err(Refusal::NotAuthorized);
        }
        file.set_len(0)
            .and_then(|_| file.write_all(&bytes))
            .and_then(|_| file.sync_all())
            .and_then(|_| fs::rename(&stage, self.path.join("state")))
            .map_err(|_| Refusal::Unavailable)?;
        sync_dir(&self.path).map_err(|_| Refusal::Unavailable)
    }
    fn index(&self, state: &State, h: SenderOrdinalV1) -> Result<usize, Refusal> {
        if h.direction != self.direction || h.ordinal == 0 {
            return Err(Refusal::NotAuthorized);
        }
        if h.ordinal <= state.retired {
            return Err(Refusal::SenderOrdinalRetired);
        }
        usize::try_from(h.ordinal - state.retired - 1).map_err(|_| Refusal::Malformed)
    }
    pub(super) fn reserve(
        &self,
        h: SenderOrdinalV1,
        intent: [u8; 32],
        seal: impl FnOnce() -> Result<Vec<u8>, Refusal>,
    ) -> Result<Original, Refusal> {
        let _guard = self.lock()?;
        let mut s = self.load()?;
        let i = self.index(&s, h)?;
        if i < s.entries.len() {
            let e = &mut s.entries[i];
            if e.intent != intent {
                return Err(Refusal::NotAuthorized);
            }
            let bytes = hex::decode(&e.seal).map_err(|_| Refusal::Malformed)?;
            if let Some(r) = &e.receipt {
                return Ok(Original::Accepted(bytes, r.clone()));
            }
            if e.attempts >= MAX_SOURCE_ATTEMPTS {
                return Err(Refusal::RetriesExhausted);
            }
            e.attempts += 1;
            self.persist(&s)?;
            return Ok(Original::Send(bytes));
        }
        if i != s.entries.len() {
            return Err(Refusal::SenderOrdinalGap);
        }
        if i == MAX_SOURCE_INTENTS {
            return Err(Refusal::QueueFull(MAX_SOURCE_INTENTS));
        }
        let bytes = seal()?;
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_INTENT_BYTES {
            return Err(Refusal::Oversized(MAX_SOURCE_INTENT_BYTES));
        }
        s.entries.push_back(Entry {
            intent,
            seal: hex::encode(&bytes),
            attempts: 1,
            receipt: None,
            settled: false,
        });
        self.persist(&s)?;
        Ok(Original::Send(bytes))
    }
    /// Called only after the ordinary destination verifier checked its signed V2
    /// against the exact retained envelope and the original current grant.
    pub(super) fn accept(
        &self,
        h: SenderOrdinalV1,
        bytes: &[u8],
        receipt: SignedDestinationReceipt,
    ) -> Result<SignedDestinationReceipt, Refusal> {
        let _guard = self.lock()?;
        let mut s = self.load()?;
        let i = self.index(&s, h)?;
        let e = s.entries.get_mut(i).ok_or(Refusal::SenderOrdinalGap)?;
        if e.seal != hex::encode(bytes) || receipt.receipt.message_id != h.message_id()? {
            return Err(Refusal::NotAuthorized);
        }
        if let Some(prior) = &e.receipt {
            return if prior == &receipt {
                Ok(prior.clone())
            } else {
                Err(Refusal::NotAuthorized)
            };
        }
        e.receipt = Some(receipt.clone());
        self.persist(&s)?;
        Ok(receipt)
    }
    pub(super) fn settle(
        &self,
        statement: &SenderSettlementV1,
        guest: &VerifyingKey,
    ) -> Result<u64, Refusal> {
        statement.verify(guest)?;
        let _guard = self.lock()?;
        let mut s = self.load()?;
        let i = match self.index(&s, statement.handle) {
            Err(Refusal::SenderOrdinalRetired) => return Ok(s.retired),
            v => v?,
        };
        let e = s.entries.get_mut(i).ok_or(Refusal::SenderOrdinalGap)?;
        let accepted = e.receipt.as_ref().ok_or(Refusal::NotAuthorized)?;
        if SenderSettlementV1::receipt_digest(accepted)? != statement.receipt_digest {
            return Err(Refusal::NotAuthorized);
        }
        e.settled = true;
        while s.entries.front().is_some_and(|e| e.settled) {
            s.entries.pop_front();
            s.retired = s.retired.checked_add(1).ok_or(Refusal::Malformed)?;
        }
        self.persist(&s)?;
        Ok(s.retired)
    }
}
use std::os::unix::fs::DirBuilderExt;
