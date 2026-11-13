//! One explicitly selected original sender generation. The trusted boot path
//! opens every descriptor before dropping UID and supplies a per-boot storage
//! key held in PID 1 memory. Helper recovery requires that same key.
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{SenderSettlementProfile, SignedDestinationReceipt};
use mvm_core::crypto::aead::{self, Key};
use mvm_core::mailbox::{
    frame::{OutboxMessage, Refusal},
    outbound::{journal_direction_commitment, journal_intent_digest},
    reader::MailboxReaderBootBinding,
    sender_ordinal::{MAX_ORDINAL_PAYLOAD, SenderOrdinalV1, SenderRequestV1, SenderSettlementV1},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const MAX_SNAPSHOT: usize = 48 * 1024;
const CURSOR_LEN: usize = 8 + 12 + 16; // u64 encrypted with the canonical AES-GCM frame.

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    last: Option<SenderSettlementV1>,
    current: Option<Pending>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    handle: SenderOrdinalV1,
    payload: Vec<u8>,
    digest: [u8; 32],
    receipt: Option<SignedDestinationReceipt>,
    settlement: Option<SenderSettlementV1>,
}

/// The operating system protects these originally opened files from the
/// workload, which shares the agent UID after privilege drop.
pub struct OrdinalOutbox {
    boot: MailboxReaderBootBinding,
    direction: [u8; 32],
    key: Arc<Key>,
    marker: File, // holds the exclusive store lock through Drop
    cursor: File,
    slots: [File; 2],
    version: u64,
    snapshot: Snapshot,
    healthy: bool,
}

fn paths(root: &Path, direction: &[u8; 32]) -> [PathBuf; 4] {
    let stem = mvm_core::mailbox::outbound::journal_slot_name(direction);
    ["marker", "cursor", "slot0", "slot1"].map(|kind| root.join(format!("{stem}.ordinal-{kind}")))
}
fn io_refusal(_: io::Error) -> Refusal {
    Refusal::Unavailable
}
fn require_root_ancestry(root: &Path) -> Result<(), Refusal> {
    if !root.is_absolute()
        || root
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Refusal::NotAuthorized);
    }
    for ancestor in root.ancestors() {
        let m = fs::symlink_metadata(ancestor).map_err(io_refusal)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(Refusal::NotAuthorized);
        }
    }
    Ok(())
}
fn open_file(path: &Path, uid: u32, fresh: bool) -> Result<File, Refusal> {
    let file = File::options()
        .read(true)
        .write(true)
        .create_new(fresh)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io_refusal)?;
    let m = file.metadata().map_err(io_refusal)?;
    if !m.is_file() || m.nlink() != 1 || m.uid() != uid || m.mode() & 0o777 != 0o600 {
        return Err(Refusal::NotAuthorized);
    }
    Ok(file)
}
fn read_bounded(file: &mut File, cap: usize) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    if file.metadata().map_err(io_refusal)?.len() > cap as u64 {
        return Err(Refusal::Malformed);
    }
    file.seek(SeekFrom::Start(0)).map_err(io_refusal)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_refusal)?;
    if bytes.len() > cap {
        return Err(Refusal::Malformed);
    }
    Ok(bytes)
}
fn replace(file: &mut File, bytes: &[u8]) -> Result<(), Refusal> {
    file.seek(SeekFrom::Start(0)).map_err(io_refusal)?;
    file.write_all(bytes).map_err(io_refusal)?;
    file.set_len(bytes.len() as u64).map_err(io_refusal)?;
    file.sync_all().map_err(io_refusal)
}
fn context(direction: &[u8; 32], version: Option<u64>) -> Vec<u8> {
    let mut aad = b"mvm.guest.original-ordinal-state.v1\0".to_vec();
    aad.extend(direction);
    if let Some(n) = version {
        aad.extend(n.to_be_bytes());
    }
    aad
}
impl OrdinalOutbox {
    /// Explicitly create on first activation only. The root must be original,
    /// root-owned and private with trusted ancestry. Never use as reopen fallback.
    pub fn create(
        root: &Path,
        boot: &MailboxReaderBootBinding,
        key: Arc<Key>,
    ) -> Result<Self, Refusal> {
        require_root_ancestry(root)?;
        Self::open_for(root, boot, 0, true, key)
    }
    /// Open the independently protected original generation; absence and
    /// damage are terminal for local recovery.
    pub fn reopen(
        root: &Path,
        boot: &MailboxReaderBootBinding,
        key: Arc<Key>,
    ) -> Result<Self, Refusal> {
        require_root_ancestry(root)?;
        Self::open_for(root, boot, 0, false, key)
    }
    fn open_for(
        root: &Path,
        boot: &MailboxReaderBootBinding,
        uid: u32,
        fresh: bool,
        key: Arc<Key>,
    ) -> Result<Self, Refusal> {
        let d = boot
            .outbound_journal_v1
            .as_ref()
            .ok_or(Refusal::NotAuthorized)?;
        if d.sender_settlement != Some(SenderSettlementProfile::OrdinalV1)
            || boot.durable_object_pair_sha256_v1.is_some()
        {
            return Err(Refusal::NotAuthorized);
        }
        let dir = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(root)
            .map_err(io_refusal)?;
        let m = dir.metadata().map_err(io_refusal)?;
        if m.uid() != uid || m.mode() & 0o777 != 0o700 {
            return Err(Refusal::NotAuthorized);
        }
        let direction = journal_direction_commitment(boot).map_err(|_| Refusal::NotAuthorized)?;
        let [name, cursor, a, b] = paths(root, &direction);
        let mut marker = open_file(&name, uid, fresh)?;
        marker.try_lock().map_err(|_| Refusal::Unavailable)?;
        let cursor = open_file(&cursor, uid, fresh)?;
        let slots = [open_file(&a, uid, fresh)?, open_file(&b, uid, fresh)?];
        if fresh {
            replace(&mut marker, &direction)?;
        } else if read_bounded(&mut marker, direction.len())?.as_slice() != direction {
            return Err(Refusal::NotAuthorized);
        }
        let mut row = Self {
            boot: boot.clone(),
            direction,
            key,
            marker,
            cursor,
            slots,
            version: 0,
            snapshot: Snapshot::default(),
            healthy: true,
        };
        if fresh {
            row.publish(Snapshot::default())?;
            dir.sync_all().map_err(io_refusal)?;
        } else {
            let encoded = read_bounded(&mut row.cursor, CURSOR_LEN)?;
            let n = aead::open(&row.key, &encoded, &context(&direction, None))
                .map_err(|_| Refusal::Malformed)?;
            row.version = u64::from_be_bytes(n.try_into().map_err(|_| Refusal::Malformed)?);
            if row.version == 0 {
                return Err(Refusal::Malformed);
            }
            let f = &mut row.slots[(row.version % 2) as usize];
            let bytes = read_bounded(f, MAX_SNAPSHOT)?;
            let clear = Zeroizing::new(
                aead::open(&row.key, &bytes, &context(&direction, Some(row.version)))
                    .map_err(|_| Refusal::Malformed)?,
            );
            row.snapshot = serde_json::from_slice(&clear).map_err(|_| Refusal::Malformed)?;
            // An earlier sync may have failed after coherent bytes became
            // visible in the page cache. Establish the selected commit on disk.
            row.marker.sync_all().map_err(io_refusal)?;
            f.sync_all().map_err(io_refusal)?;
            row.cursor.sync_all().map_err(io_refusal)?;
            dir.sync_all().map_err(io_refusal)?;
        }
        Ok(row)
    }
    fn publish(&mut self, snapshot: Snapshot) -> Result<(), Refusal> {
        let version = self.version.checked_add(1).ok_or(Refusal::StorageFull)?;
        let clear = Zeroizing::new(serde_json::to_vec(&snapshot).map_err(|_| Refusal::Malformed)?);
        let bytes = aead::seal(&self.key, &clear, &context(&self.direction, Some(version)));
        if bytes.len() > MAX_SNAPSHOT {
            return Err(Refusal::StorageFull);
        }
        let commit = aead::seal(
            &self.key,
            &version.to_be_bytes(),
            &context(&self.direction, None),
        );
        // A failed write/sync may be ambiguous. Reopening must verify the
        // original authenticated cursor; never guess a winner from the slots.
        self.healthy = false;
        replace(&mut self.slots[(version % 2) as usize], &bytes)?;
        replace(&mut self.cursor, &commit)?;
        self.snapshot = snapshot;
        self.version = version;
        self.healthy = true;
        Ok(())
    }
    pub fn retired_prefix(&self) -> u64 {
        self.snapshot.last.as_ref().map_or(0, |s| s.handle.ordinal)
    }
    fn check_live(&self, now: i64) -> Result<(), Refusal> {
        if !self.healthy
            || [&self.marker, &self.cursor, &self.slots[0], &self.slots[1]]
                .iter()
                .any(|f| !f.metadata().is_ok_and(|m| m.nlink() == 1))
        {
            return Err(Refusal::Unavailable);
        }
        let d = self
            .boot
            .outbound_journal_v1
            .as_ref()
            .ok_or(Refusal::NotAuthorized)?;
        if !(d.not_before_unix_ms..d.expires_at_unix_ms).contains(&now) {
            return Err(Refusal::Expired);
        }
        Ok(())
    }
    fn check(&self, handle: SenderOrdinalV1, now: i64) -> Result<(), Refusal> {
        self.check_live(now)?;
        if handle.direction != self.direction {
            return Err(Refusal::NotAuthorized);
        }
        handle.message_id()?;
        Ok(())
    }
    fn original(&self, h: SenderOrdinalV1) -> Result<&Pending, Refusal> {
        if h.ordinal <= self.retired_prefix() {
            return Err(Refusal::SenderOrdinalRetired);
        }
        self.snapshot
            .current
            .as_ref()
            .filter(|p| p.handle == h)
            .ok_or(Refusal::SenderOrdinalGap)
    }
    pub fn stage(&mut self, h: SenderOrdinalV1, payload: &[u8], now: i64) -> Result<(), Refusal> {
        self.check(h, now)?;
        let d = self
            .boot
            .outbound_journal_v1
            .as_ref()
            .ok_or(Refusal::NotAuthorized)?;
        let max = MAX_ORDINAL_PAYLOAD.min(d.max_payload_bytes as usize);
        if payload.is_empty() || payload.len() > max {
            return Err(Refusal::Oversized(max));
        }
        if h.ordinal <= self.retired_prefix() {
            return Err(Refusal::SenderOrdinalRetired);
        }
        let message = OutboxMessage {
            recipient: d.address.recipient,
            message_id: h.message_id()?,
            body: payload.to_vec(),
        };
        let digest = journal_intent_digest(&message);
        if let Some(p) = &self.snapshot.current {
            if p.handle != h {
                return Err(Refusal::QueueFull(1));
            }
            return if p.digest == digest && p.payload == payload {
                Ok(())
            } else {
                Err(Refusal::NotAuthorized)
            };
        }
        if Some(h.ordinal) != self.retired_prefix().checked_add(1) {
            return Err(Refusal::SenderOrdinalGap);
        }
        let mut next = self.snapshot.clone();
        next.current = Some(Pending {
            handle: h,
            payload: message.body,
            digest,
            receipt: None,
            settlement: None,
        });
        self.publish(next)
    }
    #[cfg(test)]
    fn status(
        &self,
        h: SenderOrdinalV1,
        now: i64,
    ) -> Result<Option<SignedDestinationReceipt>, Refusal> {
        self.check(h, now)?;
        Ok(self.original(h)?.receipt.clone())
    }
    pub fn request(&self, h: SenderOrdinalV1, now: i64) -> Result<SenderRequestV1, Refusal> {
        self.check(h, now)?;
        if let Some(statement) = self.snapshot.last.as_ref().filter(|s| s.handle == h) {
            return Ok(SenderRequestV1::Settle {
                statement: statement.clone(),
            });
        }
        let p = self.original(h)?;
        Ok(match &p.settlement {
            Some(s) => SenderRequestV1::Settle {
                statement: s.clone(),
            },
            None => SenderRequestV1::Submit {
                handle: h,
                payload: p.payload.clone(),
            },
        })
    }
    pub fn record_receipt(
        &mut self,
        r: &SignedDestinationReceipt,
        now: i64,
    ) -> Result<(), Refusal> {
        let p = self
            .snapshot
            .current
            .as_ref()
            .ok_or(Refusal::SenderOrdinalGap)?;
        self.check(p.handle, now)?;
        mvm_core::mailbox::sender_ordinal::verify_sender_receipt(&self.boot, p.handle, r)?;
        if let Some(saved) = &p.receipt {
            return if saved == r {
                Ok(())
            } else {
                Err(Refusal::NotAuthorized)
            };
        }
        let mut next = self.snapshot.clone();
        next.current
            .as_mut()
            .ok_or(Refusal::SenderOrdinalGap)?
            .receipt = Some(r.clone());
        self.publish(next)
    }
    pub fn begin_settle(
        &mut self,
        h: SenderOrdinalV1,
        digest: [u8; 32],
        signer: &SigningKey,
        now: i64,
    ) -> Result<SenderSettlementV1, Refusal> {
        self.check(h, now)?;
        if signer.verifying_key().to_bytes() != self.boot.ack_public_key {
            return Err(Refusal::NotAuthorized);
        }
        if let Some(s) = self.snapshot.last.as_ref().filter(|s| s.handle == h) {
            return if s.receipt_digest == digest {
                Ok(s.clone())
            } else {
                Err(Refusal::NotAuthorized)
            };
        }
        let p = self.original(h)?;
        let r = p.receipt.as_ref().ok_or(Refusal::Unavailable)?;
        if SenderSettlementV1::receipt_digest(r)? != digest {
            return Err(Refusal::NotAuthorized);
        }
        if let Some(s) = &p.settlement {
            return Ok(s.clone());
        }
        let s = SenderSettlementV1::sign(&self.boot, h.ordinal, r, signer)?;
        let mut next = self.snapshot.clone();
        next.current
            .as_mut()
            .ok_or(Refusal::SenderOrdinalGap)?
            .settlement = Some(s.clone());
        self.publish(next)?;
        Ok(s)
    }
    /// Call only after the original host has authenticated this statement and
    /// returned the corresponding prefix. A local ACK is insufficient.
    pub fn confirm(&mut self, h: SenderOrdinalV1, prefix: u64, now: i64) -> Result<(), Refusal> {
        self.check(h, now)?;
        if prefix != h.ordinal {
            return Err(Refusal::NotAuthorized);
        }
        if self.snapshot.last.as_ref().is_some_and(|s| s.handle == h) {
            return Ok(());
        }
        let statement = self
            .original(h)?
            .settlement
            .clone()
            .ok_or(Refusal::Unavailable)?;
        self.publish(Snapshot {
            last: Some(statement),
            current: None,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::*;
    use mvm_core::{
        mailbox::sign_receipt,
        plan::{Nonce, PlanId},
    };
    use std::os::unix::fs::PermissionsExt;
    fn handle(boot: &MailboxReaderBootBinding, ordinal: u64) -> SenderOrdinalV1 {
        SenderOrdinalV1 {
            direction: journal_direction_commitment(boot).unwrap(),
            ordinal,
        }
    }
    fn fixture() -> (
        MailboxReaderBootBinding,
        OutboxMessage,
        DestinationReceipt,
        SigningKey,
    ) {
        let b = SigningKey::from_bytes(&[44; 32]);
        let address = MailboxAddress {
            tenant: TenantId::from_bytes([7; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([9; 32]),
            mailbox: MailboxId::from_bytes([10; 32]),
            recipient: PrincipalId::from_bytes([11; 32]),
        };
        let epoch = ExecutionEpoch::new(1).unwrap();
        let direction = MailboxJournalDirectionV1 {
            sender_settlement: Some(SenderSettlementProfile::OrdinalV1),
            source: PrincipalId::from_bytes([12; 32]),
            destination_plan_sha256: [1; 32],
            destination_plan_nonce: [2; 16],
            destination_boot: BootId::from_bytes([3; 32]),
            address,
            execution_epoch: epoch,
            policy_epoch: 1,
            receipt_key: b.verifying_key().to_bytes(),
            source_scope_grant_sha256: [4; 32],
            send_grant_sha256: [5; 32],
            receive_grant_sha256: [6; 32],
            not_before_unix_ms: 100,
            expires_at_unix_ms: 200,
            max_payload_bytes: 313,
        };
        let boot = MailboxReaderBootBinding {
            durable_object_pair_sha256_v1: None,
            outbound_journal_v1: Some(direction),
            plan_id: PlanId(format!("sha256:{}", "ab".repeat(32))),
            plan_nonce: Nonce::from_bytes([6; 16]),
            mailbox: MailboxId::from_bytes([17; 32]),
            authority_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            execution_epoch: epoch,
            boot: BootId::from_bytes([19; 32]),
            guest_identity_key: [20; 32],
            ack_public_key: SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes(),
        };
        let msg = OutboxMessage::new(address.recipient, (0..=255).chain([0]).collect());
        let receipt = DestinationReceipt {
            protocol_version: ProtocolVersion::V2,
            signature_algorithm: SignatureAlgorithm::ED25519,
            delivery_id: DeliveryId::from_bytes([13; 32]),
            message_id: handle(&boot, 1).message_id().unwrap(),
            address,
            execution_epoch: epoch,
            outcome: DeliveryOutcome::AcceptedLocalDurable,
            observed_at_unix_ms: 149,
            ciphertext_commitment: [14; 32],
        };
        (boot, msg, receipt, b)
    }

    #[test]
    fn ordinal_guest_store_recovers_only_the_original_pending_and_signed_settlement() {
        mvm_core::util::test_env::isolated_lock_probe(|| {
            let root = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let uid = root.path().metadata().unwrap().uid();
            let (boot, msg, receipt, b) = fixture();
            let h = handle(&boot, 1);
            let key = Arc::new(Key::random());
            let mut d =
                OrdinalOutbox::open_for(root.path(), &boot, uid, true, Arc::clone(&key)).unwrap();
            d.stage(h, &msg.body, 150).unwrap();
            assert!(d.stage(h, b"changed", 150).is_err());
            assert!(d.stage(handle(&boot, 2), b"second", 150).is_err());
            let signed = sign_receipt(receipt, &b).unwrap();
            let mut other = signed.receipt.clone();
            other.ciphertext_commitment = [23; 32];
            let conflicting = sign_receipt(other, &b).unwrap();
            let forged =
                sign_receipt(signed.receipt.clone(), &SigningKey::from_bytes(&[71; 32])).unwrap();
            assert!(d.record_receipt(&forged, 150).is_err());
            d.record_receipt(&signed, 150).unwrap();
            assert!(d.record_receipt(&conflicting, 150).is_err());
            assert!(
                matches!(d.request(h,150).unwrap(),SenderRequestV1::Submit{payload,..} if payload==msg.body)
            );
            assert!(d.confirm(h, 1, 150).is_err());
            drop(d);
            assert_eq!(
                std::fs::read(&paths(root.path(), &h.direction)[0]).unwrap(),
                h.direction
            );
            assert!(
                OrdinalOutbox::open_for(root.path(), &boot, uid, false, Arc::new(Key::random()))
                    .is_err()
            );
            for entry in std::fs::read_dir(root.path()).unwrap() {
                assert!(
                    !std::fs::read(entry.unwrap().path())
                        .unwrap()
                        .windows(msg.body.len())
                        .any(|w| w == msg.body)
                );
            }
            let mut d =
                OrdinalOutbox::open_for(root.path(), &boot, uid, false, Arc::clone(&key)).unwrap();
            assert_eq!(d.status(h, 150).unwrap().as_ref(), Some(&signed));
            let signer = SigningKey::from_bytes(&[21; 32]);
            let digest = SenderSettlementV1::receipt_digest(&signed).unwrap();
            assert!(d.begin_settle(h, [77; 32], &signer, 150).is_err());
            let exact = d.begin_settle(h, digest, &signer, 150).unwrap();
            assert_eq!(d.request(h, 200), Err(Refusal::Expired));
            drop(d);
            let mut d =
                OrdinalOutbox::open_for(root.path(), &boot, uid, false, Arc::clone(&key)).unwrap();
            assert_eq!(
                d.request(h, 150).unwrap(),
                SenderRequestV1::Settle {
                    statement: exact.clone()
                }
            );
            assert!(d.confirm(h, 2, 150).is_err());
            d.confirm(h, 1, 150).unwrap();
            drop(d);
            let mut d =
                OrdinalOutbox::open_for(root.path(), &boot, uid, false, Arc::clone(&key)).unwrap();
            assert_eq!(d.retired_prefix(), 1);
            assert!(d.stage(h, &msg.body, 150).is_err());
            assert_eq!(d.begin_settle(h, digest, &signer, 150).unwrap(), exact);
            d.confirm(h, 1, 150).unwrap();
            d.stage(handle(&boot, 2), b"second", 150).unwrap();
        });
    }

    #[test]
    fn ordinal_guest_missing_or_damaged_active_state_never_restarts_a_generation() {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let uid = root.path().metadata().unwrap().uid();
        let (boot, msg, _, _) = fixture();
        let h = handle(&boot, 1);
        let key = Arc::new(Key::random());
        assert!(OrdinalOutbox::open_for(root.path(), &boot, uid, false, Arc::clone(&key)).is_err());
        let mut d =
            OrdinalOutbox::open_for(root.path(), &boot, uid, true, Arc::clone(&key)).unwrap();
        assert!(OrdinalOutbox::open_for(root.path(), &boot, uid, false, Arc::clone(&key)).is_err());
        d.stage(h, &msg.body, 150).unwrap();
        let bad_path = paths(root.path(), &h.direction)[2].clone();
        std::fs::remove_file(bad_path).unwrap();
        assert!(d.request(h, 150).is_err());
        drop(d);
        assert!(OrdinalOutbox::open_for(root.path(), &boot, uid, false, Arc::clone(&key)).is_err());
        assert!(OrdinalOutbox::open_for(root.path(), &boot, uid, true, Arc::clone(&key)).is_err());
    }
    #[test]
    fn authenticated_cursor_selects_one_original_and_never_falls_back_on_corruption() {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = dir.path().join("original");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = dir.path().metadata().unwrap().uid();
        let (boot, msg, _, _) = fixture();
        let h = handle(&boot, 1);
        let key = Arc::new(Key::random());
        let mut store = OrdinalOutbox::open_for(&root, &boot, uid, true, Arc::clone(&key)).unwrap();
        let moved = dir.path().join("moved-by-original");
        std::fs::rename(&root, &moved).unwrap();
        store.stage(h, &msg.body, 150).unwrap(); // requires only the held file descriptors
        drop(store);
        let [_, cursor, active, inactive] = paths(&moved, &h.direction);
        std::fs::write(&inactive, b"partial uncommitted snapshot").unwrap();
        let recovered =
            OrdinalOutbox::open_for(&moved, &boot, uid, false, Arc::clone(&key)).unwrap();
        assert_eq!(
            recovered.request(h, 150).unwrap(),
            SenderRequestV1::Submit {
                handle: h,
                payload: msg.body
            }
        );
        drop(recovered);
        let held = std::fs::read(&active).unwrap();
        std::fs::write(&active, [0u8; 32]).unwrap();
        assert!(OrdinalOutbox::open_for(&moved, &boot, uid, false, Arc::clone(&key)).is_err());
        std::fs::write(&active, held).unwrap();
        std::fs::write(cursor, [0u8; 36]).unwrap();
        assert!(OrdinalOutbox::open_for(&moved, &boot, uid, false, Arc::clone(&key)).is_err());
    }
}
