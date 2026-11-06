//! Shared-ledger close/cleanup tests, not a production parent grant or VM proof.
use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

fn limits() -> PayloadResourceLimits {
    PayloadResourceLimits {
        max_active: 2,
        resident_bytes: 8 << 20,
        disk_bytes: 32 << 20,
    }
}
fn charge() -> PayloadResourceCharge {
    PayloadResourceCharge {
        resident_bytes: 1 << 20,
        disk_bytes: 1 << 20,
    }
}

#[derive(Debug)]
struct GatedParent {
    gate: AtomicBool,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl ParentPayloadReservation for GatedParent {
    fn limits(&self) -> PayloadResourceLimits {
        limits()
    }
    fn authorize(
        &self,
        _: &mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan,
        _: &str,
    ) -> io::Result<()> {
        Ok(())
    }
    fn check_current(&self) -> io::Result<()> {
        if self.gate.swap(false, Ordering::AcqRel) {
            self.entered.send(()).map_err(invalid)?;
            self.release
                .lock()
                .map_err(|_| invalid("fixture release poisoned"))?
                .recv_timeout(Duration::from_secs(2))
                .map_err(invalid)?;
        }
        Ok(())
    }
}

#[test]
fn close_wins_against_inflight_parent_check_without_holding_pool_ledger() {
    let (entered, entry) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    // Private constructor isolates accounting/lock ordering. This is not an
    // admission test or a production constructor from serialized grant facts.
    let pool = PayloadResourcePool::new(
        limits(),
        Some(Arc::new(GatedParent {
            gate: AtomicBool::new(true),
            entered,
            release: Mutex::new(resume),
        })),
        0,
    )
    .unwrap();
    std::thread::scope(|scope| {
        let other = pool.clone();
        let reserve = scope.spawn(move || other.reserve_charge(charge()));
        entry.recv_timeout(Duration::from_secs(1)).unwrap();
        // Must return while parent.check_current is still blocked outside the
        // ledger, and prevent that in-flight reserve mutating it afterward.
        pool.close_admission().unwrap();
        release.send(()).unwrap();
        assert!(reserve.join().unwrap().is_err());
    });
    assert_eq!(pool.snapshot().unwrap(), PayloadPoolSnapshot::default());
    assert!(pool.drained().unwrap());
}

#[test]
fn local_fence_wins_against_inflight_parent_check_without_new_charge() {
    let (entered, entry) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let pool = PayloadResourcePool::new(
        limits(),
        Some(Arc::new(GatedParent {
            gate: AtomicBool::new(true),
            entered,
            release: Mutex::new(resume),
        })),
        0,
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wrong-store-kind");
    std::fs::write(&path, b"must remain intact").unwrap();
    std::thread::scope(|scope| {
        let other = pool.clone();
        let reserve = scope.spawn(move || other.reserve_charge(charge()));
        entry.recv_timeout(Duration::from_secs(1)).unwrap();
        // This real failed capture retains its first charge and fences local
        // admission while the first request is outside the ledger.
        assert!(
            pool.reserve_charge(charge())
                .unwrap()
                .with_owned_store(path.clone())
                .is_err()
        );
        let before = pool.snapshot().unwrap();
        release.send(()).unwrap();
        let result = reserve.join().unwrap();
        let refused = result.is_err();
        drop(result);
        assert!(refused, "a local fence must stop an in-flight reservation");
        assert_eq!(pool.snapshot().unwrap(), before);
    });
    assert_eq!(std::fs::read(path).unwrap(), b"must remain intact");
    pool.close_admission().unwrap();
    assert!(!pool.drained().unwrap());
}

#[test]
fn close_retains_live_store_charge_and_allows_verified_drop_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("actual-owned-store");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    std::fs::write(path.join("bounded-artifact"), b"exact owned bytes").unwrap();
    let pool = PayloadResourcePool::for_qualification(limits()).unwrap();
    assert!(
        !pool.drained().unwrap(),
        "open zero counters are not a close barrier"
    );
    let permit = pool
        .reserve_charge(charge())
        .unwrap()
        .with_owned_store(path.clone())
        .unwrap();
    pool.close_admission().unwrap();
    assert!(!pool.drained().unwrap(), "live value and disk remain owned");
    assert_eq!(pool.snapshot().unwrap().disk_charge, charge().disk_bytes);
    assert!(pool.reserve_charge(charge()).is_err());
    assert_eq!(
        std::fs::read(path.join("bounded-artifact")).unwrap(),
        b"exact owned bytes"
    );
    drop(permit);
    assert!(!path.exists(), "close must not prevent original cleanup");
    assert_eq!(pool.snapshot().unwrap(), PayloadPoolSnapshot::default());
    assert!(pool.drained().unwrap());
}

#[test]
fn uncertain_disk_capture_never_becomes_drained_after_close() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wrong-store-kind");
    std::fs::write(&path, b"must remain intact").unwrap();
    let pool = PayloadResourcePool::for_qualification(limits()).unwrap();
    assert!(
        pool.reserve_charge(charge())
            .unwrap()
            .with_owned_store(path.clone())
            .is_err()
    );
    pool.close_admission().unwrap();
    let snapshot = pool.snapshot().unwrap();
    assert_eq!(snapshot.quarantined, 1);
    assert_eq!(snapshot.disk_charge, charge().disk_bytes);
    assert!(!pool.drained().unwrap());
    assert_eq!(std::fs::read(path).unwrap(), b"must remain intact");
}
