//! Original-field release observations, not cleanup or collection receipts.
use super::{CustodyError, CustodyField, MutationCell};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct Item {
    id: usize,
    drops: Arc<AtomicUsize>,
}
impl Drop for Item {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn retained(drops: &Arc<AtomicUsize>) -> CustodyField<Item> {
    CustodyField::retaining(Item {
        id: 7,
        drops: Arc::clone(drops),
    })
}

#[tokio::test]
async fn release_observer_wakes_only_after_original_guard_unlocks() {
    let drops = Arc::new(AtomicUsize::new(0));
    let field = retained(&drops);
    let mut observed = field.subscribe_release();
    let loan = field.loan().unwrap();
    assert!(matches!(field.loan(), Err(CustodyError::Busy)));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), observed.changed())
            .await
            .is_err()
    );
    drop(loan);
    tokio::time::timeout(Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    let mut same = field.loan().expect("wake must follow actual guard unlock");
    assert_eq!(same.value_mut().id, 7);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(same.complete().unwrap());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn subscribe_before_busy_preserves_release_before_wait() {
    let drops = Arc::new(AtomicUsize::new(0));
    let field = retained(&drops);
    let loan = field.loan().unwrap();
    let mut observed = field.subscribe_release();
    assert!(matches!(field.loan(), Err(CustodyError::Busy)));
    // The release deliberately occurs BEFORE changed() is first awaited.
    drop(loan);
    tokio::time::timeout(Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!field.is_vacant().unwrap());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(field.loan().unwrap().complete().unwrap());
}

#[tokio::test]
async fn canceled_original_loan_wakes_without_dropping_its_value() {
    let drops = Arc::new(AtomicUsize::new(0));
    let field = Arc::new(retained(&drops));
    let mut observed = field.subscribe_release();
    let original = Arc::clone(&field);
    let (entered, held) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _loan = original.loan().unwrap();
        entered.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    held.await.unwrap();
    assert!(matches!(field.loan(), Err(CustodyError::Busy)));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    let mut same = field.loan().unwrap();
    assert_eq!(same.value_mut().id, 7);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(same.complete().unwrap());
}

#[tokio::test]
async fn unwinding_original_loan_wakes_without_erasing_custody() {
    let drops = Arc::new(AtomicUsize::new(0));
    let field = retained(&drops);
    let mut observed = field.subscribe_release();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _loan = field.loan().unwrap();
        panic!("controlled original-loan unwind");
    }));
    assert!(panic.is_err());
    tokio::time::timeout(Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    let mut same = field.loan().unwrap();
    assert_eq!(same.value_mut().id, 7);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(same.complete().unwrap());
}

#[tokio::test]
async fn completion_wakes_only_after_original_field_is_vacant() {
    let drops = Arc::new(AtomicUsize::new(0));
    let field = retained(&drops);
    let mut observed = field.subscribe_release();
    let original = field.loan().unwrap().complete().unwrap();
    tokio::time::timeout(Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(field.is_vacant().unwrap());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(original);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn vacant_raw_guard_reports_typed_busy_and_signals_after_release() {
    let cell = MutationCell::new(Arc::new(tokio::sync::Semaphore::new(256)));
    let mut observed = cell.subscribe_mutation_release();
    let original_guard = cell.inflight_mutation.try_guard().unwrap();
    assert_eq!(
        cell.has_inflight_mutation().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let busy = cell.mutation_loan().err().expect("held original field");
    assert!(busy.is::<super::MutationLoanBusy>());
    drop(original_guard);
    tokio::time::timeout(Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!cell.has_inflight_mutation().unwrap());
    let empty = cell.mutation_loan().err().expect("original field is empty");
    assert!(!empty.is::<super::MutationLoanBusy>());
    // A release notification only requests a recheck. Empty is bookkeeping,
    // never a fabricated original-service/Child collection receipt.
}
