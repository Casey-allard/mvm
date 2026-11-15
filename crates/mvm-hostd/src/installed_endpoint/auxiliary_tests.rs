use super::{InstalledEndpointComponentPermit, InstalledEndpointResources};

#[test]
fn relay_component_requires_original_resources_and_returns_only_a_retained_permit() {
    fn prepare(
        original: &InstalledEndpointResources,
    ) -> std::io::Result<InstalledEndpointComponentPermit> {
        original.claim_relay_group(2 * 1024 * 1024, 65536)
    }
    fn current(permit: &InstalledEndpointComponentPermit) -> std::io::Result<()> {
        permit.check_current()
    }
    fn same(a: &InstalledEndpointComponentPermit, b: &InstalledEndpointComponentPermit) -> bool {
        a.same_partition(b)
    }
    let _ = (prepare, current, same);
}

use super::auxiliary::{AuxiliaryLedger, Component};
use mvm_vmm::host::network_endpoint_spawn::INSTALLED_CONTROL_BUFFER_BYTES;
use std::{
    io,
    sync::{Arc, Barrier},
};

fn credits(stack: u64, metadata: u64) -> Arc<AuxiliaryLedger> {
    Arc::new(AuxiliaryLedger::new(stack, INSTALLED_CONTROL_BUFFER_BYTES + metadata).unwrap())
}

#[test]
fn relay_and_readers_draw_one_stack_and_metadata_remainder() {
    let ledger = credits(10, 100);
    ledger.reserve(Component::Relay, 4, 60, || Ok(())).unwrap();
    ledger
        .reserve(Component::CodecReaders, 6, 40, || Ok(()))
        .unwrap();
    assert_eq!(
        ledger
            .reserve(Component::Relay, 0, 0, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
}

#[test]
fn failed_dimension_is_atomic_and_the_failed_component_cannot_retry() {
    let ledger = credits(10, 100);
    assert_eq!(
        ledger
            .reserve(Component::Relay, 11, 1, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        ledger
            .reserve(Component::Relay, 0, 0, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    ledger
        .reserve(Component::CodecReaders, 10, 100, || Ok(()))
        .unwrap();
    let ledger = credits(10, 100);
    assert_eq!(
        ledger
            .reserve(Component::Relay, 1, 101, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    ledger
        .reserve(Component::CodecReaders, 10, 100, || Ok(()))
        .unwrap();
}

#[test]
fn original_control_buffer_credit_is_debited_before_components() {
    assert!(AuxiliaryLedger::new(10, INSTALLED_CONTROL_BUFFER_BYTES - 1).is_err());
    let ledger = credits(10, 0);
    assert_eq!(
        ledger
            .reserve(Component::Relay, 0, 1, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    ledger
        .reserve(Component::CodecReaders, 10, 0, || Ok(()))
        .unwrap();
}

#[test]
fn full_bootstrap_requirement_is_debited_once_before_reader_or_relay_claims() {
    let base = mvm_vmm::host::network_endpoint_spawn::INSTALLED_BOOTSTRAP_MIN_BYTES;
    assert!(AuxiliaryLedger::new_with_bootstrap(10, base + 59, base + 60).is_err());
    let ledger = AuxiliaryLedger::new_with_bootstrap(10, base + 100, base + 60).unwrap();
    ledger.reserve(Component::Relay, 4, 40, || Ok(())).unwrap();
    assert!(
        ledger
            .reserve(Component::CodecReaders, 0, 1, || Ok(()))
            .is_err()
    );
}

#[test]
fn simultaneous_distinct_components_cannot_each_spend_the_whole_projection() {
    let ledger = credits(10, 100);
    let barrier = Arc::new(Barrier::new(3));
    let threads: Vec<_> = [Component::Relay, Component::CodecReaders]
        .into_iter()
        .map(|kind| {
            let ledger = ledger.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                ledger.reserve(kind, 8, 80, || Ok(()))
            })
        })
        .collect();
    barrier.wait();
    let successes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
}

#[test]
fn current_check_runs_outside_ledger_and_failure_fences_other_components() {
    let ledger = credits(10, 100);
    ledger
        .reserve(Component::Relay, 4, 60, || {
            ledger.reserve(Component::CodecReaders, 6, 40, || Ok(()))
        })
        .unwrap();
    let ledger = credits(10, 100);
    assert!(
        ledger
            .reserve(Component::Relay, 1, 1, || Err(
                io::ErrorKind::PermissionDenied.into()
            ))
            .is_err()
    );
    assert_eq!(
        ledger
            .reserve(Component::CodecReaders, 0, 0, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}
#[test]
fn canonical_owned_collector_fits_existing_eighty_mib_auxiliary_credit() {
    use crate::telemetry_collector::{owned_collector_requirements, owned_scanner_requested_bytes};
    let policy = mvm_core::policy::RedactionPolicy::default();
    let facts = owned_collector_requirements().unwrap();
    let scanner = owned_scanner_requested_bytes(&policy).unwrap();
    let requested = facts.known_metadata_bytes.checked_add(scanner).unwrap();
    let prepaid = 80_u64 << 20;
    println!(
        "{{\"scope\":\"actual-auxiliary-collector-admission\",\"prepaid_metadata\":{prepaid},\"scanner_requested\":{scanner},\"collector_requested\":{requested}}}"
    );
    let ledger = credits(facts.known_rust_stack_bytes, prepaid);
    ledger
        .reserve(
            Component::Collector,
            facts.known_rust_stack_bytes,
            requested,
            || Ok(()),
        )
        .expect("canonical collector must fit existing prepaid auxiliary credit");
    // The SAME ledger still refuses a byte past its actual remainder; no
    // second pool, refill or live-object repricing is exercised here.
    assert_eq!(
        ledger
            .reserve(Component::Controller, 0, prepaid - requested + 1, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        ledger
            .reserve(Component::Collector, 0, 0, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
}
#[test]
fn dual_nfa_collector_fits_existing_sixty_mib_auxiliary_credit() {
    use crate::telemetry_collector::{owned_collector_requirements, owned_scanner_requested_bytes};
    let policy = mvm_core::policy::RedactionPolicy::default();
    let facts = owned_collector_requirements().unwrap();
    let scanner = owned_scanner_requested_bytes(&policy).unwrap();
    let requested = facts.known_metadata_bytes.checked_add(scanner).unwrap();
    let prepaid = 60_u64 << 20;
    println!(
        "{{\"scope\":\"actual-auxiliary-collector-admission\",\"prepaid_metadata\":{prepaid},\"scanner_requested\":{scanner},\"collector_requested\":{requested}}}"
    );
    let ledger = credits(facts.known_rust_stack_bytes, prepaid);
    ledger
        .reserve(
            Component::Collector,
            facts.known_rust_stack_bytes,
            requested,
            || Ok(()),
        )
        .expect("canonical collector must fit existing prepaid auxiliary credit");
    // The SAME ledger still refuses a byte past its actual remainder; no
    // second pool, refill or live-object repricing is exercised here.
    assert_eq!(
        ledger
            .reserve(Component::Controller, 0, prepaid - requested + 1, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        ledger
            .reserve(Component::Collector, 0, 0, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
}
