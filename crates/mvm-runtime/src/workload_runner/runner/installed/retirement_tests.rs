//! Private table/ownership qualification, not native exit evidence. These
//! tests deliberately set the private terminal flag without booting a VM.
use super::*;
use mvm_core::host_lifetime::{HostLeaseExpectation, HostLifetimeInputs, PreparedHostLifetime};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};

struct Parent(Arc<AtomicUsize>);
impl Drop for Parent {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn owner(
    name: &str,
    serial: u64,
) -> (tempfile::TempDir, Arc<HostLifetimeAnchor>, Arc<AtomicUsize>) {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.path().join(".state");
    std::fs::write(&state, b"a").unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.path().join("holders.lock"))
        .unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let owner = PreparedHostLifetime::bind(
        HostLifetimeInputs {
            directory: File::open(root.path()).unwrap(),
            holder,
            expected: HostLeaseExpectation {
                state_name: ".state".into(),
                state_bytes: 1,
                state_sha256: hex::decode(
                    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                absent_names: [".state.intent".into(), ".state.next".into()],
            },
            binding: HostLaunchBinding {
                installation: [1; 32],
                profile: [2; 32],
                generation: 1,
                grant_serial: serial,
                vm_name: name.into(),
                backend: BackendKind::Firecracker,
                cpus: 1,
                memory_mib: 128,
            },
        },
        Parent(dropped.clone()),
    )
    .unwrap()
    .into_anchor();
    (root, owner, dropped)
}

fn bookkeeping_retired(slot: &InstalledSlot) {
    slot.state.lock().unwrap().as_mut().unwrap().retired = true;
}

#[test]
fn retired_record_is_not_evicted_by_other_slot_turnover() {
    let table = InstalledSlots::default();
    let (_a, a, _) = owner("retained-first", 1);
    let (_b, b, _) = owner("retained-second", 2);
    let (_c, c, _) = owner("retained-third", 3);
    let first = table.reserve(&a).unwrap();
    let second = table.reserve(&b).unwrap();
    bookkeeping_retired(&first);
    assert!(
        table.reserve(&c).is_err(),
        "retired proof still occupies its record"
    );
    bookkeeping_retired(&second);
    let receipt: crate::workload_runner::OwnedRetirement = table.take_retired(&second).unwrap();
    assert_eq!(receipt.binding(), b.binding());
    let third = table.reserve(&c).unwrap();
    assert!(table.find(&first.id).unwrap().is_some());
    assert!(
        table.reserve(&b).is_err(),
        "old unresolved proof cannot be evicted"
    );
    bookkeeping_retired(&third);
    drop(table.take_retired(&third).unwrap());
    assert!(table.find(&first.id).unwrap().is_some());
    drop(table.take_retired(&first).unwrap());
}

#[test]
fn retirement_consume_requires_this_exact_terminal_record() {
    let table = InstalledSlots::default();
    let foreign = InstalledSlots::default();
    let (_root, a, _) = owner("retirement-exact", 4);
    let first = table.reserve(&a).unwrap();
    let other = foreign.reserve(&a).unwrap();
    bookkeeping_retired(&other);
    assert!(
        table.take_retired(&other).is_err(),
        "same facts are not the original slot"
    );
    assert!(
        table.take_retired(&first).is_err(),
        "active custody cannot produce a receipt"
    );
    assert!(table.find(&first.id).unwrap().is_some());
    bookkeeping_retired(&first);
    let proof = table.take_retired(&first).unwrap();
    assert!(table.take_retired(&first).is_err(), "consume is one-shot");
    let replacement = table.reserve(&a).unwrap();
    assert!(
        table.take_retired(&first).is_err(),
        "stale slot cannot consume replacement"
    );
    assert!(Arc::ptr_eq(
        &table.find(&replacement.id).unwrap().unwrap(),
        &replacement
    ));
    bookkeeping_retired(&replacement);
    drop(table.take_retired(&replacement).unwrap());
    drop(foreign.take_retired(&other).unwrap());
    drop(proof);
}

#[test]
fn consumed_receipt_retains_original_parent_until_its_drop() {
    let table = InstalledSlots::default();
    let (_root, a, dropped) = owner("retirement-parent", 5);
    let slot = table.reserve(&a).unwrap();
    bookkeeping_retired(&slot);
    let proof = table.take_retired(&slot).unwrap();
    assert_eq!(proof.binding(), a.binding());
    drop(a);
    drop(slot);
    drop(table);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "actual parent still owned by receipt"
    );
    drop(proof);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "exactly one final release"
    );
}

#[test]
fn retirement_checks_exact_installed_parent_permit_not_copied_facts() {
    use mvm_core::{
        host_lifetime::CoreCurrentParentPermit,
        plan::{sign_plan, test_support::PlanFixture},
    };
    struct Permit(HostLaunchBinding);
    impl CoreCurrentParentPermit for Permit {
        fn check_current(&self, binding: &HostLaunchBinding) -> Result<()> {
            anyhow::ensure!(*binding == self.0, "foreign fixture binding");
            Ok(())
        }
    }
    let table = InstalledSlots::default();
    let (_root, anchor, _) = owner("retirement-permit", 6);
    let exact: Arc<dyn CoreCurrentParentPermit> = Arc::new(Permit(anchor.binding().clone()));
    let foreign: Arc<dyn CoreCurrentParentPermit> = Arc::new(Permit(anchor.binding().clone()));
    let (_unbound_root, unbound, _) = owner("retirement-unbound", 7);
    let unbound_slot = table.reserve(&unbound).unwrap();
    bookkeeping_retired(&unbound_slot);
    let unbound_receipt = table.take_retired(&unbound_slot).unwrap();
    assert!(
        !unbound_receipt.retains_parent_permit(&exact),
        "no installed permit is not proof"
    );
    let mut config = VmStartConfig {
        name: anchor.binding().vm_name.clone(),
        cpus: 1,
        memory_mib: 128,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = PlanFixture::new().runtime_profile("firecracker").build();
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    config.plan_json = Some(
        serde_json::to_string(&sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
            "test",
        ))
        .unwrap(),
    );
    anchor
        .bind_admitted(&config, BackendKind::Firecracker, &plan)
        .unwrap();
    anchor
        .bind_parent_permit(&config, BackendKind::Firecracker, exact.clone())
        .unwrap();
    let slot = table.reserve(&anchor).unwrap();
    bookkeeping_retired(&slot);
    let receipt = table.take_retired(&slot).unwrap();
    assert!(receipt.retains_parent_permit(&exact));
    assert!(
        !receipt.retains_parent_permit(&foreign),
        "same binding is not same original permit"
    );
}

#[test]
fn helper_free_bookkeeping_never_invents_an_endpoint_retirement() {
    let table = InstalledSlots::default();
    let (_root, anchor, _) = owner("no-endpoint-receipt", 8);
    let slot = table.reserve(&anchor).unwrap();
    // Only table bookkeeping: this fixture has no helper or native exit claim.
    bookkeeping_retired(&slot);
    let mut receipt = table.take_retired(&slot).unwrap();
    assert!(receipt.take_endpoint_retirement().is_none());
    assert!(receipt.take_endpoint_retirement().is_none());
}
