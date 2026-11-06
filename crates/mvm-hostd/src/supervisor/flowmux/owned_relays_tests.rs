use super::*;
use crate::supervisor::flowmux::PayloadResourcePool;
use std::sync::Weak;

#[path = "../../../tests/support/installed_factory.rs"]
pub mod installed_factory;
#[path = "../../../tests/common/installed_resource_fixture.rs"]
pub mod installed_resource_fixture;

struct Hook {
    group: Weak<OwnedTcpRelays>,
    pool: PayloadResourcePool,
    poison: bool,
    reached: bool,
}
static HOOK: Mutex<Option<Hook>> = Mutex::new(None);
const CHILD: &str = "supervisor::flowmux::owned_relays::custody_tests::owned_child";

pub(super) fn before_attach(witness: &RelayWitness) {
    let (group, poison) = {
        let mut hook = HOOK.lock().unwrap();
        let Some(hook) = hook.as_mut() else {
            return;
        };
        let group = hook.group.upgrade().unwrap();
        assert!(Arc::ptr_eq(&group.inner, &witness.inner));
        assert_eq!(
            hook.pool.snapshot().unwrap().active,
            1,
            "actual core exists before injection"
        );
        assert!(!hook.reached, "one original prepared reader");
        hook.reached = true;
        (group, hook.poison)
    };
    if poison {
        let poisoned = std::panic::catch_unwind(|| {
            let _original = group.inner.ledger.lock().unwrap();
            panic!("controlled original prepared-reader ledger poison");
        });
        assert!(poisoned.is_err());
    } else {
        group.close_and_wake().unwrap();
    }
}

#[test]
fn owned_child() {
    let Ok(mode) = std::env::var("MVM_INSTALLED_RESOURCES_FIXTURE") else {
        return;
    };
    let poison = mode == "owned-attach-poison";
    assert!(poison || mode == "owned-attach-close");
    installed_factory::child_owned_with(
        |group, pool| {
            *HOOK.lock().unwrap() = Some(Hook {
                group: Arc::downgrade(group),
                pool: pool.clone(),
                poison,
                reached: false,
            });
        },
        |group, pool| {
            assert!(HOOK.lock().unwrap().as_ref().unwrap().reached);
            assert_eq!(
                pool.snapshot().unwrap().active,
                1,
                "Err must retain the actual mapped reader/codec owner"
            );
            let ledger = if poison {
                match group.inner.ledger.lock() {
                    Err(error) => error.into_inner(),
                    Ok(_) => panic!("controlled ledger was not poisoned"),
                }
            } else {
                group.inner.ledger.lock().unwrap()
            };
            assert!(ledger.closed);
            if poison {
                assert!(ledger.failed);
                assert!(ledger.slots.iter().any(|slot| slot.prepared.is_some()));
            } else {
                assert!(
                    ledger
                        .slots
                        .iter()
                        .any(|slot| matches!(slot.phase, Phase::Reader { .. }))
                );
            }
        },
    );
}

#[test]
fn close_between_core_creation_and_attach_retains_original_reader_until_join() {
    installed_factory::attach_close_parent(CHILD);
}

#[test]
fn poison_between_core_creation_and_attach_retains_original_reader_without_drain() {
    installed_factory::attach_poison_parent(CHILD);
}
