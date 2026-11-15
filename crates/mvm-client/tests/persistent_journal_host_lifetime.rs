//! Public ownership signatures only; these tests do not boot a workload.
#![cfg(unix)]

use mvm_client::{LocalBackend, launch::persistent::journal::InstalledJournal};
use mvm_contract::protocol::mailbox::MailboxGrant;
use mvm_core::host_lifetime::PreparedHostLifetime;

#[test]
fn persistent_journal_host_lifetime_has_an_explicit_owned_start_contract() {
    // Type-check the public call without manufacturing journal authority or
    // polling a future that could launch a native workload.
    let _call = async |backend: &std::sync::Arc<LocalBackend>,
                       name: &str,
                       grant: MailboxGrant,
                       journal: &mut InstalledJournal<'_>,
                       lifetime: PreparedHostLifetime| {
        let started = backend
            .start_persistent_with_journal_and_host_lifetime(name, grant, journal, lifetime)
            .await;
        started.map(|owner: mvm_client::launch::persistent::journal::OwnedJournalStart| owner)
    };
}

#[test]
fn ordinary_persistent_journal_start_keeps_its_existing_contract() {
    let _call = async |backend: &LocalBackend,
                       name: &str,
                       grant: MailboxGrant,
                       journal: &mut InstalledJournal<'_>| {
        backend
            .start_persistent_with_journal(name, grant, journal)
            .await
    };
}

#[cfg(target_os = "linux")]
#[test]
fn original_journal_call_requires_the_retained_start_owner() {
    let _call = |owner: &mut mvm_client::launch::persistent::journal::OwnedJournalStart,
                 input: &[u8],
                 until: std::time::Instant,
                 observer: &mut dyn mvm_client::entrypoint::CallObserver| {
        owner.run_entrypoint(input, until, observer)
    };
}
