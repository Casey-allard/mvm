//! Reject public `f` / `f_with_*` siblings within the same Rust owner scope.

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;
use syn::{ImplItem, Item, TraitItem, Visibility};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SiblingPair {
    path: String,
    owner: String,
    base: String,
    extended: String,
}

// The journal deliberately distinguishes volatile opening/admission from
// externally anchored and retained-key custody variants. Conflating their
// names would hide the authority boundary at call sites.
//
// The launch/admission entrypoints keep their `_with_verified_*` siblings
// because those variants thread the launch-verified runtime set through
// admission and start: the retained audit evidence must match the runtime
// that was actually verified, and conflating the names would hide that
// verification boundary at call sites.
const EXCEPTIONS: &[(&str, &str, &str, &str)] = &[
    // The verified kernel handoff retains the original prepared workload-root descriptor.
    (
        "crates/mvm-backends/src/driver/fc/kernel.rs",
        "module",
        "boot_descriptor",
        "boot_descriptor_with_root",
    ),
    // Journal startup retains the existing reservation and journal owner through recording.
    (
        "crates/mvm-client/src/launch/detached.rs",
        "module",
        "boot_recorded",
        "boot_recorded_with_journal",
    ),
    // Journal rollback invokes the admitted original owner and retains uncertain aborts.
    (
        "crates/mvm-client/src/launch/detached.rs",
        "module",
        "require_serving_guest",
        "require_serving_guest_with_rollback",
    ),
    // The internal start retains the existing reservation, journal and optional original context.
    (
        "crates/mvm-client/src/launch/machine_start.rs",
        "module",
        "start_machine_spec",
        "start_machine_spec_with_journal_context",
    ),
    // Installed launch consumes the original prepared lifetime and preserves failure custody.
    (
        "crates/mvm-client/src/launch/mod.rs",
        "impl LocalBackend",
        "launch",
        "launch_with_host_lifetime",
    ),
    // A journal start requires its stopped definition and original one-start grant/helper.
    (
        "crates/mvm-client/src/launch/stopped_machine.rs",
        "impl LocalBackend",
        "start_persistent",
        "start_persistent_with_journal",
    ),
    // Runtime-state confinement retains its directory while rechecking the original store lease.
    (
        "crates/mvm-hostd/src/installed_endpoint.rs",
        "impl InstalledEndpointResources",
        "confine",
        "confine_with_runtime_state",
    ),
    // Bootstrap funding enforces its model floor and debits metadata before publication.
    (
        "crates/mvm-hostd/src/installed_endpoint/auxiliary.rs",
        "impl AuxiliaryLedger",
        "new",
        "new_with_bootstrap",
    ),
    // Held directory/file identities select the confinement inputs without ambient path substitution.
    (
        "crates/mvm-hostd/src/jailer/landlock.rs",
        "module",
        "apply",
        "apply_with_owned_files",
    ),
    // Owned confinement keeps selected descriptor identities and their filter shapes together.
    (
        "crates/mvm-hostd/src/jailer/mod.rs",
        "module",
        "confine_self",
        "confine_self_with_owned_files",
    ),
    // Held store, record and runtime-state capabilities select the required syscall filter shape.
    (
        "crates/mvm-hostd/src/jailer/seccomp.rs",
        "module",
        "apply",
        "apply_with_owned_files",
    ),
    // Required orphan protection validates its reserved stack class and refuses unavailable support.
    (
        "crates/mvm-hostd/src/parent_death.rs",
        "module",
        "exit_when_orphaned",
        "exit_when_orphaned_with_stack",
    ),
    // Installed mapping carries the original selected owner and externally signed plan.
    (
        "crates/mvm-hostd/src/run.rs",
        "module",
        "admit_and_boot_local",
        "admit_and_boot_local_with_installed_mapping",
    ),
    // Bounded original-handle wait refuses unsupported deadlines instead of waiting unbounded.
    (
        "crates/mvm-vmm/src/driver/traits.rs",
        "trait RunningVm",
        "wait",
        "wait_with_deadline",
    ),
    // Native boot transfers the original lifetime; unsupported drivers refuse before effects.
    (
        "crates/mvm-vmm/src/driver/traits.rs",
        "trait VmmDriver",
        "boot_custodied",
        "boot_custodied_with_host_lifetime",
    ),
    // The caller-reserved frame cap refuses oversize before body allocation under the same deadline.
    (
        "crates/mvm-vmm/src/host/hvf_control_transport.rs",
        "module",
        "read_frame",
        "read_frame_with_limit",
    ),
    // The caller-reserved frame cap bounds encoding before any prefix or body is written.
    (
        "crates/mvm-vmm/src/host/hvf_control_transport.rs",
        "module",
        "write_frame",
        "write_frame_with_limit",
    ),
    (
        "crates/mvm-client/src/admission/mod.rs",
        "module",
        "admit_persistent_ingress",
        "admit_persistent_ingress_with_runtime",
    ),
    (
        "crates/mvm-hostd/src/plan_admission.rs",
        "impl AdmittedPlan",
        "start_persistent_object_original",
        "start_persistent_object_original_with_verified_runtime",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/installed_journal.rs",
        "impl AdmittedPlan",
        "start_persistent_journal_original",
        "start_persistent_journal_original_with_verified_runtime",
    ),
    (
        "crates/mvm-runtime/src/backend.rs",
        "impl AnyBackend",
        "start_original_object_firecracker",
        "start_original_object_firecracker_with_verified_runtime",
    ),
    (
        "crates/mvm-core/src/mailbox/journal.rs",
        "impl MailboxJournal",
        "admit",
        "admit_with_anchor",
    ),
    (
        "crates/mvm-core/src/mailbox/journal.rs",
        "impl MailboxJournal",
        "open",
        "open_with_anchor",
    ),
    (
        "crates/mvm-core/src/mailbox/journal.rs",
        "impl MailboxJournal",
        "open",
        "open_with_custody",
    ),
    (
        "crates/mvm-build/src/release_signature.rs",
        "module",
        "verify_release_archive_bytes",
        "verify_release_archive_bytes_with_signer",
    ),
    (
        "crates/mvm-client/src/admission/mod.rs",
        "module",
        "admit_plan_for_boot",
        "admit_plan_for_boot_with_verified_retained",
    ),
    (
        "crates/mvm-client/src/admission/mod.rs",
        "module",
        "admit_plan_for_boot",
        "admit_plan_for_boot_with_verified_runtime",
    ),
    (
        "crates/mvm-client/src/admission/mod.rs",
        "module",
        "admit_plan_for_boot_configured_ingress",
        "admit_plan_for_boot_configured_ingress_with_verified_runtime",
    ),
    (
        "crates/mvm-client/src/boot.rs",
        "module",
        "start_prepared_custodied",
        "start_prepared_custodied_with_verified_runtime",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/start.rs",
        "module",
        "admit_and_start",
        "admit_and_start_with_verified_release",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/start.rs",
        "module",
        "start_admitted",
        "start_admitted_with_verified_release",
    ),
    (
        "crates/mvm-runtime/src/backend.rs",
        "impl AnyBackend",
        "prepare_owned_launch",
        "prepare_owned_launch_with_verified_runtime",
    ),
    (
        "crates/mvm-runtime/src/backend.rs",
        "impl AnyBackend",
        "start",
        "start_with_verified_runtime",
    ),
];
const EXPECTED_UNEXPLAINED_PAIRS: usize = 0;

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let pairs = sibling_pairs(workspace)?;
    validate(&pairs, EXCEPTIONS, EXPECTED_UNEXPLAINED_PAIRS)?;
    eprintln!(
        "check-public-function-names: {} explained sibling pairs; zero unexplained",
        pairs.len()
    );
    Ok(())
}

fn public(vis: &Visibility) -> bool {
    !matches!(vis, Visibility::Inherited)
}

fn names_in_items(items: &[Item], path: &str, owner: &str, out: &mut Vec<SiblingPair>) {
    let mut names = BTreeSet::new();
    for item in items {
        if let Item::Fn(function) = item
            && public(&function.vis)
        {
            names.insert(function.sig.ident.to_string());
        }
    }
    add_pairs(path, owner, &names, out);
    for item in items {
        match item {
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    names_in_items(items, path, &format!("mod {}", module.ident), out);
                }
            }
            Item::Impl(block) => {
                let mut names = BTreeSet::new();
                for item in &block.items {
                    if let ImplItem::Fn(function) = item
                        && public(&function.vis)
                    {
                        names.insert(function.sig.ident.to_string());
                    }
                }
                let owner = format!("impl {}", quote_owner(&block.self_ty));
                add_pairs(path, &owner, &names, out);
            }
            Item::Trait(trait_) => {
                let names = trait_
                    .items
                    .iter()
                    .filter_map(|item| match item {
                        TraitItem::Fn(f) => Some(f.sig.ident.to_string()),
                        _ => None,
                    })
                    .collect();
                add_pairs(path, &format!("trait {}", trait_.ident), &names, out);
            }
            _ => {}
        }
    }
}

fn quote_owner(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_else(|| "?".into()),
        _ => "?".into(),
    }
}

fn add_pairs(path: &str, owner: &str, names: &BTreeSet<String>, out: &mut Vec<SiblingPair>) {
    for extended in names {
        if let Some((base, _)) = extended.split_once("_with_")
            && names.contains(base)
        {
            out.push(SiblingPair {
                path: path.into(),
                owner: owner.into(),
                base: base.into(),
                extended: extended.clone(),
            });
        }
    }
}

fn sibling_pairs(workspace: &Path) -> Result<Vec<SiblingPair>> {
    let mut pairs = Vec::new();
    crate::fs_walk::for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, contents| {
            let Ok(relative) = path.strip_prefix(workspace) else {
                return;
            };
            let relative = relative.to_string_lossy();
            if let Ok(file) = syn::parse_file(contents) {
                names_in_items(&file.items, &relative, "module", &mut pairs);
            }
        },
    )?;
    pairs.sort();
    Ok(pairs)
}

fn validate(
    pairs: &[SiblingPair],
    exceptions: &[(&str, &str, &str, &str)],
    expected_unexplained: usize,
) -> Result<()> {
    let actual: BTreeSet<_> = pairs
        .iter()
        .map(|p| {
            (
                p.path.as_str(),
                p.owner.as_str(),
                p.base.as_str(),
                p.extended.as_str(),
            )
        })
        .collect();
    let allowed: BTreeSet<_> = exceptions.iter().copied().collect();
    let stale: Vec<_> = allowed.difference(&actual).collect();
    if !stale.is_empty() {
        bail!("stale public-function-name exceptions: {stale:?}");
    }
    let unexplained: Vec<_> = actual.difference(&allowed).collect();
    if unexplained.len() != expected_unexplained {
        bail!(
            "expected {expected_unexplained} unexplained public sibling pairs, found {}: {unexplained:?}",
            unexplained.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scan(source: &str) -> Vec<SiblingPair> {
        let file = syn::parse_file(source).unwrap();
        let mut out = Vec::new();
        names_in_items(&file.items, "x.rs", "module", &mut out);
        out
    }
    #[test]
    fn detects_siblings_in_one_module_scope() {
        assert_eq!(
            scan("pub fn open(){} pub fn open_with_policy(){} ").len(),
            1
        );
    }
    #[test]
    fn separates_module_and_impl_owners() {
        assert!(
            scan("pub fn open(){} struct X; impl X { pub fn open_with_policy(){} }").is_empty()
        );
    }
    #[test]
    fn separates_individual_impl_owners() {
        assert!(scan("struct A; struct B; impl A { pub fn open(){} } impl B { pub fn open_with_policy(){} }").is_empty());
    }
    #[test]
    fn detects_siblings_inside_one_impl() {
        let pairs = scan("struct A; impl A { pub fn open(){} pub fn open_with_policy(){} }");
        assert_eq!(pairs[0].owner, "impl A");
    }
    #[test]
    fn rejects_unexpected_pairs() {
        let p = SiblingPair {
            path: "x".into(),
            owner: "module".into(),
            base: "a".into(),
            extended: "a_with_b".into(),
        };
        assert!(
            validate(&[p], &[], 0)
                .unwrap_err()
                .to_string()
                .contains("unexplained")
        );
    }
    #[test]
    fn rejects_stale_exceptions() {
        assert!(
            validate(&[], &[("x", "module", "a", "a_with_b")], 0)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }
}
