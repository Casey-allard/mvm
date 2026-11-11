# Installed resource ownership component

This MIT-licensed component is imported from SpiralCore. The full copyright
notice is preserved in `LICENSE-MIT`; `provenance.json` records the source
revision, paths, exact imported hashes and integration-test import edit.

The original owner holds an exclusive owner lock. Every participating resource
retains its own shared holder lease for the original installation/profile/epoch.
Recovery requires a fresh, separately opened exclusive holder lock; it does not
infer cleanup from a PID, timeout or metadata assertion. Drop never publishes a
clean epoch. Stable descriptor identities, private local storage and durable
publication barriers remain mandatory.

The import preserves the fixed 176-byte record and checksum domain. It uses
MVM's already locked SHA-256 dependency and adds no package version. The record
checksum is damage detection, not authentication or a FIPS-validation claim.

`mvm-vmm::host::installed_owner` is a Unix resource-lifetime primitive. Its
successful retirement proves exclusion only of resources that actually retain
the lease. It neither grants mailbox/boot authority nor proves original Child
collection. Host-agent, signer, helper and cleanup-job participation must be
integrated and tested before it can qualify installed-service recovery.

Focused Linux validation commands (serial subprocess fixtures):

```sh
cargo test --release --locked -p mvm-vmm --test installed_owner -- --test-threads=1
cargo test --release --locked -p mvm-vmm --lib host::installed_owner -- --test-threads=1
cargo clippy --release --locked -p mvm-vmm --lib --test installed_owner -- -D warnings
```

These commands exercise the imported production module. They boot no MVM and
do not establish native macOS, Windows, WAN, durable mailbox or fleet acceptance.

## Local exec handoff

`spawn_with_resource_lease(Command, HolderLease)` consumes a trusted fixed
command, retains two exact descriptors through spawn, and returns the original
Child and original parent lease. All fallible handoff preparation precedes
spawn. The caller retains both owners through actual child collection.

The child's process entry calls unsafe `receive_resource_lease_at_startup()`
once, before any descendant spawn or concurrent environment access. It consumes
bounded version-1 `MVM_RESOURCE_LEASE_V1` metadata, restores CLOEXEC, validates
the descriptors and exact current record, acquires a fresh independent shared
lease, then closes inherited aliases without unlocking. The returned lease
must outlive that resource's work. Missing metadata is an ordinary unleased
invocation; malformed metadata requires immediate startup refusal.

The marker contains only local descriptor numbers, installation/profile/epoch
labels and a record digest. It is not permission, a network envelope or a key
channel. Actual helpers must retain the lease themselves; a parent actor's
lease alone cannot protect recovery after that actor's process dies. The CLI
and signer startup boundaries and the installed daemon still require their
own exact-source integration acceptance.

## Fresh host-agent provisioning

The sibling `host_agent_installation` module reuses the original directory and
platform ACL guards and the original Clean-record initializer. It owns the
single host-agent namespace/key derivation. Its explicit fresh-home operation
requires a new directory, retains the original directory descriptors, and keeps
an initialization intent until the Clean resource and directory barriers are
complete. Existing or partial homes require verified opening or explicit
reconciliation. The receipt grants neither boot authority nor service readiness.
Canonical CLI/SDK placement and installed-service qualification remain required.

## Retained startup recovery exclusion

`InstallationOwner::reconcile_with_exclusion()` returns an opaque borrowed
`RecoveryExclusion`, retaining the original owner and a fresh independent
holders-EX lock even when the record was already Clean. Its mutable borrow
prevents a new owner epoch until the guard is dropped. `revalidate()` checks
the original namespace, current Clean record and retained holders-file identity.
The existing `reconcile()` result remains informational and is not a retained
recovery guard.

This guard excludes participating resource holders only. Startup reconciliation
still needs checked original inventory, fenced canonical lifecycle state and
bounded descriptor-relative filesystem work. An empty inventory, absent PID or
this lock alone does not prove legacy-resource absence, original Child
collection or service readiness. The host-agent startup integration remains
separate from the component's focused lock and storage tests.
