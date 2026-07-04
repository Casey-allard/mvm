# Handoff: workload Vz + checkpoint deletion (Plan 222)

**From:** a parallel session. **Status:** DONE + verified, on an isolated branch.
**Date:** 2026-07-04.

## TL;DR

The full **workload Vz backend + checkpoint/fork deletion** is already done and
green on branch **`chore/plan-222-vz-deletion`**, commit **`ca6669c7`**. That
branch is **exactly one commit ahead of `feat/plan-222-delete-vz`** (`ff6ac4e6`)
— it was branched off your HEAD, so it fast-forwards cleanly. **Do not
re-delete workload Vz** — consume this commit instead of racing it.

## Consume it (pick one)

```sh
# Option A — fast-forward the shared branch onto the deletion (cleanest):
git checkout feat/plan-222-delete-vz
git merge --ff-only chore/plan-222-vz-deletion

# Option B — cherry-pick the single self-contained commit:
git checkout feat/plan-222-delete-vz
git cherry-pick ca6669c7
```

## Scope (what this commit did)

**Deleted (−9,170 lines, 33 files):**
- `mvm-backend/src/vz.rs` (4295) + `vz_control.rs` — workload Vz backend
- `mvm-backend/src/checkpoint/` (1809) + `mvm-cli/.../vm/checkpoint.rs` (1497) —
  the fork/checkpoint feature (it was built on the Vz supervisor config;
  in-house has no fork, so it goes with Vz — this was the maintainer decision)
- `AnyBackend::Vz` variant + every match arm, catalog `vz`/`vz.pid` descriptor,
  `selection`/`compat MicrovmBackend::Vz`, `WorkloadBackend for VzBackend`,
  `VzTransport`, and the `"vz"` workload selector plumbing
- `mvm-hostd/src/audit/bind.rs` + `mvm-cli/.../vm/tenant_resolution.rs`
  (orphaned once checkpoint.rs, their sole caller, was removed)

**KEPT on purpose (separate deprecation axis — do NOT assume these are gone):**
- BUILDER Vz: `mvm-build/src/vz.rs`, `vz_builder.rs`
- `mvm-vm-host/src/bin/mvm-vz-supervisor.rs` + `vz_objc.rs` (the builder drives them)
- `mvm-vm-host/src/bin/mvm-bridge.rs` (Firecracker uses it)
- `mvm-cli/.../vm/pause.rs` (Firecracker instance-snapshot / warm-start — NOT Vz checkpoint)
- dev/builder VM path (`env/dev_vz.rs`, `dev.rs`, `persistent_builder.rs`)

## Judgment calls (already verified)

- Dev-VM console + `dev_vz` agent probe repointed `VzTransport::new(dir)` →
  `LibkrunTransport::new(dir)`. Verified byte-identical `socket_path`
  (`<dir>/vsock-<port>.sock`) — zero behavior change.
- macOS platform-default hypervisor in `down.rs`/`ps.rs`/`sandbox.rs` now routes
  `"vz"` → `"hvf"` (the in-house VMM).
- Left **dead** `CheckpointCreated`/`Forked`/`Restored` audit tokens +
  `emit_checkpoint_*` in `mvm-core` — removing them cascades into the
  mvmd-consumed audit enum, so it's a separate cleanup.

## Verification (independently re-run, not just claimed)

`cargo build --workspace` clean · `cargo nextest` **4389 pass** across
mvm-backend/mvm/mvm-cli/mvm-core/mvm-hostd (+110 mvmctl integration) · clippy 0
warnings · fmt clean · 0 live `crate::vz`/`AnyBackend::Vz`/`VzTransport` refs.

**mvmd cross-repo: SAFE.** mvmd names zero Vz symbols; its 3 `mvmctl::backend`
contract symbols (`HostAgentServicesParams` + host-agent-services fns) are intact.

## Remaining Vz work (NOT in this commit)

1. Delete the **builder** Vz (`mvm-build/vz*.rs`) + `mvm-vz-supervisor` +
   `vz_objc.rs` — the separate deprecation axis.
2. Clean the dead `Checkpoint*` audit tokens from `mvm-core`.
