# Plan 222 — Delete the Vz backend (complete the in-house VMM migration)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Remove Apple Virtualization.framework (Vz) from mvm entirely, so macOS runs on exactly one workload/builder/dev VMM — mvm's in-house HVF VMM (`WorkloadRunner<InHouseDriver>` + `InHouseBuilderVm`). End state: `rg -i 'vzbackend|virtualization\.framework|mvm-vz-supervisor'` in `crates/` is empty; `--hypervisor vz` / `--builder vz` error cleanly; the workspace builds and every gate passes.

**Source:** Plan 214 tail ([[specs/plans/221-inhouse-dev-console.md]]); scoping session 2026-07-04. Supersedes the closed PR #1423 (staged flip through the now-deleted inline `HvfBackend`).

## Status (2026-07-04)

The **workload** path is done, verified, and committed on `feat/plan-222-delete-vz` (5 commits, all gated + live-verified on macOS-26 Apple Silicon):

- [x] **Phase A** — non-interactive in-house workload relay confirmed fixed (`3f67a414` OP_SHUTDOWN-on-host-close) + device-level regression test `host_close_frames_op_shutdown_to_the_guest_agent` (`f882448c`). Live: `machine run --image alpine -- sh -c '…; exit 7'` prints + exits 7 reliably.
- [x] **Phase B** — macOS-26 workload default flipped Vz→in-house. `auto_select` → `InHouse` runner (`488bff85`); `resolve_effective_hypervisor` → classifier-safe `"hvf"` + pure `platform_default_hypervisor` ladder helper (`9fb70399`). `#1423` superseded (its `HvfBackend::security_profile` is moot; the runner carries Tier 2).
- [x] **Phase C** — inline `HvfBackend` struct + `AnyBackend::Hvf` deleted (`0829a728`); in-house VMM reached only through the runner. Catalog `hvf` descriptor constructs the runner + gains `inhouse`/`in-house` aliases; kept `name()`/`kind()`/`hvf.pid` so every classifier is unchanged. Live: default + `--hypervisor hvf` + `--hypervisor inhouse` all boot the runner.
- [x] **Phase D0** — `Platform::is_vz_default_tier` → `is_macos_vmm_tier` rename (`ff6ac4e6`), all ~24 call sites.
- [x] **Phase 1.3 (workload Vz + checkpoint/fork deletion)** — consumed from a parallel session's `ca6669c7` (handoff: `specs/notes/plan-222-workload-vz-deletion-handoff.md`). Deleted `mvm-backend/src/{vz.rs,vz_control.rs}`, `AnyBackend::Vz` + arms, catalog `vz`/`vz.pid` descriptor, `selection`/`compat` Vz, `WorkloadBackend for VzBackend`, `VzTransport`, the `"vz"` workload selector, AND the fork/checkpoint feature (`checkpoint/`, `checkpoint.rs`) — the maintainer decision (checkpoint was built on the Vz supervisor; in-house has no fork). `"vz"` workload/`down`/`ps`/`sandbox` selectors route → `"hvf"`. −9,170 lines, verified green (4389 nextest, clippy, fmt, workspace build; mvmd contract intact). Dead `Checkpoint*` audit tokens in `mvm-core` left for a separate cleanup.

**Remaining (this plan):** the **builder** and **dev-VM** paths are still Vz on macOS-26, and `mvm-vz-supervisor` (+ `vz_objc.rs`) is shared by both — so it cannot be deleted until the dev VM moves to the in-house VMM. The dev VM's blocker is a genuine VMM-feature gap (§Phase 2). Phases below.

## Blocking facts (verified 2026-07-04)

- `feat/plan-222-delete-vz` is **25 behind / 35 ahead** of `origin/main`. `main` HAS: `WorkloadRunner`, `InHouseDriver`, Plan 221 console, the OP_SHUTDOWN relay fix, and **`BuilderBackendChoice::InHouse` + `InHouseBuilderVm`** (the in-house builder selection wiring). `main` LACKS: Plan 220 stdin DX, the workload flip (A/B), the `HvfBackend` deletion (C), the rename (D0). On **this branch** `BuilderBackendChoice` is only `{Libkrun, Vz, Qemu}` — the builder auto-detects **Vz** (proven: the flake run logged "Vz builder VM").
- The interactive dev VM (`mvmctl dev up/shell/status/down/park`, `DevBackend` enum) is **still Vz on every branch incl. `main`** — there is no `DevBackend::InHouse` anywhere. `dev up` → `detect_backend` → `DevBackend::Vz` → `dev_vz::cmd_dev_vz*` → `mvm-vz-supervisor`.
- **`dev_vz.rs` is misnamed** — it is the dev-environment CORE (`bootstrap_builder_vm_image`, `KernelVariant`, `ensure_default_microvm_image`, `DEV_VM_NAME`, stage0/cache/reap helpers, status-JSON builders) consumed by build/kernel/cache/pool/bootstrap/cleanup. **Not deletable.** Only its Vz-specific fns (`cmd_dev_vz`, `cmd_dev_vz_down/park/status`, `is_vz_dev_running`, snapshot/residency helpers) are replaced.
- **The `/work` gap (tent-pole):** the Vz dev VM live-mounts `/work` (host CWD), `/job`, `/out` via **virtio-fs** (`crate::vz::VirtioFsShare`). The in-house HVF VMM supports **only virtio-blk** — `HvfSupervisorConfig` has no virtio-fs field and the `vmm/` device model has no virtio-fs device. `InHouseBuilderVm` sidesteps this by moving jobs/output through **disk images**; an interactive dev VM cannot (no live host-CWD editing). The guest kernel already carries `VIRTIO_FS` (Plan 209) — the gap is host-side only.
- **The snapshot gap:** `InHouseDriver::pause/resume` `bail!("not yet implemented")`. The Vz dev VM's `dev park` (memory→disk snapshot, resume-on-`up`) has no in-house equivalent.

## Global constraints

- No backwards-compat shims. No `#[allow(clippy::too_many_arguments)]`. No plan/PR/ADR citations in code comments.
- Each phase: `cargo fmt --all -- --check` · `clippy --workspace --all-targets -D warnings` · `nextest` (touched crates) · `cargo test --workspace --doc` · `just check-linux` if `cfg(linux)` touched. Live-proof on macOS-26 where the phase changes a runtime path.
- Every phase must leave the workspace **building and dev-usable** — never a state where `mvmctl dev up` is broken on macOS-26.
- Reuse: `mvm-core::config` path helpers; the `<vm_state_dir>/vsock/vsock-<port>.sock` socket convention; the existing persistent-VM lifecycle + Plan 221 console.

---

## Phase 1 — Reconcile with `main`; delete the **builder + workload** Vz

Brings the in-house builder onto the branch, then removes the two Vz paths that already have an in-house replacement. Leaves the dev-VM Vz + `mvm-vz-supervisor` intact (Phase 4 removes those).

- [ ] **1.1 Reconcile.** Rebase the branch onto `origin/main` (git auto-drops the Plan-221/relay commits already upstream), OR create `feat/plan-222-delete-vz-v2` off `main` and cherry-pick the unmerged set: the flip-prep (`4b38a9f1`, `82573f74`, `f6161e91`, `ccb8d66a`), Plan 220 (optional/orthogonal — decide), and the 5 A/B/C/D0 commits. Resolve conflicts in `backend.rs`/`catalog.rs`/`resolve.rs`/`builder_backend_select.rs` (both sides edited selection). **Verify:** full workspace build + `nextest -p mvm-backend -p mvm-cli -p mvm-build -p mvm-core` green; live `machine run --image` on default/hvf/inhouse still boot the runner; **`mvmctl dev up` still works (on Vz for now)**; a `--flake` build now uses the **in-house** builder (`InHouseBuilderVm`), not Vz.
- [ ] **1.2 Delete the Vz builder.** Remove `mvm-build/src/vz.rs` + `vz_builder.rs`, `BuilderBackendChoice::Vz` (+ arms, `builder_backend_select.rs` env/flag/auto-detect/fallback), `--builder vz` from the value_parser, `MVM_BUILDER_BACKEND=vz` parsing, `mvm-build/tests/vz_supervisor_parity.rs` + `vz_builder_flake_invariant.rs`, and the Vz half of `mvm-build/fuzz/…fuzz_supervisor_config`. Make `--builder vz` / `MVM_BUILDER_BACKEND=vz` **error** ("the vz builder was removed; the in-house HVF builder is the macOS default") — add a test. Update `builder_health.rs`, `persistent_builder.rs` (`PersistentBackend::Vz`, `VzPersistentBuilderVm`, `start_vz_persistent`, `leak_vz_handle`). **CAUTION:** the dev VM (`dev_vz::cmd_dev_vz`) uses `VzPersistentBuilderVm` — Phase 4 must land the in-house dev VM *before* this, OR keep `VzPersistentBuilderVm` until Phase 4. Reorder: do 1.2's persistent-builder deletion in Phase 4.
- [ ] **1.3 Delete the Vz workload backend.** Remove `mvm-backend/src/vz.rs` + `vz_control.rs`, `AnyBackend::Vz` (+ every arm), the catalog `vz` descriptor + `BackendKind::Vz` + `vz.pid` selectors, `workload_backend.rs` `impl WorkloadBackend for VzBackend`, `selection.rs`/`compat.rs` (`MicrovmBackend::Vz`) Vz bits, `codesign.rs` Vz-supervisor signing, and `VzTransport` in `mvm/src/vsock_transport.rs` (+ the picker arm). Update `mvm-cli` consumers: `console.rs` (VzTransport probe), `pause.rs` (`is_vz_vm` + Vz pause/resume branch), `checkpoint.rs` (Vz checkpoint), `bench.rs` (`run_vz_*`). Make `--hypervisor vz` / `MVM_HYPERVISOR=vz` **error** ("the vz backend was removed; the in-house HVF VMM is the macOS default") — add a test. **Blocker:** `mvm-backend/src/vz.rs` also holds `resolve_supervisor_path` used by `codesign.rs` to sign `mvm-vz-supervisor` for the dev VM — relocate that into the dev-VM path or keep it until Phase 4. Reorder if needed.

> **Sequencing note:** because `resolve_supervisor_path`/codesign and `VzPersistentBuilderVm` are shared with the dev VM, the *clean* order is **Phase 2 → Phase 4 (dev VM on in-house) → Phase 1.2/1.3 → Phase 5**. Phase 1.1 (reconcile) can and should go first.

## Phase 2 — In-house virtio-fs directory shares (**the tent-pole**)

The dev VM needs live `/work` (host CWD) + `/job`/`/out`. Decide the mechanism, then implement it in the in-house VMM. **This is the single largest piece and gates the whole deletion.**

- [x] **2.0 Design decision:** **(A) virtio-fs** (owner-approved 2026-07-04). Parity with Vz/libkrun, best dev-workload UX; guest kernel already has `CONFIG_VIRTIO_FS` (Plan 209) so it's a host-side-only build. v1 is FUSE-over-virtio **without DAX** (a plain read/write device — still far better than 9p; DAX perf path later). No `virtiofsd` on macOS, so the FUSE server is in-house.
- [x] **2.1a Device: FUSE wire ABI** — `vmm/fuse/abi.rs`: the fixed FUSE structs as explicit LE encode/decode + a fail-closed cursor; layout tests assert the ABI sizes (40/16/88/128/104/64/16). 7 tests.
- [x] **2.1b Device: passthrough FUSE server** — `vmm/fuse/server.rs`: `PassthroughFs::dispatch(&[u8]) -> Option<Vec<u8>>` executing FUSE against a host dir (INIT/GETATTR/SETATTR/LOOKUP/FORGET/OPENDIR/READDIR/OPEN/READ/WRITE/CREATE/MKDIR/UNLINK/RMDIR/RENAME/RELEASE/FLUSH/ACCESS/STATFS). Fails closed; rejects `/`/`..` escape. Transport-free, tested against a temp dir. 10 tests.
- [x] **2.1c Device: virtio-fs mmio transport** — `vmm/virtio_fs.rs`: `VirtioFs` (virtio id 26), per-queue split-virtqueue (hiprio + request), gathers request descriptors → `dispatch` → scatters reply; config tag + num_request_queues. End-to-end FUSE INIT+LOOKUP driven through the virtqueue. 3 tests. **20 virtio-fs tests total, all VM-free + clippy -D warnings clean.**
- [ ] **2.1d Run-loop + FDT integration (needs live HVF)** — register `VirtioFs` in the in-house run loop (`vmm/run.rs`): dispatch its MMIO exits, raise its IRQ; add a `virtio_mmio` node to the FDT (`vmm/fdt.rs`) so the guest kernel probes it. cfg-gated macOS/HVF; validated by live boot, not unit tests.
- [ ] **2.2** Extend `HvfSupervisorConfig` (`mvm-build/src/hvf_supervisor.rs`) with `dir_shares: Vec<DirShare>` (tag, host_path, read_only) + `VmmSpec` (`driver/spec.rs`); map in `InHouseDriver::relay_supervisor_config`. Supervisor constructs a `VirtioFs` per share.
- [ ] **2.3** Guest-side mount: the in-house guest `/init` mounts `virtio-fs` by tag at `/work`/`/job`/`/out` (`mount -t virtiofs work /work`).
- [ ] **2.4** Live-proof: an in-house VM with a `/work` share sees host-CWD edits live (write on host → read in guest, and vice versa). Add the FUSE-request parser to the fuzz job (claim 5 family).

## Phase 3 — (optional) in-house snapshot for `dev park`

- [ ] **3.1** Decide: implement in-house pause/snapshot/resume (memory + disk state via the HVF supervisor), OR **descope `dev park`** on the in-house backend (document the loss; `dev up`/`down` still work). If descoped, `dev park` prints a clear "not supported on the in-house VMM" and Phase 4 omits the park arm. Recommendation: **descope for v1**, revisit under a warm-start plan.

## Phase 4 — `DevBackend::InHouse`: migrate the interactive dev VM

Wire `mvmctl dev` to a long-lived in-house dev VM, reusing the persistent-VM lifecycle + Plan 221 console + Phase 2 shares. Then the Vz dev path (and its supervisor dependency) can go.

- [ ] **4.1** Add `DevBackend::InHouse`; `detect_backend` returns it on `is_macos_vmm_tier` (replacing `DevBackend::Vz`); `effective_hypervisor` reports `"hvf"`.
- [ ] **4.2** Implement the in-house dev-VM boot (new `dev_inhouse.rs`, sibling to the kept `dev_vz.rs` helpers): boot a long-lived in-house VM named `DEV_VM_NAME` via the persistent runner path, with the nix-store overlay disk (`/dev/vdb`), the `/work`/`/job`/`/out` shares (Phase 2), and networking; reuse `ensure_dev_image`, image cache, JSON builders from `dev_vz.rs`.
- [ ] **4.3** Wire `dev up/shell/status/down` arms: `up` → boot/reuse; `shell` → Plan 221 `console_interactive(DEV_VM_NAME)` (already in-house-capable); `status` → persistent-VM `status()`; `down` → `stop()`. `park` → per Phase 3.
- [ ] **4.4** Live-proof on macOS-26: `mvmctl dev up` boots the dev VM **on the in-house VMM** (no `mvm-vz-supervisor` process), `dev shell` gives an interactive shell with a live `/work`, `nix build` works inside, `dev status`/`down` correct. Update `is_vz_dev_running` → `is_dev_vm_running` (backend-agnostic) across cache/cleanup/tests callers.

## Phase 5 — Delete `mvm-vz-supervisor` + all remaining Vz

Only reachable after Phases 1–4: nothing spawns `mvm-vz-supervisor` anymore.

- [ ] **5.1** Delete `mvm-vm-host/src/bin/mvm-vz-supervisor.rs` + `src/vz_objc.rs` + the `[[bin]]` entry + `pub mod vz_objc` + the `objc2-virtualization` deps in `mvm-vm-host/Cargo.toml` (and root `Cargo.toml` comments/feature).
- [ ] **5.2** Remove the Vz-specific fns in `dev_vz.rs` (`cmd_dev_vz*`, `is_vz_dev_running`, snapshot/residency helpers) now that Phase 4 replaced them; delete `VzPersistentBuilderVm`/`start_vz_persistent`; delete the leftover `mvm-backend/src/vz.rs` `resolve_supervisor_path`/codesign hook.
- [ ] **5.3** `mvm-core`: remove `Platform::has_vz`, `config::vm_vz_vsock_dir`/`vm_vz_vsock_port_socket` (migrate the socket convention to a Vz-free name if still used), `residency.rs` Vz refs, `packs::PackBackend::Vz`.
- [ ] **5.4** Doctor: remove `vz_check`, `vz_warm_start`/`vz_standby`, Vz entitlement/snapshot checks.
- [ ] **5.5** Docs/gates: ADR-002 tier matrix (drop the Vz row), ADR-098, `CLAUDE.md` backend-selection prose, `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`, `xtask` claim-catalog/backend-matrix/kernel-config gates that enumerate "vz".
- [ ] **5.6** Final gate: `rg -i 'vzbackend|virtualization\.framework|mvm-vz-supervisor'` in `crates/` empty (spec archives may retain historical refs). Workspace builds; all gates + live `dev up` / `machine run` / `--flake` green on macOS-26.

## Risk / ordering summary

1. **Phase 1.1 (reconcile) first** — safe, unblocks the in-house builder.
2. **Phase 2 (virtio-fs)** is the critical path and needs the §2.0 owner decision (A/B/C) before implementation — it is a real VMM feature, not wiring.
3. **Phase 4 (dev migration)** depends on Phase 2.
4. **Phases 1.2/1.3/5 (deletions)** land last, once nothing references Vz.
5. Keep `mvmctl dev up` working at **every** step (do not delete the Vz dev path before Phase 4 proves the in-house one).
