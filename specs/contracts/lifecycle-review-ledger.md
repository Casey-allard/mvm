# Lifecycle and unsafe review: reviewed to date (umbrella #4839)

Backing: preview
Validation: none — this records what was read and what was fixed, as stated in the fixing PRs; it is not a claim that the review is exhaustive and enforces nothing beyond the `undocumented_unsafe_blocks` lint it cites.

The umbrella issue owns status. This file records the "reviewed to date" half of the box
"Review ownership, allocation, errors, state transitions, cancellation, lock/task ownership,
cleanup/rollback, unsafe/FFI boundaries, and panic paths affected by changes" in
[#4839](https://github.com/tinylabscom/mvm/issues/4839). The ongoing half is the PR checklist item in
`AGENTS.md` ("Definition of Done", item 7).

**The review is not exhaustive.** The tables list the areas read, the defects they produced, and,
separately, the files that were not read. Absence from the "read" column is not evidence of
soundness. "Read" is taken from the fixing PR descriptions and the review notes for the lane; the
line ranges are as recorded there and were not re-derived when this file was written.

## Compile-time AES-GCM boundary

Reviewed `crates/mvm-crypto/src/aead.rs`,
`crates/mvm-core/src/crypto/aead.rs`, and the seal/open paths and independent
cipher tests in `crates/mvm-core/src/net/session.rs`. The shared crypto crate
only instantiates the existing `aes-gcm` implementation in its own optimized
compilation unit. It borrows fixed-size keys and nonces for one operation and
returns owned ciphertext/plaintext; it owns no persistent keys, process, task,
lock, or lifecycle state.

The public `aead::Aead` trait lets implementations define their key, nonce,
and error types. `Aes256Gcm` remains the concrete selection at both production
call sites; no algorithm negotiation, protocol switch, or new cipher is added.
Integration tests cover trait-object dispatch and a downstream refusal-only
implementation with different associated types.

The callers retain key zeroization, nonce generation, associated-data selection,
framing, signature verification before session decryption, sequence advancement,
replay checks, and existing error mapping. The at-rest encryption `expect`
retains its existing message and failure condition. The leaf adds a known AES-256-GCM
vector and wrong-key/nonce/AAD, truncated-tag, and byte-tampering tests; the
independent direct-cipher tests in `mvm-core` remain. This is not a review of
the upstream cipher implementation or of the broader snapshot/session lifecycle.

## Mechanical gate

`clippy::undocumented_unsafe_blocks` is `deny` workspace-wide ([#5438](https://github.com/tinylabscom/mvm/pull/5438);
about 200 `SAFETY` comments were written after reading each site, and three packages that had skipped
the lint table now inherit it). The earlier unsafe documentation pass for `mvm-setpriv` and
`mvm-host-services` is [#4993](https://github.com/tinylabscom/mvm/pull/4993). The lint checks that a
comment exists, not that its claim is true; the sites were read, but a comment is not a proof.

## Reviewed areas and defects fixed

| Area reviewed | Defect class | Fixed in | Files read and found sound or fixed |
| --- | --- | --- | --- |
| Typed local admission integration | preserving original selected-runtime custody while adopting the canonical library stages | [Canonical local launch migration](https://github.com/tinylabscom/mvm/pull/5564) | Ordinary launches retain private resolve/verify/admit stages; signed resolution carries the canonical `VerifiedExternalPlan` and checks the authorized image/config before runtime attachment. The selected direct branch retains its signed bundle, original parent, startup workspace, backend, kernel/root and runtime checks, then returns the same one-use `AdmittedLocal` dispatch owner. Signed admission records once, and all paths retain the existing final/start/rollback gates. Original contribution controls and both canonical stage controls remain. Independent focused source/security review found no defect in this composition; merged-source execution is pending, and the preceding frozen-source results do not qualify it. CLI, warm/template, session and persistent migrations remain with their canonical owners. |
| FlowMux returned upload credit | registry and wire grants failed to replenish the same session validator that debited guest uploads | [SpiralCore original-parent load gate](https://github.com/R4-Laboratories/SpiralCore/issues/258) | `FlowMuxSession::send_window_update` admits the existing host-to-guest grant with the actual delta before wire emission. The validator retains its stream-state, zero-credit and checked-overflow rules; its guard is released before session/writer locks. Wire failure follows the existing reset path. The original actual TCP regression fails at round 16 with zero remaining credit despite returned grants; after repair twenty 16 KiB exact echoes and returned credit pass. The existing large-download control, 119 FlowMux controls and strict hostd all-target Clippy also pass. This scoped review is not full installed, VM, WAN or capacity acceptance. |
| Selected serial Object-TCP worker funding | provider counted controller/session but omitted concurrent collector, relay and codec-reader workers | [SpiralCore resource gate](https://github.com/R4-Laboratories/SpiralCore/issues/258) | The existing selected-runtime query composes the complete seven-worker requirement from controller/session facts, the canonical collector count and the pinned serial relay/reader owners. Provider preflight and selected-child startup use the same check before component effects, retaining the one-stream restriction. The aggregate allowance is unchanged; unfunded concurrency refuses. The SDK's original two-worker acceptance has a retained failing-before control. The canonical quote control passes with original source/executable custody. A joined original-parent/selected-child store-load witness and live thread-fanout qualification remain separate; no VM, WAN or capacity acceptance is implied by this row. |
| Launch-owned release verification with original mailbox custody | carrying the checked-runtime binder without its original reader projection admits unsupported mailbox semantics | [Runtime verification design](../adrs/112-verify-the-runtime-release-proof-once-per-launch.md) | Admission and dispatch borrow the launch's authenticated runtime set while retaining original journal/object authorization, resource owners, selected external-plan verification and native observations. Checked custody projects compatibility from that authenticated declaration before snapshotting and retains it for the original endpoint. Three failing-before controls cover valid legacy mailbox profile retention, unsupported object semantics on an old checked source runtime, and absent runtime evidence. Dispatch also reuses the canonical runtime-identity check when the owner is absent, refusing a signed release identity before state/start effects and emitting the existing failed audit. Its failing-before test pairs ordinary no-release dispatch with signed-identity/owner-loss refusal through a test-only admitted snapshot. Neither fixture establishes signed release authentication. Live signed boot, per-launch verifier-count/timing, private MVMD and platform/WAN/capacity acceptance remain separate; this row is not an exhaustive review. |
| Reviewed shared payload-core adoption | compatibility and original resource custody across a pinned dependency update; no new source defect found in the reviewed consumer paths | [Published core storage contract](https://github.com/R4-Laboratories/SpiralCore/blob/adcc7197aa277277be5d074383c6267476163206/docs/network/owned-unix-store.md) | `spiralcore_payload.rs`, `spiralcore_payload/installed.rs`, `owned_relays.rs` and their custody/resource fixtures: both direct dependencies share the reviewed public pin; receiver funding reads the live SmallV1 operation quote before booking; original prepared-reader close/poison custody and parent-relative store retirement remain. This source review does not establish a new native guest, WAN, aggregate capacity or allocator bound from FD/RSS observations. |
| Installed codec-store final destruction | workspace credit visible before the retained store buffers/handles were destroyed | [Original-store contract](https://github.com/R4-Laboratories/SpiralCore/blob/29393e9b476daeef41f51485d2fb8829c4bbefde/docs/network/owned-unix-store.md) | `spiralcore_payload.rs`: successful cleanup stays outside the ledger, all debit checks resolve first, and final store destruction completes under the original ledger lock before credit is published. A test-only drop probe supplies a failing-before control; original child replacement and poisoned ledger retain custody/debit. The core buffer quote is checked against the unchanged 1 MiB workspace floor; larger unqualified requirements refuse. This is process-level source/fixture evidence, not a booted MVM, WAN, RSS or capacity qualification. |
| Installed codec-store explicit workspace declaration | three-argument consumer incompatible with the core's explicit funding contract | [Reviewed core contract](https://github.com/R4-Laboratories/SpiralCore/blob/86497e8868146f2a21ba581dd09fcfabfca6486d/docs/network/owned-unix-store.md) | `spiralcore_payload/workspace.rs` returns only the original installed workspace after current-permit, SmallV1 and checked charge-coverage validation; `installed.rs` supplies the actual context lane and separately funded execution stack class before directory creation. The unchanged 1 MiB floor, native controller/session/reader terms, enforced-owner boundary and destruction-before-credit remain. Focused Linux payload/resource tests retain exact-charge, one-byte-short, no-installed-workspace and original-lock/quarantine controls. This frozen consumer compatibility slice is not adoption into the current upstream owner or proof of physical allocator, installed native/WAN or capacity acceptance. |
| Installed collector-only mapping | missing original collector-only startup and drain integration | [Preview contract](installed-collector-lifetime.md) | `host_lifetime` collector admission, registered endpoint producer, installed collector controller and runtime selection; focused source review and registered-process tests. Journal early-refusal review covers original unconverted-token extraction, irreversible preparation entry, opaque parent handoff and Drop quarantine. It does not qualify new parent-credit release or general uncertain/restarted cleanup. Funded persistent SDK finalization and complete native retirement remain open. |
| Original journal helper configuration | unwind after exec dropped the local original Child before journal-owner publication | [Preview contract](installed-collector-lifetime.md) | `original_journal/stop.rs` post-spawn configuration/socket capture and both A/B constructors, SDK owner-before-readiness ordering. Actual-child tests cover successful configuration, ordinary refusal, panic and panic-payload destructor panic. This scope does not qualify process abort, later constructor unwinds, detached recovery or native guest delivery. |
| Silent `let _ =` on teardown and rollback paths | cleanup failure discarded | [#4989](https://github.com/tinylabscom/mvm/pull/4989) | builder pipeline teardown, transient-run Ctrl-C handler, Firecracker `teardown_paused` restore branches, idle-pool claim rollback (`crates/mvm-backends/src/fc/idle_pool.rs`) |
| Production `unwrap` on guaranteed values | panic path encoded in types | [#4992](https://github.com/tinylabscom/mvm/pull/4992) | `embed_toolchain::strip_glibc`, stage0 nix-seed lift, `vm artifact` prefix resolution, TypeScript decorator site scan, manifest image validation |
| Panics and truncation on hostile sizes | arithmetic overflow, narrowing casts, lock poisoning | [#5168](https://github.com/tinylabscom/mvm/pull/5168) | `mvm-fs` ext4 writer and `elf.rs`; cpio writer in `mvm-builder-guest`; `mvm-agentd/src/process_rpc.rs` and `mvm-core` instance metrics locks. Census is heuristic (script, not a parser) |
| Unproven `expect`/`unwrap` in six crates | panic path | [#5352](https://github.com/tinylabscom/mvm/pull/5352) | `mvm-fs`, `mvm-net`, `mvm-client`, `mvm-bundler`, `mvm-http`, `mvm-hostd`; poisoned-mutex expects and static schema parses left alone on purpose |
| Other typed-error conversions | panic path | [#5075](https://github.com/tinylabscom/mvm/pull/5075), [#5083](https://github.com/tinylabscom/mvm/pull/5083), [#5139](https://github.com/tinylabscom/mvm/pull/5139) | empty workloads, bare image refs, unnamed persistent requests; agentd, vmm and hostd reachable panics; registry `block_on` bridge inside a tokio runtime |
| Persistent builder pid and kernel cache | signalling pid 0 (own process group); racy fixed staging name | [#5385](https://github.com/tinylabscom/mvm/pull/5385) | persistent-builder stop path, `extract_bundled_kernel` |
| Pid-file readers | corrupt pid file reaching `kill(2)` | [#5388](https://github.com/tinylabscom/mvm/pull/5388), [#5395](https://github.com/tinylabscom/mvm/pull/5395) | `EndpointPid::parse`, broker, audit-signer, network-endpoint, QEMU and GPU endpoint pid readers; one `signalable_pid` rule in `crates/mvm-vmm/src/host/process_liveness.rs` |
| Stale pid file at boot | boot proceeding past an unremovable pid file | [#4991](https://github.com/tinylabscom/mvm/pull/4991) | libkrun and QEMU boot paths |
| FlowMux registry and UDP relay | peer-chosen stream id overflow; unsolicited datagrams holding an association; UDP slot leak on open failure | [#5390](https://github.com/tinylabscom/mvm/pull/5390) | `crates/mvm-hostd/src/supervisor/endpoint/flowmux/registry.rs`, `udp_relay.rs`. The slot-leak fix has no test (needs fd or thread exhaustion) |
| HVF guest PC, SMP unwind, HTTP flow cancellation | guest-chosen PC overflow; panic wedging `thread::scope`; cancellation unwatched after response head | [#5402](https://github.com/tinylabscom/mvm/pull/5402) | `crates/mvm-runtime/src/backends/hvf/smp.rs` (non-test code), `http_flow.rs`, `open_flow.rs` lines 1-352 |
| HVF snapshot and cancellation lifecycle | pause/capture races, completion notification | [#4994](https://github.com/tinylabscom/mvm/pull/4994), [#5064](https://github.com/tinylabscom/mvm/pull/5064), [#4983](https://github.com/tinylabscom/mvm/pull/4983) | fixed under the HVF owner work; not re-read for this table |
| Volume, checkpoint and peer-EOF custody | custody, removal guard, EOF after timeout refusal | [#4880](https://github.com/tinylabscom/mvm/pull/4880), [#4957](https://github.com/tinylabscom/mvm/pull/4957), [#4864](https://github.com/tinylabscom/mvm/pull/4864), [#4879](https://github.com/tinylabscom/mvm/pull/4879) | fixed under the volume and vmm owner work; not re-read for this table |
| Unsafe/FFI documentation | missing `SAFETY` claims | [#4993](https://github.com/tinylabscom/mvm/pull/4993), [#5438](https://github.com/tinylabscom/mvm/pull/5438) | every `unsafe` block in the workspace has a comment; see the gate above |

The selected-worker repair's complete tracked Rust tree contains 2,996 files,
1,050,291 source lines and 1,322,491 physical lines across all categories.
Its additional 70 source / 79 physical lines include the quote, refusal check
and regression source. Both source-footprint ceilings equal those measured
totals, with no unused source allowance. These are source-accounting terms,
not runtime memory or worker grants.

The subsequent upload-credit correction's measured complete tree contains
2,997 Rust files, 1,050,375 source lines and 1,322,580 physical lines.
Its additional 84 source / 89 physical lines include the regression source and
the canonical validator update. The exact ceilings retain no unused allowance.
The earlier failed footprint invocation lacked repository metadata and is not
a source-count result; the fresh current-root measurement above includes all
tracked generated, vendored and test code.

Adopting canonical main `dd2af083` and composing its typed admission stages with
the selected-runtime contribution yields 2,997 Rust files, 1,050,561 source
lines and 1,322,770 physical lines: 186 source / 190 physical lines above the
upload-credit checkpoint. Exact ceilings match these measured totals with no
headroom. This preliminary measurement invokes the unchanged canonical counter
and comment lexer with an explicit merged source root, binding all 4,717 source
inputs and the counter executable before/after. The old compiled xtask resolves
its own source root, so invoking it from another cwd measured the old tree and
is not evidence for this merge. Fresh merged-root xtask and execution gates
remain required. These counters do not increase runtime resource allowances.
The first merged candidate stopped in strict Clippy on an oversized private
authority enum. Its replacement uses the existing two-way optional verified
plan carrier without an extra heap allocation or lint suppression; that failure
remains recorded separately from qualification of the corrected source.

## Files NOT read

None of the following was read for lifecycle, ownership or cancellation defects. Treat them as
unreviewed.

- `crates/mvm-backends/src/driver/hvf_restore.rs` lines 1-380 and 620 to the end (the part between was read).
- Snapshot codecs: `crates/mvm-runtime/src/backends/hvf/snapshot.rs` and `crates/mvm-vmm/src/snapshot.rs`.
- `crates/mvm-runtime/src/backends/hvf/kernel_boot.rs`: most of `run_primary` and the device wiring.
- Tests in `crates/mvm-runtime/src/backends/hvf/smp.rs`.
- `crates/mvm-hostd/src/supervisor/endpoint/flowmux/`: `ingress.rs`, `tcp_relay.rs`, `open_flow.rs` beyond line 352, `socket.rs`, `wire.rs`, `resources.rs`.
- `crates/mvm-backends/src/driver/libkrun.rs` configuration building.
- Async cancellation safety outside FlowMux.
- The volume bridge beyond its wire codec (`crates/mvm-agentd/src/volume.rs`, `crates/mvm-client/src/volume/`).

## Known and unfixed

Found during the #5390 review and left alone. No item has a fix in flight; the owner is the
maintainer of the named area until an issue is opened, and the next step is a failing-before test
at the cited site, then the fix.

| Item | Site | Owner | Next step |
| --- | --- | --- | --- |
| `child.kill()` on boot timeout is never followed by `wait()` (zombie); same shape in other drivers | `crates/mvm-backends/src/driver/libkrun.rs` lines 340 and 369; also `driver/hvf/stop_state.rs`, `driver/hvf_restore.rs`, `fc/idle_pool.rs` | backends maintainer | add `wait()` after each kill with a test using a stub child; sweep the other sites (tracked in #5489) |
| `await_restored` returns an error without killing the supervisor when the pid is negative or the agent socket is missing after the ready marker | `crates/mvm-backends/src/driver/hvf_restore.rs` (`await_restored`) | HVF restore owner | kill and reap on every error return; test with a ready marker and no socket (tracked in #5490) |
| `hvf/standby.rs` leaves the VM running when its pid is negative | `crates/mvm-backends/src/driver/hvf/standby.rs` | HVF owner | refuse and stop through the owned-stop path; test with a negative pid (tracked in #5491) |
| `HvfVm::create` does not destroy the VM or release the GIC config when GIC creation fails | `crates/mvm-runtime/src/backends/hvf/hv_impl.rs` (`HvfVm::create`) | HVF owner | release on the error path; needs a fault-injection seam on the GIC call, so a live HVF host or a seam first (tracked in #5492) |
| FlowMux registry keeps `Closed` entries for the session lifetime (memory only, rate-limited) | `crates/mvm-hostd/src/supervisor/endpoint/flowmux/registry.rs` | hostd maintainer | evict closed entries on a bound; test that a long session does not grow without limit (tracked in #5493) |
