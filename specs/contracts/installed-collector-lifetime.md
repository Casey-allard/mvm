# Original installed collector lifetime

Backing: preview
Validation: focused registered-process tests; native persistent-journal integration remains unqualified.

The opt-in `spawn_telemetry_collector_installed_registered` operation uses the
existing profile-1 installed endpoint mapping. It requires the original
`PreparedEndpointHandoff` and `InstalledHostServices`, not a serialized quota,
pidfile, VM name, or reconstructed registration. The selected platform is Linux
with enforced process address-space and confinement support.

The canonical mailbox and receipt formats do not change. Collector-only mode
starts no FlowMux session, network listener, proxy, guest NIC, or SSH service.
The caller must supply a deny-all admission with no ingress or secrets and
exactly one signed `Policy/network_policy` asset matching that policy digest.
The handoff matches the supplied redaction policy to the original admitted policy.
Unsupported shapes refuse before protected telemetry preparation.

The parent retains an actual partition funding the controller, collector
workers and encrypted records plus sidecars. A resource requirement query or
projection does not reserve capacity. The original registration supplies the
existing audit/signing capability; the operation adds no mailbox keys or
signing authority to it.

## Ownership transitions

1. Validate original admission, parent, registration, shape and bounded config.
2. Through the same original parent guard, prepare protected telemetry and bind
   its actual state, records and wrapped-key file identities before spawning.
3. Spawn the canonical endpoint executable and place its actual Child and
   supporting custody in `OwnedEndpoint` before any fallible post-spawn step.
4. The child adopts the original partition and descriptors through the private
   challenge exchange, enforces confinement and starts the owned collector.
   Ready reports startup only.
5. Closing the original control stream fences further work. The controller
   cancels the collector's original transport and joins its original workers
   under one cleanup deadline. Failure cannot produce Drained.
6. The parent requires matched Drained and the actual Child's successful
   collected exit before returning `EndpointRetirement`. The receipt retains
   the same partition guard; it does not dispose of retained files or return
   their storage credit.

Timeout, worker failure, uncertain wait, stale parent, or partial preparation
retains original custody and debt. A caller cannot recreate an owner from files
or late process absence. The generic runtime-state protection gate continues to
refuse removal of encrypted records, keys and status files.

## Persistent integration boundary

The collector operation alone does not make ordinary persistent journal startup
an installed lifecycle. That integration must carry the actual prepared host
lifetime through canonical admission and original backend startup, then retain
its positive retirement and protected generation under the parent retention
catalog. Existing PID-based compatibility startup does not acquire this
stronger guarantee. Retained ciphertext and its wrapped key remain together;
publication, expiry, archival and disposal require their separate original-owner
transactions. No native, WAN, platform, fleet-capacity or FIPS qualification
follows from the registered-process fixture.

## Preview SDK integration

`Arc<LocalBackend>::start_persistent_with_journal_and_host_lifetime` is an
explicit installed start operation. It consumes the original
`PreparedHostLifetime`, requires a prepared canonical Linux kernel and the
original parent's funded workspace, and returns an `OwnedJournalStart`.
The ordinary `start_persistent_with_journal` operation retains its existing
contract. The installed operation uses canonical admission and final gates,
the same backend instance for activation and rollback, and the existing
original source or destination journal helper. It creates no second mailbox
authority or ordinary mailbox helper.

The installed entrypoint admits exactly `activate-environment` and
`run-entrypoint`, with ephemeral workload I/O streams and no stream edges.
An empty verb request selects that pair; an explicit request must contain both
names exactly once. Broader requests and persistent workload streams are
unsupported. The ordinary persistent API retains its existing recorded-stream
default. Workload transcript retention is separate from durable mailbox data:
this selection changes neither the mailbox grant nor message durability,
receipt, admission or retry semantics.

The SDK retains the original unconverted preparation while reserving the named
lifecycle, loading and checking the stopped definition, validating sidecars and
resolving the image. An early refusal can return that same preparation through
`OwnedJournalStartFailure::into_unused`. `into_unused_for_parent` applies the
same extraction guard and returns the existing opaque SDK proof accepted by
the original parent's cancellation path. Neither operation releases credit,
reconstructs an owner or attests that earlier filesystem/image-resolution
effects were undone; their existing owners remain responsible for rollback.

Before entering journal preparation or exposing its anchor to a callback or
config, the SDK irreversibly converts the preparation to its original anchor.
Every retained boot, native, helper, retirement or completion state refuses
unused extraction. Converted failures retain the actual backend, anchor and
prepared custody even when preparation failed before producing a boot or VM
ID; they do not establish that no effects occurred. Abandoning either an unused
context or a successful/converted owner is not retirement and conservatively
retains its original lifetime, resources and admission.
Recovery before an original journal helper exists still requires a separate
positive disposition transaction; preservation alone is not successful cleanup.

The owned `stop_and_collect` operation validates the original journal boot,
state, marker and kernel identity and stops through the retained backend and
anchor. A successful rollback records that positive stop on the original
journal owner so subsequent collection does not require a stopped process to
appear live. The SDK holds the positive runtime retirement receipt while the
caller publishes retained telemetry through its original parent. The callback
must preserve and reconcile any receipt it moves before returning an error;
the SDK cannot recreate a moved receipt. Only successful parent publication
and SDK finalization permit journal marker clearance. Neither path calls the
generic protected-state reaper or waives retained telemetry protection.

The collection deadline bounds the journal's kernel observer and mailbox-helper
collection. Existing native stop, endpoint drain and broker control operations
have their own stage bounds; synchronous storage and parent publication do not
yet share a hard whole-operation deadline. These preview operations still need
native clean, failed-start and retry witnesses with actual parent retention.
They do not establish end-to-end WAN, sustained capacity or security validation.

## Pre-helper refusal recovery

The tracked original constructor distinguishes proven no-exec, an actual
returned child, and uncertainty. Only the canonical creation boundary can arm
the no-exec proof, retaining its original launch exclusion, state directory and
boot binding. Entering process creation fences that proof; a returned exec
failure can restore it. A construction panic remains uncertain. An empty owner
slot, missing marker or absent process is never no-exec evidence.

An installed SDK serving refusal immediately attempts stop through its retained
backend and anchor. The no-exec branch retains the positive runtime retirement
receipt and typed construction proof. `OwnedJournalStartFailure` exposes
`helper_disposition()` for reporting and `finish_without_helper(until, finish)`
for that branch. The callback receives the original admitted plan and mutable
runtime retirement receipt; it must publish the retained endpoint telemetry and
finish the original parent transaction before returning success. Callback or
state-validation failure preserves the original proof, receipt and charges for
retry. The result is `NoHelperRetirement`, with no invented mailbox-helper exit
status. Runtime files remain retained; the generic state reaper is not used.

Post-exec readiness failures retain their actual `JournalOwner` and use the
existing owned helper collection path. Uncertain construction may be contained
through the original native owner, but cannot use the no-helper publication
path or claim that all helper resources have retired.

## Owned journal control

The directed retained-journal mode closes its original activation-only
continuation after authenticated ACK and current-owner checks, allowing the
unchanged signed guest to initialize its mailbox and concurrent control loop.
It retains the original Firecracker owner, anchor, host identity and first
learned guest key. Readiness and bounded one-shot entrypoint calls use existing
protected guest messages on original-instance-authenticated sessions; a fresh
peer key or VM-name lookup cannot replace that identity.

Selection requires the actual retained signed mailbox grant with exactly one
journal direction, no object-pair mapping, matching boot binding, exact two
entrypoint verbs and ephemeral workload streams. Input is bounded at 64 KiB and
cumulative output at 128 KiB, in addition to canonical serialized-frame limits.
Journal execution honors canonical zero-as-unbounded `exec_secs`; each operation
still expires at the earlier of its caller deadline and signed plan validity.
A nonzero execution duration further caps that bound. Ordinary one-shot timeout
behavior remains unchanged.
Calls serialize; ambiguous I/O, changed authority/key, timeout or callback
unwind fences later calls while retaining original stop custody. Other
installed entrypoints keep their one-shot behavior. This is a preview host-only
endpoint mapping, with no guest wire or durable-mailbox semantic change.

Canonical admission captures the actual journal anchor before admission completes,
with the directed mailbox authorization and signed deny-all policy. Final gates
revalidate that same binding; repeated entrypoint calls still require the exact
original anchor Arc and dispatched admission. No owner is attached after admission.

The reviewed design and qualification history are retained in SpiralCore's
2026-11-14 owned-journal-control proposal. Component tests do not qualify native
paired delivery, full failure recovery, platform/WAN operation or FIPS.
