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

Pure preflight refusals can return the unused preparation. Converted failures
retain the actual backend, anchor and prepared custody; they do not establish
that no effects occurred. Abandoning a successful or converted owner is not
retirement and conservatively retains its original resources and admission.
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
