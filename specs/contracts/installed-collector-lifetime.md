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
