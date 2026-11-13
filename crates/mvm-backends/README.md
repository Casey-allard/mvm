# mvm-backends

`mvm-backends` implements the concrete VMM drivers used by mvm. It translates
the portable `mvm-vmm` driver contract into Firecracker, Hypervisor.framework,
libkrun, and QEMU mechanics while leaving workload orchestration to
`mvm-runtime`.

## Who uses it

`mvm-runtime` selects these drivers and wraps them in machine lifecycle logic.
`mvm-cli` enables the backend features requested by the product surface. The
crate is not intended as a user-facing API.

## How it works

Each driver consumes a validated `VmmSpec`, creates platform resources, starts
or attaches to its VMM, exposes a lifecycle handle, and implements stop,
observation, checkpoint, and restore capabilities supported by that backend.
Process-based backends use dedicated process modules; the in-house HVF path
implements the low-level hypervisor traits and reuses the shared device model.

Firecracker support is split further because it owns a daemon API socket,
namespace setup, control requests, snapshots, host resources, and event-driven
process observation. Guards use RAII so partial launch failures tear down only
resources created by that attempt.

The selected Linux installed-lifetime path retains the original `Child`, a
kernel process descriptor and the original installation holder through cold
boot and teardown. It authenticates configuration and readiness against that
process, and does not adopt an idle process or recover authority from a PID
file. Its workload-exit listener owns one explicitly sized worker, cancellation
socket and original join handle. Workload status comes from that worker's
single report rather than a prior run's file. Retirement requires original
process exit, actual child collection and worker collection before returning
the retained lease to the caller. A failed or uncertain launch keeps custody;
it cannot become a successful no-spawn or retirement result.

The runtime can clone `OriginalWorkloadReport` while it owns the original VM
slot, release that slot's lock, and wait to a monotonic deadline. This report
retains only the workload result and its notification state; it cannot keep a
VM alive or grant retirement credit. Backends without an original report
return `None` and refuse the bounded wait instead of substituting a named file
or an unbounded operation.

These driver mechanics do not grant launch, mailbox or egress authority. The
canonical runtime must supply a matching admitted parent and enforce its
resource budget. The component controls do not establish installed native,
restart, WAN or fleet acceptance. The exit-report writer provides visibility
before its best-effort acknowledgment, without a power-loss durability claim;
the final native thread join has no hard real-time deadline. Orphan recovery,
complete disk/log limits and the supported native capacity envelope still
require qualification through the installed service.

## Main modules

| Module | Responsibility |
|---|---|
| `driver::fc` | Firecracker `VmmDriver` implementation |
| `driver::hvf` | In-house macOS Hypervisor.framework driver |
| `driver::libkrun` | libkrun supervisor-backed driver |
| `driver::qemu` | Development/test QEMU driver |
| `fc` | Firecracker API, lifecycle, snapshot, namespace, and I/O helpers |
| `mock` | Deterministic driver used by higher-level tests |

## Features and platforms

The default feature set is empty. `test-support` exposes fixtures and controls
needed by downstream tests. Firecracker and Linux-specific behavior is gated
by target OS; HVF is macOS-only. Unsupported platforms compile the portable
surfaces but cannot start the corresponding backend.

## Developing

Run `cargo test -p mvm-backends` on the host for portable tests. Linux/KVM and
Firecracker tests run only in the approved builder/test environment, while
explicit HVF live tests run on macOS. Always compile Linux-gated targets after
changing a shared driver type.
