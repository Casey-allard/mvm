---
title: Networking and storage
description: How egress, ports, files, volumes, and snapshots fit the mvm model.
---

## Networking

Local runtime networking is policy-shaped. Examples should start from deny-by-default and add only the destinations or ports the workload needs.

For a release-backed launch, the authenticated runtime selection stays with that launch through admission and artifact custody. The signed runtime identity does not replace the owned verification result. Mailbox compatibility is checked against the authenticated declaration before dispatch and again before taking artifact custody; unsupported object or journal semantics refuse. Another launch verifies its own selection. These source checks do not establish compatible signed publication or successful installed mailbox delivery on a backend.

## Ports

Port forwarding is an explicit operation. Treat service exposure as part of the workload contract: name the guest port, host binding, protocol, and expected readiness behavior.

## Files

File operations cross the host/guest boundary and need path checks. SDK examples should avoid broad host mounts and should explain whether data is copied, mounted, generated during build, or persisted in a volume.

## Volumes

Volumes are stateful. They need explicit lifecycle, ownership, encryption-at-rest posture, and cleanup semantics.

On Unix, launches with registered or explicit volumes acquire the original regular lifecycle lock before resolving their leases. Symlinks, special files and a changed lock-file identity refuse; contention is bounded by the existing five-second launch wait. A launch with no explicit or registered volumes keeps the independent fast path and does not take that host-wide lock.

## Snapshots and cold mode

Snapshots preserve machine state. They can contain sensitive data, process memory, generated files, and credentials that were present in the guest. Restore flows must name backend support and integrity evidence.
