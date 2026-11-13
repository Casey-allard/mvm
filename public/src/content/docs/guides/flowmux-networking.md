---
title: FlowMux networking
description: Policy-enforced workload networking through one authenticated vsock path.
---

FlowMux is mvm's single workload-networking path. Workload microVMs have no
routable network device. Guest loopback adapters describe connection intent to
an authenticated per-VM endpoint over vsock, and the host opens only the
connections admitted by the signed plan.

There is no transport selector. Declaring network policy makes the FlowMux
service available; omitting it leaves networking closed. Retired raw-stack
fields and packet-tunnel plan values are rejected with migration guidance
instead of silently selecting another path.

The contributor SDK exposes an opt-in direct TCP payload mapping through
`LocalBackend::try_launch_with_host_lifetime_and_direct_policy`. The operator
provides an externally signed plan for a local portable bundle, the cooperating
peer mapping and routes covered by its signed `network_policy` digest, and an
installation owner that funds the endpoint. A mapped `OpenTcp` first passes
the ordinary destination and protocol checks. The installed endpoint authenticates
the enrolled peer on that same TCP connection before exchanging object data.
Omitting the mapping keeps the ordinary FlowMux path.

The selected endpoint uses the original registration's audit signer and bounded
worker and cache allocation. On Linux, the process address-space limit must fit
within the reservation. A failed peer handshake closes that connection and
returns the stream reservation. Guest ingress, UDP, typed HTTP, secret
substitution and delegated proxies have no selected mapping in this profile.
Starting the endpoint binary alone cannot select it.

The installed SmallV1 object receiver keeps the parent and child directory
descriptors admitted by that owner. Store operations and retirement stay
relative to those held descriptors. Before spawning the selected endpoint,
the original partition guard must confirm funding for one serial receiver:
seven descriptors and a 1 MiB store workspace in addition to the codec operation
charge. Providers that do not implement this check refuse activation. A
projection or cache digest does not grant resource or mailbox authority.

Cancellation closes the original guest transport through one shared wake
handle. Setup, relay and lease fencing reuse a successful shutdown; a failed
kernel shutdown remains an error. Shutdown alone does not release storage:
the owner must collect the original reader and verify retirement of the
original store. An uncertain join or changed directory retains its charge.

The SDK checks the native backend's lifetime support before launch. Releasing a
VM reservation requires the original owner's proof of disposal or a proved
pre-spawn refusal. A successful endpoint shutdown settles its own allocation.
For a Linux VMM that has started, the kernel exit observation must match both
the launch binding and the held installation lease. A missing process ID or
socket cannot settle the VM reservation.

```sh
mvmctl machine run \
  --allow-host api.example.com:443 \
  --image alpine \
  -- curl https://api.example.com/
```

## Supported application surfaces

Applications reach FlowMux through one of these loopback or SDK surfaces:

- **HTTP and HTTPS proxy:** standard proxy-aware clients use the injected
  loopback proxy settings. HTTPS uses `CONNECT`; a typed HTTP flow can opt into
  host-owned transforms such as secret substitution and redaction.
- **SOCKS5h and UDP associate:** TCP and UDP clients use the loopback SOCKS5h
  adapter. Hostname resolution stays host-controlled because the `h` form sends
  the hostname to FlowMux rather than resolving it inside the guest.
- **Controlled DNS:** guest DNS requests go through the loopback adapter and are
  checked against the same signed destination policy before a result is used.
- **Mediated ping:** the loopback service offers the admitted reachability probe;
  it does not give the workload a raw ICMP socket.
- **Typed connectors:** SDK connectors name the destination and protocol shape
  explicitly. The host can then apply connector-specific validation,
  transformation, substitution, and audit behavior without exposing credentials
  to the guest.

Opaque TCP and UDP remain byte streams or datagrams. FlowMux does not pretend it
can inspect encrypted payloads. Selective L7 behavior runs only when the signed
plan declares a typed flow that gives the endpoint ownership of that protocol.

## Reaching a key-value store

A workload that needs durable storage does not need a network for it:

```sh
mvmctl machine run --name worker --image myworker --host-service host.kv.v1
```

`host.kv.v1` is served on the host-services broker channel, so the bytes stay
on the host and nothing hands the guest a credential. The namespace comes from
the supervisor's call context rather than any request field, so one workload
cannot address another's by asking for it. A workload whose signed plan did not
bind the service gets `NotBound` before any handler runs.

Workload code reaches the store through the language SDK, which loads the
host-services library from the sidecar that binding the service attaches. There
is no shell surface for it: a bare `sh` in the guest has nothing to call, by
design — the store is for programs, not for poking at.

Verbs are `get`, `put`, `delete`, and `list`. Keys are validated rather than
sanitized — a key that would need rewriting to be safe is refused, because a
caller that read back a different key than it wrote has no way to notice.
Values are bounded: the broker is a control channel, not a bulk transport.

A catalog runtime can declare the services it needs, so an operator does not
have to know that a given runtime wants a store and pass the flag every time.
Declared bindings and `--host-service` are unioned: the entry says what the
runtime needs, the flag says what the operator wants, and neither drops the
other.

## Reaching another workload

```sh
mvmctl run --peer db.mvm.peer:5432=127.0.0.1:34567 -- ./my-service
```

The workload dials `db.mvm.peer:5432`; the host resolves it and opens the
connection. The left side is what the guest dials, the right is the peer's
admitted ingress address — neither is inferred. The name and the address it
resolves to are both bound in the signed plan, and that address is the peer's
own admitted ingress mapping, so the reachable set is fixed at admission rather
than discovered at runtime. The guest never learns an address and still has no
NIC.

Resolution happens in front of the same gate that decides ordinary egress, so
east-west traffic inherits default-deny instead of carrying its own rule:

- A gate with no peer bindings admits no peer.
- A binding authorizes one `name:port` route. The same peer on a port the
  binding does not name is refused; a binding is not a blanket grant to a host.
- Nothing listens at the address until the peer boots, so a dial to a stopped
  peer is refused by the connect. There is no liveness registry that could
  disagree with reality.

The reserved `.mvm.peer` suffix keeps the peer and host-name namespaces from
overlapping. A target either ends in it and resolves as a peer, or does not and
is decided as ordinary egress; a malformed peer name is refused at peer
resolution rather than looked up as a public host.
`xtask check-single-network-path` pins that branch to one place and both
connect sites to it.

A malformed route is refused at the CLI rather than at the gate, so it never
reaches the signed plan where it would read as an admitted destination that
happens never to resolve.

Three limits worth knowing:

- Peer dialing is **TCP-only**. The UDP path uses a different decision and has
  no peer branch.
- Peers are **not reachable through the credential-substituting HTTP proxy**.
- Peers are a **transient-run** capability. `machine create` and `machine start`
  do not persist a peer set, so a stored machine has none.

## Applications that open direct sockets

A non-cooperative application that ignores the injected loopback adapters and
opens a socket directly fails closed: the guest has no routable NIC or default
route, and mvm does not fall back to a packet tunnel. Use the HTTP proxy,
SOCKS5h/UDP adapter, controlled DNS, mediated ping, or a typed connector. If an
application cannot use any of those surfaces, it is not network-compatible with
the workload boundary.

This is deliberate. A hidden fallback would bypass the single policy,
resource-accounting, substitution, redaction, and audit decision point that
FlowMux exists to provide.

## Security and resource properties

Every FlowMux session is authenticated to one admitted VM. The endpoint applies
destination and port policy before opening a host socket, keeps secrets and TLS
material host-side, bounds streams, datagrams, DNS state, connector work, and
ingress peers, and emits the canonical audit result. Declared ingress uses the
same endpoint and delivers only to a signed guest-loopback target.

The same contract applies across the standard Firecracker and HVF backends and
the optional libkrun integration: no production backend attaches a routable
workload NIC, and none may substitute a second networking implementation.

## Data path

```text
guest application
  -> HTTP / SOCKS5h+UDP / DNS / ping / typed connector loopback adapter
  -> authenticated FlowMux session on GuestService::NetworkFlow
  -> one per-VM mvm-network-endpoint
  -> policy + limits + optional typed transforms + audit
  -> host-owned TCP/UDP socket or declared ingress listener
```

Control and data share the authenticated FlowMux protocol but retain bounded,
independent progress. Saturating one flow cannot create an unbounded queue or
silently widen another flow's authority.


### Canonical Linux input for an installed direct TCP endpoint

The local SDK entry `try_launch_with_canonical_direct_policy` takes the externally
signed request, the original prepared host lifetime, its direct TCP mapping, and the
same `Arc<PreparedCanonicalLinux>` created for the installed signed bundle. The
parent checks its reservation before MVM resolves installed artifacts. The kernel,
CLI runtime release, workload root digest and length must agree with the original
signed inputs.

The parent also authorizes one full private copy of the workload root into the
original kernel-generation directory. MVM caps writes at the signed length,
checks the private file digest, unlinks it and passes its read-only descriptor to
the backend. The storage reservation must cover this copy through final release.
Preparing the archive, kernel, runtime and temporary files consumes additional
resources. A deployment providing this profile must fund and enforce those
resources separately. Canonical FlowMux still applies destination and tenant policy
on each network operation.
