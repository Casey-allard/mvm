# Plan 223 — vsock-only TSI egress (in-house VMM networking)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Give the in-house HVF VMM full-protocol (TCP + UDP), fully-tracked network egress **entirely over vsock** — no guest NIC, and **no gvproxy / passt / rvproxy, ever**. This is the Plan-214 vsock-only data plane. It unblocks the dev-VM migration ([[specs/plans/222-delete-vz.md]] Phase 4): a dev VM's `nix build` must reach caches over vsock. The model is **TSI (Transparent Socket Impl)** — the guest's TCP/UDP is intercepted and serviced by a host-side forwarder that opens the real socket; the host terminates every connection, so it is the single mandatory egress gate.

**Source:** owner direction 2026-07-04 (vsock-only, all protocols, track all traffic; reference: supermachine's TSI model — but where supermachine falls back to virtio-net for the gaps, we do not). Supersedes any NIC/gateway approach for the in-house VMM.

## Non-negotiables

- **No guest NIC. No gvproxy / passt / rvproxy.** vsock is the only transport off the guest.
- **TSI is the single egress path**, so it is the single claim-10 gate — the ADR-058 "no-bypass" objection *inverts* into the reason to do this (there is no other path to bypass).
- No backwards-compat shims. No `#[allow(clippy::too_many_arguments)]`. No plan/PR/ADR citations in code comments.
- Every phase: `fmt --all` / `clippy --workspace --all-targets -D warnings` / `nextest` / `--doc`; `just check-linux` if `cfg(linux)` touched (the guest daemon is Linux). Live-proof where a runtime path changes.

## Architecture

```
 guest app (nix/git/curl)                          HOST
   └─ TCP/UDP connect()                             per-VM TSI forwarder (mvm-hostd)
       └─ [interception]  ── vsock TSI port ──►  parse (proto,dest,port)  [FUZZED, fail-closed]
                                                  → destination guardrail  (R1)
                                                  → trust gate: trusted? ungated : claim-10 policy  (R3)
                                                  → open REAL host socket (TCP connect / UDP)
                                                  → relay bytes  ◄──►  guest
                                                  → audit every flow (chain-signed)  (R6/R7)
```

- **Interception (guest):** two fidelities, same host side.
  - **Userspace TSI (v1, TRUSTED VMs only — dev/builder):** a baked guest daemon `mvm-guest-netd` installs nft `TPROXY` (TCP+UDP) → a local listener; per flow it reads the original destination (`SO_ORIGINAL_DST` / `IP_RECVORIGDSTADDR`) and relays over vsock. No kernel patch; needs nft in the rootfs — which we control for the dev VM.
  - **Kernel TSI (end-state, ALL workloads):** the guest kernel's `AF_INET` transport is vsock-backed (libkrun-style), so interception is unforgeable from userspace. Bigger lift; lands after v1.
- **Transport:** the existing per-VM vsock `EGRESS_PORT` relay (device → host UDS). No new port needed.
- **Host forwarder — REUSE, do not rebuild.** The host end already exists as `mvm_hostd::supervisor::raw_egress::serve_raw_egress` (+ `serve_raw_egress_vsock`): a NIC-less guest sends `host:port\n`, it is decided by the shared `EgressGate`, then byte-spliced (`copy_bidirectional`). **`EgressGate` already implements R1 + R3 + R4:** mandatory-deny (loopback/link-local/metadata/SSH) is built in (R1), `from_network_policy` gives claim-10 default-deny for a workload vs open for `unrestricted`/`trusted_build_egress` (R3), and the `host:port` line parser fails closed (`Malformed`, bounded length) (R4). Host-side DNS: the gate resolves the hostname via the admission DNS pins, so the guest sends **hostnames**, not IPs — no guest resolver needed. **The genuine host-side gap is R6/R7 per-flow audit** (raw_egress emits none today).

## Threat model → the 7 mitigations (each is a REQUIREMENT with a witness)

### R1 — Host-initiated connections are an SSRF surface *(the new risk)*
The forwarder dials from the **host** netns, so a guest (or a malicious `nix` dep) can target host-local/internal endpoints.
- **Mitigation:** a **destination guardrail** enforced in the forwarder for EVERY connection, trusted or not: deny loopback (`127.0.0.0/8`, `::1`), link-local + cloud metadata (`169.254.0.0/16`, incl. `169.254.169.254`), unspecified/broadcast, and mvm's own host control sockets/ports. The guardrail is a pure function of the destination; configurable deny-list, default-deny for the dangerous classes.
- **Witness:** unit tests that each class is rejected; a live test that a guest CANNOT reach `127.0.0.1:<port>` or `169.254.169.254` through TSI. `tsi_guardrail_rejects_ssrf_classes`.

### R2 — The no-bypass invariant must hold
TSI is only the single gate if there is provably no other egress.
- **Mitigation:** the in-house `VmmSpec`/device list exposes **zero network devices** (no virtio-net) and only the TSI + agent/console vsock ports; the FDT carries no net node; the guest has no non-loopback interface.
- **Witness:** `xtask` (or a unit gate) asserting the in-house device set has no NIC and no net FDT node; a live check that `ip link` in the guest shows only `lo`. `in_house_vmm_exposes_no_network_device`.

### R3 — Trust-flag integrity (ungated ↔ gated)
Ungated egress is reachable only for genuinely trusted VMs; a forged trust flag = a full claim-10 bypass.
- **Mitigation:** the ungated path keys on a `TrustTier` derived from admission / `VmmSpec.trusted_builder` — never from any guest-controlled field. Untrusted workloads route through the claim-10 policy on every destination (default-deny). Dev/builder VMs are the only ungated tier.
- **Witness:** a test that an untrusted workload's TSI connections are claim-10-gated (default-deny; unadmitted dest refused), and that no guest-supplied input can set the trusted tier. `untrusted_tsi_is_claim10_gated` + `trust_tier_not_guest_settable`.

### R4 — New untrusted-input parser → fuzz it (claim 5)
The `(proto, dest, port)` header + framing is attacker-controlled host-side input.
- **Mitigation:** a strict, fail-closed parser (bounded lengths, `deny_unknown`-style, no allocation from unchecked lengths); added to the cargo-fuzz set next to the vsock/FUSE parsers.
- **Witness:** `crates/.../fuzz/fuzz_tsi_frame.rs` in the security-workflow fuzz job; parser unit tests for truncated/oversized/garbage input → refusal.

### R5 — Userspace TSI is guest-disableable → untrusted needs kernel TSI
A root guest can tear down nft/kill the daemon. It fails **closed** (no NIC to fall back to → loss of connectivity, not bypass), but that's a convenience boundary, not a security one.
- **Mitigation:** userspace TSI is scoped to **TRUSTED VMs only** (dev/builder). Untrusted workloads keep the existing gated vsock egress until **kernel TSI** lands (Phase 6). Documented explicitly: userspace TSI ≠ a security boundary for untrusted code.
- **Witness:** the untrusted-workload path never selects userspace TSI (test); a doc note in the guest daemon + the plan.

### R6 — Trusted dev VM has broad reach (network + shared `/work`)
A malicious build dependency in `nix build` can exfiltrate source (`/work` virtio-fs) and reach allowed network — same exposure the **Vz dev VM already has** (unrestricted gvproxy + shares).
- **Mitigation:** R1 guardrail (no host-internal reach) + **full per-flow audit** (the "track all traffic" requirement) into the chain-signed log; an optional developer-set allow/deny policy for the dev VM. Residual risk (a trusted dev env can reach the allowed internet) is accepted and documented — TSI does not worsen it and adds the audit Vz lacks.
- **Witness:** every dev-VM egress flow appears in the audit; a doc'd residual-risk note. `dev_vm_egress_is_audited`.

### R7 — DNS/UDP as a covert / exfil channel
UDP (esp. DNS) is a classic low-bandwidth exfil path.
- **Mitigation:** the forwarder logs DNS queries and all UDP flows into the same audit stream; ties into the claim-10 DNS/covert-egress follow-up (Plan 111 Workstream A).
- **Witness:** DNS queries appear in the audit log; `tsi_udp_dns_is_audited`.

## Phases

### Phase 1 — Host-side TSI forwarder (VM-free, fully unit-tested)
> **Reuse first: the forwarder + gate ALREADY EXIST.** `raw_egress` (serve loop + `splice`) + `EgressGate` cover 1.1/1.2/1.3/R4 already (relay, mandatory-deny guardrail R1, claim-10 trust gate R3, fail-closed `host:port` parse R4). Do NOT rebuild them. Phase 1 is therefore small: add the missing audit, provision the trusted gate, and lock the reused pieces with tests.
- [x] **1.1/1.2/1.3/R4 — reused.** `raw_egress::serve_raw_egress` + `EgressGate::from_network_policy` provide the NIC-less-guest `host:port` relay, the R1 mandatory-deny guardrail, the R3 claim-10 trust gate (deny-all vs unrestricted), and the R4 fail-closed target parser.
- [ ] **1.4** **R6/R7 per-flow audit (the genuine host gap)** — emit a chain-signed per-flow record `(vm, proto, host:port, verdict)` from the raw-egress serve path for every decision (allow + deny), incl. DNS (host-resolved) — reusing the existing audit signer, not a new one. Tests assert allow + deny + DNS flows land in the audit.
- [ ] **1.5** **R3 provisioning + regression tests** — a helper that builds the dev VM's gate from `NetworkPolicy::trusted_build_egress()` (ungated-but-guardrailed) vs a workload's `deny_all` (fail-closed); tests: trusted reaches public + is still mandatory-denied for loopback/metadata; workload default-denies.
- [ ] **1.6** **R4 fuzz** — confirm/add a cargo-fuzz target over `EgressGate::decide_request` / the `host:port` line reader; wire into `security.yml`'s fuzz job if absent.

### Phase 2 — Guest-side userspace TSI daemon (Linux)
- [ ] **2.1** `mvm-guest-netd` (`mvm-guest-helpers` `[[bin]]`): nft `TPROXY` install for TCP+UDP → local listener; per-conn `SO_ORIGINAL_DST` (TCP) / `IP_RECVORIGDSTADDR` (UDP) → frame `(proto,dest,port)` → vsock relay to the TSI port. `just check-linux` compiles it.
- [ ] **2.2** Fail-closed: if the vsock TSI port is unreachable, connections are refused (never leak to a non-existent NIC). Baked into the dev rootfs by `mkGuest`; started by the dev `/init` before the shell.

### Phase 3 — Wire into the dev VM + live-proof
- [ ] **3.1** The in-house dev VM (Plan 222 Phase 4 `DevBackend::InHouse`) boots with the TSI vsock port bound + `mvm-guest-netd` started, `TrustTier::Trusted`.
- [ ] **3.2** **Live-proof** on macOS-26: inside the dev VM, `curl https://…` and a real `nix build` fetch succeed **over vsock only** (no NIC: `ip link` shows only `lo`); the flows appear in the audit; `127.0.0.1`/metadata are refused (**R1**).

### Phase 4 — UDP/DNS completeness + hardening
- [ ] **4.1** UDP flow support end-to-end (DNS working for nix); **R7** audit of DNS.
- [ ] **4.2** **R2 no-bypass gate** — assert the in-house VMM exposes no network device / no net FDT node; live `ip link == lo` check.

### Phase 6 — (later) Kernel TSI for ALL workloads
- [ ] **6.1** Guest-kernel vsock-backed `AF_INET` transport (unforgeable interception) so untrusted workloads go vsock-only too (**R5** end-state) — retires the last NIC egress paths and lets Plan 222 delete more. Own sub-plan; gated on Phase 1–4 proving the host + protocol.

## Dependencies / ordering

- Plan 222 Phase 4 (`DevBackend::InHouse`) **consumes** this plan's Phases 1–3.
- Phase 1 is VM-free and can land immediately (highest-value, lowest-risk). Phase 2 needs `just check-linux`. Phase 3 needs a live macOS-26 boot. Phase 6 is a separate, larger kernel effort.

## Security summary (for the ADR that should ratify this)

TSI-over-vsock **strengthens** claim-10 vs a NIC+gateway: a single mandatory gate, connection-level audit, no bypass. It holds iff (R1) the SSRF guardrail exists, (R3) the trust tier is unforgeable, and (R4) the frame parser is fuzzed. Userspace TSI (R5) is a trusted-only convenience; untrusted workloads get the same guarantees only under kernel TSI (Phase 6). For the dev VM specifically it is a strict improvement over the Vz+gvproxy status quo (same trust level, now with the full-traffic audit).
