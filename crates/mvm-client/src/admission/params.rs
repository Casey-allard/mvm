//! Inputs for the existing signed-plan admission boundary.

use mvm_core::deploy_record::BootArtifactIdentity;

use super::entrypoint_resolve::ResolvedEntrypoint;
use super::{BundlePin, InMemoryNonceLedger, InstructionSources};

/// A content-bound asset. Operator-declared files and internally selected
/// signed packs are recorded in the plan without sharing them with the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetSpec {
    /// An operator-declared host file or directory to hash.
    File {
        kind: mvm_contract::plan::AssetKind,
        host_path: String,
    },
    /// An internally selected signed pack; never accepted from `--asset`.
    RegistryPack(mvm_core::registry_pack::PackPin),
    /// The resident owner's exact project-policy generation and closure.
    /// Host admission revalidates it before signing; it is not a host file.
    CommittedPolicy(mvm_core::plan::AssetIdentity),
}

pub struct AdmitPlanForBootParams<'a> {
    /// Bundle sizing decisions recorded on the admitted plan.
    pub bundle_sizing: super::bundle_resources::AppliedSizing,
    /// Mailbox this launch grants, minted into the plan before signing.
    pub mailbox: Option<mvm_contract::protocol::mailbox::MailboxGrant>,
    pub tenant: &'a str,
    pub vm_name: &'a str,
    pub backend_name: &'a str,
    /// Local image checkout selected by the process entry point, if any.
    ///
    /// Admission consumes this captured value instead of rereading
    /// `MVM_IMAGES_DIR`. Besides making the authority explicit for library
    /// callers, that keeps one admission stable if unrelated code changes the
    /// process environment concurrently.
    pub configured_images_dir: Option<&'a std::path::Path>,
    pub rootfs_path: &'a std::path::Path,
    /// The kernel this launch will boot, pinned into the plan's
    /// `EnvironmentRef` and re-checked by the admitted-environment gate.
    ///
    /// `None` only for backends that carry their own kernel (libkrun's
    /// bundled image, the mock). For everything else this must be the same
    /// path handed to the backend: the image digest says what the workload
    /// *is* and says nothing about what confines it, so a plan that names the
    /// image but not the kernel admits a workload onto whatever kernel the
    /// host happened to have cached.
    pub kernel_path: Option<&'a std::path::Path>,
    /// Skip re-hashing `rootfs_path` and admit with this sha256 instead.
    /// Only sound when a fail-closed integrity check re-hashes the same
    /// bytes before boot (the checkpoint fork path: `verify_content`
    /// refuses a tampered blob before any supervisor spawns) — a
    /// mismatch then aborts the launch, never boots a mis-admitted image.
    pub precomputed_image_sha256: Option<String>,
    /// Optional deploy-record identity for the exact rootfs selected by this
    /// boot. When present, both labeled digests and the byte count are
    /// reverified before plan synthesis.
    pub boot_artifact_identity: Option<&'a BootArtifactIdentity>,
    /// The exact selected runtime, verified before it can contribute assurance.
    pub runtime_config: Option<&'a mvm_core::vm_backend::VmStartConfig>,
    pub cpus: u32,
    pub mem_mib: u64,
    /// The transport this launch gives the guest, recorded on the plan.
    ///
    /// Was hardcoded to `Default::default()` — `NetworkMode::None`, whose own
    /// doc reads "no guest NIC, no broker, the workload cannot reach the
    /// network" — while every ordinary launch derives `HostVsockProxy` and the
    /// host stands a broker up for it. The signed record said the workload had
    /// no path to the network while it was being given one.
    pub network_mode: mvm_contract::plan::NetworkMode,
    pub seccomp_tier: mvm_core::plan::PlanSeccompTier,
    pub secret_release: mvm_core::plan::SecretReleasePolicy,
    pub secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Opaque caller commitment copied into the plan and its audit entries.
    pub caller_commitment: Option<mvm_core::plan::CallerCommitment>,
    pub ledger: &'a InMemoryNonceLedger,
    /// Override for the host-signer keys directory. Production callers
    /// pass `None`, which resolves to `~/.mvm/keys/`; tests pass a
    /// tempdir so they don't write into the real user's home.
    pub keys_dir: Option<&'a std::path::Path>,
    /// Override for the audit-chain directory (`~/.mvm/audit/`).
    /// Tests inject a tempdir; production passes `None`.
    pub audit_dir: Option<&'a std::path::Path>,
    /// Override for the policy-bundle root (`~/.mvm/policies/`). The
    /// resolver reads `<dir>/<tenant>/<workload>.toml` when a
    /// plan's policy refs name a tenant-scoped bundle; tests inject a
    /// tempdir so a bogus bundle can be staged without touching the
    /// real user's home.
    pub policy_dir: Option<&'a std::path::Path>,
    /// Optional path to a `.mvmpkg` bundle archive. When set, the
    /// archive is read + verified at admit time, the resulting
    /// `PlanArtifact` is embedded into the plan, and the supervisor's
    /// admit path re-verifies on every launch. Once the plan is
    /// admitted, the boot's root filesystem and kernel must be the
    /// ones the bundle signed, and an installed copy beside the archive
    /// must still match it; a mismatch is refused and recorded as
    /// `plan.failed`. Boots resolved from an installed bundle
    /// (`--manifest <bundle-sha256>`) set it to the registry archive.
    /// A child forked or restored from a parent whose plan pins a bundle
    /// inherits that pin ([`InheritedBundle`](super::InheritedBundle)): the archive is re-verified
    /// and must still be the bundle the parent was admitted under.
    pub bundle_pin: Option<BundlePin<'a>>,
    /// The signed security posture of the installed bundle this run boots,
    /// when it boots one. The launch may only narrow it: admission refuses a
    /// run whose network policy, host shares, or agent verbs ask for more,
    /// and records the refusal as `plan.failed`. A pinned bundle's own
    /// posture is checked the same way.
    pub bundle_posture: Option<mvm_core::plan::BundleSecurityPosture>,
    /// Optional deps-volume binding from the app-deps install pipeline.
    /// No boot path supplies one today. When `Some`, the
    /// synthesised `ExecutionPlan` carries `deps_volume = Some(...)`,
    /// and the supervisor's admission gate re-verifies
    /// the on-disk sealed volume before launch — claim 9.
    /// `None` preserves the claim-8 baseline (no deps gate).
    pub deps_volume: Option<mvm_core::plan::DepsVolumeBinding>,
    /// User-supplied host-fs grants (`--volume` / `MVM_VOLUMES`) baked
    /// into the signed plan + emitted to the chain-signed audit log
    /// (claim 1 / claim 8). Empty for the common no-volume case.
    pub shares: Vec<mvm_core::plan::HostShareGrant>,
    /// Declared `--asset KIND:HOST_PATH` bindings hashed into content
    /// identities at admission and recorded in the signed plan's
    /// `asset_identities` (with the environment, bundle, deps volume,
    /// digested shares, and the resolved network policy). Empty for runs
    /// that declare no assets.
    pub assets: Vec<AssetSpec>,
    /// Output grants recorded in the signed plan: which guest directories the
    /// workload may hand back, where they land on the host, and the bounds the
    /// collection enforces. Each must be backed by a writable disk in `shares`.
    pub outputs: Vec<mvm_core::plan::OutputGrant>,
    /// Per-destination egress redaction authored by `--redact HOST[=audit]`.
    /// Default (all-off) preserves the curated-only baseline.
    pub redaction: mvm_core::policy::RedactionPolicy,
    /// The resolved runtime egress policy (`--allow-host`,
    /// template default, or deny-all default). Non-deny
    /// policies are lowered into a generated PolicyBundle and referenced by the
    /// signed plan so the bridge never relies on an unsigned bare carrier to

    /// authorize outbound traffic.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Raw `--agent-verb` strings from the CLI. Empty ⇒ use the computed
    /// default. Validated inside `admit_plan_for_boot` via
    /// `parse_agent_verb_override`; any unknown/DevOnly verb is an error.
    pub agent_verb_override: Vec<String>,
    /// Host services this workload is authorized to call over the broker
    /// channel, baked into the signed plan. The broker's dispatch gate refuses
    /// anything absent from this set, and the launch path reads the same set to
    /// decide whether the optional glibc SDK sidecar must be attached. Empty
    /// (the common case) means the workload calls no host service.
    pub services: Vec<mvm_contract::protocol::broker::ServiceId>,
    /// Whether this launch arms the GPU remoting plane. Its shims dial the
    /// host GPU endpoint over vsock from inside the workload, so admission
    /// raises the seccomp tier to one that opens `AF_VSOCK` sockets.
    pub gpu: bool,
    /// True iff this run should receive an attenuated (ProdSafe-only) agent-verb
    /// grant. Set this with `grant_eligible(pty, has_ad_hoc_argv, is_dev_profile)`.
    /// Interactive / ad-hoc / dev runs must pass `false`: they issue DevOnly verbs
    /// (ConsoleOpen, Exec) that a ProdSafe grant would refuse.
    pub restrict_agent_verbs: bool,
    /// What the caller worked out this image will run.
    ///
    /// Feeds [`entrypoint_is_shell_shaped`](super::entrypoint_is_shell_shaped), which refuses the workload input
    /// grant under a sealed production posture (`restrict_agent_verbs`) when
    /// the entrypoint looks like a shell.
    /// [`Unresolved`](ResolvedEntrypoint::Unresolved) refuses that grant too:
    /// a launch that cannot say what it runs has not established that what it
    /// runs is not a shell, and admitting on that basis would leave a control
    /// that reports present and never fires. Callers that never request the
    /// input grant may pass `Unresolved` freely — the check is reached only
    /// through the grant.
    pub entrypoint: ResolvedEntrypoint,
    /// What this workload is permitted to consume or reach, as resolved from
    /// the surfaces that may author one (CLI flags, a JSON grants file, the
    /// project manifest, the operator's host config). Baked into the signed
    /// plan and checked against the host's ceiling inside `admit_for_run`. Its
    /// egress dimension is already reflected in
    /// [`network_policy`](Self::network_policy), which the caller derived from
    /// the same resolution.
    ///
    /// `None` means no surface authored anything, which is the pre-grant
    /// baseline: no CPU cap, no wall-clock bound, deny-all egress.
    pub grants: Option<mvm_contract::grants::Grants>,
    /// The backend this run will actually boot on, when the caller has one in
    /// hand. Admission measures a declared grant against the mechanisms that
    /// tier really has; without it a sealed run refuses a grant whose
    /// enforceability nothing can confirm, and a dev run is warned. Taken from
    /// the backend object, never parsed from
    /// [`backend_name`](Self::backend_name) — a name is a label, and a grant
    /// checked against a label is checked against whatever the caller typed.
    pub backend_kind: Option<mvm_contract::protocol::vm_backend::BackendKind>,
    /// Where instruction-file provenance looks beyond `shares` and `assets`:
    /// the workload's own source directory, and an override for the user
    /// policy. Every instruction file the boot copies into the guest is
    /// verified against that policy before the boot is admitted.
    pub instructions: InstructionSources<'a>,
}
