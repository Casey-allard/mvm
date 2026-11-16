//! Host-side plan-admission pipeline (claim 8).
//!
//! Lives in `mvm-hostd` beside the host signing key it uses, so every driver
//! reaches one admission contract: `mvmctl run` and `mvmctl machine run`
//! today, and the `mvm-client` local backend once the boot seam wires local
//! `run`.
//!
//! Threads `synthesize_plan` + the host keypair into the
//! supervisor-equivalent admission flow:
//!
//! ```text
//! cmd_run(args)
//!   ↓ synthesize_plan(args)
//!   ↓ load_or_init_host_signer()
//!   ↓ sign_plan(plan, signer)
//!   ↓ verify_plan(signed, trusted) — catches signing-time bugs
//!   ↓ check_window(plan, now)      — G4 validity window
//!   ↓ nonce_store.check_and_insert  — G4 replay protection
//!   ↓ return AdmittedPlan { plan, plan_id, signer_id, signed }
//!   ↓ caller invokes backend.start() as before
//! ```
//!
//! What this module does NOT do (intentional scope reduction):
//!
//! - **Drive `Supervisor::launch`.** The supervisor's backend
//!   dispatch slot expects a `BackendLauncher` trait impl that
//!   wraps today's `AnyBackend::start()`; landing that wrapper
//!   means refactoring three call sites in 1084 lines of `up.rs`
//!   (the main path, the MVM_DIRECT_BOOT branch, and the `--watch`
//!   path). That refactor lands in a follow-up. **This module is
//!   the substrate that makes the eventual supervisor refactor a
//!   one-line change** — `admit_for_run` produces the
//!   `SignedExecutionPlan` the supervisor needs.
//!
//! - **Emit audit lines.** A later step wires `FileAuditSigner` onto
//!   the `AdmittedPlan`'s `plan_id`; this module is silent on audit.
//!
//! - **Resolve component slots.** A later step maps `PolicyRef →
//!   concrete SupervisorEgressProxy/ToolGate/...`. This module returns the
//!   plan with refs unresolved.
//!
//! ## Test seam
//!
//! `admit_for_run` takes a `Clock` and a `NonceLedger` so tests can
//! drive the validity window + replay protection deterministically.
//! Production callers use `SystemClock` + the host's nonce store.
//!
//! ## Externally-signed plans
//!
//! [`admit_signed_plan_for_run`] admits a plan signed by a fleet issuer the
//! operator pinned in the host config's `trusted_plan_signers`, verifying the
//! envelope against that set — never the host's own key — before any policy
//! gate reads the plan body. From the content-address check onward it runs
//! the same `finish_admission` tail as the self-signed path: the host's
//! ceiling, budget, validity window, and replay protection apply unchanged,
//! so the host stays the final authority over what it boots.

use anyhow::{Context, Result};
use mvm_core::plan::{ExecutionPlan, PlanId, SignedExecutionPlan, Variant};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mvm_core::policy::PolicyBundle;
use mvm_core::vm_backend::{BackendKind, VmStartConfig};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mvm_runtime::AnyBackend;

mod admission_support;
mod admit;
mod assurance_runtime;
mod bundle_environment;
mod canonical_kernel;
mod composition;
mod display_grants;
mod extension_packs;
mod final_gates;
#[cfg(unix)]
mod installed_journal;
#[cfg(unix)]
pub use installed_journal::prepare_runtime as prepare_installed_journal_runtime;
mod grant_validation;
mod host_gates;
mod launch_substrate;
mod mailbox_posture;
mod nonce_ledger;
#[cfg(target_os = "macos")]
pub(crate) mod object_hvf;
mod registry_pack;
mod runtime_posture;
pub use runtime_posture::RunPosture;
mod sdk_sidecar;
pub use sdk_sidecar::{
    SdkSidecarBackendCompatibilityError, enforce_sdk_sidecar_attachment,
    enforce_sdk_sidecar_backend_compatibility, enforce_sdk_sidecar_for_launch,
};
mod rollback;
mod shares;
mod start;
mod verb_grant_sidecar;

use assurance_runtime::AssuranceRuntimeBinding;

pub use admission_support::{
    AdmitAndStartParams, AdmitAndStartParamsBuilder, enforce_admitted_environment,
};
pub use admit::{
    BundleAdmissionContext, BundleImageAdmissionContext, admit_for_run, admit_plan_for_run,
    admit_signed_plan_for_run,
};
pub(crate) use admit::{VerifiedExternalPlan, verify_external_plan};
pub use bundle_environment::BundleEnvironmentRefused;
pub use extension_packs::{AdmittedExtension, ExtensionAdmissionContext};
pub use launch_substrate::{
    populate_audit_substrate, stash_plan_and_mint_verb_grant, stash_plan_for_bridge,
    thread_cpu_grant, thread_tenant_id,
};
pub use mailbox_posture::{MailboxLaunchPosture, MailboxPostureHandoff};
pub use mvm_core::time::{Clock, SystemClock};
pub use nonce_ledger::InMemoryNonceLedger;
pub use registry_pack::{BuiltPackBootCheck, PreparedBuiltPackRuntime, prepare_built_pack_start};
pub use rollback::{
    apply_admitted_grants_or_undo_launch, record_charge_or_undo_launch,
    record_charge_with_owned_rollback,
};
pub use shares::enforce_admitted_shares;
pub use start::{StartAdmittedParams, StartedMachine, admit_and_start, start_admitted};
pub(crate) use start::{
    admit_synthesized_with_verified_release, start_admitted_with_verified_release,
};

/// Result of a successful admission. Carries everything the caller
/// needs to hand to the backend (the plan + its id), to the audit
/// chain (the plan again, for `crate::supervisor::audit::signer::for_plan`), and — for the
/// bridge audit substrate and any cross-process consumer — the canonical
/// `SignedExecutionPlan` envelope, which [`populate_audit_substrate`]
/// serializes verbatim onto `VmStartConfig.plan_json`.
///
/// **The fields are private, and that is the type's whole point.** Consumers
/// downstream of admission — the egress gate, the share enforcer, the workload
/// input gate — decide what a workload may do by reading this plan, so a value
/// of this type has to be a claim that the plan *was* signed, verified,
/// window-checked and replay-checked, not merely a struct shaped like one. Both
/// halves of that are enforced by privacy: `finish_admission` — the shared
/// tail of [`admit_for_run`] and [`admit_signed_plan_for_run`] — is the only
/// non-test code that can build one (a struct literal needs every field named,
/// and there is no `Default` to spread from), and no accessor hands out a `&mut`
/// or an owned field, so a caller that legitimately holds one cannot afterwards
/// push a grant into `plan.services` that admission never saw.
#[derive(Debug)]
pub struct AdmittedPlan {
    plan: ExecutionPlan,
    plan_id: PlanId,
    variant: Variant,
    signer_id: String,
    signed: SignedExecutionPlan,
    extensions: Vec<AdmittedExtension>,
    assurance_runtime: Option<AssuranceRuntimeBinding>,
    canonical_kernel: Option<std::sync::Arc<canonical_kernel::AdmittedKernel>>,
    #[cfg(unix)]
    direct_owner: Option<std::sync::Weak<mvm_core::host_lifetime::HostLifetimeAnchor>>,
    backend: Option<BackendKind>,
    /// Set once the backend has been started under this admission. An
    /// admission authorizes one launch; the plan is handed back on
    /// `StartedMachine`, and holding it again must not start a second backend.
    dispatched: bool,
    #[cfg(target_os = "linux")]
    object_firecracker: Option<mvm_runtime::backend::OriginalObjectFirecracker>,
    #[cfg(target_os = "macos")]
    object_hvf: Option<object_hvf::OriginalHvf>,
}

#[cfg(target_os = "macos")]
fn object_host_backend() -> BackendKind {
    BackendKind::Hvf
}
#[cfg(target_os = "linux")]
fn object_host_backend() -> BackendKind {
    BackendKind::Firecracker
}

impl AdmittedPlan {
    /// The verified plan body — what every downstream authorization decision
    /// reads.
    #[must_use]
    pub fn plan(&self) -> &ExecutionPlan {
        &self.plan
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn object_firecracker(
        &self,
    ) -> Result<&mvm_runtime::backend::OriginalObjectFirecracker> {
        self.object_firecracker
            .as_ref()
            .context("no original selected Firecracker launch for this admission")
    }
    /// Dispatch a selected persistent SDK boot only under this original
    /// reservation, rootfs digest and signed local plan. This consumes the
    /// admission even if the backend subsequently reports a launch error.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn start_persistent_object_original(
        &mut self,
        launch: &crate::mailbox_process::original_journal::object_workers::OriginalObjectLaunch<'_>,
        backend: &AnyBackend,
        config: VmStartConfig,
        images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        bundle: Option<&PolicyBundle>,
    ) -> Result<mvm_core::vm_backend::VmId> {
        self.start_persistent_object_original_with_verified_runtime(
            launch, backend, config, images, bundle, None,
        )
    }

    /// Keep authenticated runtime evidence beside the original selected admission.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn start_persistent_object_original_with_verified_runtime(
        &mut self,
        launch: &crate::mailbox_process::original_journal::object_workers::OriginalObjectLaunch<'_>,
        backend: &AnyBackend,
        config: VmStartConfig,
        images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        bundle: Option<&PolicyBundle>,
        verified_runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<mvm_core::vm_backend::VmId> {
        anyhow::ensure!(
            !self.dispatched
                && self.variant == Variant::Prod
                && self.backend == Some(object_host_backend())
                && backend.kind() == object_host_backend(),
            "requires a fresh original object admission for this native backend"
        );
        launch.require_open()?;
        launch
            .plan()
            .verify_selected_plan(self.plan(), SystemClock.now().timestamp_millis())?;
        let signed: SignedExecutionPlan = serde_json::from_str(
            config
                .plan_json
                .as_deref()
                .context("missing original signed plan")?,
        )?;
        anyhow::ensure!(
            signed.0.signature == self.signed.0.signature
                && signed.0.payload == self.signed.0.payload
                && signed.0.signer_id == self.signed.0.signer_id
                && config.name == self.plan.image.name
                && mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(
                    &config.rootfs_path
                ))? == self.plan.image.sha256,
            "different persistent boot image or original signed plan"
        );
        RunPosture::on_backend(self.variant, backend.kind())
            .with_runtime(Some(&config))
            .with_verified_runtime(verified_runtime)
            .verify_launch_runtime(self.plan())?;
        if self.assurance_runtime.is_some() {
            self.verify_assurance_launch(&config, verified_runtime)?;
        }
        let (config, runtime) =
            final_gates::run_post_admission_gates(config, self, backend.kind(), bundle)
                .map_err(|(stage, e)| e.context(stage))?;
        registry_pack::verify_runtime_at_dispatch(runtime.as_ref(), &config, self, None)?;
        crate::mailbox_process::require_servable(
            &config,
            backend,
            self.mailbox_posture().as_ref(),
        )?;
        self.dispatched = true;
        #[cfg(target_os = "linux")]
        {
            let (id, original) = backend.start_original_object_firecracker_with_verified_runtime(
                &config,
                images,
                verified_runtime,
            )?;
            self.object_firecracker = Some(original);
            Ok(id)
        }
        #[cfg(target_os = "macos")]
        self.activate_object_hvf(
            launch.hvf_original(),
            backend,
            config,
            images,
            verified_runtime,
        )
    }

    #[cfg(target_os = "linux")]
    pub fn abort_unserved_object(
        &self,
        backend: &AnyBackend,
        id: &mvm_core::vm_backend::VmId,
    ) -> Result<()> {
        let native = self.object_firecracker()?;
        native.require_live()?;
        native.boot()?.check_plan(self.plan())?;
        let (pid, _) = native.original_peer()?;
        anyhow::ensure!(
            backend.kind() == BackendKind::Firecracker
                && self.plan.image.name == id.0
                && backend.host_process_id(id)? == Some(pid),
            "original VMM changed before abort"
        );
        backend.abort_start(id).map(|_| ())
    }
    /// The plan's content-address, re-derived and checked during admission.
    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    /// Retain this host admission's mailbox posture for the exact VM it admitted.
    #[must_use]
    pub fn mailbox_posture(&self) -> Option<MailboxLaunchPosture> {
        self.plan.mailbox.map(|grant| MailboxLaunchPosture {
            variant: self.variant,
            plan_id: self.plan_id.clone(),
            plan_nonce: self.plan.nonce.clone(),
            vm_name: self.plan.image.name.clone(),
            grant,
        })
    }

    /// The signer whose key the plan verified under — this host's own signer
    /// for a synthesized run, or the pinned external signer for a
    /// fleet-issued one.
    #[must_use]
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// Check the exact original parent bound into this dispatched direct Linux admission.
    #[cfg(target_os = "linux")]
    pub fn check_original_entrypoint(
        &self,
        owner: &std::sync::Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
    ) -> Result<()> {
        let same_original = self
            .direct_owner
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|bound| std::sync::Arc::ptr_eq(&bound, owner));
        anyhow::ensure!(
            same_original
                && !self.plan.stream_retention.persists()
                && self.plan.stream_edges.is_empty()
                && self.dispatched
                && self.backend == Some(BackendKind::Firecracker)
                && self
                    .plan
                    .agent_verbs
                    .as_ref()
                    .is_some_and(|verbs| verbs.iter().any(|v| v.as_str() == "run-entrypoint")),
            "entrypoint differs from original signed direct launch"
        );
        Ok(())
    }

    /// The canonical signed envelope, for a consumer that re-verifies rather
    /// than trusting this process.
    #[must_use]
    pub fn signed(&self) -> &SignedExecutionPlan {
        &self.signed
    }

    /// Exact re-verified extension artifacts available to this launch.
    #[must_use]
    pub fn extensions(&self) -> &[AdmittedExtension] {
        &self.extensions
    }

    /// Mint one without admitting it — **tests only**, and unreachable from a
    /// production build because the whole `impl` is `#[cfg(test)]`.
    ///
    /// A test that exercises a downstream consumer needs a plan of its own
    /// choosing; going through [`admit_for_run`] for each would drag the
    /// keystore and the nonce ledger into tests about something else. That
    /// convenience is exactly the forgery this type exists to prevent, so it is
    /// compiled out of every artifact anyone ships.
    #[cfg(test)]
    pub(crate) fn for_test(
        plan: ExecutionPlan,
        signer_id: String,
        signed: SignedExecutionPlan,
    ) -> Self {
        Self {
            plan_id: plan.plan_id.clone(),
            variant: Variant::Dev,
            signer_id,
            plan,
            signed,
            extensions: Vec::new(),
            assurance_runtime: None,
            canonical_kernel: None,
            #[cfg(unix)]
            direct_owner: None,
            backend: None,
            dispatched: false,
            #[cfg(target_os = "linux")]
            object_firecracker: None,
            #[cfg(target_os = "macos")]
            object_hvf: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_assurance_runtime_for_test(mut self, config: &VmStartConfig) -> Self {
        self.assurance_runtime = Some(
            AssuranceRuntimeBinding::verify(config, &self.plan, None)
                .expect("verified test runtime"),
        );
        self
    }
}

#[cfg(test)]
mod admission_support_tests;
#[cfg(test)]
mod admit_tests;
#[cfg(test)]
mod admitted_plan_tests;
#[cfg(test)]
mod bundle_admission_tests;
#[cfg(test)]
mod extension_tests;
#[cfg(test)]
mod grant_gate_tests;
#[cfg(test)]
mod launch_substrate_tests;
#[cfg(test)]
mod registry_pack_tests;
#[cfg(test)]
mod shares_tests;
#[cfg(test)]
mod signed_plan_admission_tests;
#[cfg(test)]
mod start_tests;
#[cfg(test)]
mod test_support;
