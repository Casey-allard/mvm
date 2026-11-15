//! Selected backend and original verified runtime facts for admission.
use super::*;

/// What admission has to be told, because the plan cannot be trusted to say
/// it: the posture this run carries, and the backend that will actually boot
/// it.
///
/// The backend is a [`BackendKind`] taken from the backend object itself, never
/// parsed out of `ExecutionPlan.runtime_profile`. A profile is a label chosen
/// by whoever wrote the plan and is not always even a tier name — `mvmctl exec`
/// writes `transient-run`, the lineage path writes the workload's name — so a
/// gate that read it would be deciding which resource controls apply from a
/// string a caller picked.
#[derive(Debug, Clone, Copy)]
pub struct RunPosture<'a> {
    pub(super) variant: Variant,
    pub(super) backend: Option<BackendKind>,
    pub(super) runtime_config: Option<&'a VmStartConfig>,
    #[cfg(unix)]
    pub(super) direct_owner:
        Option<&'a std::sync::Arc<mvm_core::host_lifetime::HostLifetimeAnchor>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) object_worker: Option<
        &'a crate::mailbox_process::original_journal::object_workers::OriginalObjectLaunch<'a>,
    >,
    pub(super) object_plan: Option<&'a crate::mailbox_launch::object_pair::OriginalObjectPlan<'a>>,
    pub(super) incoming_journal:
        Option<&'a crate::mailbox_process::paired_incoming::IncomingJournalAdmission>,
    pub(super) paired_journal:
        Option<&'a crate::mailbox_process::original_journal::authorization::PairedJournalAdmission>,
    pub(super) verified_runtime: Option<&'a mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    pub(super) verified_retained: Option<&'a mvm_runtime::checkpoint::VerifiedRetainedRuntime>,
}

impl<'a> RunPosture<'a> {
    /// A run whose backend is in hand. The only shape that can measure a grant
    /// against the mechanisms that will really be there.
    #[must_use]
    pub fn on_backend(variant: Variant, backend: BackendKind) -> Self {
        Self {
            variant,
            backend: Some(backend),
            runtime_config: None,
            #[cfg(unix)]
            direct_owner: None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            object_worker: None,
            object_plan: None,
            incoming_journal: None,
            paired_journal: None,
            verified_runtime: None,
            verified_retained: None,
        }
    }

    /// A caller admitting without a backend object — a dry-run admission, or a
    /// path that resolves its backend only after admission.
    ///
    /// Fail-closed rather than fall back to the plan's label: a declared grant
    /// is then unverifiable, which a sealed run refuses and a dev run is warned
    /// about. Guessing a tier from a string here is exactly the mistake that
    /// would let a mislabelled plan pick its own resource controls.
    #[must_use]
    pub fn without_backend(variant: Variant) -> Self {
        Self {
            variant,
            backend: None,
            runtime_config: None,
            #[cfg(unix)]
            direct_owner: None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            object_worker: None,
            object_plan: None,
            incoming_journal: None,
            paired_journal: None,
            verified_runtime: None,
            verified_retained: None,
        }
    }

    /// The actual launch selection, not claims copied from plan JSON.
    #[must_use]
    pub fn with_runtime(mut self, runtime_config: Option<&'a VmStartConfig>) -> Self {
        self.runtime_config = runtime_config;
        self
    }

    #[cfg(unix)]
    pub(crate) fn with_selected_direct_owner(
        mut self,
        config: &'a VmStartConfig,
        owner: &'a std::sync::Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
    ) -> Self {
        self.runtime_config = Some(config);
        self.direct_owner = Some(owner);
        self
    }

    /// Select a previously authorized original nonce and image before signing.
    /// The installed service readiness check remains independently required.
    pub fn with_original_object_plan(
        mut self,
        original: &'a crate::mailbox_launch::object_pair::OriginalObjectPlan<'a>,
    ) -> Self {
        self.object_plan = Some(original);
        self
    }

    /// Supply the independent destination's original live authorization only
    /// for this paired source admission. Ordinary admission remains unchanged.
    pub fn with_paired_journal(
        mut self,
        pair: &'a crate::mailbox_process::original_journal::authorization::PairedJournalAdmission,
    ) -> Self {
        self.paired_journal = Some(pair);
        self
    }

    pub fn with_incoming_journal(
        mut self,
        incoming: &'a crate::mailbox_process::paired_incoming::IncomingJournalAdmission,
    ) -> Self {
        self.incoming_journal = Some(incoming);
        self
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn with_original_object_worker(
        mut self,
        launch: &'a crate::mailbox_process::original_journal::object_workers::OriginalObjectLaunch<
            'a,
        >,
    ) -> Self {
        self.object_plan = Some(launch.plan());
        self.object_worker = Some(launch);
        self
    }

    pub(super) fn enforce_journal(&self, plan: &ExecutionPlan, max_ms: Option<u64>) -> Result<()> {
        if let Some(original) = self.object_plan {
            anyhow::ensure!(
                self.variant == Variant::Prod
                    && matches!(
                        self.backend,
                        Some(BackendKind::Firecracker | BackendKind::Hvf)
                    )
                    && self.incoming_journal.is_none()
                    && self.paired_journal.is_none(),
                "object selection requires a dedicated sealed native participant"
            );
            original.verify_selected_plan(plan, SystemClock.now().timestamp_millis())?;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Some(worker) = self.object_worker {
                anyhow::ensure!(
                    std::ptr::eq(original, worker.plan())
                        && self.backend == Some(object_host_backend()),
                    "original platform worker selection required"
                );
                worker.require_open()?;
                return grant_validation::enforce_retention_ceiling(plan.mailbox.as_ref(), max_ms);
            }
        }
        anyhow::ensure!(
            plan.mailbox
                .and_then(|g| g.durable_object_pair_sha256_v1)
                .is_none(),
            "durable object Call/Reply service is not installed"
        );
        if let Some(incoming) = self.incoming_journal {
            anyhow::ensure!(
                self.paired_journal.is_none()
                    && self.variant == Variant::Prod
                    && self.backend.is_some(),
                "incoming journal requires an original production destination backend"
            );
            grant_validation::enforce_retention_ceiling(plan.mailbox.as_ref(), max_ms)?;
            return incoming.verify(plan);
        }
        anyhow::ensure!(
            plan.mailbox
                .and_then(|g| g.incoming_journal_policy_sha256_v1)
                .is_none(),
            "incoming journal needs explicit original destination authorization"
        );
        let Some(pair) = self.paired_journal else {
            return enforce_mailbox_retention(plan.mailbox.as_ref(), max_ms);
        };
        anyhow::ensure!(
            self.variant == Variant::Prod && self.backend.is_some(),
            "paired journal requires an original production backend"
        );
        grant_validation::enforce_retention_ceiling(plan.mailbox.as_ref(), max_ms)?;
        pair.verify(plan)
    }

    /// Carry authenticated release bytes beside the cloneable launch config.
    #[must_use]
    pub fn with_verified_runtime(
        mut self,
        runtime: Option<&'a mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Self {
        self.verified_runtime = runtime;
        self
    }

    /// Carry authenticated checkpoint runtime evidence beside a fork's config.
    #[must_use]
    pub fn with_verified_retained(
        mut self,
        retained: Option<&'a mvm_runtime::checkpoint::VerifiedRetainedRuntime>,
    ) -> Self {
        self.verified_retained = retained;
        self
    }

    pub(super) fn release_identity(&self) -> Result<Option<mvm_core::plan::RuntimeIdentity>> {
        anyhow::ensure!(
            self.verified_runtime.is_none() || self.verified_retained.is_none(),
            "launch cannot mix fresh and retained runtime verification"
        );
        if let Some(retained) = self.verified_retained {
            if let Some(identity) = retained.identity() {
                mvm_runtime::runtime_evidence::verify_runtime_for_claim(
                    retained,
                    self.runtime_config,
                )?;
                return Ok(Some(identity.clone()));
            }
            // Source and legacy forks have no signed release identity. Keep
            // their existing admission verifier; the warm-claim comparator
            // deliberately refuses legacy bindings and is not a fork gate.
            return Ok(None);
        }
        self.verified_runtime
            .map(|runtime| {
                runtime.verify_config(
                    self.runtime_config
                        .context("verified runtime has no selected launch config")?,
                )?;
                Ok(runtime.identity().clone())
            })
            .transpose()
    }

    pub(super) fn verify_launch_runtime(&self, plan: &ExecutionPlan) -> Result<()> {
        if let Some(identity) = self.release_identity()? {
            plan.require_runtime_identity(&identity)?;
            if let Some(runtime) = self.verified_runtime {
                runtime.require_mailbox_reader(plan, None)?;
            }
        } else {
            anyhow::ensure!(
                plan.runtime_identity.is_none(),
                "signed runtime identity has no verified launch evidence"
            );
            anyhow::ensure!(
                !self
                    .runtime_config
                    .is_some_and(|config| config.runtime_release_proof.is_some()),
                "release runtime requires verified launch evidence"
            );
            self.verify_runtime()?;
        }
        Ok(())
    }

    /// The sealed-production / developer posture this run carries.
    #[must_use]
    pub fn variant(&self) -> Variant {
        self.variant
    }
}
