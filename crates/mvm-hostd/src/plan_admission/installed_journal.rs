//! Canonical dispatch for an original resource-owned persistent journal.
use super::*;

pub(super) fn verify_original_owner(
    config: &VmStartConfig,
    owner: &std::sync::Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
    backend: BackendKind,
    plan: &ExecutionPlan,
) -> Result<()> {
    owner.verify_config(config, backend)?;
    mvm_core::policy::direct_plan::AdmittedNetworkPlan::from_plan(
        plan,
        &config.name,
        &config.network_policy,
    )?;
    anyhow::ensure!(
        cfg!(target_os = "linux")
            && backend == BackendKind::Firecracker
            && config.network_policy == mvm_core::network_policy::NetworkPolicy::deny_all()
            && plan.image.name == config.name
            && plan.resources.cpus == config.cpus
            && plan.resources.mem_mib == u64::from(config.memory_mib)
            && plan.secrets.is_empty()
            && plan.ingress.is_empty()
            && plan.mailbox.is_some_and(|grant| grant.retention.is_some()
                && grant.durable_object_pair_sha256_v1.is_none()
                && (grant.incoming_journal_policy_sha256_v1.is_some()
                    ^ grant.outbound_journal_v1.is_some()))
            && !plan.stream_retention.persists()
            && plan.stream_edges.is_empty()
            && plan
                .agent_verbs
                .as_ref()
                .is_some_and(|verbs| verbs.len() == 2
                    && verbs
                        .iter()
                        .any(|verb| verb.as_str() == "activate-environment")
                    && verbs.iter().any(|verb| verb.as_str() == "run-entrypoint")),
        "original installed journal admission differs"
    );
    Ok(())
}

pub(super) fn capture_owner(posture: RunPosture<'_>, plan: &ExecutionPlan) -> Result<()> {
    let Some(owner) = posture.direct_owner else {
        return Ok(());
    };
    let config = posture
        .runtime_config
        .context("original selected runtime missing")?;
    if config.network_policy.payload_mapping().is_some() {
        return Ok(());
    }
    verify_original_owner(
        config,
        owner,
        posture
            .backend
            .context("original journal backend missing")?,
        plan,
    )?;
    let grant = plan.mailbox.context("original journal grant missing")?;
    anyhow::ensure!(
        (grant.incoming_journal_policy_sha256_v1.is_some()
            && posture.incoming_journal.is_some()
            && posture.paired_journal.is_none())
            || (grant.outbound_journal_v1.is_some()
                && posture.paired_journal.is_some()
                && posture.incoming_journal.is_none()),
        "original journal direction admission missing"
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "installed_journal/owner_tests.rs"]
mod owner_tests;

impl<'a> RunPosture<'a> {
    /// Bind actual journal launch custody before signing and canonical admission.
    pub fn with_installed_journal_owner(
        mut self,
        config: &'a VmStartConfig,
        owner: &'a std::sync::Arc<mvm_core::host_lifetime::HostLifetimeAnchor>,
    ) -> Result<Self> {
        let backend = self.backend.context("original journal backend missing")?;
        owner.verify_config(config, backend)?;
        anyhow::ensure!(
            cfg!(target_os = "linux")
                && backend == BackendKind::Firecracker
                && config.network_policy == mvm_core::network_policy::NetworkPolicy::deny_all()
                && self.direct_owner.is_none()
                && self
                    .runtime_config
                    .is_some_and(|bound| std::ptr::eq(bound, config))
                && (self.incoming_journal.is_some() ^ self.paired_journal.is_some()),
            "original journal launch selection differs"
        );
        self.direct_owner = Some(owner);
        Ok(self)
    }
}

/// Reuse the original parent's funded canonical runtime workspace before admission.
pub fn prepare_runtime(config: &mut VmStartConfig, backend: &AnyBackend) -> Result<()> {
    let owner = config
        .host_lifetime
        .as_ref()
        .context("original journal owner missing")?;
    owner.verify_config(config, backend.kind())?;
    let kernel = owner
        .canonical_kernel()
        .context("installed journal requires a prepared canonical kernel")?;
    let pin = kernel.pin().clone();
    let bytes = crate::host_lifetime_parent::check_portable_startup_workspace(
        config,
        backend.kind(),
        &pin,
    )?;
    mvm_runtime::bundle_runtime::attach_direct_runtime(config, backend.name(), &pin, bytes)?;
    Ok(())
}

impl AdmittedPlan {
    /// Run the canonical final gates without starting a second mailbox helper.
    #[cfg(unix)]
    pub fn start_persistent_journal_original(
        &mut self,
        backend: &AnyBackend,
        config: VmStartConfig,
        images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        bundle: Option<&PolicyBundle>,
    ) -> Result<VmId> {
        anyhow::ensure!(
            !self.dispatched
                && cfg!(target_os = "linux")
                && backend.kind() == BackendKind::Firecracker
                && self.backend == Some(backend.kind())
                && config.host_lifetime.is_some()
                && config.network_policy == mvm_core::network_policy::NetworkPolicy::deny_all()
                && self.plan.secrets.is_empty()
                && self.plan.ingress.is_empty()
                && self
                    .plan
                    .mailbox
                    .is_some_and(|grant| grant.durable_object_pair_sha256_v1.is_none()),
            "requires a fresh original installed journal admission"
        );
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
        verify_selected_runtime(&config)?;
        if self.assurance_runtime.is_some() {
            self.verify_assurance_launch(&config)?;
        }
        let (config, runtime) =
            final_gates::run_post_admission_gates(config, self, backend.kind(), bundle)
                .map_err(|(stage, error)| error.context(stage))?;
        anyhow::ensure!(
            config
                .host_lifetime
                .as_ref()
                .is_some_and(|owner| owner.requires_registered_collector()),
            "original installed collector admission missing"
        );
        registry_pack::verify_runtime_at_dispatch(runtime.as_ref(), &config, self, None)?;
        crate::mailbox_process::require_servable(
            &config,
            backend,
            self.mailbox_posture().as_ref(),
        )?;
        self.dispatched = true;
        backend.start_custodied(&config, images)
    }
}
