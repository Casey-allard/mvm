//! Canonical dispatch for an original resource-owned persistent journal.
use super::*;

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
