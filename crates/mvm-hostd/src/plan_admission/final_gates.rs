//! Host checks and prepared attachments performed after plan admission.

use super::*;

/// The post-admission gates between `plan.admitted` and backend start, run in
/// order. On refusal, return the failing stage label for the terminal audit
/// record.
pub(super) fn run_post_admission_gates(
    mut config: VmStartConfig,
    admitted: &AdmittedPlan,
    backend: BackendKind,
    policy_bundle: Option<&PolicyBundle>,
) -> std::result::Result<
    (VmStartConfig, Option<PreparedBuiltPackRuntime>),
    (&'static str, anyhow::Error),
> {
    if config.network_policy.payload_mapping().is_some() {
        mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan::from_plan(
            admitted.plan(),
            &config.name,
            &config.network_policy,
        )
        .map_err(|error| ("direct-network-policy", error))?;
        #[cfg(unix)]
        {
            let bound = admitted
                .direct_owner
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            if !(cfg!(target_os = "linux")
                && backend == BackendKind::Firecracker
                && bound
                    .as_ref()
                    .zip(config.host_lifetime.as_ref())
                    .is_some_and(|(original, supplied)| std::sync::Arc::ptr_eq(original, supplied)))
            {
                return Err((
                    "direct-network-resources",
                    anyhow::anyhow!(
                        "selected direct TCP payload mapping requires original launcher resources"
                    ),
                ));
            }
        }
        #[cfg(not(unix))]
        return Err((
            "direct-network-resources",
            anyhow::anyhow!("selected direct TCP unavailable on this host"),
        ));
    }
    #[cfg(unix)]
    if admitted.direct_owner.is_some() && config.network_policy.payload_mapping().is_none() {
        return Err((
            "direct-network-policy",
            anyhow::anyhow!("original direct mapping removed before launch"),
        ));
    }
    if let Err(error) = populate_audit_substrate(&mut config, admitted, policy_bundle) {
        return Err(("audit-substrate", error));
    }
    if let Err(error) = enforce_admitted_shares(&config.volumes, admitted.plan()) {
        return Err(("admitted-shares", error));
    }
    if let Err(error) = enforce_admitted_environment(
        config.kernel_path.as_deref().map(std::path::Path::new),
        admitted.plan(),
    ) {
        return Err(("admitted-environment", error));
    }
    if let Err(error) = enforce_sdk_sidecar_backend_compatibility(backend, admitted.plan()) {
        return Err(("sdk-sidecar", error.into()));
    }
    if let Err(error) = enforce_sdk_sidecar_attachment(
        &config.volumes,
        admitted.plan(),
        mvm_build::guest_libc::recorded_image_libc(std::path::Path::new(&config.rootfs_path)),
    ) {
        return Err(("sdk-sidecar", error));
    }
    if let Err(error) = attach_admitted_extensions(&mut config, admitted) {
        return Err(("extension-attachment", error));
    }
    let runtime = prepare_built_pack_start(admitted, &mut config, backend)
        .map_err(|error| ("registry-pack-boot", error))?;
    #[cfg(unix)]
    crate::host_lifetime_parent::bind_current(admitted, &config, backend)
        .map_err(|error| ("original-resources", error))?;
    #[cfg(target_os = "linux")]
    {
        if config.registered_boot_grant.is_some() {
            return Err((
                "original-boot-grant",
                anyhow::anyhow!("caller supplied a boot grant issuer"),
            ));
        }
        if mvm_vmm::host::cmdline::uses_installed_payload_anchor(&config) {
            config.registered_boot_grant =
                verb_grant_sidecar::installed_issuer(admitted, &config.name)
                    .map_err(|error| ("original-boot-grant", error))?;
        }
    }
    Ok((config, runtime))
}

pub(super) fn attach_admitted_extensions(
    config: &mut VmStartConfig,
    admitted: &AdmittedPlan,
) -> Result<()> {
    if !admitted.extensions().is_empty() {
        config.extension_plan_id = Some(admitted.plan_id().0.clone());
    }
    for extension in admitted.extensions() {
        if extension.binding.placement
            != mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload
        {
            anyhow::bail!(
                "extension placement isolated_controller reached guest attachment after admission"
            );
        }
        let digest = hex::encode(extension.binding.pack_digest);
        let guest = format!("/run/mvm/extensions/{digest}");
        if config.volumes.iter().any(|volume| volume.guest == guest) {
            anyhow::bail!("extension mountpoint collision at {guest}");
        }
        config.volumes.push(mvm_core::vm_backend::VmVolume {
            materialized_image: None,
            volume_label: None,
            host: extension
                .root
                .join(&extension.binding.artifact)
                .display()
                .to_string(),
            guest,
            size: String::new(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
            share_include: Vec::new(),
            share_exclude: Vec::new(),
        });
        config.extensions.push(extension.binding.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::policy::network_policy::{
        CooperatingPayloadPolicy, CooperatingTcpPeer, NetworkPolicy, PayloadMappingProfile,
    };

    #[test]
    fn selected_direct_policy_requires_signed_binding_and_owned_resources_before_start() {
        let policy = |pin| {
            NetworkPolicy::deny_all().with_payload_mapping(Some(
                CooperatingPayloadPolicy::new(vec![CooperatingTcpPeer {
                    host: "peer.example".into(),
                    port: 443,
                    server_name: "peer.example".into(),
                    spki_sha256: pin,
                    profile: PayloadMappingProfile::SpiralCoreObjectStreamSmallV1,
                }])
                .unwrap(),
            ))
        };
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.asset_identities.push(
            mvm_core::plan::AssetIdentity::new(
                mvm_core::plan::AssetKind::Policy,
                "network_policy",
                mvm_core::policy::network_policy::content_sha256(&policy([7; 32])),
            )
            .unwrap(),
        );
        plan.bundle = Some(mvm_core::plan::bundle::PlanArtifact::new(
            "a".repeat(64),
            &[0; 64],
            mvm_core::plan::bundle::KeyId("fixture".into()),
        ));
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let signer = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let signed = mvm_core::plan::sign_plan(&plan, &signer, "fixture");
        let admitted = AdmittedPlan::for_test(plan, "fixture".into(), signed);
        for (pin, expected) in [
            ([8; 32], "direct-network-policy"),
            ([7; 32], "direct-network-resources"),
        ] {
            let cfg = VmStartConfig {
                name: "direct-original".into(),
                network_policy: policy(pin),
                ..VmStartConfig::default()
            };
            let (stage, _) =
                run_post_admission_gates(cfg, &admitted, BackendKind::Firecracker, None)
                    .expect_err("no resources supplied");
            assert_eq!(stage, expected);
        }
    }
}
