//! Offline runtime selection from a signed, installed bundle.
//!
//! Cache markers are indexes, not authentication. Every launch checks the
//! installed archives and reinstalls authenticated bytes under the original
//! set root. Neither the CLI lock nor the network participates.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{BackendImageSupport, ImageSetMember};
use mvm_core::plan::FsTrustStore;
use mvm_core::plan::bundle::{
    ArtifactRole, BUNDLE_ORIGIN_LABEL, BundleOrigin, BundleRegistry, LOCAL_BUILD_ORIGIN,
    LocalBundleTrustStore, TrustStore, VerifiedBundleFile, VerifiedEmbeddedImageSet, bundle_origin,
    key_id_from_pubkey, select_boot_asset_members, verify_bundle_file,
};
use mvm_core::vm_backend::{BackendKind, BundleBootAssetsPin, VmStartConfig};

/// Locate a registry-owned bundle. This path is only a hint; never proof.
pub fn installed_archive_for_rootfs(rootfs: &Path) -> Result<Option<PathBuf>> {
    let registry = BundleRegistry::default_path()?;
    let Ok(relative) = rootfs.strip_prefix(registry.root()) else {
        return Ok(None);
    };
    let Some(sha) = relative
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
    else {
        return Ok(None);
    };
    ensure!(
        mvm_core::manifest::is_slot_hash_dirname(sha),
        "invalid installed bundle identity"
    );
    Ok(Some(registry.archive_path(sha)))
}

/// False means an ordinary source or a legacy bundle without boot assets.
pub fn attach_if_installed_bundle(
    config: &mut VmStartConfig,
    backend: &str,
    host_key: impl FnOnce() -> Result<Option<ed25519_dalek::VerifyingKey>>,
) -> Result<bool> {
    let mut selected = config.clone();
    let attached = attach_installed_bundle(&mut selected, backend, None, host_key)?;
    *config = selected;
    Ok(attached)
}

#[cfg(unix)]
pub fn attach_direct_runtime(
    config: &mut VmStartConfig,
    backend: &str,
    pin: &mvm_core::plan::PlanArtifact,
    bytes: std::num::NonZeroU64,
) -> Result<()> {
    let mut selected = config.clone();
    ensure!(
        attach_installed_bundle(&mut selected, backend, Some((pin, bytes)), || Ok(None))?
            && (selected
                .legacy_portable_runtime
                .as_ref()
                .is_some_and(|runtime| &runtime.pin == pin)
                || selected.canonical_kernel.as_ref().is_some_and(
                    |kernel| kernel.pin() == pin && selected.runtime_release_proof.is_some()
                )),
        "direct mapping requires the original installed portable bundle"
    );
    *config = selected;
    Ok(())
}

fn attach_installed_bundle(
    config: &mut VmStartConfig,
    backend: &str,
    quote: Option<(&mvm_core::plan::PlanArtifact, std::num::NonZeroU64)>,
    host_key: impl FnOnce() -> Result<Option<ed25519_dalek::VerifyingKey>>,
) -> Result<bool> {
    let Some(archive) = installed_archive_for_rootfs(Path::new(&config.rootfs_path))? else {
        return Ok(false);
    };
    let registry = BundleRegistry::default_path()?;
    let release = mvm_core::registry_pack::application_bundle::trust_for_installed_archive(
        FsTrustStore::default_path()?,
        &archive,
    );
    let (verified, trust): (VerifiedBundleFile, Box<dyn TrustStore>) = if let Some((pin, bytes)) =
        quote
    {
        let trust = FsTrustStore::default_path()?;
        let verified =
            mvm_core::plan::bundle::verify_exact_bundle_file(&archive, &trust, pin, bytes)?;
        let boot = verified
            .boot_assets
            .as_ref()
            .context("selected bundle boot assets missing")?;
        let canonical = verified.manifest.members.iter().any(|m| {
            matches!(
                m,
                mvm_core::plan::bundle::BundleMember::CanonicalLinuxProof(_)
            )
        });
        match &config.canonical_kernel {
            Some(owner) => {
                ensure!(
                    verified.manifest.schema_version == 7
                        && canonical
                        && boot.cli_runtime.is_some()
                        && owner.pin() == pin,
                    "selected canonical launch requires its original schema-7 CLI runtime and proof"
                );
                owner.verify_bundle_manifest(&verified.manifest)?;
            }
            None => ensure!(
                matches!(verified.manifest.schema_version, 4 | 5)
                    && !canonical
                    && boot.cli_runtime.is_none(),
                "installed direct mapping requires signed portable boot assets"
            ),
        }
        (verified, Box::new(trust))
    } else if let Some(host_key) = host_key()? {
        let host_key_id = key_id_from_pubkey(&host_key);
        let trust = LocalBundleTrustStore::new(release, host_key_id.clone(), host_key);
        let verified =
            verify_bundle_file(&archive, &trust).context("verifying bundle boot assets")?;
        ensure!(
            bundle_origin(&verified.manifest, &host_key_id, trust.release())
                != BundleOrigin::Untrusted,
            "installed bundle is neither release-verified nor a local build signed by this host"
        );
        (verified, Box::new(trust))
    } else {
        let verified =
            verify_bundle_file(&archive, &release).context("verifying bundle boot assets")?;
        ensure!(
            verified
                .manifest
                .labels
                .get(BUNDLE_ORIGIN_LABEL)
                .is_none_or(|value| value != LOCAL_BUILD_ORIGIN),
            "a local build requires this host's signing key"
        );
        (verified, Box::new(release))
    };
    mvm_core::plan::bundle::require_composable_local_enrollment(
        &verified.manifest,
        &FsTrustStore::default_path()?,
    )?;
    let canonical = verified.manifest.members.iter().any(|member| {
        matches!(
            member,
            mvm_core::plan::bundle::BundleMember::CanonicalLinuxProof(_)
        )
    });
    let kind = BackendKind::from_label(backend).context("unknown bundle boot backend")?;
    if let Some(owner) = &config.canonical_kernel {
        ensure!(
            canonical && owner.pin() == &verified.plan_artifact(),
            "canonical owner pin differs from installed bundle"
        );
        owner.verify_bundle_manifest(&verified.manifest)?;
        owner.verify_config(
            config,
            kind,
            &mvm_build::stage0_kernel::current_image_set_protocol_support(),
        )?;
    }
    ensure!(
        registry.archive_path(&verified.bundle_sha256) == archive,
        "installed bundle archive identity changed"
    );
    let installed = match registry.find(&verified.bundle_sha256)? {
        Some(installed) => installed,
        None if quote.is_some() => {
            anyhow::bail!("selected portable bundle must already be installed")
        }
        None => registry
            .materialize_cached(&verified.bundle_sha256, trust.as_ref())
            .context("restoring installed bundle from its signed archive")?,
    };
    ensure!(
        installed.manifest == verified.manifest,
        "installed bundle manifest changed"
    );
    if quote.is_some() && config.canonical_kernel.is_none() {
        let kernel = installed
            .manifest
            .find_by_role(&ArtifactRole::Kernel)
            .context("signed bundle kernel missing")?;
        let path = installed.root.join(&kernel.path);
        ensure!(
            config
                .kernel_path
                .as_deref()
                .is_none_or(|selected| Path::new(selected) == path),
            "selected kernel differs from the signed installed bundle"
        );
        config.kernel_path = Some(path.display().to_string());
    }
    attach_workload_verity(config, &installed)?;
    let Some(boot) = &verified.boot_assets else {
        return Ok(false);
    };
    if let Some(runtime) = &boot.cli_runtime {
        ensure!(
            config.legacy_bundle_runtime.is_none()
                && config.legacy_portable_runtime.is_none()
                && config.bundle_boot_assets.is_none()
                && config.source_runtime_archive_sha256.is_none()
                && !config.unsigned_runtime_development,
            "CLI portable bundle conflicts with another runtime selection"
        );
        ensure!(
            boot.arch == GuestArch::host(),
            "bundle boot-assets architecture differs from host"
        );
        let kind = BackendKind::from_label(backend).context("unknown bundle boot backend")?;
        // A canonical bundle retains a kernel generation only where the
        // backend can prove that generation's exit; refuse the rest before
        // paying for image selection or runtime assembly, not after.
        let needs_owner = canonical && config.canonical_kernel.is_none();
        ensure!(
            !needs_owner || mvm_core::canonical_linux::supports_lifetime_custody(kind),
            "canonical kernel lifetime custody unsupported by this backend"
        );
        let support = BackendImageSupport::for_backend(kind)
            .context("backend cannot consume bundle boot assets")?;
        mvm_core::plan::bundle::check_boot_assets_for_backend(
            boot,
            &support,
            &mvm_build::stage0_kernel::current_image_set_protocol_support(),
        )?;
        attach_cli_runtime(config, &installed, runtime)?;
        if needs_owner {
            let owner = std::sync::Arc::new(mvm_core::canonical_linux::prepare_canonical_linux(
                &archive,
                &verified.plan_artifact(),
                kind,
                mvm_build::stage0_kernel::current_image_set_protocol_support(),
                trust.as_ref(),
            )?);
            owner.bind_to_config(config)?;
        }
        return Ok(true);
    }
    ensure!(
        config.legacy_bundle_runtime.is_none()
            && config.runtime_release_proof.is_none()
            && config.source_runtime_archive_sha256.is_none()
            && !config.unsigned_runtime_development,
        "conflicting portable runtime evidence"
    );
    let proof = mvm_core::vm_backend::LegacyPortableRuntimeProof {
        archive: archive.clone(),
        pin: verified.plan_artifact(),
        manifest_sha256: boot.image_set.manifest_sha256.as_str().to_owned(),
        arch: boot.arch,
    };
    if let Some(previous) = &config.legacy_portable_runtime {
        ensure!(
            previous == &proof,
            "explicit portable proof differs from installed bundle"
        );
        crate::runtime_evidence::verify_runtime_for_launch(
            config,
            crate::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
        )?;
    }
    if let Some(pin) = &config.bundle_boot_assets {
        ensure!(
            pin.manifest_sha256 == boot.image_set.manifest_sha256 && pin.arch == boot.arch,
            "explicit boot-assets pin differs from installed bundle"
        );
        let signed_initrd = verified
            .manifest
            .find_by_role(&ArtifactRole::Initrd)
            .context("signed initrd missing")?;
        ensure!(
            pin.initrd_sha256.as_str() == signed_initrd.sha256,
            "explicit initrd pin differs from installed bundle"
        );
    }
    ensure!(
        boot.arch == GuestArch::host(),
        "bundle boot-assets architecture differs from host"
    );
    let kind = BackendKind::from_label(backend).context("unknown bundle boot backend")?;
    let support = BackendImageSupport::for_backend(kind)
        .context("backend cannot consume bundle boot assets")?;
    mvm_core::plan::bundle::check_boot_assets_for_backend(
        boot,
        &support,
        &mvm_build::stage0_kernel::current_image_set_protocol_support(),
    )?;
    let initrd = verified
        .manifest
        .find_by_role(&ArtifactRole::Initrd)
        .context("bundle boot assets require a signed initrd")?;
    let set = mvm_build::published_image_set::SetMemberCache::for_root(
        boot.image_set.manifest_sha256.clone(),
    );
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let staging = tempfile::tempdir()?;
    let [overlay_member, initramfs_member] =
        select_boot_asset_members(&boot.image_set.manifest, boot.arch)?;
    let overlay_archive = authenticated_copy(
        overlay_member,
        &boot.image_set,
        &installed.root,
        staging.path(),
    )?;
    let initramfs_archive = authenticated_copy(
        initramfs_member,
        &boot.image_set,
        &installed.root,
        staging.path(),
    )?;
    mvm_build::runtime_overlay::install_image_set_runtime_overlay_archive(
        &overlay_archive,
        &set,
        boot.image_set.manifest_sha256.as_str(),
        boot.arch,
        &cache,
    )?;
    mvm_build::initramfs::install_image_set_initramfs_archive(
        &initramfs_archive,
        &set,
        boot.arch,
        &cache,
    )?;
    let overlay =
        mvm_build::runtime_overlay::resolve_image_set_runtime_overlay(&cache, &set, boot.arch)?;
    let ramdisk = mvm_build::initramfs::resolve_image_set_initramfs(&cache, &set, boot.arch)?;
    let initrd_sha256 = mvm_core::crypto::image_verify::sha256_file(&ramdisk.image_path)?;
    ensure!(
        std::fs::metadata(&ramdisk.image_path)?.len() == initrd.size_bytes
            && initrd_sha256 == initrd.sha256,
        "bundle member initrd differs from the signed boot initrd"
    );
    config.runtime_overlay_path = Some(overlay.overlay_ext4.display().to_string());
    config.runtime_overlay_verity_path = Some(overlay.sidecar.display().to_string());
    config.runtime_overlay_roothash = Some(overlay.roothash);
    config.runtime_overlay_version = Some(overlay.version);
    config.initrd_path = Some(ramdisk.image_path.display().to_string());
    config.bundle_boot_assets = Some(BundleBootAssetsPin {
        manifest_sha256: boot.image_set.manifest_sha256.clone(),
        arch: boot.arch,
        initrd_sha256: mvm_core::packs::Sha256Hex::new(initrd_sha256)?,
    });
    config.legacy_portable_runtime = Some(proof);
    crate::runtime_evidence::verify_runtime_for_launch(
        config,
        crate::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
    )?;
    Ok(true)
}

/// Reuse the canonical release verifier; a bundle publisher cannot authorize
/// unsigned runtime bytes. The backend retains its own verified generation
/// before spawning, so these installed paths are inputs, not custody authority.
fn attach_cli_runtime(
    config: &mut VmStartConfig,
    installed: &mvm_core::plan::bundle::InstalledBundle,
    runtime: &mvm_core::plan::bundle::EmbeddedCliBootAssets,
) -> Result<()> {
    use mvm_build::guest_runtime::evidence::{
        RuntimeArtifactSelection, verify_runtime_release_proof,
    };
    use mvm_core::protocol::runtime_release::{
        CliRuntimeLaunchBinding, RuntimeBindingProvenance, RuntimeLaunchBinding,
        RuntimeReleaseProof,
    };
    let artifact = |name: &str| -> Result<PathBuf> {
        verify_installed_artifact(
            &installed.root,
            installed
                .manifest
                .find_by_name(name)
                .context("CLI runtime artifact missing")?,
        )
    };
    let archive = installed
        .manifest
        .find_by_name(&runtime.archive_artifact)
        .context("CLI runtime archive declaration missing")?;
    let proof = RuntimeReleaseProof {
        archive: artifact(&runtime.archive_artifact)?,
        checksum: artifact(&runtime.checksum_artifact)?,
        signature_bundle: artifact(&runtime.signature_bundle_artifact)?,
        archive_sha256: archive.sha256.clone(),
        version: runtime.version.clone(),
        arch: GuestArch::host(),
    };
    if let Some(existing) = &config.runtime_release_proof {
        ensure!(
            existing == &proof,
            "CLI portable runtime proof conflicts with the signed bundle"
        );
        crate::runtime_evidence::verify_release_runtime_for_launch(
            config,
            crate::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
        )
        .context("verifying existing explicit portable CLI runtime selection")?;
    }
    let checksum_bundle = artifact(&runtime.checksum_signature_bundle_artifact)?;
    ensure!(
        checksum_bundle
            == mvm_build::guest_runtime::evidence::checksum_bundle_path(&proof.checksum),
        "retained checksum signature bundle is not paired with its checksum"
    );
    let overlay_path = artifact(&runtime.overlay_artifact)?;
    let overlay_verity_path = artifact(&runtime.overlay_verity_artifact)?;
    let initramfs_path = artifact(&runtime.initramfs_artifact)?;
    let verified = verify_runtime_release_proof(&proof, &runtime.version, proof.arch)
        .context("verifying retained portable CLI runtime release proof")?;
    let declaration = verified.declaration(proof.arch)?;
    ensure!(
        declaration.protocol_version == runtime.protocol_version
            && declaration.min_supported_protocol_version == runtime.min_supported_protocol_version
            && declaration.overlay_roothash == runtime.overlay_roothash,
        "bundle runtime protocol or verity declaration differs from signed release"
    );
    verified.verify_selected_artifacts(&RuntimeArtifactSelection {
        arch: proof.arch,
        overlay: &overlay_path,
        overlay_verity: &overlay_verity_path,
        overlay_roothash: &runtime.overlay_roothash,
        initramfs: &initramfs_path,
        minimum_protocol: crate::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
        host_protocol: crate::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
    })?;
    RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
        provenance: RuntimeBindingProvenance::Release { proof },
        overlay_path,
        overlay_verity_path,
        initramfs_path,
        overlay_roothash: runtime.overlay_roothash.clone(),
    })
    .apply_to_config(config);
    config.bundle_boot_assets = None;
    config.legacy_portable_runtime = None;
    // The portable closure is selected for this cold launch, not a substitute
    // for the runtime of an independently prepared standby parent.
    config.warm_pool_size = 0;
    Ok(())
}

fn attach_workload_verity(
    config: &mut VmStartConfig,
    installed: &mvm_core::plan::bundle::InstalledBundle,
) -> Result<()> {
    let rootfs = installed
        .manifest
        .find_by_role(&ArtifactRole::Rootfs)
        .context("bundle rootfs missing")?;
    ensure!(
        Path::new(&config.rootfs_path) == installed.root.join(&rootfs.path),
        "boot rootfs differs from bundle"
    );
    let kernel = installed
        .manifest
        .find_by_role(&ArtifactRole::Kernel)
        .context("bundle kernel missing")?;
    match &config.canonical_kernel {
        Some(owner) => {
            owner.verify_bundle_manifest(&installed.manifest)?;
            ensure!(
                config.kernel_path.as_deref() == owner.kernel_path().to_str(),
                "boot kernel differs from the actual canonical owner"
            );
        }
        None => ensure!(
            config.kernel_path.as_deref().map(Path::new)
                == Some(installed.root.join(&kernel.path).as_path()),
            "boot kernel differs from bundle"
        ),
    }
    for artifact in [rootfs, kernel] {
        verify_installed_artifact(&installed.root, artifact)?;
    }
    let binding = installed
        .manifest
        .verity
        .as_ref()
        .map(|verity| {
            let artifact = installed
                .manifest
                .find_by_name(&verity.sidecar_artifact)
                .context("bundle verity artifact missing")?;
            ensure!(
                artifact.role == ArtifactRole::VerityHashSidecar,
                "bundle verity artifact has the wrong role"
            );
            let path = verify_installed_artifact(&installed.root, artifact)?;
            Ok::<_, anyhow::Error>((path.display().to_string(), verity.roothash.clone()))
        })
        .transpose()?;
    // An authenticated bundle declaration supersedes any ambient sibling pair.
    (config.verity_path, config.roothash) = match binding {
        Some((path, hash)) => (Some(path), Some(hash)),
        None => (None, None),
    };
    Ok(())
}

fn verify_installed_artifact(
    root: &Path,
    artifact: &mvm_core::plan::bundle::BundleArtifact,
) -> Result<PathBuf> {
    let path = root.join(&artifact.path);
    ensure!(
        std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading installed bundle artifact {}", artifact.path))?
            .file_type()
            .is_file(),
        "installed bundle artifact is not a regular file: {}",
        artifact.path
    );
    let size = std::fs::metadata(&path)
        .with_context(|| format!("reading installed bundle artifact {}", artifact.path))?
        .len();
    ensure!(
        size == artifact.size_bytes,
        "installed bundle artifact size changed: {}",
        artifact.path
    );
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(&path)? == artifact.sha256,
        "installed bundle artifact digest changed: {}",
        artifact.path
    );
    Ok(path)
}

fn authenticated_copy(
    member: &ImageSetMember,
    image_set: &VerifiedEmbeddedImageSet,
    installed_root: &Path,
    staging: &Path,
) -> Result<PathBuf> {
    ensure!(
        member.artifacts.len() == 1,
        "bundle runtime member must contain one archive"
    );
    let artifact = &member.artifacts[0];
    let path = image_set
        .artifact_paths
        .get(artifact.name.as_str())
        .context("bundle runtime archive missing")?;
    let authenticated = staging.join(artifact.name.as_str());
    // Parse only a private copy, authenticated after copying so a changing
    // installed archive cannot replace the bytes between verification and use.
    let size = std::fs::copy(installed_root.join(path), &authenticated)
        .with_context(|| format!("copying installed bundle runtime archive {path}"))?;
    ensure!(
        size == artifact.size,
        "bundle runtime archive size changed: {path}"
    );
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(&authenticated)? == artifact.sha256.as_str(),
        "bundle runtime archive digest changed: {path}"
    );
    Ok(authenticated)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_runtime_rejects_untrusted_release_inputs_without_changing_config() {
        use mvm_core::plan::bundle::{
            BundleArtifact, BundleManifest, EmbeddedCliBootAssets, InstalledBundle, KeyId,
            sha256_hex,
        };
        let home = tempfile::tempdir().unwrap();
        let runtime = EmbeddedCliBootAssets {
            manifest_artifact: "boot-image-set.json".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            arch: GuestArch::host().to_string(),
            archive_artifact: "runtime.tar.gz".into(),
            checksum_artifact: "runtime.sha256".into(),
            signature_bundle_artifact: "runtime.bundle".into(),
            checksum_signature_bundle_artifact: "runtime.sha256.bundle".into(),
            overlay_artifact: "overlay.ext4".into(),
            overlay_verity_artifact: "overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: "a".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 2,
        };
        let artifacts = [
            "runtime.tar.gz",
            "runtime.sha256",
            "runtime.bundle",
            "runtime.sha256.bundle",
            "overlay.ext4",
            "overlay.verity",
            "initrd",
        ]
        .into_iter()
        .map(|name| {
            let bytes = format!("untrusted {name}");
            std::fs::write(home.path().join(name), &bytes).unwrap();
            BundleArtifact {
                name: name.into(),
                path: name.into(),
                role: ArtifactRole::Other,
                sha256: sha256_hex(bytes.as_bytes()),
                size_bytes: bytes.len() as u64,
            }
        })
        .collect();
        let installed = InstalledBundle {
            sha256: "b".repeat(64),
            root: home.path().to_owned(),
            manifest: BundleManifest {
                schema_version: 6,
                publisher: "test-only".into(),
                key_id: KeyId("test".into()),
                arch: runtime.arch.clone(),
                kernel_version: None,
                profile: None,
                workload_label: None,
                created_at: "2026-10-16T00:00:00Z".into(),
                labels: Default::default(),
                artifacts,
                members: Vec::new(),
                verity: None,
                resources: None,
            },
        };
        let mut config = VmStartConfig {
            name: "must-not-boot".into(),
            ..Default::default()
        };
        let before = format!("{config:?}");
        let error = attach_cli_runtime(&mut config, &installed, &runtime).unwrap_err();
        assert!(
            format!("{error:#}").contains("verifying retained portable CLI runtime release proof")
        );
        assert_eq!(format!("{config:?}"), before);
        std::fs::write(home.path().join("overlay.ext4"), b"changed").unwrap();
        let error = attach_cli_runtime(&mut config, &installed, &runtime).unwrap_err();
        assert!(format!("{error:#}").contains("digest") || format!("{error:#}").contains("size"));
        assert_eq!(format!("{config:?}"), before);
    }
}
