//! Original portable bundles retain their publisher and protocol declarations.

use anyhow::{Context, Result, ensure};
use mvm_core::plan::bundle::{
    ArtifactRole, FsTrustStore, VerifiedBundle, select_boot_asset_members, verify_plan_bundle_bytes,
};
use mvm_core::vm_backend::VmStartConfig;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct VerifiedLegacyPortableRuntime {
    archive: Vec<u8>,
    rootfs: Vec<u8>,
    workload_verity: Option<WorkloadVerity>,
    kernel: Vec<u8>,
    overlay: Vec<u8>,
    overlay_version: String,
    overlay_roothash: String,
    verity: Vec<u8>,
    initrd: Vec<u8>,
    initrd_version: String,
}

#[derive(Debug)]
struct WorkloadVerity {
    roothash: String,
    sha256: String,
    bytes: Vec<u8>,
}

impl WorkloadVerity {
    fn from_bundle(bundle: &VerifiedBundle) -> Result<Option<Self>> {
        let Some(info) = &bundle.manifest.verity else {
            return Ok(None);
        };
        mvm_core::packs::Sha256Hex::new(&info.roothash)
            .context("invalid portable workload verity root")?;
        let artifact = bundle
            .manifest
            .find_by_name(&info.sidecar_artifact)
            .context("signed portable workload verity sidecar missing")?;
        ensure!(
            artifact.role == ArtifactRole::VerityHashSidecar,
            "signed portable workload verity sidecar has the wrong role"
        );
        let bytes = bundle
            .artifacts
            .get(&artifact.path)
            .context("signed portable workload verity bytes missing")?;
        Ok(Some(Self {
            roothash: info.roothash.clone(),
            sha256: artifact.sha256.clone(),
            bytes: bytes.clone(),
        }))
    }

    fn verify_selection(&self, config: &VmStartConfig) -> Result<()> {
        use std::io::Read;

        ensure!(
            config.roothash.as_deref() == Some(self.roothash.as_str()),
            "selected portable workload verity root differs from signed bundle"
        );
        let path = config
            .verity_path
            .as_deref()
            .context("selected portable workload verity sidecar missing")?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        let size = self.bytes.len() as u64;
        ensure!(
            metadata.is_file()
                && metadata.len() == size
                && mvm_core::crypto::image_verify::sha256_reader(file.take(size + 1))?
                    == self.sha256,
            "selected portable workload verity sidecar differs from signed bundle"
        );
        Ok(())
    }
}

impl VerifiedLegacyPortableRuntime {
    pub(crate) fn rootfs_sha256(&self) -> String {
        mvm_core::plan::bundle::sha256_hex(&self.rootfs)
    }

    pub(crate) fn kernel_sha256(&self) -> String {
        mvm_core::plan::bundle::sha256_hex(&self.kernel)
    }

    pub(crate) fn snapshot_in(
        &self,
        config: &VmStartConfig,
        parent: &Path,
        #[cfg(unix)] custody: &std::sync::Mutex<
            crate::runtime_evidence::portable_generation::PortableCustody,
        >,
        #[cfg(unix)] parent_fd: &std::fs::File,
    ) -> Result<VmStartConfig> {
        let mut bound = config.clone();
        let proof = bound
            .legacy_portable_runtime
            .as_mut()
            .context("portable proof missing")?;
        let members = [
            ("bundle.mvmpkg", &self.archive),
            ("rootfs", &self.rootfs),
            ("kernel", &self.kernel),
            ("overlay.ext4", &self.overlay),
            ("overlay.verity", &self.verity),
            ("initramfs.cpio.gz", &self.initrd),
        ]
        .into_iter()
        .chain(
            self.workload_verity
                .as_ref()
                .map(|verity| ("rootfs.verity", &verity.bytes)),
        );
        #[cfg(unix)]
        let installed_path = if config.host_lifetime.is_some() {
            use crate::runtime_evidence::portable_generation::{
                OwnedPortableGeneration, PortableCustody,
            };
            let mut held = custody
                .lock()
                .map_err(|_| anyhow::anyhow!("portable generation custody poisoned"))?;
            ensure!(
                matches!(*held, PortableCustody::Empty),
                "original portable generation already retained"
            );
            // A failure after exclusive mkdir may leave original bytes in the
            // namespace. Fence retirement until the exact directory is held.
            *held = PortableCustody::Uncertain;
            *held = PortableCustody::Owned(OwnedPortableGeneration::create(parent, parent_fd)?);
            let PortableCustody::Owned(owner) = &mut *held else {
                unreachable!();
            };
            for (name, bytes) in members.clone() {
                owner.write_member(name, bytes)?;
            }
            owner.finish()?;
            Some(owner.path())
        } else {
            None
        };
        #[cfg(not(unix))]
        let installed_path: Option<PathBuf> = None;
        let generation: PathBuf = if let Some(path) = installed_path {
            path
        } else {
            let generation = tempfile::Builder::new()
                .prefix("portable-runtime-")
                .tempdir_in(parent)?;
            mvm_core::private_fs::set_mode(generation.path(), 0o700)?;
            for (name, bytes) in members {
                let path = generation.path().join(name);
                mvm_core::util::atomic_io::write_private_new(&path, bytes)?;
                mvm_core::private_fs::set_mode(&path, 0o400)?;
                mvm_core::util::atomic_io::sync_file(&path)?;
            }
            mvm_core::util::atomic_io::sync_dir(generation.path())?;
            let path = generation.keep();
            mvm_core::util::atomic_io::sync_dir(parent)?;
            path
        };
        proof.archive = generation.join("bundle.mvmpkg");
        bound.rootfs_path = generation.join("rootfs").display().to_string();
        bound.verity_path = self
            .workload_verity
            .as_ref()
            .map(|_| generation.join("rootfs.verity").display().to_string());
        bound.roothash = self
            .workload_verity
            .as_ref()
            .map(|verity| verity.roothash.clone());
        bound.kernel_path = Some(generation.join("kernel").display().to_string());
        bound.runtime_overlay_path = Some(generation.join("overlay.ext4").display().to_string());
        bound.runtime_overlay_verity_path =
            Some(generation.join("overlay.verity").display().to_string());
        bound.initrd_path = Some(generation.join("initramfs.cpio.gz").display().to_string());
        Ok(bound)
    }
}

pub(crate) fn verify(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<VerifiedLegacyPortableRuntime> {
    let verified = verify_retained(config, minimum_protocol)?;
    verified.verify_workload_selection(config, installed(config))?;
    Ok(verified)
}

#[cfg(unix)]
fn installed(config: &VmStartConfig) -> bool {
    config.host_lifetime.is_some()
}

#[cfg(not(unix))]
fn installed(_config: &VmStartConfig) -> bool {
    false
}

/// Authenticate the original bundle before projecting cache paths. The
/// installed route consumes only the preprovisioned payload files.
pub(crate) fn select_preprovisioned_cache(
    config: &mut VmStartConfig,
    cache: &Path,
    minimum_protocol: u32,
) -> Result<()> {
    ensure!(
        installed(config),
        "preprovisioned cache requires an installed owner"
    );
    let verified = verify_archive(config, minimum_protocol)?;
    verified.project_cache(config, cache)?;
    verified.verify_workload_selection(config, true)?;
    verified.verify_boot_selection(config, true)
}

impl VerifiedLegacyPortableRuntime {
    fn verify_workload_selection(&self, config: &VmStartConfig, installed: bool) -> Result<()> {
        ensure!(
            selected_file_matches(Path::new(&config.rootfs_path), &self.rootfs, installed)?,
            "selected portable rootfs differs from signed bundle"
        );
        let kernel = config
            .kernel_path
            .as_deref()
            .context("portable kernel missing")?;
        ensure!(
            selected_file_matches(Path::new(kernel), &self.kernel, installed)?,
            "selected portable kernel differs from signed bundle"
        );
        if let Some(verity) = &self.workload_verity {
            verity.verify_selection(config)?;
        } else {
            ensure!(
                config.verity_path.is_none() && config.roothash.is_none(),
                "selected portable workload verity is absent from signed bundle"
            );
        }
        Ok(())
    }

    fn project_cache(&self, config: &mut VmStartConfig, cache: &Path) -> Result<()> {
        use mvm_build::published_image_set::{MemberVersion, SetMemberCache};
        use mvm_fs::{
            initramfs::{INITRAMFS_IMAGE_FILE, InitramfsResolver},
            overlay::RuntimeOverlayLayout,
        };
        let proof = config
            .legacy_portable_runtime
            .as_ref()
            .context("portable proof missing")?;
        let manifest = mvm_core::packs::Sha256Hex::new(proof.manifest_sha256.clone())?;
        let cache = SetMemberCache::for_root(manifest.clone()).cache_root(cache);
        let arch = proof.arch.to_string();
        let overlay_version = MemberVersion::parse(&self.overlay_version)?;
        let initrd_version = MemberVersion::parse(&self.initrd_version)?;
        let overlay = RuntimeOverlayLayout::under(&cache, overlay_version.as_str(), &arch);
        let initrd = InitramfsResolver::new(&cache, initrd_version.as_str())
            .artifact_dir(&arch)
            .join(INITRAMFS_IMAGE_FILE);
        config.runtime_overlay_path = Some(overlay.overlay_ext4.display().to_string());
        config.runtime_overlay_verity_path = Some(overlay.sidecar.display().to_string());
        config.runtime_overlay_roothash = Some(self.overlay_roothash.clone());
        config.runtime_overlay_version = Some(self.overlay_version.clone());
        config.initrd_path = Some(initrd.display().to_string());
        config.bundle_boot_assets = Some(mvm_core::vm_backend::BundleBootAssetsPin {
            manifest_sha256: manifest,
            arch: proof.arch,
            initrd_sha256: mvm_core::packs::Sha256Hex::new(mvm_core::plan::bundle::sha256_hex(
                &self.initrd,
            ))?,
        });
        Ok(())
    }

    fn verify_boot_selection(&self, config: &VmStartConfig, installed: bool) -> Result<()> {
        ensure!(
            config.runtime_overlay_roothash.as_deref() == Some(self.overlay_roothash.as_str())
                && config.runtime_overlay_version.as_deref() == Some(self.overlay_version.as_str()),
            "portable runtime root or version differs from original payload"
        );
        for (selected, expected) in [
            (config.runtime_overlay_path.as_deref(), &self.overlay),
            (config.runtime_overlay_verity_path.as_deref(), &self.verity),
            (config.initrd_path.as_deref(), &self.initrd),
        ] {
            let path = selected.context("portable runtime selection incomplete")?;
            ensure!(
                selected_file_matches(Path::new(path), expected, installed)?,
                "selected portable bytes differ from authenticated original payload"
            );
        }
        Ok(())
    }
}

/// Root and kernel observations are compared separately, allowing authenticated
/// checkpoint forks to remap an identical copy without changing its identity.
pub(crate) fn verify_retained(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<VerifiedLegacyPortableRuntime> {
    let verified = verify_archive(config, minimum_protocol)?;
    verified.verify_boot_selection(config, installed(config))?;
    Ok(verified)
}

fn verify_archive(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<VerifiedLegacyPortableRuntime> {
    ensure!(
        config.legacy_bundle_runtime.is_none()
            && config.runtime_release_proof.is_none()
            && config.source_runtime_archive_sha256.is_none()
            && !config.unsigned_runtime_development,
        "conflicting portable runtime evidence"
    );
    let proof = config
        .legacy_portable_runtime
        .as_ref()
        .context("portable proof missing")?;
    ensure!(
        proof.arch == mvm_core::arch::GuestArch::host(),
        "portable guest architecture mismatch"
    );
    #[cfg(unix)]
    let exact_bytes = config
        .host_lifetime
        .as_ref()
        .map(|owner| owner.portable_archive_bytes(&proof.pin))
        .transpose()?;
    #[cfg(not(unix))]
    let exact_bytes = None;
    let original = match exact_bytes {
        Some(bytes) => mvm_core::plan::bundle::read_exact_bundle_archive(&proof.archive, bytes)?,
        None => std::fs::read(&proof.archive)?,
    };
    let bundle = verify_plan_bundle_bytes(&proof.pin, &original, &FsTrustStore::default_path()?)?;
    ensure!(
        matches!(bundle.manifest.schema_version, 4 | 5)
            && bundle.manifest.members.iter().any(|member| {
                matches!(
                    member,
                    mvm_core::plan::bundle::BundleMember::EmbeddedBootAssets { .. }
                )
            }),
        "portable runtime requires original schema-4/5 legacy boot-assets bundle"
    );
    mvm_core::arch::GuestArch::require_host(&bundle.manifest.arch)?;
    let boot = bundle
        .boot_assets
        .as_ref()
        .context("portable signed boot assets missing")?;
    ensure!(
        boot.cli_runtime.is_none(),
        "portable legacy runtime refuses CLI runtime boot assets"
    );
    ensure!(
        boot.arch == proof.arch && boot.image_set.manifest_sha256.as_str() == proof.manifest_sha256,
        "portable image-set identity mismatch"
    );
    ensure!(
        boot.image_set.manifest.schema_version == 2,
        "portable runtime requires original schema-2 image set"
    );
    let protocol = boot
        .image_set
        .manifest
        .compatibility
        .guest_agent_protocol
        .context("portable runtime lacks original guest protocol declaration")?;
    ensure!(
        protocol.max() >= minimum_protocol
            && protocol.min() <= crate::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
        "authenticated portable guest protocol is incompatible"
    );
    let [overlay_member, initramfs_member] =
        select_boot_asset_members(&boot.image_set.manifest, proof.arch)?;
    let signed_member = |member: &mvm_core::image_set::ImageSetMember| -> Result<&[u8]> {
        ensure!(
            member.artifacts.len() == 1,
            "portable role requires exactly one archive"
        );
        let artifact = &member.artifacts[0];
        let path = boot
            .image_set
            .artifact_paths
            .get(artifact.name.as_str())
            .context("signed portable member mapping missing")?;
        let bytes = bundle
            .artifacts
            .get(path)
            .context("signed portable member bytes missing")?;
        ensure!(
            bytes.len() as u64 == artifact.size
                && mvm_core::plan::bundle::sha256_hex(bytes) == artifact.sha256.as_str(),
            "portable member differs from original image set"
        );
        Ok(bytes)
    };
    let overlay_bytes = signed_member(overlay_member)?;
    let initrd_bytes = signed_member(initramfs_member)?;
    let (overlay, initrd) = if exact_bytes.is_some() {
        (
            mvm_build::legacy_boot_payload::overlay(overlay_bytes)?,
            mvm_build::legacy_boot_payload::initramfs(initrd_bytes)?,
        )
    } else {
        decode_ordinary_boot_assets(overlay_bytes, initrd_bytes, proof.arch)?
    };
    ensure!(
        role_bytes(&bundle, ArtifactRole::Initrd)? == initrd.image,
        "portable initrd differs from signed Initrd role"
    );
    if let Some(pin) = &config.bundle_boot_assets {
        ensure!(
            pin.arch == proof.arch
                && pin.manifest_sha256.as_str() == proof.manifest_sha256
                && pin.initrd_sha256.as_str() == mvm_core::plan::bundle::sha256_hex(&initrd.image),
            "portable boot pin differs from original bundle"
        );
    }
    Ok(VerifiedLegacyPortableRuntime {
        rootfs: role_bytes(&bundle, ArtifactRole::Rootfs)?.to_vec(),
        workload_verity: WorkloadVerity::from_bundle(&bundle)?,
        kernel: role_bytes(&bundle, ArtifactRole::Kernel)?.to_vec(),
        archive: original,
        overlay: overlay.image,
        overlay_version: overlay.version,
        overlay_roothash: overlay.roothash,
        verity: overlay.verity,
        initrd: initrd.image,
        initrd_version: initrd.version,
    })
}

fn decode_ordinary_boot_assets(
    overlay_bytes: &[u8],
    initrd_bytes: &[u8],
    arch: mvm_core::arch::GuestArch,
) -> Result<(
    mvm_build::legacy_boot_payload::OverlayPayload,
    mvm_build::legacy_boot_payload::InitramfsPayload,
)> {
    use mvm_build::legacy_boot_payload::{InitramfsPayload, OverlayPayload};
    let scratch = tempfile::tempdir()?;
    let overlay_archive = scratch.path().join("archive-0");
    let initrd_archive = scratch.path().join("archive-1");
    std::fs::write(&overlay_archive, overlay_bytes)?;
    std::fs::write(&initrd_archive, initrd_bytes)?;
    let overlay_stage = tempfile::tempdir_in(scratch.path())?;
    let initrd_stage = tempfile::tempdir_in(scratch.path())?;
    let overlay = mvm_build::runtime_overlay::parse_authenticated_legacy_overlay(
        &overlay_archive,
        overlay_stage.path(),
        arch,
    )?;
    let initrd = mvm_build::initramfs::parse_authenticated_legacy_initramfs(
        &initrd_archive,
        initrd_stage.path(),
    )?;
    Ok((
        OverlayPayload {
            image: std::fs::read(&overlay.overlay_ext4)?,
            verity: std::fs::read(&overlay.sidecar)?,
            roothash: overlay.roothash,
            version: overlay.version,
        },
        InitramfsPayload {
            image: std::fs::read(&initrd.image_path)?,
            version: initrd.version,
        },
    ))
}

fn selected_file_matches(path: &Path, expected: &[u8], installed: bool) -> Result<bool> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    if installed {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    let _ = installed;
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return Ok(false);
    }
    let mut buffer = [0; 8192];
    for chunk in expected.chunks(buffer.len()) {
        let selected = &mut buffer[..chunk.len()];
        file.read_exact(selected)?;
        if selected != chunk {
            return Ok(false);
        }
    }
    // Recheck end of stream after the comparison in case the file grew.
    Ok(file.read(&mut buffer[..1])? == 0)
}

fn role_bytes(bundle: &VerifiedBundle, role: ArtifactRole) -> Result<&[u8]> {
    let artifact = bundle
        .manifest
        .find_by_role(&role)
        .context("portable signed artifact role missing")?;
    bundle
        .artifacts
        .get(&artifact.path)
        .map(Vec::as_slice)
        .context("portable signed artifact bytes missing")
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) mod fixtures {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_build::{boot_asset_fixture, published_image_set::fixture::ImageSetFixture};
    use mvm_core::arch::GuestArch;
    use mvm_core::plan::bundle::{
        BundleArtifact, BundleManifest, BundleMember, key_id_from_pubkey, sha256_hex,
        verify_bundle_file, write_bundle,
    };
    use mvm_core::vm_backend::LegacyPortableRuntimeProof;

    /// Signed original portable inputs, not a verified capability.
    pub fn signed_legacy_portable_runtime_fixture(home: &Path) -> VmStartConfig {
        fixture(home, Some(2), false, 4).unwrap()
    }

    pub(super) fn fixture(
        home: &Path,
        protocol: Option<u32>,
        wrong_role: bool,
        schema: u32,
    ) -> std::result::Result<VmStartConfig, mvm_core::plan::BundleVerifyError> {
        fixture_with_verity(home, protocol, wrong_role, schema, false)
    }

    pub(super) fn fixture_with_verity(
        home: &Path,
        protocol: Option<u32>,
        wrong_role: bool,
        schema: u32,
        workload_verity: bool,
    ) -> std::result::Result<VmStartConfig, mvm_core::plan::BundleVerifyError> {
        let arch = GuestArch::host();
        let version = "99.2.3";
        let overlay = boot_asset_fixture::runtime_overlay_archive_bytes(
            arch,
            &boot_asset_fixture::valid_overlay_ext4_bytes(),
            b"verity",
            format!("{}\n", "a".repeat(64)).as_bytes(),
            version.as_bytes(),
        );
        let (initrd, hash, size) = boot_asset_fixture::initramfs_fixture(b"signed cpio");
        let initramfs = boot_asset_fixture::initramfs_archive_bytes(
            &initrd,
            hash.as_bytes(),
            size.as_bytes(),
            version.as_bytes(),
        );
        let mut set = ImageSetFixture::complete()
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_OVERLAY_ROLE,
                mvm_core::image_set::MemberTarget::Arch(arch),
                "overlay.tar.gz",
                overlay.clone(),
            )
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_INITRAMFS_ROLE,
                mvm_core::image_set::MemberTarget::Arch(arch),
                "initramfs.tar.gz",
                initramfs.clone(),
            )
            .into_manifest();
        set.compatibility.guest_agent_protocol =
            protocol.map(|p| mvm_core::image_set::ProtocolRange::new(p, p).unwrap());
        let set_bytes = serde_json::to_vec(&set).unwrap();
        let mut baked_metadata =
            mvm_build::builder_vm::GuestSidecar::for_oci_run("hybrid", true, false);
        baked_metadata.agent_binary = "real".into();
        baked_metadata.protocol_version = 2;
        let mut payloads = vec![
            (
                mvm_core::guest_sidecar::SIDECAR_FILENAME,
                ArtifactRole::Other,
                serde_json::to_vec(&baked_metadata).unwrap(),
            ),
            ("image-set.json", ArtifactRole::Other, set_bytes.clone()),
            ("overlay.tar.gz", ArtifactRole::Other, overlay),
            ("initramfs.tar.gz", ArtifactRole::Other, initramfs),
            (
                "rootfs",
                if wrong_role {
                    ArtifactRole::Other
                } else {
                    ArtifactRole::Rootfs
                },
                b"signed root".to_vec(),
            ),
            ("kernel", ArtifactRole::Kernel, b"signed kernel".to_vec()),
            ("initrd", ArtifactRole::Initrd, initrd),
        ];
        let verity = workload_verity.then(|| {
            payloads.push((
                "workload.verity",
                ArtifactRole::VerityHashSidecar,
                b"signed workload sidecar".to_vec(),
            ));
            mvm_core::plan::bundle::VerityInfo {
                roothash: "d".repeat(64),
                sidecar_artifact: "workload.verity".into(),
            }
        });
        let key = SigningKey::from_bytes(&[83; 32]);
        let key_id = key_id_from_pubkey(&key.verifying_key());
        let mut manifest = BundleManifest {
            schema_version: schema,
            publisher: "portable-fixture".into(),
            key_id: key_id.clone(),
            arch: arch.to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            labels: Default::default(),
            artifacts: payloads
                .iter()
                .map(|(name, role, bytes)| BundleArtifact {
                    name: (*name).into(),
                    role: role.clone(),
                    path: format!("artifacts/{name}"),
                    sha256: sha256_hex(bytes),
                    size_bytes: bytes.len() as u64,
                })
                .collect(),
            members: vec![BundleMember::EmbeddedBootAssets {
                manifest_artifact: "image-set.json".into(),
            }],
            verity: verity.clone(),
            resources: None,
        };
        if schema == 5 {
            manifest.members.push(BundleMember::Environment(
                serde_json::from_value(serde_json::json!({
                    "descriptor_version": 1,
                    "target": format!("{arch}-linux"),
                    "entrypoint": { "argv": ["/usr/bin/agent"] },
                    "capabilities": [],
                }))
                .unwrap(),
            ));
        }
        let bytes = write_bundle(
            &manifest,
            &key,
            payloads
                .iter()
                .map(|(name, _, bytes)| (format!("artifacts/{name}"), bytes.clone()))
                .collect(),
        )
        .unwrap();
        let archive = home.join("bundle.mvmpkg");
        std::fs::write(&archive, bytes).unwrap();
        for (name, _, bytes) in &payloads {
            std::fs::write(home.join(name), bytes).unwrap();
        }
        let trust = FsTrustStore::default_path().unwrap();
        std::fs::create_dir_all(trust.root()).unwrap();
        std::fs::write(
            trust.root().join(format!("{}.pub", key_id.0)),
            key.verifying_key().as_bytes(),
        )
        .unwrap();
        let verified = verify_bundle_file(&archive, &trust)?;
        let overlay_stage = home.join("overlay");
        let initrd_stage = home.join("ramdisk");
        std::fs::create_dir_all(&overlay_stage).unwrap();
        std::fs::create_dir_all(&initrd_stage).unwrap();
        let overlay = mvm_build::runtime_overlay::parse_authenticated_legacy_overlay(
            &home.join("overlay.tar.gz"),
            &overlay_stage,
            arch,
        )
        .unwrap();
        let ramdisk = mvm_build::initramfs::parse_authenticated_legacy_initramfs(
            &home.join("initramfs.tar.gz"),
            &initrd_stage,
        )
        .unwrap();
        Ok(VmStartConfig {
            name: "portable-fixture".into(),
            rootfs_path: home.join("rootfs").display().to_string(),
            verity_path: verity
                .as_ref()
                .map(|info| home.join(&info.sidecar_artifact).display().to_string()),
            roothash: verity.map(|info| info.roothash),
            kernel_path: Some(home.join("kernel").display().to_string()),
            initrd_path: Some(ramdisk.image_path.display().to_string()),
            runtime_overlay_path: Some(overlay.overlay_ext4.display().to_string()),
            runtime_overlay_verity_path: Some(overlay.sidecar.display().to_string()),
            runtime_overlay_roothash: Some(overlay.roothash),
            runtime_overlay_version: Some(overlay.version),
            legacy_portable_runtime: Some(LegacyPortableRuntimeProof {
                archive,
                pin: verified.plan_artifact(),
                manifest_sha256: sha256_hex(&set_bytes),
                arch,
            }),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::fixture;
    use super::*;
    use crate::runtime_evidence::{
        RuntimeLifecycleLease, verify_runtime_binding, verify_runtime_for_launch,
    };
    use mvm_core::arch::GuestArch;
    use mvm_core::plan::bundle::sha256_hex;
    use mvm_core::protocol::runtime_release::{
        CliRuntimeLaunchBinding, RuntimeBindingProvenance, RuntimeLaunchBinding,
    };
    use mvm_core::vm_backend::LegacyPortableRuntimeProof;

    fn binding(config: &VmStartConfig) -> RuntimeLaunchBinding {
        RuntimeLaunchBinding::LegacyPortable {
            proof: config.legacy_portable_runtime.clone().unwrap(),
            rootfs_path: config.rootfs_path.clone().into(),
            kernel_path: config.kernel_path.clone().unwrap().into(),
            overlay_path: config.runtime_overlay_path.clone().unwrap().into(),
            overlay_verity_path: config.runtime_overlay_verity_path.clone().unwrap().into(),
            initramfs_path: config.initrd_path.clone().unwrap().into(),
            overlay_roothash: config.runtime_overlay_roothash.clone().unwrap(),
            version: config.runtime_overlay_version.clone().unwrap(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn quoted_portable_verification_needs_no_filesystem_scratch() {
        use mvm_core::host_lifetime::{
            HostLaunchBinding, HostLeaseExpectation, HostLifetimeInputs, PreparedHostLifetime,
        };
        use std::{
            fs::{File, OpenOptions},
            num::NonZeroU64,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };

        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut config = fixture(home.path(), Some(2), false, 4).unwrap();
        let expected = verify_archive(&config, 2).unwrap();
        let proof = config.legacy_portable_runtime.as_ref().unwrap();
        let length = NonZeroU64::new(std::fs::metadata(&proof.archive).unwrap().len()).unwrap();
        let private = home.path().join("owner");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = private.join("state");
        std::fs::write(&state, b"a").unwrap();
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o600)).unwrap();
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(private.join("holder"))
            .unwrap();
        let prepared = PreparedHostLifetime::bind(
            HostLifetimeInputs {
                directory: File::open(&private).unwrap(),
                holder,
                expected: HostLeaseExpectation {
                    state_name: "state".into(),
                    state_bytes: 1,
                    state_sha256: hex::decode(sha256_hex(b"a")).unwrap().try_into().unwrap(),
                    absent_names: ["next".into(), "intent".into()],
                },
                binding: HostLaunchBinding {
                    installation: [1; 32],
                    profile: [2; 32],
                    generation: 1,
                    grant_serial: 1,
                    vm_name: config.name.clone(),
                    backend: mvm_core::vm_backend::BackendKind::Hvf,
                    cpus: 1,
                    memory_mib: 128,
                },
            },
            (),
        )
        .unwrap()
        .with_portable_archive(proof.pin.clone(), length)
        .unwrap();
        config.host_lifetime = Some(prepared.into_anchor());

        let unavailable = home.path().join("no-scratch");
        std::fs::write(&unavailable, b"regular file, not a scratch directory").unwrap();
        env.set("TMPDIR", &unavailable);
        let actual = verify_archive(&config, 2).expect("quoted verification must not use TMPDIR");
        assert_eq!(actual.archive, expected.archive);
        assert_eq!(actual.rootfs, expected.rootfs);
        assert_eq!(actual.kernel, expected.kernel);
        assert_eq!(actual.overlay, expected.overlay);
        assert_eq!(actual.verity, expected.verity);
        assert_eq!(actual.initrd, expected.initrd);
        assert_eq!(actual.overlay_roothash, expected.overlay_roothash);
        assert_eq!(actual.overlay_version, expected.overlay_version);
        assert_eq!(actual.initrd_version, expected.initrd_version);

        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        let bound = lease
            .bind(&config)
            .expect("quoted runtime must bind without scratch");
        let bound_archive = &bound.legacy_portable_runtime.as_ref().unwrap().archive;
        let generation = bound_archive.parent().unwrap();
        assert_eq!(std::fs::read(bound_archive).unwrap(), expected.archive);
        assert_eq!(std::fs::read(&bound.rootfs_path).unwrap(), expected.rootfs);
        assert_eq!(
            std::fs::read(bound.initrd_path.as_ref().unwrap()).unwrap(),
            expected.initrd
        );
        assert!(lease.retire_portable_generation().unwrap());
        assert!(!generation.exists());
        assert!(lease.retire_portable_generation().unwrap());
    }

    #[test]
    fn signed_cache_projection_uses_only_preprovisioned_payload_files() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut config = fixture(home.path(), Some(2), false, 4).unwrap();
        let verified = verify_archive(&config, 2).unwrap();
        let cache = home.path().join("preprovisioned");
        verified.project_cache(&mut config, &cache).unwrap();
        let selected = [
            (
                config.runtime_overlay_path.as_deref().unwrap(),
                &verified.overlay,
            ),
            (
                config.runtime_overlay_verity_path.as_deref().unwrap(),
                &verified.verity,
            ),
            (config.initrd_path.as_deref().unwrap(), &verified.initrd),
        ];
        assert!(verified.verify_boot_selection(&config, true).is_err());
        assert!(!cache.exists());
        for (path, bytes) in selected {
            let path = Path::new(path);
            assert!(path.starts_with(&cache));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        verified.verify_boot_selection(&config, true).unwrap();
        for (path, _) in selected {
            let path = Path::new(path);
            let count = if path == Path::new(config.initrd_path.as_deref().unwrap()) {
                1
            } else {
                2
            };
            assert_eq!(
                std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
                count
            );
        }
        std::fs::write(config.initrd_path.as_ref().unwrap(), b"bad").unwrap();
        assert!(verified.verify_boot_selection(&config, true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn selected_asset_comparison_binds_content_length_and_file_kind() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let expected = vec![17; 16_385];
        std::fs::write(&input, &expected).unwrap();
        assert!(selected_file_matches(&input, &expected, true).unwrap());
        let mut changed = expected.clone();
        *changed.last_mut().unwrap() = 0;
        assert!(!selected_file_matches(&input, &changed, true).unwrap());
        changed.push(0);
        assert!(!selected_file_matches(&input, &changed, true).unwrap());
        assert!(!selected_file_matches(&input, &expected[..8192], true).unwrap());

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&input, &link).unwrap();
        assert!(selected_file_matches(&link, &expected, true).is_err());
        assert!(selected_file_matches(&link, &expected, false).unwrap());
    }

    #[test]
    fn quoted_portable_attachment_checks_length_and_the_same_signed_bytes() {
        use mvm_core::plan::bundle::verify_exact_bundle_file;
        use std::num::NonZeroU64;

        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), Some(2), false, 4).unwrap();
        let proof = config.legacy_portable_runtime.unwrap();
        let trust = FsTrustStore::default_path().unwrap();
        let mut archive = std::fs::read(&proof.archive).unwrap();
        let length = NonZeroU64::new(archive.len() as u64).unwrap();
        let verified =
            verify_exact_bundle_file(&proof.archive, &trust, &proof.pin, length).unwrap();
        assert_eq!(verified.plan_artifact(), proof.pin);
        let short_quote = NonZeroU64::new(length.get() - 1).unwrap();
        let error = verify_exact_bundle_file(&proof.archive, &trust, &proof.pin, short_quote)
            .err()
            .expect("wrong archive length refused");
        assert!(
            error.to_string().contains("quoted archive length"),
            "{error}"
        );
        *archive.last_mut().unwrap() ^= 1;
        std::fs::write(&proof.archive, archive).unwrap();
        let error = verify_exact_bundle_file(&proof.archive, &trust, &proof.pin, length)
            .err()
            .expect("same-length substitution refused");
        assert!(
            error.to_string().contains("signed archive digest"),
            "{error}"
        );
    }

    #[test]
    fn authenticated_legacy_class_accepts_environment5_but_refuses_envelope6_and_tampering() {
        for schema in [4, 5, 6] {
            let home = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(home.path());
            let prepared = fixture(home.path(), Some(2), false, schema);
            if schema == 6 {
                match prepared {
                    Err(mvm_core::plan::BundleVerifyError::UnsupportedSchema {
                        found: 6, ..
                    }) => {}
                    Ok(config) => assert!(verify_runtime_for_launch(&config, 2).is_err()),
                    Err(error) => panic!("unexpected future-envelope refusal: {error}"),
                }
                continue;
            }
            let config = prepared.unwrap();
            assert!(verify_runtime_for_launch(&config, 2).is_ok());
            let mut mixed = config.clone();
            mixed.source_runtime_archive_sha256 = Some("a".repeat(64));
            assert!(verify_runtime_for_launch(&mixed, 2).is_err());
            let archive = &config.legacy_portable_runtime.as_ref().unwrap().archive;
            let mut bytes = std::fs::read(archive).unwrap();
            let needle = format!("\"schema_version\":{schema}");
            let offset = bytes
                .windows(needle.len())
                .position(|b| b == needle.as_bytes())
                .unwrap();
            bytes[offset + needle.len() - 1] = b'3';
            std::fs::write(archive, bytes).unwrap();
            assert!(verify_runtime_for_launch(&config, 2).is_err());
        }
    }

    #[test]
    fn portable_signed_fixture_retains_original_proof_and_refuses_pin_manifest_role_bytes() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), Some(2), false, 4).unwrap();
        assert!(matches!(
            verify_runtime_for_launch(&config, 2).unwrap(),
            Some(crate::runtime_evidence::VerifiedLaunchRuntime::LegacyPortable(_))
        ));
        assert!(VmStartConfig::default().legacy_portable_runtime.is_none());
        let proof = config.legacy_portable_runtime.clone().unwrap();
        assert_eq!(
            serde_json::from_slice::<LegacyPortableRuntimeProof>(
                &serde_json::to_vec(&proof).unwrap()
            )
            .unwrap(),
            proof
        );
        for field in [
            "pin",
            "manifest",
            "arch",
            "overlay",
            "verity",
            "initrd",
            "root",
            "kernel",
            "version",
            "conflict",
            "undeclared_workload_verity",
        ] {
            let mut changed = config.clone();
            match field {
                "pin" => {
                    changed
                        .legacy_portable_runtime
                        .as_mut()
                        .unwrap()
                        .pin
                        .bundle_sha256 = "0".repeat(64)
                }
                "manifest" => {
                    changed
                        .legacy_portable_runtime
                        .as_mut()
                        .unwrap()
                        .manifest_sha256 = "0".repeat(64)
                }
                "arch" => {
                    changed.legacy_portable_runtime.as_mut().unwrap().arch = match GuestArch::host()
                    {
                        GuestArch::Aarch64 => GuestArch::X86_64,
                        GuestArch::X86_64 => GuestArch::Aarch64,
                    }
                }
                "overlay" => {
                    changed.runtime_overlay_path = config.runtime_overlay_verity_path.clone()
                }
                "verity" => {
                    changed.runtime_overlay_verity_path = config.runtime_overlay_path.clone()
                }
                "initrd" => changed.initrd_path = config.kernel_path.clone(),
                "root" => changed.rootfs_path = config.kernel_path.clone().unwrap(),
                "kernel" => changed.kernel_path = Some(config.rootfs_path.clone()),
                "version" => changed.runtime_overlay_version = Some("different".into()),
                "conflict" => changed.source_runtime_archive_sha256 = Some("a".repeat(64)),
                "undeclared_workload_verity" => {
                    changed.verity_path = config.runtime_overlay_verity_path.clone();
                    changed.roothash = config.runtime_overlay_roothash.clone();
                }
                _ => unreachable!(),
            }
            assert!(verify_runtime_for_launch(&changed, 2).is_err(), "{field}");
        }
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        let bound = lease.bind(&config).unwrap();
        let record = binding(&bound);
        verify_runtime_binding(&record).unwrap();
        assert_eq!(
            serde_json::from_slice::<RuntimeLaunchBinding>(&serde_json::to_vec(&record).unwrap())
                .unwrap(),
            record
        );
        // Original installation may disappear; only the retained original proof
        // and payloads are authority for subsequent launches.
        std::fs::remove_file(&proof.archive).unwrap();
        verify_runtime_binding(&record).unwrap();
        let mut reapplied = config.clone();
        reapplied.unsigned_runtime_development = true;
        reapplied.source_runtime_archive_sha256 = Some("b".repeat(64));
        record.apply_to_config(&mut reapplied);
        assert!(!reapplied.unsigned_runtime_development);
        assert!(reapplied.source_runtime_archive_sha256.is_none());
        assert!(reapplied.legacy_bundle_runtime.is_none());
        assert!(reapplied.bundle_boot_assets.is_none());
        assert!(mvm_vmm::host::boot_config::booted_with_universal_initramfs(
            &reapplied
        ));
        let before = format!("{reapplied:?}");
        crate::universal_initramfs::attach_universal_initramfs_if_cached(&mut reapplied, "qemu")
            .unwrap();
        assert_eq!(format!("{reapplied:?}"), before);
        let mut invalid = reapplied.clone();
        invalid
            .legacy_portable_runtime
            .as_mut()
            .unwrap()
            .manifest_sha256 = "0".repeat(64);
        let before = format!("{invalid:?}");
        assert!(
            crate::universal_initramfs::attach_universal_initramfs_if_cached(&mut invalid, "qemu")
                .is_err()
        );
        assert_eq!(format!("{invalid:?}"), before);
        let cli = RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
            provenance: RuntimeBindingProvenance::Source {
                version: "new".into(),
                arch: GuestArch::host(),
                archive_sha256: "c".repeat(64),
            },
            overlay_path: "/new/overlay".into(),
            overlay_verity_path: "/new/verity".into(),
            initramfs_path: "/new/initrd".into(),
            overlay_roothash: "d".repeat(64),
        });
        cli.apply_to_config(&mut reapplied);
        assert!(reapplied.legacy_portable_runtime.is_none());
        assert_eq!(reapplied.runtime_overlay_version.as_deref(), Some("new"));
        let archive = &bound.legacy_portable_runtime.as_ref().unwrap().archive;
        mvm_core::private_fs::set_mode(archive, 0o600).unwrap();
        std::fs::write(archive, b"tampered").unwrap();
        mvm_core::private_fs::set_mode(archive, 0o400).unwrap();
        assert!(verify_runtime_binding(&record).is_err());
    }

    #[test]
    fn portable_launch_uses_the_retained_signed_workload_verity() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixtures::fixture_with_verity(home.path(), Some(2), false, 4, true).unwrap();
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        let bound = lease.bind(&config).unwrap();
        let sidecar = Path::new(bound.verity_path.as_deref().unwrap());
        let generation = bound
            .legacy_portable_runtime
            .as_ref()
            .unwrap()
            .archive
            .parent()
            .unwrap();
        assert_eq!(
            sidecar.parent(),
            Some(generation),
            "launch still uses ambient sidecar"
        );
        assert_eq!(std::fs::read(sidecar).unwrap(), b"signed workload sidecar");
        assert_eq!(bound.roothash, config.roothash);
        let args =
            mvm_vmm::host::cmdline::runner_cmdline(&bound, home.path(), |_| "console=hvc0".into());
        let spec = mvm_vmm::host::spec_map::workload_device_spec(
            &bound,
            &args,
            &home.path().join("console"),
        );
        assert!(mvm_vmm::host::cmdline::verity_enabled(&bound));
        assert_eq!(spec.blocks[1].source, sidecar);
        assert!(spec.blocks[1].read_only);
        assert_eq!(
            mvm_core::private_fs::mode_bits(sidecar, &std::fs::metadata(sidecar).unwrap()).unwrap(),
            0o400
        );

        let original = config.verity_path.as_deref().unwrap();
        std::fs::write(original, b"replacement").unwrap();
        assert!(verify_runtime_for_launch(&config, 2).is_err());
        assert!(verify_runtime_for_launch(&bound, 2).is_ok());

        for (path, hash) in [
            (None, None),
            (bound.verity_path.clone(), Some("e".repeat(64))),
            (Some(original.to_owned()), bound.roothash.clone()),
        ] {
            let mut changed = bound.clone();
            changed.verity_path = path;
            changed.roothash = hash;
            assert!(lease.bind(&changed).is_err());
        }
    }

    #[test]
    fn portable_original_protocol_and_signed_roles_are_required() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        for (protocol, wrong_role) in [
            (None, false),
            (Some(1), false),
            (Some(999), false),
            (Some(2), true),
        ] {
            let source = tempfile::tempdir().unwrap();
            let config = fixture(source.path(), protocol, wrong_role, 4).unwrap();
            assert!(
                verify_runtime_for_launch(&config, 2).is_err(),
                "{protocol:?} {wrong_role}"
            );
            let proof = config.legacy_portable_runtime.as_ref().unwrap();
            let downgraded = VmStartConfig {
                rootfs_path: config.rootfs_path.clone(),
                initrd_path: config.initrd_path.clone(),
                legacy_bundle_runtime: Some(mvm_core::vm_backend::LegacyBundleRuntimeProof {
                    archive: proof.archive.clone(),
                    pin: proof.pin.clone(),
                }),
                ..Default::default()
            };
            assert!(
                verify_runtime_for_launch(&downgraded, 2)
                    .unwrap_err()
                    .to_string()
                    .contains("portable bundle")
            );
        }
    }

    #[test]
    fn portable_checkpoint_lineage_fork_slots_and_hmac_authenticate_every_field() {
        use mvm_core::checkpoint::{
            CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob, HVF_FRAME_BLOB,
        };
        use mvm_core::crypto::snapshot_hmac::{self, SnapshotFiles};
        use mvm_vmm::runtime_artifacts::{FirecrackerDrive, RuntimeArtifact, RuntimeArtifacts};
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), Some(2), false, 4).unwrap();
        let bound = RuntimeLifecycleLease::acquire(&config.name)
            .unwrap()
            .bind(&config)
            .unwrap();
        mvm_vmm::host::runtime_meta::record_from_start_config(
            &bound.name,
            mvm_core::vm_backend::StartMode::Detached,
            &bound,
        )
        .unwrap();
        let binding = mvm_vmm::host::runtime_meta::read(&bound.name)
            .unwrap()
            .unwrap()
            .runtime_launch_binding
            .unwrap();
        assert!(matches!(
            binding,
            RuntimeLaunchBinding::LegacyPortable { .. }
        ));
        let observe = |path: &str| RuntimeArtifact {
            path: path.into(),
            sha256: mvm_core::crypto::image_verify::sha256_file(Path::new(path)).unwrap(),
        };
        let actual = RuntimeArtifacts {
            kernel: Some(observe(bound.kernel_path.as_deref().unwrap())),
            initramfs: Some(observe(bound.initrd_path.as_deref().unwrap())),
            disks: vec![
                observe(&bound.rootfs_path),
                observe(bound.runtime_overlay_path.as_deref().unwrap()),
                observe(bound.runtime_overlay_verity_path.as_deref().unwrap()),
            ],
            kernel_cmdline: "console=hvc0".into(),
            firecracker_drives: None,
        };
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &actual).unwrap();
        for kernel in [
            None,
            Some(RuntimeArtifact {
                path: "/unrelated/kernel".into(),
                sha256: "0".repeat(64),
            }),
            Some(RuntimeArtifact {
                path: "/unannounced/remap".into(),
                sha256: actual.kernel.as_ref().unwrap().sha256.clone(),
            }),
        ] {
            let mut wrong = actual.clone();
            wrong.kernel = kernel;
            assert!(
                crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &wrong).is_err()
            );
        }
        let mut fc = actual.clone();
        fc.firecracker_drives = Some(
            actual
                .disks
                .iter()
                .enumerate()
                .map(|(index, disk)| FirecrackerDrive {
                    drive_id: format!("blk{index}"),
                    path: disk.path.clone(),
                    is_root_device: index == 0,
                    is_read_only: true,
                })
                .collect(),
        );
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &fc).unwrap();
        fc.firecracker_drives.as_mut().unwrap()[1].is_read_only = false;
        assert!(crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &fc).is_err());
        let mut swapped = actual.clone();
        swapped.disks.swap(1, 2);
        assert!(
            crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &swapped).is_err()
        );
        let mut duplicate = actual.clone();
        duplicate.disks.push(actual.disks[1].clone());
        assert!(
            crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &duplicate).is_err()
        );
        let child = home.path().join("child-root");
        std::fs::copy(&bound.rootfs_path, &child).unwrap();
        let mut remapped = actual.clone();
        remapped.disks[0].path = child.clone();
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &remapped).unwrap();
        std::fs::remove_file(&bound.rootfs_path).unwrap();
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &remapped).unwrap();
        mvm_core::private_fs::set_mode(&child, 0o600).unwrap();
        std::fs::write(&child, b"changed child root").unwrap();
        assert!(
            crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &remapped).is_err()
        );
        std::fs::copy(&config.rootfs_path, &bound.rootfs_path).unwrap();

        let store = crate::checkpoint::CheckpointStore::at(home.path().join("checkpoints"));
        let id = CheckpointId::new("portable");
        let content = store.content_dir(&id);
        std::fs::create_dir_all(&content).unwrap();
        let bytes = serde_json::to_vec(&actual).unwrap();
        std::fs::write(content.join("runtime-artifacts.json"), &bytes).unwrap();
        let meta = CheckpointMeta::builder(id, CheckpointClass::VmFull, &bound.name)
            .runtime_launch_binding(Some(binding.clone()))
            .content(vec![
                ContentBlob {
                    name: "runtime-artifacts.json".into(),
                    sha256: sha256_hex(&bytes),
                },
                ContentBlob {
                    name: HVF_FRAME_BLOB.into(),
                    sha256: "ab".repeat(32),
                },
            ])
            .build();
        crate::checkpoint::verify_checkpoint_runtime(&store, &meta).unwrap();
        let files = SnapshotFiles {
            vmstate: home.path().join("vmstate"),
            mem: home.path().join("mem"),
        };
        std::fs::write(&files.vmstate, b"state").unwrap();
        std::fs::write(&files.mem, b"memory").unwrap();
        let key = [19; 32];
        let sidecar = snapshot_hmac::seal(
            home.path(),
            &snapshot_hmac::SnapshotIntegrityParams::new(&files, 1, "1", &key)
                .with_runtime_binding(Some(&binding)),
        )
        .unwrap();
        snapshot_hmac::verify(home.path(), &files, 1, "1", &key, false).unwrap();
        let encoded = serde_json::to_value(&binding).unwrap();
        for pointer in [
            "/proof/archive",
            "/proof/pin/bundle_sha256",
            "/proof/pin/manifest_sig_base64",
            "/proof/pin/key_id",
            "/proof/manifest_sha256",
            "/rootfs_path",
            "/kernel_path",
            "/overlay_path",
            "/overlay_verity_path",
            "/initramfs_path",
            "/overlay_roothash",
            "/version",
            "/proof/arch",
        ] {
            let mut changed = encoded.clone();
            *changed.pointer_mut(pointer).unwrap() = if pointer == "/proof/arch" {
                match GuestArch::host() {
                    GuestArch::Aarch64 => "x86_64",
                    GuestArch::X86_64 => "aarch64",
                }
                .into()
            } else {
                "tampered".into()
            };
            let changed: RuntimeLaunchBinding = serde_json::from_value(changed).unwrap();
            let mut changed_meta = meta.clone();
            changed_meta.runtime_launch_binding = Some(changed.clone());
            assert_ne!(
                meta.meta_digest,
                changed_meta.compute_meta_digest(),
                "{pointer}"
            );
            let mut changed_sidecar = sidecar.clone();
            changed_sidecar.runtime_launch_binding = Some(changed);
            std::fs::write(
                home.path().join(snapshot_hmac::SIDECAR_FILENAME),
                serde_json::to_vec(&changed_sidecar).unwrap(),
            )
            .unwrap();
            assert!(
                snapshot_hmac::verify(home.path(), &files, 1, "1", &key, false).is_err(),
                "{pointer}"
            );
        }
        std::fs::write(
            content.join("runtime-artifacts.json"),
            b"tampered observation",
        )
        .unwrap();
        assert!(crate::checkpoint::verify_checkpoint_runtime(&store, &meta).is_err());
    }
}
