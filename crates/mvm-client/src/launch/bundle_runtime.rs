//! SDK exports for offline runtime selection from a signed, installed bundle.
pub use mvm_runtime::bundle_runtime::{attach_if_installed_bundle, installed_archive_for_rootfs};

#[cfg(test)]
#[path = "../../../mvm-core/src/image_set/fixtures/published_root.rs"]
mod published_root;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    use anyhow::Result;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use mvm_build::boot_asset_fixture;
    use mvm_build::published_image_set::fixture::ImageSetFixture;
    use mvm_bundler::{
        BootAssetsInputs, BundleExportInputs, BundleSigner, export_bundle_with_signer,
    };
    use mvm_core::arch::GuestArch;
    use mvm_core::image_set::{ImageSetVersion, MemberTarget};
    use mvm_core::packs::Sha256Hex;
    use mvm_core::plan::bundle::{ArtifactRole, BundleRegistry, FsTrustStore, verify_bundle_file};
    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::{BundleBootAssetsPin, VmStartConfig};

    struct Publisher(SigningKey);

    impl BundleSigner for Publisher {
        fn publisher_id(&self) -> String {
            "offline-runtime-test".into()
        }
        fn verifying_key(&self) -> VerifyingKey {
            self.0.verifying_key()
        }
        fn sign(&self, bytes: &[u8]) -> Result<[u8; 64]> {
            Ok(self.0.sign(bytes).to_bytes())
        }
    }

    fn assert_retained_portable_reentry(selected: &VmStartConfig) {
        use mvm_core::protocol::runtime_release::RuntimeLaunchBinding;

        let retained = tempfile::tempdir().unwrap();
        mvm_core::private_fs::set_mode(retained.path(), 0o700).unwrap();
        let copy = |source: &Path, name: &str| {
            let path = retained.path().join(name);
            std::fs::copy(source, &path).unwrap();
            mvm_core::private_fs::set_mode(&path, 0o400).unwrap();
            path
        };
        let mut proof = selected.legacy_portable_runtime.clone().unwrap();
        proof.archive = copy(&proof.archive, "bundle.mvmpkg");
        let binding = RuntimeLaunchBinding::LegacyPortable {
            proof,
            rootfs_path: copy(Path::new(&selected.rootfs_path), "rootfs"),
            kernel_path: copy(
                Path::new(selected.kernel_path.as_deref().unwrap()),
                "kernel",
            ),
            overlay_path: copy(
                Path::new(selected.runtime_overlay_path.as_deref().unwrap()),
                "overlay.ext4",
            ),
            overlay_verity_path: copy(
                Path::new(selected.runtime_overlay_verity_path.as_deref().unwrap()),
                "overlay.verity",
            ),
            initramfs_path: copy(
                Path::new(selected.initrd_path.as_deref().unwrap()),
                "initramfs.cpio.gz",
            ),
            overlay_roothash: selected.runtime_overlay_roothash.clone().unwrap(),
            version: selected.runtime_overlay_version.clone().unwrap(),
        };
        let mut reapplied = selected.clone();
        binding.apply_to_config(&mut reapplied);
        assert!(reapplied.bundle_boot_assets.is_none());
        assert!(
            installed_archive_for_rootfs(Path::new(&reapplied.rootfs_path))
                .unwrap()
                .is_none()
        );
        // There is no ambient cache entry for this version. Reentry must use
        // the original portable proof and never resolve the caller's CLI hint.
        let before = format!("{reapplied:?}");
        super::super::runtime_source::attach_runtime_overlay_if_cached_version(
            &mut reapplied,
            "qemu",
            Some("absent-ambient-version"),
            None,
        )
        .unwrap();
        assert_eq!(format!("{reapplied:?}"), before);

        reapplied
            .legacy_portable_runtime
            .as_mut()
            .unwrap()
            .manifest_sha256 = "0".repeat(64);
        let before = format!("{reapplied:?}");
        assert!(
            super::super::runtime_source::attach_runtime_overlay_if_cached_version(
                &mut reapplied,
                "qemu",
                Some("absent-ambient-version"),
                None,
            )
            .is_err()
        );
        assert_eq!(format!("{reapplied:?}"), before);
    }

    #[test]
    fn signed_boot_assets_attach_offline_and_refuse_missing_or_corrupt_members() {
        let home = tempfile::tempdir().unwrap();
        let producer = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.set("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:1/unreachable");
        let arch = GuestArch::host();
        let version = "99.2.3";
        let overlay_bytes = boot_asset_fixture::runtime_overlay_archive_bytes(
            arch,
            &boot_asset_fixture::valid_overlay_ext4_bytes(),
            b"synthetic-verity-sidecar",
            format!("{}\n", "a".repeat(64)).as_bytes(),
            version.as_bytes(),
        );
        let (initrd_bytes, hash, size) = boot_asset_fixture::initramfs_fixture(b"synthetic cpio");
        let initramfs_bytes = boot_asset_fixture::initramfs_archive_bytes(
            &initrd_bytes,
            hash.as_bytes(),
            size.as_bytes(),
            version.as_bytes(),
        );
        let mut manifest = ImageSetFixture::complete()
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_OVERLAY_ROLE,
                MemberTarget::Arch(arch),
                "overlay.tar.gz",
                overlay_bytes.clone(),
            )
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_INITRAMFS_ROLE,
                MemberTarget::Arch(arch),
                "initramfs.tar.gz",
                initramfs_bytes.clone(),
            )
            .into_manifest();
        // Deliberately not the running CLI's locked root or release.
        manifest.compatibility.guest_agent_protocol =
            Some(mvm_core::image_set::ProtocolRange::new(2, 2).unwrap());
        manifest.set_version = ImageSetVersion::new(version).unwrap();
        if let mvm_core::image_set::ImageSetProducer::Release(release) = &mut manifest.producer {
            release.release_tag =
                mvm_core::image_set::ReleaseTag::new(format!("v{version}")).unwrap();
        }
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let root = Sha256Hex::from_bytes(&manifest_bytes);
        assert_ne!(
            root,
            mvm_core::image_set::image_train_lock()
                .image_set
                .manifest_sha256
        );
        let kernel = producer.path().join("kernel");
        let rootfs = producer.path().join("rootfs.ext4");
        let initrd = producer.path().join("initrd");
        let overlay = producer.path().join("overlay.tar.gz");
        let initramfs = producer.path().join("initramfs.tar.gz");
        let archive = producer.path().join("bundle.mvmpkg");
        let legacy_archive = producer.path().join("legacy.mvmpkg");
        let unsealed_archive = producer.path().join("unsealed.mvmpkg");
        std::fs::write(&kernel, b"synthetic kernel").unwrap();
        std::fs::write(&rootfs, b"synthetic rootfs").unwrap();
        std::fs::write(&initrd, &initrd_bytes).unwrap();
        std::fs::write(&overlay, overlay_bytes).unwrap();
        std::fs::write(&initramfs, initramfs_bytes).unwrap();
        std::fs::write(producer.path().join("mvm-meta.json"), b"{}").unwrap();
        let publisher = Publisher(SigningKey::from_bytes(&rand::random()));
        let arch_label = arch.to_string();
        let workload_hash = "b".repeat(64);
        let mut inputs = BundleExportInputs::new(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            &arch_label,
            &archive,
        )
        .initrd(initrd.to_str().unwrap())
        .verity(b"workload merkle tree", &workload_hash);
        inputs.boot_assets = Some(BootAssetsInputs {
            manifest_bytes: &manifest_bytes,
            manifest_sha256: &root,
            runtime_overlay: &overlay,
            initramfs: &initramfs,
        });
        export_bundle_with_signer(&inputs, &publisher).unwrap();
        let original_archive_bytes = std::fs::read(&archive).unwrap();
        let trust = FsTrustStore::default_path().unwrap();
        std::fs::create_dir_all(trust.root()).unwrap();
        std::fs::write(
            trust.root().join(format!("{}.pub", publisher.key_id().0)),
            publisher.verifying_key().as_bytes(),
        )
        .unwrap();
        let registry = BundleRegistry::default_path().unwrap();
        let installed = registry.install_file(&archive, &trust, false).unwrap();
        assert_eq!(installed.manifest.schema_version, 4);
        let verified = verify_bundle_file(&archive, &trust).unwrap();
        let boot = verified.boot_assets.unwrap();
        let config = VmStartConfig {
            rootfs_path: installed
                .root
                .join(
                    &installed
                        .manifest
                        .find_by_role(&ArtifactRole::Rootfs)
                        .unwrap()
                        .path,
                )
                .display()
                .to_string(),
            kernel_path: Some(
                installed
                    .root
                    .join(
                        &installed
                            .manifest
                            .find_by_role(&ArtifactRole::Kernel)
                            .unwrap()
                            .path,
                    )
                    .display()
                    .to_string(),
            ),
            ..Default::default()
        };
        assert!(!Path::new(&mvm_core::config::mvm_cache_dir()).exists());
        let mut attached = config.clone();
        assert!(attach_if_installed_bundle(&mut attached, "qemu").unwrap());
        assert!(attached.legacy_portable_runtime.is_some());
        let pin = &attached.legacy_portable_runtime.as_ref().unwrap().pin;
        let mut selected = config.clone();
        selected.kernel_path = None;
        mvm_runtime::bundle_runtime::attach_pinned_legacy_runtime(&mut selected, "qemu", pin)
            .expect("installed signed launch resolves its original bundle kernel and runtime");
        assert_eq!(selected.kernel_path, attached.kernel_path);
        assert_eq!(
            selected.legacy_portable_runtime,
            attached.legacy_portable_runtime
        );
        let mut wrong_pin = pin.clone();
        wrong_pin.bundle_sha256 = "0".repeat(64);
        let mut refused = config.clone();
        assert!(
            mvm_runtime::bundle_runtime::attach_pinned_legacy_runtime(
                &mut refused,
                "qemu",
                &wrong_pin
            )
            .is_err()
        );
        assert!(refused.legacy_portable_runtime.is_none());
        assert_retained_portable_reentry(&attached);
        let mut dispatched = config.clone();
        super::super::runtime_source::attach_runtime_overlay_if_cached_version(
            &mut dispatched,
            "qemu",
            Some("not-the-cli-version"),
            None,
        )
        .unwrap();
        assert_eq!(
            dispatched.legacy_portable_runtime,
            attached.legacy_portable_runtime
        );
        for mutation in 0..4 {
            let mut refused = attached.clone();
            match mutation {
                0 => {
                    refused
                        .legacy_portable_runtime
                        .as_mut()
                        .unwrap()
                        .manifest_sha256 = "0".repeat(64)
                }
                1 => {
                    refused
                        .legacy_portable_runtime
                        .as_mut()
                        .unwrap()
                        .pin
                        .bundle_sha256 = "0".repeat(64)
                }
                2 => refused.source_runtime_archive_sha256 = Some("0".repeat(64)),
                3 => refused.initrd_path = refused.kernel_path.clone(),
                _ => unreachable!(),
            }
            let original = format!("{refused:?}");
            assert!(
                super::super::runtime_source::attach_runtime_overlay_if_cached_version(
                    &mut refused,
                    "qemu",
                    None,
                    None,
                )
                .is_err()
            );
            assert_eq!(
                format!("{refused:?}"),
                original,
                "config mutation {mutation}"
            );
        }
        assert_eq!(attached.roothash.as_deref(), Some(workload_hash.as_str()));
        let verity_path = PathBuf::from(attached.verity_path.as_ref().unwrap());
        let raw_hash_path = verity_path.with_extension("roothash");
        let raw_hash = format!("{workload_hash}\n").into_bytes();
        assert_eq!(raw_hash.len(), 65);
        assert_eq!(std::fs::read(&raw_hash_path).unwrap(), raw_hash);
        let declarations: Vec<_> = installed
            .manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.name == "rootfs.roothash")
            .collect();
        assert_eq!(declarations.len(), 1);
        let declaration = declarations[0];
        assert_eq!(declaration.role, ArtifactRole::Other);
        assert_eq!(declaration.size_bytes, 65);
        assert_eq!(
            declaration.sha256,
            mvm_core::plan::bundle::sha256_hex(&raw_hash)
        );
        assert_eq!(installed.root.join(&declaration.path), raw_hash_path);
        assert_eq!(
            verity_path,
            installed.root.join(
                &installed
                    .manifest
                    .find_by_role(&ArtifactRole::VerityHashSidecar)
                    .unwrap()
                    .path
            )
        );
        let mut ambient = config.clone();
        ambient.verity_path = Some("/untrusted/tree".into());
        ambient.roothash = Some("c".repeat(64));
        assert!(attach_if_installed_bundle(&mut ambient, "qemu").unwrap());
        assert_eq!(ambient.verity_path, attached.verity_path);
        assert_eq!(ambient.roothash, attached.roothash);
        let mut wrong_kernel = config.clone();
        wrong_kernel.kernel_path = Some("/untrusted/kernel".into());
        assert!(
            attach_if_installed_bundle(&mut wrong_kernel, "qemu")
                .unwrap_err()
                .to_string()
                .contains("boot kernel differs")
        );
        let mut wrong_rootfs = config.clone();
        wrong_rootfs.rootfs_path = installed.root.join("other.ext4").display().to_string();
        assert!(
            attach_if_installed_bundle(&mut wrong_rootfs, "qemu")
                .unwrap_err()
                .to_string()
                .contains("boot rootfs differs")
        );
        for artifact in [
            ArtifactRole::Rootfs,
            ArtifactRole::Kernel,
            ArtifactRole::VerityHashSidecar,
        ] {
            let path = installed
                .root
                .join(&installed.manifest.find_by_role(&artifact).unwrap().path);
            let original = std::fs::read(&path).unwrap();
            for corruption in [None, Some(vec![0; original.len()]), Some(vec![0])] {
                if let Some(bytes) = corruption {
                    std::fs::write(&path, bytes).unwrap();
                } else {
                    std::fs::remove_file(&path).unwrap();
                }
                let error = attach_if_installed_bundle(&mut config.clone(), "qemu").unwrap_err();
                assert!(format!("{error:#}").contains("installed bundle artifact"));
                std::fs::write(&path, &original).unwrap();
            }
        }
        let pin = attached.bundle_boot_assets.as_ref().unwrap();
        assert_eq!(pin.manifest_sha256, root);
        assert_eq!(pin.initrd_sha256, Sha256Hex::from_bytes(&initrd_bytes));
        assert_eq!(
            mvm_core::crypto::image_verify::sha256_file(Path::new(
                attached.initrd_path.as_ref().unwrap()
            ))
            .unwrap(),
            installed
                .manifest
                .find_by_role(&ArtifactRole::Initrd)
                .unwrap()
                .sha256,
        );
        assert_eq!(attached.runtime_overlay_version.as_deref(), Some(version));
        assert!(
            attached
                .runtime_overlay_path
                .as_ref()
                .unwrap()
                .contains(root.as_str())
        );
        for path in boot.image_set.artifact_paths.values() {
            let installed_member = installed.root.join(path);
            let original = std::fs::read(&installed_member).unwrap();
            for missing in [true, false] {
                if missing {
                    std::fs::remove_file(&installed_member).unwrap();
                } else {
                    let mut corrupt = original.clone();
                    corrupt[0] ^= 1;
                    std::fs::write(&installed_member, corrupt).unwrap();
                }
                let mut refused = config.clone();
                let original_config = format!("{refused:?}");
                let error = super::super::runtime_source::attach_runtime_overlay_if_cached_version(
                    &mut refused,
                    "qemu",
                    None,
                    None,
                )
                .unwrap_err();
                let message = format!("{error:#}");
                assert!(
                    message.contains(if missing {
                        "copying installed"
                    } else {
                        "digest changed"
                    }),
                    "{message}"
                );
                assert!(refused.bundle_boot_assets.is_none());
                assert!(refused.runtime_overlay_path.is_none());
                assert!(refused.initrd_path.is_none());
                assert_eq!(format!("{refused:?}"), original_config);
                std::fs::write(&installed_member, &original).unwrap();
            }
        }

        // Legacy bundles still leave runtime selection to their original path.
        inputs.boot_assets = None;
        inputs.out = &legacy_archive;
        export_bundle_with_signer(&inputs, &publisher).unwrap();
        let legacy = registry
            .install_file(&legacy_archive, &trust, false)
            .unwrap();
        let mut legacy_config = VmStartConfig {
            rootfs_path: legacy
                .root
                .join(
                    &legacy
                        .manifest
                        .find_by_role(&ArtifactRole::Rootfs)
                        .unwrap()
                        .path,
                )
                .display()
                .to_string(),
            kernel_path: Some(
                legacy
                    .root
                    .join(
                        &legacy
                            .manifest
                            .find_by_role(&ArtifactRole::Kernel)
                            .unwrap()
                            .path,
                    )
                    .display()
                    .to_string(),
            ),
            ..Default::default()
        };
        assert!(!attach_if_installed_bundle(&mut legacy_config, "qemu").unwrap());
        assert_eq!(
            legacy_config.roothash.as_deref(),
            Some(workload_hash.as_str())
        );
        assert!(legacy_config.runtime_overlay_path.is_none());
        assert!(legacy_config.initrd_path.is_none());
        assert!(legacy_config.bundle_boot_assets.is_none());
        assert_eq!(std::fs::read(&archive).unwrap(), original_archive_bytes);

        inputs.verity_bytes = None;
        inputs.roothash = None;
        inputs.out = &unsealed_archive;
        export_bundle_with_signer(&inputs, &publisher).unwrap();
        let unsealed = registry
            .install_file(&unsealed_archive, &trust, false)
            .unwrap();
        let rootfs = unsealed.root.join(
            &unsealed
                .manifest
                .find_by_role(&ArtifactRole::Rootfs)
                .unwrap()
                .path,
        );
        let stray_tree = rootfs.with_extension("verity");
        std::fs::write(&stray_tree, b"ambient tree").unwrap();
        std::fs::write(rootfs.with_extension("roothash"), &workload_hash).unwrap();
        let mut unsealed_config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            kernel_path: Some(
                unsealed
                    .root
                    .join(
                        &unsealed
                            .manifest
                            .find_by_role(&ArtifactRole::Kernel)
                            .unwrap()
                            .path,
                    )
                    .display()
                    .to_string(),
            ),
            verity_path: Some(stray_tree.display().to_string()),
            roothash: Some(workload_hash),
            ..Default::default()
        };
        assert!(!attach_if_installed_bundle(&mut unsealed_config, "qemu").unwrap());
        assert!(unsealed_config.verity_path.is_none());
        assert!(unsealed_config.roothash.is_none());
        assert_eq!(std::fs::read(&archive).unwrap(), original_archive_bytes);
    }

    #[test]
    fn ordinary_sources_keep_their_verity_binding() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut config = VmStartConfig {
            rootfs_path: home.path().join("rootfs.ext4").display().to_string(),
            verity_path: Some("/source/rootfs.verity".into()),
            roothash: Some("a".repeat(64)),
            ..Default::default()
        };
        assert!(!attach_if_installed_bundle(&mut config, "qemu").unwrap());
        assert_eq!(config.verity_path.as_deref(), Some("/source/rootfs.verity"));
        assert_eq!(config.roothash, Some("a".repeat(64)));
    }

    #[test]
    fn missing_bundle_never_falls_back_to_a_source_build_or_download() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.set("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:1/unreachable");
        let mut config = VmStartConfig {
            rootfs_path: home
                .path()
                .join("bundles")
                .join("a".repeat(64))
                .join("artifacts/rootfs.ext4")
                .display()
                .to_string(),
            ..Default::default()
        };
        let error = super::super::runtime_source::attach_runtime_overlay_if_cached_version(
            &mut config,
            "firecracker",
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("verifying bundle boot assets"));
        assert!(config.runtime_overlay_path.is_none());
        assert!(config.initrd_path.is_none());
        assert!(!home.path().join("cache").exists());
    }

    #[test]
    fn a_cache_pin_alone_cannot_authorize_runtime_assets() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut config = VmStartConfig {
            rootfs_path: home.path().join("rootfs.ext4").display().to_string(),
            bundle_boot_assets: Some(BundleBootAssetsPin {
                manifest_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"set"),
                arch: GuestArch::host(),
                initrd_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"initrd"),
            }),
            ..Default::default()
        };
        let error = super::super::runtime_source::attach_runtime_overlay_if_cached_version(
            &mut config,
            "firecracker",
            None,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusing runtime fallback"));
        assert!(config.runtime_overlay_path.is_none());
    }

    /// The genuine pinned kernel and signed Linux root, with synthetic CLI
    /// runtime bytes: the bundle and its embedded set verify, but nothing here
    /// is runtime authentication or a native start.
    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn a_canonical_bundle_is_refused_for_libkrun_and_qemu_before_runtime_assembly() {
        use mvm_core::plan::bundle::{
            BundleArtifact, BundleManifest, BundleMember, CanonicalLinuxProof,
            EmbeddedCliBootAssets, key_id_from_pubkey, sha256_hex, write_bundle,
        };
        const REVOCATIONS: &[u8] = include_bytes!(
            "../../../mvm-core/tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json"
        );
        const REVOCATIONS_SIGNATURE: &[u8] = include_bytes!(
            "../../../mvm-core/tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json.bundle"
        );
        let kernel = std::fs::read(
            std::env::var_os("MVM_TEST_CANONICAL_KERNEL").expect("public kernel path"),
        )
        .unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let producer = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[76; 32]);
        let runtime = EmbeddedCliBootAssets {
            manifest_artifact: "linux.json".into(),
            version: "0.24.0".into(),
            arch: GuestArch::host().to_string(),
            archive_artifact: "runtime.tar.gz".into(),
            checksum_artifact: "runtime.sha256".into(),
            signature_bundle_artifact: "runtime.bundle".into(),
            checksum_signature_bundle_artifact: "runtime.sha256.bundle".into(),
            overlay_artifact: "overlay".into(),
            overlay_verity_artifact: "overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: "a".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 2,
        };
        let mut payload: Vec<(String, Vec<u8>)> = vec![
            ("kernel".into(), kernel),
            ("rootfs.ext4".into(), b"synthetic rootfs".to_vec()),
            ("initrd".into(), b"synthetic initrd".to_vec()),
            ("linux.json".into(), published_root::MANIFEST.to_vec()),
            ("linux.bundle".into(), published_root::BUNDLE.to_vec()),
            ("revocations.json".into(), REVOCATIONS.to_vec()),
            ("revocations.bundle".into(), REVOCATIONS_SIGNATURE.to_vec()),
        ];
        for name in [
            "runtime.tar.gz",
            "runtime.sha256",
            "runtime.bundle",
            "runtime.sha256.bundle",
            "overlay",
            "overlay.verity",
        ] {
            payload.push((name.into(), format!("synthetic {name}").into_bytes()));
        }
        let artifacts: Vec<BundleArtifact> = payload
            .iter()
            .map(|(name, bytes)| BundleArtifact {
                name: name.clone(),
                path: format!("artifacts/{name}"),
                role: match name.as_str() {
                    "kernel" => ArtifactRole::Kernel,
                    "rootfs.ext4" => ArtifactRole::Rootfs,
                    "initrd" => ArtifactRole::Initrd,
                    _ => ArtifactRole::Other,
                },
                sha256: sha256_hex(bytes),
                size_bytes: bytes.len() as u64,
            })
            .collect();
        let manifest = BundleManifest {
            schema_version: 7,
            publisher: "test-only-application".into(),
            key_id: key_id_from_pubkey(&key.verifying_key()),
            arch: GuestArch::host().to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-10-16T00:00:00Z".into(),
            labels: Default::default(),
            artifacts,
            members: vec![
                BundleMember::EmbeddedCliBootAssets(runtime),
                BundleMember::CanonicalLinuxProof(CanonicalLinuxProof {
                    manifest_artifact: "linux.json".into(),
                    signature_bundle_artifact: "linux.bundle".into(),
                    revocation_document_artifact: "revocations.json".into(),
                    revocation_signature_bundle_artifact: "revocations.bundle".into(),
                }),
            ],
            verity: None,
            resources: None,
        };
        let archive = producer.path().join("canonical.mvmpkg");
        let payload = payload
            .into_iter()
            .map(|(name, bytes)| (format!("artifacts/{name}"), bytes))
            .collect();
        std::fs::write(&archive, write_bundle(&manifest, &key, payload).unwrap()).unwrap();
        let trust = FsTrustStore::default_path().unwrap();
        std::fs::create_dir_all(trust.root()).unwrap();
        std::fs::write(
            trust.root().join(format!("{}.pub", manifest.key_id.0)),
            key.verifying_key().as_bytes(),
        )
        .unwrap();
        let registry = BundleRegistry::default_path().unwrap();
        let installed = registry.install_file(&archive, &trust, false).unwrap();
        let config = VmStartConfig {
            name: "canonical-refusal-unit".into(),
            rootfs_path: installed
                .root
                .join("artifacts/rootfs.ext4")
                .display()
                .to_string(),
            kernel_path: Some(
                installed
                    .root
                    .join("artifacts/kernel")
                    .display()
                    .to_string(),
            ),
            ..Default::default()
        };
        let original = format!("{config:?}");
        for backend in ["libkrun", "qemu"] {
            let mut refused = config.clone();
            let error = attach_if_installed_bundle(&mut refused, backend).unwrap_err();
            assert!(
                format!("{error:#}").contains("canonical kernel lifetime custody unsupported"),
                "{backend}: {error:#}"
            );
            assert_eq!(format!("{refused:?}"), original, "{backend}");
        }
        assert!(
            !home.path().join("canonical-kernel-generations").exists(),
            "a refused attach must not retain a kernel generation"
        );
        // A custody-capable backend clears this gate and fails later — on this
        // host the unsigned synthetic runtime or the builder-ABI support of a
        // payload-less test shell, never on custody.
        #[cfg(unix)]
        {
            let mut admitted = config.clone();
            let error = attach_if_installed_bundle(&mut admitted, "hvf").unwrap_err();
            let message = format!("{error:#}");
            assert!(
                !message.contains("canonical kernel lifetime custody unsupported"),
                "hvf: {message}"
            );
            assert_eq!(format!("{admitted:?}"), original, "hvf");
        }
    }
}
