//! Bounded diskless decoding of already-authenticated legacy boot members.

use anyhow::{Context, Result, ensure};
use mvm_core::{crypto::image_verify::sha256_reader, packs::Sha256Hex};
use mvm_fs::{
    initramfs::{
        CHECKSUM_MANIFEST_FILE, INITRAMFS_HASH_FILE, INITRAMFS_IMAGE_FILE, INITRAMFS_SIZE_FILE,
        VERSION_FILE,
    },
    overlay::parse_checksums_manifest,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    path::Path,
};

use crate::{
    initramfs::INITRAMFS_ARCHIVE_LIMITS,
    runtime_overlay::{
        ExpandedArchiveLimits, OVERLAY_ARCHIVE_LIMITS, OVERLAY_ARCHIVE_MEMBERS,
        scan_release_archive,
    },
};

const METADATA_BYTES: u64 = 64 * 1024;
const UNCOMPRESSED_INITRAMFS_BYTES: u64 = 512 * 1024 * 1024;

pub struct OverlayPayload {
    pub image: Vec<u8>,
    pub verity: Vec<u8>,
    pub roothash: String,
    pub version: String,
}

pub struct InitramfsPayload {
    pub image: Vec<u8>,
    pub version: String,
}

/// Verify all eight content hashes in the authenticated overlay archive.
/// Executables are hashed without retaining their expanded bytes.
pub fn overlay(archive: &[u8]) -> Result<OverlayPayload> {
    let limits = OVERLAY_ARCHIVE_LIMITS;
    let manifest_name = mvm_fs::overlay::CHECKSUM_MANIFEST_FILE;
    let mut payloads = BTreeMap::new();
    let mut digests = BTreeMap::new();
    scan_release_archive(
        archive,
        Path::new("signed-overlay"),
        &OVERLAY_ARCHIVE_MEMBERS,
        limits,
        |name, entry, remaining| -> Result<()> {
            match name {
                "overlay.ext4" | "overlay.verity" | "overlay.roothash" | "VERSION" => {
                    let bytes = collect(limits, name, entry, remaining)?;
                    digests.insert(name, hex::encode(Sha256::digest(&bytes)));
                    payloads.insert(name, bytes);
                }
                name if name == manifest_name => {
                    payloads.insert(name, collect(limits, name, entry, remaining)?);
                }
                _ => {
                    let mut digest = DigestWriter(Sha256::new());
                    limits.copy_entry(entry, &mut digest, remaining)?;
                    digests.insert(name, hex::encode(digest.0.finalize()));
                }
            }
            Ok(())
        },
    )?;
    let expected = parse_checksums_manifest(text(&payloads, manifest_name)?);
    for (name, actual) in digests {
        ensure!(
            expected.get(name) == Some(&actual),
            "signed overlay member {name} checksum differs"
        );
    }
    let roothash = Sha256Hex::new(text(&payloads, "overlay.roothash")?)?
        .as_str()
        .to_owned();
    let version = text(&payloads, "VERSION")?.to_owned();
    ensure!(
        !version.is_empty() && !version.bytes().any(|byte| byte.is_ascii_whitespace()),
        "invalid signed overlay version"
    );
    Ok(OverlayPayload {
        image: payloads
            .remove("overlay.ext4")
            .context("signed overlay image missing")?,
        verity: payloads
            .remove("overlay.verity")
            .context("signed overlay verity missing")?,
        roothash,
        version,
    })
}

pub fn initramfs(archive: &[u8]) -> Result<InitramfsPayload> {
    let limits = INITRAMFS_ARCHIVE_LIMITS;
    let mut payloads = BTreeMap::new();
    scan_release_archive(
        archive,
        Path::new("signed-initramfs"),
        &[
            INITRAMFS_IMAGE_FILE,
            INITRAMFS_HASH_FILE,
            INITRAMFS_SIZE_FILE,
            VERSION_FILE,
            CHECKSUM_MANIFEST_FILE,
        ],
        limits,
        |name, entry, remaining| -> Result<()> {
            if matches!(
                name,
                INITRAMFS_IMAGE_FILE | INITRAMFS_HASH_FILE | VERSION_FILE
            ) {
                payloads.insert(name, collect(limits, name, entry, remaining)?);
            } else {
                let metadata = ExpandedArchiveLimits {
                    file_bytes: METADATA_BYTES,
                    ..limits
                };
                metadata.copy_entry(entry, &mut io::sink(), remaining)?;
            }
            Ok(())
        },
    )?;
    let version = text(&payloads, VERSION_FILE)?.to_owned();
    let expected = text(&payloads, INITRAMFS_HASH_FILE)?.to_ascii_lowercase();
    let image = payloads
        .remove(INITRAMFS_IMAGE_FILE)
        .context("signed initramfs image missing")?;
    let mut decoded =
        flate2::read::GzDecoder::new(image.as_slice()).take(UNCOMPRESSED_INITRAMFS_BYTES);
    let actual = sha256_reader(&mut decoded)?;
    ensure!(
        decoded.limit() != 0 || decoded.get_mut().read(&mut [0])? == 0,
        "signed initramfs exceeds uncompressed size bound"
    );
    ensure!(
        actual == expected,
        "signed initramfs uncompressed checksum differs"
    );
    Ok(InitramfsPayload { image, version })
}

fn collect(
    mut limits: ExpandedArchiveLimits,
    name: &str,
    entry: &mut dyn Read,
    remaining: &mut u64,
) -> Result<Vec<u8>> {
    if !matches!(
        name,
        "overlay.ext4" | "overlay.verity" | INITRAMFS_IMAGE_FILE
    ) {
        limits.file_bytes = METADATA_BYTES;
    }
    let mut bytes = Vec::new();
    limits.copy_entry(entry, &mut bytes, remaining)?;
    Ok(bytes)
}

fn text<'a>(payloads: &'a BTreeMap<&str, Vec<u8>>, name: &str) -> Result<&'a str> {
    let bytes = payloads
        .get(name)
        .with_context(|| format!("signed boot member {name} missing"))?;
    Ok(std::str::from_utf8(bytes)?.trim())
}

struct DigestWriter(Sha256);

impl io::Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_asset_fixture::{
        initramfs_archive_bytes, initramfs_fixture, runtime_overlay_archive_bytes,
    };

    #[test]
    fn diskless_overlay_refuses_altered_discarded_executable() {
        let signed = runtime_overlay_archive_bytes(
            mvm_core::arch::GuestArch::Aarch64,
            b"exact overlay",
            b"exact verity",
            "a".repeat(64).as_bytes(),
            b"2.3.4",
        );
        let parsed = overlay(&signed).unwrap();
        assert_eq!(parsed.image, b"exact overlay");
        assert_eq!(parsed.verity, b"exact verity");

        let decoder = flate2::read::GzDecoder::new(signed.as_slice());
        let mut archive = tar::Archive::new(decoder);
        let mut modified = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let mut header = entry.header().clone();
            if entry.path().unwrap() == Path::new("mvm-guest-agent") {
                let replacement = b"changed executable";
                header.set_size(replacement.len() as u64);
                header.set_cksum();
                modified.append(&header, replacement.as_slice()).unwrap();
            } else {
                modified.append(&header, &mut entry).unwrap();
            }
        }
        let changed = modified.into_inner().unwrap().finish().unwrap();
        let error = overlay(&changed)
            .err()
            .expect("tampered executable refused");
        assert!(
            error
                .to_string()
                .contains("mvm-guest-agent checksum differs")
        );
    }

    #[test]
    fn diskless_initramfs_checks_inner_digest_and_metadata_limit() {
        let (image, digest, size) = initramfs_fixture(b"test cpio content");
        let archive = |hash: &[u8], version: &[u8]| {
            initramfs_archive_bytes(&image, hash, size.as_bytes(), version)
        };
        let parsed = initramfs(&archive(digest.as_bytes(), b"2.3.4")).unwrap();
        assert_eq!(parsed.image, image);
        assert_eq!(parsed.version, "2.3.4");
        let error = initramfs(&archive("a".repeat(64).as_bytes(), b"2.3.4"))
            .err()
            .expect("bad inner digest refused");
        assert!(error.to_string().contains("uncompressed checksum differs"));
        let error = initramfs(&archive(
            digest.as_bytes(),
            &vec![b'v'; METADATA_BYTES as usize + 1],
        ))
        .err()
        .expect("oversized metadata refused");
        assert!(
            error
                .to_string()
                .contains("expanded archive budget exceeded")
        );
    }
}
