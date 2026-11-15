//! Whether a boot is provisioned for host-side telemetry collection, and the
//! on-disk names the embedded collector shares with its readers.
//!
//! There is no collector process: the collector runs as a thread inside the
//! per-VM network endpoint, so it lives and dies with the one host process
//! every workload boot already has. Provisioning is a single decision made
//! by the spawner and consumed twice — the endpoint config grows a telemetry
//! section, and the guest cmdline grows the `mvm.telemetry=1` assertion that
//! tells the agent to serve its listener. One decision, so the guest can
//! never assert a listener the host did not provision for.

use std::path::Path;

/// Where the embedded collector keeps its coverage-status snapshot, in the
/// VM state dir.
pub const TELEMETRY_COLLECTOR_STATUS_FILE: &str = "telemetry-collector-status.json";
/// Where the embedded collector appends received records, size-capped.
pub const TELEMETRY_RECORDS_FILE: &str = "telemetry-records.jsonl";
/// Default byte cap for the records file. Deliberately modest: retention is
/// its own workstream, and this file exists so collection is observable, not
/// as a durable store.
pub const DEFAULT_RECORDS_BYTE_CAP: u64 = 8 * 1024 * 1024;
/// The records file's data key, wrapped under the host transcript
/// key-encryption key. Every line of [`TELEMETRY_RECORDS_FILE`] is sealed
/// under the key this file wraps.
pub const TELEMETRY_RECORDS_KEY_FILE: &str = "telemetry-records.key";
/// Marker written only after this boot's telemetry-capable endpoint spawned.
const TELEMETRY_PROVISIONED_FILE: &str = "telemetry-provisioned";

/// The variable that turns collection off for every boot this host starts.
pub const ENV_TELEMETRY_COLLECT: &str = "MVM_TELEMETRY_COLLECT";

/// Whether this host collects guest telemetry for the boots it starts.
///
/// On by default: collection is a product feature, not a side effect of
/// configuring an exporter, and it costs a launch nothing measurable (the
/// collector starts inside the endpoint process every boot already has, and
/// the guest's listener is a thread). `MVM_TELEMETRY_COLLECT=0` turns it off;
/// an OTLP exporter remains optional either way.
pub fn telemetry_collection_enabled() -> bool {
    collection_enabled_from(std::env::var(ENV_TELEMETRY_COLLECT).ok().as_deref())
}

/// Record whether the endpoint spawned for this boot actually carries a
/// telemetry collector. Absence is fail-closed: the guest asserts no listener.
pub fn record_boot_provisioning(state_dir: &Path, provisioned: bool) -> std::io::Result<()> {
    let marker = state_dir.join(TELEMETRY_PROVISIONED_FILE);
    if provisioned {
        std::fs::write(marker, b"1")
    } else {
        match std::fs::remove_file(marker) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Whether this specific boot has a successfully spawned telemetry endpoint.
pub fn boot_is_provisioned(state_dir: &Path) -> bool {
    state_dir.join(TELEMETRY_PROVISIONED_FILE).is_file()
}

/// The data key this VM's records file is sealed under, minted (and stored
/// wrapped under the host KEK in `keys_dir`, created if absent) on the VM's
/// first provisioned boot and reused after, so a restart keeps the records
/// already written readable. A wrapped key that will not unwrap is replaced
/// along with the records it sealed, which nothing could read any more.
pub fn provision_records_key(
    state_dir: &Path,
    keys_dir: &Path,
) -> std::io::Result<mvm_core::crypto::aead::Key> {
    let kek = mvm_core::transcript::load_or_init_kek(keys_dir)?;
    let key_file = state_dir.join(TELEMETRY_RECORDS_KEY_FILE);
    match std::fs::read_to_string(&key_file) {
        Ok(wrapped) => {
            if let Ok(key) = mvm_core::transcript::unwrap_data_key(&kek, wrapped.trim()) {
                return Ok(key);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match std::fs::remove_file(state_dir.join(TELEMETRY_RECORDS_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let key = mvm_core::crypto::aead::Key::random();
    // Not synced: this runs on every new VM's launch path, where two fsyncs
    // cost tens of milliseconds on rotational storage. A crash that loses the
    // wrapped key loses only records nothing could read without it, and the
    // next provisioning replaces both.
    mvm_core::atomic_io::write_private_ephemeral(
        &key_file,
        mvm_core::transcript::wrap_data_key(&kek, &key).as_bytes(),
    )?;
    Ok(key)
}

/// The data key a reader opens this VM's records with, or `None` when the VM
/// has none or the host has no KEK. Never mints either: a read path that
/// created keys would make every record already written unreadable.
pub fn load_records_key(
    state_dir: &Path,
    keys_dir: &Path,
) -> std::io::Result<Option<mvm_core::crypto::aead::Key>> {
    let wrapped = match std::fs::read_to_string(state_dir.join(TELEMETRY_RECORDS_KEY_FILE)) {
        Ok(wrapped) => wrapped,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(kek) = mvm_core::transcript::load_kek(keys_dir)? else {
        return Ok(None);
    };
    mvm_core::transcript::unwrap_data_key(&kek, wrapped.trim())
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(unix)]
pub(crate) fn provision_records_key_owned_with_file(
    state: &std::fs::File,
    keys_dir: &Path,
) -> std::io::Result<(mvm_core::crypto::aead::Key, std::fs::File)> {
    use mvm_core::crypto::aead::{KEY_SIZE, Key};
    use std::io;

    owned_private_directory(state)?;
    let keys = crate::host::restore_image::open_trusted_dir(keys_dir)
        .map_err(|_| owned_key_storage_error())?;
    owned_private_directory(&keys)?;
    let kek_name = mvm_core::transcript::TRANSCRIPT_KEK_FILENAME;
    match owned_read_private(state, TELEMETRY_RECORDS_KEY_FILE, 1024) {
        Ok((wrapped, file)) => {
            let (kek, _) = owned_read_private(&keys, kek_name, KEY_SIZE)?;
            let kek = Key::from_slice(&kek).map_err(|_| owned_key_storage_error())?;
            return owned_unwrap(&kek, &wrapped).map(|key| (key, file));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // A missing key cannot authorize dropping or replacing retained records.
    match open_owned_private_file(state, TELEMETRY_RECORDS_FILE) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(owned_key_storage_error()),
    }
    let (kek, _) = match owned_read_private(&keys, kek_name, KEY_SIZE) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            publish_owned_key(&keys, kek_name, Key::random().expose_bytes())?;
            owned_read_private(&keys, kek_name, KEY_SIZE)?
        }
        result => result?,
    };
    let kek = Key::from_slice(&kek).map_err(|_| owned_key_storage_error())?;
    let wrapped = mvm_core::transcript::wrap_data_key(&kek, &Key::random());
    publish_owned_key(state, TELEMETRY_RECORDS_KEY_FILE, wrapped.as_bytes())?;
    let (wrapped, file) = owned_read_private(state, TELEMETRY_RECORDS_KEY_FILE, 1024)?;
    owned_unwrap(&kek, &wrapped).map(|key| (key, file))
}

#[cfg(unix)]
fn owned_key_storage_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid owned telemetry key storage",
    )
}

#[cfg(unix)]
fn owned_private_directory(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::{fd::AsFd, unix::fs::MetadataExt};
    let metadata = file.metadata()?;
    mvm_core::private_fs::require_current_owner(&metadata)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o7777 != 0o700
        || crate::host::restore_image::fd_acl_grants_access(file.as_fd())?
    {
        return Err(owned_key_storage_error());
    }
    Ok(())
}

#[cfg(unix)]
fn owned_private_file(file: &std::fs::File) -> std::io::Result<std::fs::Metadata> {
    use std::os::{fd::AsFd, unix::fs::MetadataExt};
    let metadata = file.metadata()?;
    mvm_core::private_fs::require_current_owner(&metadata)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || crate::host::restore_image::fd_acl_grants_access(file.as_fd())?
    {
        return Err(owned_key_storage_error());
    }
    Ok(metadata)
}

#[cfg(unix)]
fn open_owned_private_file(
    directory: &std::fs::File,
    name: &str,
) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, openat};
    let file = std::fs::File::from(openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    owned_private_file(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn owned_read_private(
    directory: &std::fs::File,
    name: &str,
    limit: usize,
) -> std::io::Result<(zeroize::Zeroizing<Vec<u8>>, std::fs::File)> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let mut file = open_owned_private_file(directory, name)?;
    let before = owned_private_file(&file)?;
    let mut scratch = zeroize::Zeroizing::new([0_u8; 1025]);
    if limit >= scratch.len() || before.len() > limit as u64 {
        return Err(owned_key_storage_error());
    }
    let mut used = 0;
    while used <= limit {
        match file.read(&mut scratch[used..=limit]) {
            Ok(0) => break,
            Ok(bytes) => used += bytes,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let after = owned_private_file(&file)?;
    let named = open_owned_private_file(directory, name)?.metadata()?;
    if used > limit
        || (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
        || (after.dev(), after.ino(), after.len()) != (named.dev(), named.ino(), named.len())
        || used as u64 != after.len()
    {
        return Err(owned_key_storage_error());
    }
    Ok((zeroize::Zeroizing::new(scratch[..used].to_vec()), file))
}

/// Publish a durable private key relative to the retained directory. The
/// exclusive rename publishes a complete single-link file or leaves the winner.
#[cfg(unix)]
fn publish_owned_key(directory: &std::fs::File, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use rand::Rng;
    use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};
    use std::io::Write;

    let mut token = [0_u8; 16];
    rand::rng().fill_bytes(&mut token);
    let temp = format!(".mvm-telemetry-key-{}", hex::encode(token));
    let mut file = std::fs::File::from(openat(
        directory,
        temp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?);
    let check_staging_name = |file: &std::fs::File| -> std::io::Result<()> {
        let named = rustix::fs::statat(directory, temp.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        let held = rustix::fs::fstat(file)?;
        if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino) {
            return Err(owned_key_storage_error());
        }
        Ok(())
    };
    let result = (|| -> std::io::Result<bool> {
        owned_private_file(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        check_staging_name(&file)?;
        match rename_owned_key(directory, &temp, name) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    })();
    if !matches!(&result, Ok(true)) {
        let removed = check_staging_name(&file).and_then(|()| {
            unlinkat(directory, temp.as_str(), AtFlags::empty()).map_err(Into::into)
        });
        result?;
        removed?;
    }
    directory.sync_all()
}

#[cfg(target_os = "linux")]
fn rename_owned_key(
    directory: &std::fs::File,
    source: &str,
    destination: &str,
) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        directory,
        source,
        directory,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}

#[cfg(target_os = "macos")]
fn rename_owned_key(
    directory: &std::fs::File,
    source: &str,
    destination: &str,
) -> std::io::Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    let source = CString::new(source).map_err(|_| owned_key_storage_error())?;
    let destination = CString::new(destination).map_err(|_| owned_key_storage_error())?;
    // SAFETY: the directory is held and both path components are NUL-terminated.
    if unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rename_owned_key(_: &std::fs::File, _: &str, _: &str) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(unix)]
fn owned_unwrap(
    kek: &mvm_core::crypto::aead::Key,
    wrapped: &[u8],
) -> std::io::Result<mvm_core::crypto::aead::Key> {
    let encoded = std::str::from_utf8(wrapped).map_err(|_| owned_key_storage_error())?;
    mvm_core::transcript::unwrap_data_key(kek, encoded.trim())
        .map_err(|_| owned_key_storage_error())
}

/// The pure decision, split from the environment so it is testable without
/// process-global state: only an explicit off value disables collection.
pub fn collection_enabled_from(explicit_collect: Option<&str>) -> bool {
    !matches!(
        explicit_collect
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0" | "false" | "off" | "no")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_key_publication_stays_in_the_captured_directory() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let original = root.path().join("original");
        mvm_core::config::create_private_dir(&state).unwrap();
        let held = std::fs::File::open(&state).unwrap();
        std::fs::rename(&state, &original).unwrap();
        mvm_core::config::create_private_dir(&state).unwrap();
        publish_owned_key(&held, "key", b"original bytes").unwrap();
        publish_owned_key(&held, "key", b"must not replace").unwrap();
        assert!(!state.join("key").exists());
        assert_eq!(
            std::fs::read(original.join("key")).unwrap(),
            b"original bytes"
        );
        assert_eq!(std::fs::read_dir(original).unwrap().count(), 1);
    }

    #[test]
    fn collection_is_on_unless_explicitly_turned_off() {
        assert!(collection_enabled_from(None));
        assert!(collection_enabled_from(Some("1")));
        assert!(collection_enabled_from(Some("")));
        for off in ["0", "false", "OFF", " no "] {
            assert!(!collection_enabled_from(Some(off)), "{off:?}");
        }
    }

    #[test]
    fn the_records_key_is_minted_once_wrapped_and_reused() {
        let state = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        assert!(
            load_records_key(state.path(), keys.path())
                .unwrap()
                .is_none()
        );

        let minted = provision_records_key(state.path(), keys.path()).unwrap();
        let wrapped = std::fs::read(state.path().join(TELEMETRY_RECORDS_KEY_FILE)).unwrap();
        assert!(
            !wrapped
                .windows(32)
                .any(|w| w == minted.expose_bytes().as_slice()),
            "the key is stored wrapped, never raw"
        );
        let again = provision_records_key(state.path(), keys.path()).unwrap();
        assert_eq!(again.expose_bytes(), minted.expose_bytes());
        let read = load_records_key(state.path(), keys.path())
            .unwrap()
            .unwrap();
        assert_eq!(read.expose_bytes(), minted.expose_bytes());
    }

    #[test]
    fn a_key_wrapped_under_another_kek_is_replaced_with_its_records() {
        let state = tempfile::tempdir().unwrap();
        let first_keys = tempfile::tempdir().unwrap();
        let other_keys = tempfile::tempdir().unwrap();
        provision_records_key(state.path(), first_keys.path()).unwrap();
        std::fs::write(state.path().join(TELEMETRY_RECORDS_FILE), b"sealed\n").unwrap();

        // A host with no KEK reads no key, and mints none.
        assert!(
            load_records_key(state.path(), other_keys.path())
                .unwrap()
                .is_none()
        );
        provision_records_key(state.path(), other_keys.path()).unwrap();
        assert!(!state.path().join(TELEMETRY_RECORDS_FILE).exists());
        assert!(
            load_records_key(state.path(), other_keys.path())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn boot_provisioning_is_absent_until_recorded_and_can_be_cleared() {
        let state = tempfile::tempdir().unwrap();
        assert!(!boot_is_provisioned(state.path()));

        record_boot_provisioning(state.path(), true).unwrap();
        assert!(boot_is_provisioned(state.path()));

        record_boot_provisioning(state.path(), false).unwrap();
        assert!(!boot_is_provisioned(state.path()));
    }
}
