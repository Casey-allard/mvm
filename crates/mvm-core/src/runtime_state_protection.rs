//! Serialize canonical retained-state publication and runtime removal.
//!
//! This lock and the refusal markers grant no cleanup authority or exit proof.
//! Cooperating callers hold the guard through their complete filesystem action.
//! Identity checks detect observed replacement; they do not make path-based
//! recursive removal atomic against a hostile concurrent namespace owner.

/// Fixed lock beneath the canonical VM-state parent, independent of VM count.
pub const RUNTIME_STATE_PROTECTION_LOCK_FILE: &str = ".runtime-state-protection.lock";
/// Denial marker published before installed retained telemetry writer effects.
pub const RETAINED_TELEMETRY_MARKER_FILE: &str = ".installed-retained-telemetry";
/// Declared logical allowance for one retained scope's bounded sidecars.
/// Owned catalog/status/key/marker writers must enforce their individual caps
/// before activation; this definition alone qualifies no numeric profile.
/// Global catalog headers require a separate reservation from the same pool.
pub const INSTALLED_TELEMETRY_SIDECAR_BYTES: u64 = 32 * 1024;
/// Canonical retained telemetry records filename.
pub const TELEMETRY_RECORDS_FILE: &str = "telemetry-records.jsonl";
/// Canonical wrapped telemetry records key filename.
pub const TELEMETRY_RECORDS_KEY_FILE: &str = "telemetry-records.key";
/// Canonical telemetry collector coverage-status filename.
pub const TELEMETRY_COLLECTOR_STATUS_FILE: &str = "telemetry-collector-status.json";

#[cfg(unix)]
use std::{fs::File, io, path::Path};

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
    use std::{
        fs::Metadata,
        os::unix::fs::MetadataExt as _,
        path::{Component, PathBuf},
    };

    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    /// A held, freshly opened serialization lock and its original parent pin.
    ///
    /// Directory mode checks allow legacy owner-controlled 0755 namespaces.
    /// They are not private-read, ACL or installed-resource admission checks.
    #[must_use]
    #[derive(Debug)]
    pub struct RuntimeStateProtection {
        parent_path: PathBuf,
        parent: File,
        lock: File,
    }

    fn denied() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime state protection refused",
        )
    }

    fn identity(metadata: &Metadata) -> (u64, u64) {
        (metadata.dev(), metadata.ino())
    }

    fn directory_metadata(file: &File) -> io::Result<Metadata> {
        let metadata = file.metadata()?;
        crate::private_fs::require_current_owner(&metadata)?;
        if !metadata.is_dir() || metadata.mode() & 0o022 != 0 || metadata.nlink() == 0 {
            return Err(denied());
        }
        Ok(metadata)
    }

    fn validate_lock_stat(stat: &rustix::fs::Stat) -> io::Result<()> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || stat.st_size != 0
        {
            return Err(denied());
        }
        Ok(())
    }

    fn open_lock(parent: &File) -> io::Result<File> {
        let flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        match rustix::fs::openat(
            parent,
            RUNTIME_STATE_PROTECTION_LOCK_FILE,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => Ok(File::from(file)),
            Err(rustix::io::Errno::EXIST) => {
                validate_lock_stat(&rustix::fs::statat(
                    parent,
                    RUNTIME_STATE_PROTECTION_LOCK_FILE,
                    AtFlags::SYMLINK_NOFOLLOW,
                )?)?;
                Ok(File::from(rustix::fs::openat(
                    parent,
                    RUNTIME_STATE_PROTECTION_LOCK_FILE,
                    flags,
                    Mode::empty(),
                )?))
            }
            Err(error) => Err(error.into()),
        }
    }

    impl RuntimeStateProtection {
        /// Acquire an independently opened exclusive nonblocking lock.
        ///
        /// The caller supplies its actual original parent pin; this method
        /// never chmods, adopts a replacement, or duplicates a lock OFD.
        pub fn acquire(parent_path: &Path, original_parent: &File) -> io::Result<Self> {
            if !parent_path.is_absolute()
                || parent_path
                    .components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            {
                return Err(denied());
            }
            let original = directory_metadata(original_parent)?;
            let parent = File::from(rustix::fs::open(
                parent_path,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            if identity(&directory_metadata(&parent)?) != identity(&original) {
                return Err(denied());
            }
            let lock = open_lock(&parent)?;
            validate_lock_stat(&rustix::fs::fstat(&lock)?)?;
            rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
            let guard = Self {
                parent_path: parent_path.to_path_buf(),
                parent,
                lock,
            };
            guard.check_guard()?;
            guard.lock.sync_all()?;
            guard.parent.sync_all()?;
            guard.check_guard()?;
            Ok(guard)
        }

        fn check_guard(&self) -> io::Result<()> {
            let original = directory_metadata(&self.parent)?;
            let current = File::from(rustix::fs::open(
                &self.parent_path,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            if identity(&directory_metadata(&current)?) != identity(&original) {
                return Err(denied());
            }
            let held = rustix::fs::fstat(&self.lock)?;
            let named = rustix::fs::statat(
                &self.parent,
                RUNTIME_STATE_PROTECTION_LOCK_FILE,
                AtFlags::SYMLINK_NOFOLLOW,
            )?;
            validate_lock_stat(&held)?;
            validate_lock_stat(&named)?;
            if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) {
                return Err(denied());
            }
            Ok(())
        }

        fn state_name<'a>(&self, state_path: &'a Path) -> io::Result<&'a std::ffi::OsStr> {
            if state_path.parent() != Some(self.parent_path.as_path())
                || state_path
                    .components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            {
                return Err(denied());
            }
            state_path.file_name().ok_or_else(denied)
        }

        /// Revalidate the original state pin and direct-child path identity.
        pub fn check_state(&self, state_path: &Path, original_state: &File) -> io::Result<()> {
            self.check_guard()?;
            let name = self.state_name(state_path)?;
            let original = directory_metadata(original_state)?;
            let current = File::from(rustix::fs::openat(
                &self.parent,
                name,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            if identity(&directory_metadata(&current)?) != identity(&original) {
                return Err(denied());
            }
            self.check_guard()
        }

        /// Require exact direct-child absence under the same held guard.
        pub fn check_missing_state(&self, state_path: &Path) -> io::Result<()> {
            self.check_guard()?;
            let name = self.state_name(state_path)?;
            match rustix::fs::statat(&self.parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => self.check_guard(),
                Err(error) => Err(error.into()),
                Ok(_) => Err(denied()),
            }
        }

        /// Refuse every retained/native marker or telemetry entry, even malformed.
        /// Absence is accepted only as ENOENT; no contents are read or trusted.
        pub fn check_removal_allowed(
            &self,
            state_path: &Path,
            original_state: &File,
        ) -> io::Result<()> {
            self.check_state(state_path, original_state)?;
            for name in [
                RETAINED_TELEMETRY_MARKER_FILE,
                TELEMETRY_RECORDS_FILE,
                TELEMETRY_RECORDS_KEY_FILE,
                TELEMETRY_COLLECTOR_STATUS_FILE,
                crate::host_lifetime::INSTALLED_NATIVE_CUSTODY_MARKER,
            ] {
                match rustix::fs::statat(original_state, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(rustix::io::Errno::NOENT) => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(denied()),
                }
            }
            self.check_state(state_path, original_state)
        }
    }
}

#[cfg(unix)]
pub use unix::RuntimeStateProtection;

#[cfg(all(test, unix))]
#[path = "runtime_state_protection_tests.rs"]
mod tests;
