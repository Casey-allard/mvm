//! The one original records writer, never a public descriptor constructor.
use super::*;
use std::os::{
    fd::{AsFd, BorrowedFd},
    unix::fs::MetadataExt,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordsProjection {
    version: u8,
    descriptor: i32,
    state_path: PathBuf,
    state_device: u64,
    state_inode: u64,
    device: u64,
    inode: u64,
}

fn refused() -> anyhow::Error {
    anyhow!("installed original records writer refused")
}

fn check_state(path: &Path, device: u64, inode: u64) -> Result<File> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path.components().any(|part| {
            !matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(refused());
    }
    let directory = crate::host::restore_image::open_trusted_dir(path).map_err(|_| refused())?;
    let metadata = directory.metadata().map_err(|_| refused())?;
    if (metadata.dev(), metadata.ino()) != (device, inode) {
        return Err(refused());
    }
    Ok(directory)
}

fn check_file(fd: BorrowedFd<'_>) -> Result<rustix::fs::Stat> {
    let metadata = rustix::fs::fstat(fd).map_err(|_| refused())?;
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| refused())?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
        || metadata.st_size < 0
        || metadata.st_size as u64 > crate::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP
        || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDWR
        || !flags.contains(rustix::fs::OFlags::APPEND)
        || crate::host::restore_image::fd_acl_grants_access(fd).map_err(|_| refused())?
    {
        return Err(refused());
    }
    Ok(metadata)
}

fn object(metadata: &rustix::fs::Stat) -> (u64, u64) {
    #[cfg(target_os = "macos")]
    {
        (metadata.st_dev as u64, metadata.st_ino)
    }
    #[cfg(not(target_os = "macos"))]
    {
        (metadata.st_dev, metadata.st_ino)
    }
}

impl RecordsProjection {
    pub(super) fn from_original(state_path: &Path, state: &File, records: &File) -> Result<Self> {
        let directory = state.metadata().map_err(|_| refused())?;
        let file = check_file(records.as_fd())?;
        let projection = Self {
            version: 1,
            descriptor: records.as_raw_fd(),
            state_path: state_path.into(),
            state_device: directory.dev(),
            state_inode: directory.ino(),
            device: object(&file).0,
            inode: object(&file).1,
        };
        projection.preflight(&[])?;
        Ok(projection)
    }
    pub(super) fn descriptor(&self) -> i32 {
        self.descriptor
    }
    /// Borrow only: no supplied descriptor has been adopted at this point.
    pub(super) fn preflight(&self, existing: &[i32]) -> Result<()> {
        if self.version != 1 || self.descriptor <= 2 || existing.contains(&self.descriptor) {
            return Err(refused());
        }
        let mut raw: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: raw query only; a closed/unrecognized number refuses before
        // BorrowedFd's validity contract or an ownership conversion is used.
        if unsafe { libc::fstat(self.descriptor, &mut raw) } != 0 {
            return Err(refused());
        }
        // SAFETY: borrowed for metadata only; no ownership conversion occurs.
        let fd = unsafe { BorrowedFd::borrow_raw(self.descriptor) };
        let file = check_file(fd)?;
        if object(&file) != (self.device, self.inode) {
            return Err(refused());
        }
        let directory = check_state(&self.state_path, self.state_device, self.state_inode)?;
        let named = rustix::fs::statat(
            &directory,
            crate::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| refused())?;
        if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
            || object(&named) != (self.device, self.inode)
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(super) fn adopt(
        self,
        file: File,
        lease: InstalledEndpointLease,
    ) -> Result<InstalledTelemetryRecords> {
        let metadata = check_file(file.as_fd())?;
        if object(&metadata) != (self.device, self.inode) {
            return Err(refused());
        }
        rustix::io::fcntl_setfd(
            &file,
            rustix::io::fcntl_getfd(&file)? | rustix::io::FdFlags::CLOEXEC,
        )?;
        Ok(InstalledTelemetryRecords {
            file,
            lease,
            projection: self,
        })
    }
}

/// Original installed records writer. It has no public constructor, Clone,
/// descriptor getter, AsRawFd, Deref or conversion into File. The original
/// parent owns its independent retention custody through writer completion.
pub struct InstalledTelemetryRecords {
    file: File,
    lease: InstalledEndpointLease,
    projection: RecordsProjection,
}
impl InstalledTelemetryRecords {
    /// Check original-context continuity before the one collector claim.
    /// Path data is compared; it does not create storage or quota authority.
    pub fn check_for(&self, lease: &InstalledEndpointLease, state_path: &Path) -> Result<()> {
        if !Arc::ptr_eq(&self.lease.authority, &lease.authority)
            || state_path != self.projection.state_path
        {
            return Err(refused());
        }
        lease.check_current()?;
        self.projection.preflight(&[])
    }
    pub fn current_len(&self) -> std::io::Result<u64> {
        self.file.metadata().map(|metadata| metadata.len())
    }
    /// Refuse retirement on a partial append. The confined writer has no
    /// truncation authority over the original retained record stream.
    pub fn rollback_to(&mut self, length: u64) -> std::io::Result<()> {
        if self.current_len().is_ok_and(|current| current == length) {
            Ok(())
        } else {
            self.lease.fail_cleanup();
            Err(std::io::Error::other("installed records append left unverified bytes"))
        }
    }
}

impl std::io::Write for InstalledTelemetryRecords {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self.current_len()?;
        let cap = crate::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP;
        if length.checked_add(bytes.len() as u64).is_none_or(|end| end > cap) {
            return Err(std::io::Error::other("installed records append refused"));
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;
