//! Explicit first-use provisioning; existing or partial homes are never reset.
//! Directory identities and local labels are not mailbox/boot authority.

use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::installed_owner::{InstallationKey, InstallationOwner, check_acl, open_root};

const INTENT: &str = ".host-agent-provisioning.intent";

pub struct HostAgentInstallation {
    pub root: PathBuf,
    pub key: InstallationKey,
}

/// Owns the actual original directory handles. Not serializable or a grant.
pub struct ProvisionedHome {
    home: PathBuf,
    directories: Vec<(PathBuf, File)>,
}

/// Filesystem preparation only. Existing storage still needs canonical
/// service/lifecycle admission before any child-bearing native operation.
pub enum HomePreparation {
    Fresh(ProvisionedHome),
    ExistingUnverified(ExistingHome),
}

/// Holds the original private home without initializing or trusting its store.
pub struct ExistingHome {
    home: PathBuf,
    original: File,
}

impl HomePreparation {
    pub fn home(&self) -> &Path {
        match self {
            Self::Fresh(home) => home.home(),
            Self::ExistingUnverified(home) => &home.home,
        }
    }

    /// Check original directory custody, not service readiness or authority.
    pub fn verify(&self) -> io::Result<()> {
        match self {
            Self::Fresh(home) => home.verify(),
            Self::ExistingUnverified(home) => {
                let current = open_root(&home.home).map_err(io::Error::other)?;
                if identity(&current)? != identity(&home.original)? {
                    return Err(invalid("existing home identity changed"));
                }
                require_no_intent(&current)
            }
        }
    }
}

/// Prepare the selected home before configuration/key/cache writers. Only an
/// exclusive new-directory creation returns Fresh. An existing private home
/// stays unverified; this function never acquires the live service's owner EX,
/// repairs metadata, starts children, or grants legacy activation.
pub fn prepare_home(home: &Path, tenant: &str) -> io::Result<HomePreparation> {
    validate(home, tenant)?;
    match std::fs::symlink_metadata(home) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_new_home_and_provision(home, tenant).map(HomePreparation::Fresh)
        }
        Err(error) => Err(error),
        Ok(_) => {
            let original = open_root(home).map_err(io::Error::other)?;
            require_no_intent(&original)?;
            let prepared = HomePreparation::ExistingUnverified(ExistingHome {
                home: home.to_path_buf(),
                original,
            });
            prepared.verify()?;
            Ok(prepared)
        }
    }
}

impl ProvisionedHome {
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Recheck the original namespace; this does not establish service readiness.
    pub fn verify(&self) -> io::Result<()> {
        for (path, original) in &self.directories {
            let current = if path == &self.home || path.starts_with(&self.home) {
                open_root(path).map_err(io::Error::other)?
            } else {
                open_parent(path)?
            };
            if identity(&current)? != identity(original)? {
                return Err(invalid("provisioned directory identity changed"));
            }
        }
        let home = self
            .directories
            .get(1)
            .ok_or_else(|| invalid("original home handle missing"))?;
        require_no_intent(&home.1)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate(home: &Path, tenant: &str) -> io::Result<()> {
    if !home.is_absolute()
        || home.file_name().is_none()
        || home
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("host-agent home must be an absolute normal path"));
    }
    let mut parts = Path::new(tenant).components();
    if tenant.is_empty()
        || tenant.len() > 512
        || tenant.chars().any(char::is_control)
        || !matches!(parts.next(), Some(Component::Normal(_)))
        || parts.next().is_some()
    {
        return Err(invalid(
            "host-agent tenant must be one bounded normal component",
        ));
    }
    CString::new(home.as_os_str().as_bytes()).map_err(|_| invalid("invalid home path"))?;
    CString::new(tenant).map_err(|_| invalid("invalid tenant"))?;
    Ok(())
}

fn identity(file: &File) -> io::Result<(u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn open_parent(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    mvm_core::private_fs::require_current_owner(&metadata)?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "home parent must be owned and not writable by other users",
        ));
    }
    check_acl(&file).map_err(io::Error::other)?;
    Ok(file)
}

fn require_no_intent(home: &File) -> io::Result<()> {
    let name = CString::new(INTENT).map_err(|_| invalid("invalid intent name"))?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: name is live/NUL-terminated; output is read only on success.
    let result = unsafe {
        libc::fstatat(
            home.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(invalid("host-agent provisioning requires reconciliation"));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

fn derive(home: &Path, tenant: &str) -> io::Result<HostAgentInstallation> {
    validate(home, tenant)?;
    let home_bytes = home.as_os_str().as_bytes();
    let mut installation = Sha256::new();
    installation.update(b"mvm/host-agent-resource-installation/v1\0");
    installation.update(
        u64::try_from(home_bytes.len())
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    installation.update(home_bytes);
    installation.update(
        u64::try_from(tenant.len())
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    installation.update(tenant.as_bytes());
    Ok(HostAgentInstallation {
        root: mvm_core::config::host_agent_dir_at(home, tenant).join("resource-owner-v1"),
        key: InstallationKey {
            installation: installation.finalize().into(),
            profile: Sha256::digest(b"mvm/host-agent-owned-resources/v1\0").into(),
        },
    })
}

/// Resolve namespace/key labels from the original private home without creating
/// anything. Labels prove neither initialized storage nor service readiness.
/// The caller must open the original owner to validate its record and exclusion.
pub fn descriptor(home: &Path, tenant: &str) -> io::Result<HostAgentInstallation> {
    let installation = derive(home, tenant)?;
    let directory = open_root(home).map_err(io::Error::other)?;
    require_no_intent(&directory)?;
    let current = open_root(home).map_err(io::Error::other)?;
    if identity(&directory)? != identity(&current)? {
        return Err(invalid("host-agent home identity changed"));
    }
    Ok(installation)
}

fn create_directory(parent: &File, parent_path: &Path, name: &OsStr) -> io::Result<File> {
    let name_c = CString::new(name.as_bytes()).map_err(|_| invalid("invalid directory name"))?;
    // SAFETY: parent is retained and name is one live/NUL-terminated component.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this opens a fresh owned directory FD relative to the held parent.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat returned this newly owned descriptor.
    let original = unsafe { File::from_raw_fd(fd) };
    let current = open_root(&parent_path.join(name)).map_err(io::Error::other)?;
    if identity(&original)? != identity(&current)? {
        return Err(invalid("new directory identity changed"));
    }
    Ok(original)
}

/// Create one absent home, initialize its original tenant's Clean resource
/// owner and synchronize publication. Existing/partial homes refuse. Failure
/// retains created evidence. This does not start a service or grant authority.
pub fn create_new_home_and_provision(home: &Path, tenant: &str) -> io::Result<ProvisionedHome> {
    create_with_sync(home, tenant, File::sync_all)
}

fn create_with_sync(
    home: &Path,
    tenant: &str,
    mut sync: impl FnMut(&File) -> io::Result<()>,
) -> io::Result<ProvisionedHome> {
    let installation = derive(home, tenant)?;
    let parent_path = home
        .parent()
        .ok_or_else(|| invalid("home parent missing"))?;
    let parent = open_parent(parent_path)?;
    let directory = create_directory(
        &parent,
        parent_path,
        home.file_name()
            .ok_or_else(|| invalid("home name missing"))?,
    )?;
    sync(&parent)?;
    let intent = CString::new(INTENT).map_err(|_| invalid("invalid intent name"))?;
    // SAFETY: create a new private marker in the original held home directory.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            intent.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat returned this fresh owned marker descriptor.
    let mut marker = unsafe { File::from_raw_fd(fd) };
    marker.write_all(b"mvm/host-agent-home/v1\n")?;
    sync(&marker)?;
    sync(&directory)?;
    let mut receipt = ProvisionedHome {
        home: home.to_path_buf(),
        directories: vec![
            (parent_path.to_path_buf(), parent),
            (home.to_path_buf(), directory),
        ],
    };
    let relative = installation
        .root
        .parent()
        .ok_or_else(|| invalid("tenant directory missing"))?
        .strip_prefix(home)
        .map_err(io::Error::other)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(invalid("invalid managed directory component"));
        };
        let (path, original) = receipt
            .directories
            .last()
            .ok_or_else(|| invalid("parent missing"))?;
        let child = create_directory(original, path, name)?;
        sync(original)?;
        receipt.directories.push((path.join(name), child));
    }
    let owner = InstallationOwner::initialize(&installation.root, installation.key)
        .map_err(io::Error::other)?;
    owner.snapshot().map_err(io::Error::other)?;
    receipt.directories.push((
        installation.root.clone(),
        open_root(&installation.root).map_err(io::Error::other)?,
    ));
    for (_, directory) in receipt.directories.iter().rev() {
        sync(directory)?;
    }
    let original_home = &receipt.directories[1].1;
    // SAFETY: remove only the fixed marker relative to the original home FD.
    if unsafe { libc::unlinkat(original_home.as_raw_fd(), intent.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    sync(original_home)?;
    drop(owner);
    drop(marker);
    receipt.verify()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn failed_initial_parent_sync_leaves_no_openable_resource_or_fresh_retry() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let home = parent.path().canonicalize().unwrap().join("fresh-home");
        assert!(
            create_with_sync(&home, "local", |_| {
                Err(io::Error::other("controlled first parent sync refusal"))
            })
            .is_err()
        );
        assert!(home.is_dir(), "retain the actual partial directory");
        let labels = descriptor(&home, "local").unwrap();
        assert!(InstallationOwner::open(&labels.root, labels.key).is_err());
        assert!(!labels.root.exists());
        assert!(create_new_home_and_provision(&home, "local").is_err());
        assert!(!labels.root.exists());
    }

    #[test]
    fn failed_post_record_directory_sync_keeps_intent_and_fences_verified_opening() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let home = parent.path().canonicalize().unwrap().join("fresh-home");
        let record = home.join("host-agent/local/resource-owner-v1/state.bin");
        let injected = Cell::new(false);
        let outcome = create_with_sync(&home, "local", |file| {
            if record.is_file() && !injected.replace(true) {
                return Err(io::Error::other(
                    "controlled post-record directory sync refusal",
                ));
            }
            file.sync_all()
        });
        assert!(outcome.is_err());
        assert!(
            injected.get(),
            "controlled failure never reached the published record"
        );
        assert!(home.join(INTENT).is_file());
        let original_bytes = fs::read(&record).unwrap();
        assert!(
            descriptor(&home, "local").is_err(),
            "a failed directory barrier cannot become verified provisioning"
        );
        assert!(create_new_home_and_provision(&home, "local").is_err());
        assert_eq!(fs::read(&record).unwrap(), original_bytes);
        assert!(home.join(INTENT).is_file());
    }
}
