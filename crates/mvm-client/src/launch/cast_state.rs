//! Create the explicitly enrolled original pair's runtime directories with
//! private modes before plan preparation writes its signed boot sidecars.
use anyhow::{Result, ensure};
use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
use std::{fs::File, os::unix::fs::MetadataExt, path::Path};

const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn trusted(fd: &File) -> Result<()> {
    let m = fd.metadata()?;
    mvm_core::private_fs::require_current_owner(&m)?;
    ensure!(
        m.is_dir() && m.mode() & 0o022 == 0,
        "original mailbox runtime directory writable by another user"
    );
    Ok(())
}

/// Caller holds the VM name claim. The usual stale-state cleanup is allowed
/// only within an already trusted original namespace.
pub(super) fn prepare(home: &Path, name: &str, discard: impl FnOnce() -> Result<()>) -> Result<()> {
    mvm_core::naming::validate_vm_name(name)?;
    let root = File::from(open(home, DIR, Mode::empty())?);
    trusted(&root)?;
    match mkdirat(&root, "vms", Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => (),
        Err(e) => return Err(e.into()),
    }
    let vms = File::from(openat(&root, "vms", DIR, Mode::empty())?);
    trusted(&vms)?;
    match openat(&vms, name, DIR, Mode::empty()) {
        Ok(fd) => trusted(&File::from(fd))?,
        Err(rustix::io::Errno::NOENT) => (),
        Err(e) => return Err(e.into()),
    }
    discard()?;
    // A surviving original is never adopted. mkdirat applies 0700 on creation,
    // independent of a cooperative process's umask (e.g. 0002).
    mkdirat(&vms, name, Mode::RWXU)?;
    let created = File::from(openat(&vms, name, DIR, Mode::empty())?);
    trusted(&created)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn original_cast_creates_private_state_and_refuses_unsafe_existing_namespace() -> Result<()> {
        let home = tempfile::tempdir()?;
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))?;
        prepare(home.path(), "alpha", || Ok(()))?;
        let vms = home.path().join("vms");
        let alpha = vms.join("alpha");
        assert_eq!(fs::metadata(&vms)?.mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&alpha)?.mode() & 0o777, 0o700);
        let called = Cell::new(false);
        let discard = || {
            called.set(true);
            Ok(())
        };
        fs::set_permissions(&alpha, fs::Permissions::from_mode(0o770))?;
        assert!(prepare(home.path(), "alpha", discard).is_err());
        assert!(!called.get());
        assert_eq!(fs::metadata(&alpha)?.mode() & 0o777, 0o770);
        symlink(&alpha, vms.join("beta"))?;
        assert!(prepare(home.path(), "beta", discard).is_err());
        assert!(!called.get());
        fs::set_permissions(&vms, fs::Permissions::from_mode(0o770))?;
        assert!(prepare(home.path(), "gamma", discard).is_err());
        assert!(!called.get());
        assert!(!vms.join("gamma").exists());
        Ok(())
    }
}
