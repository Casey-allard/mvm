//! Create the explicitly enrolled original pair's runtime directories with
//! private modes before plan preparation writes its signed boot sidecars.
use anyhow::{Context, Result, ensure};
use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

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

struct FreshDirectory {
    path: PathBuf,
    original: File,
}
pub(super) struct FreshState(Vec<FreshDirectory>);
impl FreshState {
    fn create(&mut self, parent: &File, path: &Path) -> Result<()> {
        let name = path.file_name().context("original directory name absent")?;
        mkdirat(parent, name, Mode::RWXU)?;
        let original = File::from(openat(parent, name, DIR, Mode::empty())?);
        trusted(&original)?;
        self.0.push(FreshDirectory {
            path: path.to_owned(),
            original,
        });
        Ok(())
    }
    pub(super) fn commit(mut self) {
        self.0.clear();
    }
}
impl Drop for FreshState {
    fn drop(&mut self) {
        for d in self.0.iter().rev() {
            if let (Ok(a), Ok(b)) = (d.original.metadata(), fs::symlink_metadata(&d.path))
                && (a.dev(), a.ino()) == (b.dev(), b.ino())
            {
                // Empty directories only; populated or uncertain state remains.
                let _ = fs::remove_dir(&d.path);
            }
        }
    }
}

/// The SDK holds the VM name claim. Inline stopped-state cleanup may operate
/// only on a trusted namespace. A split socket path lives outside MVM_HOME and
/// must be freshly claimed without traversing or removing a prior entry.
pub(super) fn prepare(
    home: &Path,
    name: &str,
    discard: impl FnOnce() -> Result<()>,
) -> Result<FreshState> {
    mvm_core::naming::validate_vm_name(name)?;
    let root = File::from(open(home, DIR, Mode::empty())?);
    trusted(&root)?;
    match mkdirat(&root, "vms", Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => (),
        Err(e) => return Err(e.into()),
    }
    let vms = File::from(openat(&root, "vms", DIR, Mode::empty())?);
    trusted(&vms)?;
    let existing = match openat(&vms, name, DIR, Mode::empty()) {
        Ok(fd) => {
            trusted(&File::from(fd))?;
            true
        }
        Err(rustix::io::Errno::NOENT) => false,
        Err(e) => return Err(e.into()),
    };
    let state = mvm_core::config::vm_state_dir_at(home, name);
    let socket = mvm_core::config::vm_socket_dir_at(&state);
    let mut new = FreshState(Vec::with_capacity(2));
    if socket == state {
        discard()?;
    } else {
        ensure!(
            !existing,
            "existing split original runtime must be retired by its owner"
        );
        // macOS /tmp itself is a symlink. Resolve only the OS temporary root,
        // then require its owner and sticky protections before mkdirat.
        ensure!(
            socket.parent() == Some(Path::new("/tmp")),
            "unknown split socket root"
        );
        let tmp = File::from(open(fs::canonicalize("/tmp")?, DIR, Mode::empty())?);
        let m = tmp.metadata()?;
        ensure!(
            m.uid() == 0 && m.mode() & 0o1000 != 0,
            "untrusted split-socket temporary root"
        );
        new.create(&tmp, &socket)?;
    }
    new.create(&vms, &state)?;
    Ok(new)
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
        let home = tempfile::Builder::new().prefix("sc").tempdir_in("/tmp")?;
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))?;
        let fresh = prepare(home.path(), "alpha", || Ok(()))?;
        fresh.commit();
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
    #[test]
    fn split_original_refuses_foreign_socket_before_cleanup_and_releases_empty_fresh_paths()
    -> Result<()> {
        let base = tempfile::tempdir()?;
        let home = base.path().join("s".repeat(112));
        fs::create_dir(&home)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        let state = mvm_core::config::vm_state_dir_at(&home, "alpha");
        let short = mvm_core::config::vm_socket_dir_at(&state);
        assert_ne!(state, short);
        // Guard against collisions with any existing path in the real /tmp.
        fs::create_dir(&short)?;
        struct MarkerDir(PathBuf);
        impl Drop for MarkerDir {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0.join("marker"));
                let _ = fs::remove_dir(&self.0);
            }
        }
        let guard = MarkerDir(short.clone());
        let marker = short.join("marker");
        fs::write(&marker, b"existing original")?;
        fs::set_permissions(&short, fs::Permissions::from_mode(0o770))?;
        assert!(
            prepare(&home, "alpha", || panic!(
                "untrusted split directory reached cleanup"
            ))
            .is_err()
        );
        assert_eq!(fs::read(&marker)?, b"existing original");
        assert!(!state.exists());
        drop(guard);
        let fresh = prepare(&home, "alpha", || {
            panic!("fresh split must not recurse through /tmp")
        })?;
        assert_eq!(fs::metadata(&short)?.mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&state)?.mode() & 0o777, 0o700);
        drop(fresh);
        assert!(!short.exists() && !state.exists());
        Ok(())
    }
}
