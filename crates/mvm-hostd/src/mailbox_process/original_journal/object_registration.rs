//! Exclusive, nonblocking registration of both installed object mailbox originals.
use super::{LaunchClaim, claim_launch, owner_dir};
use anyhow::{Result, ensure};
use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

struct OriginalDirectory {
    path: PathBuf,
    fd: File,
}

impl OriginalDirectory {
    fn open(path: &Path) -> Result<Self> {
        let fd = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = fd.metadata()?;
        mvm_core::private_fs::require_current_owner(&metadata)?;
        ensure!(
            metadata.mode() & 0o022 == 0,
            "mailbox registration directory writable by another principal"
        );
        Ok(Self {
            path: path.into(),
            fd,
        })
    }

    fn identity(&self) -> Result<(u64, u64)> {
        let meta = self.fd.metadata()?;
        Ok((meta.dev(), meta.ino()))
    }

    fn require_current(&self) -> Result<()> {
        let current = fs::symlink_metadata(&self.path)?;
        ensure!(
            current.is_dir()
                && current.mode() & 0o022 == 0
                && (current.dev(), current.ino()) == self.identity()?,
            "original mailbox registration directory changed"
        );
        Ok(())
    }
}

struct Participant {
    _claim: Arc<LaunchClaim>,
    state: OriginalDirectory,
    owner: OriginalDirectory,
    socket_dir: Option<OriginalDirectory>,
}

impl Participant {
    fn claim(keys: &Path, name: &str, state: &Path) -> Result<Self> {
        mvm_core::naming::validate_vm_name(name)?;
        let state = OriginalDirectory::open(state)?;
        let socket_path = mvm_core::config::vm_socket_dir_at(&state.path);
        let socket_dir = if socket_path != state.path {
            Some(OriginalDirectory::open(&socket_path)?)
        } else {
            None
        };
        let owner = OriginalDirectory::open(&owner_dir(keys, name)?)?;
        let claim = claim_launch(&state.path, &owner.path, true)?;
        state.require_current()?;
        owner.require_current()?;
        Ok(Self {
            _claim: claim,
            state,
            owner,
            socket_dir,
        })
    }
}

pub(crate) struct Registration {
    caller: Participant,
    callee: Participant,
}

impl Registration {
    pub(crate) fn claim(keys: &Path, caller: (&str, &Path), callee: (&str, &Path)) -> Result<Self> {
        ensure!(
            caller.0 != callee.0,
            "object pair requires distinct machines"
        );
        // claim_launch uses try_lock. Failure to acquire the second drops the
        // first; neither original is spawned and no orphan marker is removed.
        let caller = Participant::claim(keys, caller.0, caller.1)?;
        let callee = Participant::claim(keys, callee.0, callee.1)?;
        ensure!(
            caller.state.identity()? != callee.state.identity()?
                && caller.owner.identity()? != callee.owner.identity()?,
            "object pair aliases an original mailbox directory"
        );
        let registration = Self { caller, callee };
        registration.require_originals()?;
        Ok(registration)
    }

    pub(crate) fn require_originals(&self) -> Result<()> {
        for original in [&self.caller, &self.callee] {
            original.state.require_current()?;
            original.owner.require_current()?;
            if let Some(socket_dir) = &original.socket_dir {
                socket_dir.require_current()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn private(path: &Path) {
        mvm_core::private_fs::create_owned_private_dir(path).unwrap();
    }
    #[test]
    fn both_original_launches_remain_exclusive_and_released_together() {
        let root = tempfile::tempdir().unwrap();
        let keys = root.path().join("keys");
        let a = root.path().join("a");
        let b = root.path().join("b");
        for d in [&keys, &a, &b] {
            private(d);
        }
        let hold = || Registration::claim(&keys, ("a", &a), ("b", &b));
        let owned = hold().unwrap();
        for (name, state) in [("a", &a), ("b", &b)] {
            let owner = owner_dir(&keys, name).unwrap();
            assert!(claim_launch(state, &owner, false).is_err());
        }
        assert!(hold().is_err());
        fs::rename(&b, root.path().join("original-b")).unwrap();
        private(&b);
        assert!(owned.require_originals().is_err());
        drop(owned);
        hold().unwrap();
    }

    #[test]
    fn occupied_or_orphaned_second_original_refunds_first_without_touching_marker() {
        let root = tempfile::tempdir().unwrap();
        let keys = root.path().join("keys");
        let a = root.path().join("a");
        let b = root.path().join("b");
        for d in [&keys, &a, &b] {
            private(d);
        }
        let owner_b = owner_dir(&keys, "b").unwrap();
        let claim_b = claim_launch(&b, &owner_b, true).unwrap();
        let hold = || Registration::claim(&keys, ("a", &a), ("b", &b));
        assert!(hold().is_err());
        let owner_a = owner_dir(&keys, "a").unwrap();
        claim_launch(&a, &owner_a, true).unwrap();
        drop(claim_b);
        let marker = owner_b.join(super::super::MARKER);
        fs::write(&marker, b"prior original").unwrap();
        assert!(hold().is_err());
        assert_eq!(fs::read(&marker).unwrap(), b"prior original");
        claim_launch(&a, &owner_a, true).unwrap();
    }
}
