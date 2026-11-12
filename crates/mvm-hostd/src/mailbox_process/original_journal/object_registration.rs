//! Exclusive, nonblocking registration of both installed object mailbox originals.
//! The canonical host installation owns and protects the MVM home/keys
//! ancestry. Keep independent file descriptors for the concrete directories
//! used below; a same-name replacement cannot inherit their registration.
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
        mvm_core::private_fs::require_current_owner(&current)?;
        ensure!(
            current.is_dir()
                && current.mode() & 0o022 == 0
                && (current.dev(), current.ino()) == self.identity()?,
            "original mailbox registration directory changed"
        );
        Ok(())
    }
}

/// Private original launch witness. Names are always re-derived from the two
/// verified plans and MVM home. The bootstrap does not supply arbitrary paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalPathPins {
    state: (u64, u64),
    owner: (u64, u64),
    socket: Option<(u64, u64)>,
}
/// Keeping these directories open prevents reuse of a retired inode for the
/// life of a serving helper; path authority is still rechecked on each turn.
pub(crate) struct OriginalDirectories {
    _held: Vec<OriginalDirectory>,
}
impl OriginalPathPins {
    fn members(&self, home: &Path, name: &str) -> Result<Vec<(PathBuf, (u64, u64))>> {
        mvm_core::naming::validate_vm_name(name)?;
        let state = mvm_core::config::vm_state_dir_at(home, name);
        let socket = mvm_core::config::vm_socket_dir_at(&state);
        let owner = mvm_core::config::vm_mailbox_original_owner_at(
            &mvm_core::config::mvm_keys_dir_at(home),
            name,
        );
        ensure!(
            (socket != state) == self.socket.is_some(),
            "changed original socket path"
        );
        let mut members = vec![(state, self.state), (owner, self.owner)];
        if let Some(id) = self.socket {
            members.push((socket, id));
        }
        Ok(members)
    }
    pub(crate) fn require_current(&self, home: &Path, name: &str) -> Result<()> {
        for (path, id) in self.members(home, name)? {
            let meta = fs::symlink_metadata(path)?;
            mvm_core::private_fs::require_current_owner(&meta)?;
            ensure!(
                meta.is_dir() && meta.mode() & 0o022 == 0 && (meta.dev(), meta.ino()) == id,
                "original protected mailbox directory changed"
            );
        }
        Ok(())
    }
    pub(crate) fn hold(&self, home: &Path, name: &str) -> Result<OriginalDirectories> {
        let mut held = Vec::with_capacity(3);
        for (path, id) in self.members(home, name)? {
            let dir = OriginalDirectory::open(&path)?;
            ensure!(
                dir.identity()? == id,
                "worker bound to replacement directory"
            );
            dir.require_current()?;
            held.push(dir);
        }
        Ok(OriginalDirectories { _held: held })
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

    #[cfg(target_os = "linux")]
    pub(super) fn original_claim(
        &self,
        role: mvm_core::mailbox::object_pair::role::ObjectParticipantRole,
    ) -> Result<Arc<LaunchClaim>> {
        self.require_originals()?;
        Ok(Arc::clone(match role {
            mvm_core::mailbox::object_pair::role::ObjectParticipantRole::Caller => {
                &self.caller._claim
            }
            mvm_core::mailbox::object_pair::role::ObjectParticipantRole::Callee => {
                &self.callee._claim
            }
        }))
    }
    pub(crate) fn directory_pins(&self) -> Result<[OriginalPathPins; 2]> {
        self.require_originals()?;
        let pin = |p: &Participant| -> Result<OriginalPathPins> {
            Ok(OriginalPathPins {
                state: p.state.identity()?,
                owner: p.owner.identity()?,
                socket: p
                    .socket_dir
                    .as_ref()
                    .map(OriginalDirectory::identity)
                    .transpose()?,
            })
        };
        Ok([pin(&self.caller)?, pin(&self.callee)?])
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
    fn current_directory_must_remain_private_for_its_original_owner() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let keys = root.path().join("keys");
        let a = root.path().join("a");
        let b = root.path().join("b");
        for d in [&keys, &a, &b] {
            private(d);
        }
        let hold = || Registration::claim(&keys, ("a", &a), ("b", &b));
        let owned = hold().unwrap();
        fs::set_permissions(&b, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(owned.require_originals().is_err());
        drop(owned);
        assert!(hold().is_err());
        fs::set_permissions(&b, fs::Permissions::from_mode(0o700)).unwrap();
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
