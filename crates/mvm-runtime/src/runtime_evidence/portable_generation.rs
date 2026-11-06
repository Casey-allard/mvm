//! Original private installed portable runtime generation custody.

use anyhow::{Context, Result, ensure};
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, Stat},
    io::Errno,
};
use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

const MAX_MEMBERS: usize = 7;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn same_entry(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

#[derive(Default)]
pub(crate) enum PortableCustody {
    #[default]
    Empty,
    Uncertain,
    Owned(OwnedPortableGeneration),
}

/// In-process ownership only. No pathname recovery after controller loss.
pub(crate) struct OwnedPortableGeneration {
    parent_path: PathBuf,
    parent: File,
    name: OsString,
    directory: File,
    entries: Vec<(&'static str, Option<File>)>,
    removed: bool,
}

impl OwnedPortableGeneration {
    pub(crate) fn create(parent_path: &Path, parent: &File) -> Result<Self> {
        super::namespace::check_held_directory(parent_path, parent)?;
        let parent = parent.try_clone()?;
        let name = OsString::from(format!("portable-runtime-{}", uuid::Uuid::new_v4()));
        let entries = Vec::with_capacity(MAX_MEMBERS);
        fs::mkdirat(&parent, &name, Mode::RWXU)?;
        let directory = File::from(fs::openat(&parent, &name, DIRECTORY, Mode::empty())?);
        Ok(Self {
            parent_path: parent_path.to_owned(),
            parent,
            name,
            directory,
            entries,
            removed: false,
        })
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.parent_path.join(&self.name)
    }

    pub(crate) fn write_member(&mut self, name: &'static str, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.entries.len() < MAX_MEMBERS
                && Path::new(name).file_name().is_some_and(|part| part == name)
                && !self.entries.iter().any(|(existing, _)| *existing == name),
            "portable generation member already held or member limit reached"
        );
        self.check_parent()?;
        self.check_directory()?;
        let file = File::from(fs::openat(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        // Keep the exact descriptor even if writing, chmod or sync fails.
        self.entries.push((name, Some(file)));
        let file = self
            .entries
            .last_mut()
            .and_then(|(_, file)| file.as_mut())
            .unwrap();
        file.write_all(bytes)?;
        fs::fchmod(&*file, Mode::RUSR)?;
        file.sync_all()?;
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<()> {
        fs::fsync(&self.directory)?;
        fs::fsync(&self.parent)?;
        self.check_parent()?;
        self.check_directory()?;
        self.check_entries(true)
    }

    fn check_parent(&self) -> Result<()> {
        super::namespace::check_held_directory(&self.parent_path, &self.parent)
    }

    fn check_directory(&self) -> Result<()> {
        let held = fs::fstat(&self.directory)?;
        ensure!(
            same_entry(
                &fs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)?,
                &held
            ) && held.st_mode & 0o7777 == 0o700
                && held.st_uid == unsafe { libc::geteuid() },
            "portable generation directory was substituted"
        );
        Ok(())
    }

    fn check_member(&self, name: &str, original: &File, immutable: bool) -> Result<()> {
        let current = fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            same_entry(&current, &fs::fstat(original)?)
                && FileType::from_raw_mode(current.st_mode) == FileType::RegularFile
                && current.st_nlink == 1
                && current.st_uid == unsafe { libc::geteuid() }
                && (current.st_mode & 0o7777 == 0o400
                    || !immutable && current.st_mode & 0o7777 == 0o600),
            "portable generation member was substituted"
        );
        Ok(())
    }

    fn check_entries(&self, immutable: bool) -> Result<()> {
        let mut found = 0;
        for entry in fs::Dir::read_from(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let (known, original) = self
                .entries
                .iter()
                .find_map(|(known, stat)| {
                    (known.as_bytes() == name).then_some((*known, stat.as_ref()?))
                })
                .context("portable generation contains an unexpected entry")?;
            self.check_member(known, original, immutable)?;
            found += 1;
        }
        ensure!(
            found
                == self
                    .entries
                    .iter()
                    .filter(|(_, stat)| stat.is_some())
                    .count(),
            "portable generation member disappeared before owned cleanup"
        );
        Ok(())
    }

    pub(crate) fn retire(&mut self) -> Result<()> {
        self.retire_with(|parent| Ok(fs::fsync(parent)?))
    }

    fn retire_with(&mut self, sync_parent: impl FnOnce(&File) -> Result<()>) -> Result<()> {
        self.check_parent()?;
        if !self.removed {
            self.check_directory()?;
            self.check_entries(false)?;
            for index in 0..self.entries.len() {
                if let (name, Some(original)) = &self.entries[index] {
                    self.check_member(name, original, false)?;
                    fs::unlinkat(&self.directory, *name, AtFlags::empty())?;
                    self.entries[index].1 = None;
                }
            }
            fs::fsync(&self.directory)?;
            self.check_directory()?;
            fs::unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR)?;
            self.removed = true;
        }
        self.check_absent()?;
        sync_parent(&self.parent)?;
        self.check_parent()?;
        self.check_absent()
    }

    fn check_absent(&self) -> Result<()> {
        ensure!(
            matches!(
                fs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW),
                Err(Errno::NOENT)
            ),
            "portable generation name remains occupied after owned cleanup"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replacement_lifecycle_directory_refuses_generation_before_creation() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("lifecycle");
        super::super::namespace::private_directory(&parent).unwrap();
        let (directory, _lock) = super::super::namespace::lock(&parent).unwrap();
        let original = root.path().join("original");
        std::fs::rename(&parent, &original).unwrap();
        super::super::namespace::private_directory(&parent).unwrap();

        assert!(OwnedPortableGeneration::create(&parent, &directory).is_err());
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
    }

    #[test]
    fn exclusive_write_never_adopts_an_existing_member() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::from(fs::open(parent.path(), DIRECTORY, Mode::empty()).unwrap());
        let mut owner = OwnedPortableGeneration::create(parent.path(), &directory).unwrap();
        let generation = owner.path();
        let member = generation.join("bundle.mvmpkg");
        std::fs::write(&member, b"foreign").unwrap();
        assert!(owner.write_member("bundle.mvmpkg", b"owned").is_err());
        assert!(owner.retire().is_err());
        assert_eq!(std::fs::read(&member).unwrap(), b"foreign");
        std::fs::remove_file(&member).unwrap();
        owner.write_member("bundle.mvmpkg", b"owned").unwrap();
        owner.finish().unwrap();
        assert_eq!(std::fs::read(member).unwrap(), b"owned");
        owner.retire().unwrap();
    }

    #[test]
    fn retirement_retries_parent_sync_without_removing_replacement() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::from(fs::open(parent.path(), DIRECTORY, Mode::empty()).unwrap());
        let mut owner = OwnedPortableGeneration::create(parent.path(), &directory).unwrap();
        owner.write_member("bundle.mvmpkg", b"owned").unwrap();
        owner.finish().unwrap();
        let generation = owner.path();
        assert!(
            owner
                .retire_with(|_| anyhow::bail!("injected parent sync error"))
                .is_err()
        );
        assert!(!generation.exists());
        std::fs::create_dir(&generation).unwrap();
        assert!(owner.retire().is_err());
        assert!(generation.exists());
        std::fs::remove_dir(&generation).unwrap();
        owner.retire().unwrap();
    }

    #[test]
    fn original_generation_refuses_replacements_then_retires_exactly() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::from(fs::open(parent.path(), DIRECTORY, Mode::empty()).unwrap());
        let mut owner = OwnedPortableGeneration::create(parent.path(), &directory).unwrap();
        owner.write_member("bundle.mvmpkg", b"original").unwrap();
        owner.finish().unwrap();
        let generation = owner.path();
        let member = generation.join("bundle.mvmpkg");

        let moved = parent.path().join("moved");
        std::fs::rename(&generation, &moved).unwrap();
        std::fs::create_dir(&generation).unwrap();
        std::fs::write(generation.join("foreign"), b"foreign").unwrap();
        assert!(owner.retire().is_err());
        assert_eq!(
            std::fs::read(generation.join("foreign")).unwrap(),
            b"foreign"
        );
        std::fs::remove_file(generation.join("foreign")).unwrap();
        std::fs::remove_dir(&generation).unwrap();
        std::fs::rename(moved, &generation).unwrap();

        let extra = generation.join("extra");
        std::fs::write(&extra, b"unexpected").unwrap();
        assert!(owner.retire().is_err());
        assert_eq!(std::fs::read(&member).unwrap(), b"original");
        std::fs::remove_file(extra).unwrap();

        let saved = parent.path().join("saved-member");
        std::fs::rename(&member, &saved).unwrap();
        std::fs::write(&member, b"foreign member").unwrap();
        std::fs::set_permissions(&member, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(owner.retire().is_err());
        assert_eq!(std::fs::read(&member).unwrap(), b"foreign member");
        std::fs::remove_file(&member).unwrap();
        std::fs::rename(saved, &member).unwrap();

        owner.retire().unwrap();
        assert!(!generation.exists());
        owner.retire().unwrap();
    }
}
