//! Darwin cannot open a socket vnode. An uninterrupted watch on the original
//! private parent instead fences *any* change to its entries, including a
//! replacement followed by restoration of the same inode.
use rustix::{
    event::kqueue::{Event, EventFilter, EventFlags, VnodeEvents, kevent, kqueue},
    fs::{AtFlags, FileType, statat, unlinkat},
    io::{FdFlags, fcntl_setfd},
    process::geteuid,
};
use std::{
    fs::File,
    io,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::{Duration, Instant},
};

pub(super) struct DirectoryWatch {
    // The registration is destroyed before its monitored descriptor.
    queue: OwnedFd,
    parent: File,
    socket: (libc::dev_t, libc::ino_t),
    fenced: bool,
}

fn deadline(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}

fn require_parent(parent: &File, path: &Path) -> io::Result<()> {
    let held = parent.metadata()?;
    let named = std::fs::symlink_metadata(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
    if !held.is_dir()
        || !named.is_dir()
        || held.uid() != geteuid().as_raw()
        || held.mode() & 0o077 != 0
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
    {
        return Err(io::Error::other(
            "original private socket directory changed",
        ));
    }
    Ok(())
}

fn socket_id(parent: &File, path: &Path) -> io::Result<(libc::dev_t, libc::ino_t)> {
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let s = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Socket || s.st_nlink != 1 {
        return Err(io::Error::other("original socket entry changed"));
    }
    Ok((s.st_dev, s.st_ino))
}

fn poll(queue: &OwnedFd, change: &[Event]) -> io::Result<Option<Event>> {
    let mut events = [MaybeUninit::uninit()];
    // SAFETY: the registered filter refers only to the held parent, which
    // outlives the queue. The single-event buffer never escapes this call.
    let (ready, _) = unsafe { kevent(queue, change, &mut events[..], Some(Duration::ZERO)) }?;
    Ok(ready.first().copied())
}

impl DirectoryWatch {
    pub(super) fn capture(parent: &File, path: &Path, until: Instant) -> io::Result<Self> {
        deadline(until)?;
        let parent = parent.try_clone()?;
        require_parent(&parent, path)?;
        let queue = kqueue()?;
        fcntl_setfd(&queue, FdFlags::CLOEXEC)?;
        let filter = EventFilter::Vnode {
            vnode: parent.as_raw_fd(),
            flags: VnodeEvents::WRITE
                | VnodeEvents::DELETE
                | VnodeEvents::RENAME
                | VnodeEvents::REVOKE
                | VnodeEvents::ATTRIBUTES
                | VnodeEvents::LINK
                | VnodeEvents::EXTEND,
        };
        let change = Event::new(
            filter,
            EventFlags::ADD | EventFlags::CLEAR | EventFlags::RECEIPT,
            std::ptr::null_mut(),
        );
        if !poll(&queue, &[change])?
            .is_some_and(|r| r.flags().contains(EventFlags::ERROR) && r.data() == 0)
        {
            return Err(io::Error::other("socket directory watch was not armed"));
        }
        let socket = socket_id(&parent, path)?;
        let mut watch = Self {
            queue,
            parent,
            socket,
            fenced: false,
        };
        watch.current(path, until)?;
        Ok(watch)
    }

    pub(super) fn current(&mut self, path: &Path, until: Instant) -> io::Result<()> {
        deadline(until)?;
        if !self.fenced
            && require_parent(&self.parent, path).is_ok()
            && socket_id(&self.parent, path).is_ok_and(|s| s == self.socket)
            && matches!(poll(&self.queue, &[]), Ok(None))
        {
            return deadline(until);
        }
        self.fenced = true;
        Err(io::Error::other(
            "original socket directory changed or watch is uncertain",
        ))
    }

    pub(super) fn retire(
        &mut self,
        path: &Path,
        until: Instant,
        refuse_live: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        deadline(until)?;
        if let Err(error) = require_parent(&self.parent, path) {
            self.fenced = true;
            return Err(error);
        }
        match socket_id(&self.parent, path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return deadline(until),
            _ => self.current(path, until)?,
        }
        refuse_live()?;
        self.current(path, until)?;
        unlinkat(
            &self.parent,
            path.file_name().ok_or(io::ErrorKind::InvalidInput)?,
            AtFlags::empty(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{
            fs::{PermissionsExt, symlink},
            net::{UnixListener, UnixStream},
        },
    };

    fn live() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        UnixListener,
        DirectoryWatch,
    ) {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .unwrap();
        let path = root.path().join("journal.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let watch =
            DirectoryWatch::capture(&File::open(root.path()).unwrap(), &path, later()).unwrap();
        (root, path, listener, watch)
    }
    fn later() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }
    fn refused(path: &Path) -> io::Result<()> {
        match UnixStream::connect(path) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            _ => Err(io::Error::other("still live or uncertain")),
        }
    }

    #[test]
    fn unchanged_stale_socket_is_removed_only_after_kernel_refusal() {
        let (_root, path, listener, mut watch) = live();
        assert!(watch.retire(&path, later(), || refused(&path)).is_err());
        assert!(watch.current(&path, later()).is_ok());
        drop(listener);
        watch.retire(&path, later(), || refused(&path)).unwrap();
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn replacement_then_restoration_fences_original_inode_permanently() {
        let (root, path, listener, mut watch) = live();
        let old = fs::symlink_metadata(&path).unwrap();
        let saved = root.path().join("saved");
        fs::rename(&path, &saved).unwrap();
        let other = UnixListener::bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::rename(saved, &path).unwrap();
        let restored = fs::symlink_metadata(&path).unwrap();
        assert_eq!((old.dev(), old.ino()), (restored.dev(), restored.ino()));
        assert!(watch.current(&path, later()).is_err());
        drop((listener, other));
        for _ in 0..2 {
            assert!(
                watch
                    .retire(&path, later(), || panic!("fenced before probe"))
                    .is_err()
            );
            assert!(path.exists());
        }
    }

    #[test]
    fn substituted_names_remain_untouched_and_vacancy_needs_no_probe() {
        let (_root, path, listener, mut watch) = live();
        drop(listener);
        fs::remove_file(&path).unwrap();
        let other = UnixListener::bind(&path).unwrap();
        assert!(
            watch
                .retire(&path, later(), || panic!("substitution"))
                .is_err()
        );
        assert!(UnixStream::connect(&path).is_ok());
        drop(other);
        fs::remove_file(&path).unwrap();
        symlink("absent", &path).unwrap();
        assert!(watch.retire(&path, later(), || panic!("symlink")).is_err());
        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
        fs::remove_file(&path).unwrap();
        watch.retire(&path, later(), || panic!("vacant")).unwrap();
    }

    #[test]
    fn refused_untrusted_parent_and_elapsed_deadline_after_probe_preserve_entry() {
        let (root, path, listener, mut watch) = live();
        drop(listener);
        assert!(
            watch
                .retire(&path, Instant::now(), || panic!("expired"))
                .is_err()
        );
        let until = Instant::now() + Duration::from_millis(40);
        assert!(
            watch
                .retire(&path, until, || {
                    refused(&path)?;
                    std::thread::sleep(
                        until.saturating_duration_since(Instant::now()) + Duration::from_millis(2),
                    );
                    Ok(())
                })
                .is_err()
        );
        assert!(path.exists());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770)).unwrap();
        let parent = File::open(root.path()).unwrap();
        assert!(DirectoryWatch::capture(&parent, &path, later()).is_err());
        assert!(watch.retire(&path, later(), || panic!("parent")).is_err());
        assert!(path.exists());
    }
}
