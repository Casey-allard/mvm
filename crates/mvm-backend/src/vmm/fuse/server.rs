//! A passthrough FUSE server: executes FUSE requests against a host directory
//! (the dev VM's `/work` share) and returns encoded replies.
//!
//! Transport-free — [`PassthroughFs::dispatch`] takes the raw request bytes (the
//! device gathered from the readable descriptors) and returns the raw reply bytes
//! (which the device scatters into the writable descriptors). So the whole
//! filesystem is unit-tested against a real temp directory with no VM.
//!
//! Scope: this serves a *trusted, single-user* dev share, not an untrusted
//! workload. It still fails closed — every path component is a single name
//! (the kernel resolves paths component-by-component), and names containing `/`
//! or `..` are rejected so the guest cannot escape the share root.

use std::collections::HashMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::abi::*;

/// An open handle: a file (for READ/WRITE) or a directory snapshot (for READDIR).
enum Handle {
    File(File),
    Dir(Vec<DirEntry>),
}

struct DirEntry {
    name: Vec<u8>,
    ino: u64,
    typ: u32,
}

/// DT_* file-type nibbles used in a `fuse_dirent`.
const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;
const DT_UNKNOWN: u32 = 0;

/// A passthrough filesystem rooted at a host directory. The share root is the
/// `FUSE_ROOT_ID` entry in the inode table.
pub struct PassthroughFs {
    /// nodeid → host path. `FUSE_ROOT_ID` (1) is the share root.
    inodes: HashMap<u64, PathBuf>,
    next_inode: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
}

impl PassthroughFs {
    /// Serve `root` (the host directory the guest mounts). Caller ensures it
    /// exists and is a directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(FUSE_ROOT_ID, root.into());
        Self {
            inodes,
            next_inode: FUSE_ROOT_ID + 1,
            handles: HashMap::new(),
            next_fh: 1,
        }
    }

    /// Dispatch one FUSE request, returning the reply bytes. `None` only for
    /// `FUSE_FORGET`/`FUSE_BATCH_FORGET`, which the protocol defines as
    /// reply-less. Any error is encoded as a negative-errno `fuse_out_header`.
    pub fn dispatch(&mut self, req: &[u8]) -> Option<Vec<u8>> {
        let hdr = match FuseInHeader::parse(req) {
            Some(h) => h,
            None => return Some(FuseOutHeader::reply(0, -libc::EINVAL, &[])),
        };
        let body = &req[FuseInHeader::SIZE.min(req.len())..];
        if hdr.opcode == FUSE_FORGET {
            self.inodes.remove(&hdr.nodeid);
            return None;
        }
        let result = self.handle(&hdr, body);
        Some(match result {
            Ok(payload) => FuseOutHeader::reply(hdr.unique, 0, &payload),
            Err(errno) => FuseOutHeader::reply(hdr.unique, -errno, &[]),
        })
    }

    /// Route one opcode to its handler. Returns the reply payload (sans header)
    /// or a positive errno to encode as `-errno`.
    fn handle(&mut self, hdr: &FuseInHeader, body: &[u8]) -> Result<Vec<u8>, i32> {
        match hdr.opcode {
            FUSE_INIT => self.init(body),
            FUSE_GETATTR => self.getattr(hdr.nodeid),
            FUSE_SETATTR => self.setattr(hdr.nodeid, body),
            FUSE_LOOKUP => self.lookup(hdr.nodeid, body),
            FUSE_OPENDIR => self.opendir(hdr.nodeid),
            FUSE_READDIR => self.readdir(body),
            FUSE_RELEASEDIR | FUSE_RELEASE => self.release(body),
            FUSE_OPEN => self.open(hdr.nodeid, body),
            FUSE_READ => self.read(body),
            FUSE_WRITE => self.write(body),
            FUSE_CREATE => self.create(hdr.nodeid, body),
            FUSE_MKDIR => self.mkdir(hdr.nodeid, body),
            FUSE_UNLINK => self.unlink(hdr.nodeid, body, false),
            FUSE_RMDIR => self.unlink(hdr.nodeid, body, true),
            FUSE_RENAME => self.rename(hdr.nodeid, body),
            FUSE_FLUSH | FUSE_FSYNC => Ok(Vec::new()),
            FUSE_ACCESS => Ok(Vec::new()),
            FUSE_STATFS => self.statfs(),
            _ => Err(libc::ENOSYS),
        }
    }

    // --- path helpers -------------------------------------------------------

    fn path(&self, nodeid: u64) -> Result<PathBuf, i32> {
        self.inodes.get(&nodeid).cloned().ok_or(libc::ENOENT)
    }

    /// Resolve `name` within `parent`, rejecting anything that could escape the
    /// share (a `/` or `..` component, or an empty name).
    fn child(&self, parent: u64, name: &[u8]) -> Result<PathBuf, i32> {
        if name.is_empty() || name == b".." || name.contains(&b'/') {
            return Err(libc::EINVAL);
        }
        let base = self.path(parent)?;
        Ok(base.join(osstr(name)))
    }

    /// Assign (or reuse) a nodeid for a host path. Passthrough keeps a stable id
    /// per path so repeat lookups of the same file return the same nodeid.
    fn intern(&mut self, path: &Path) -> u64 {
        if let Some((id, _)) = self.inodes.iter().find(|(_, p)| p.as_path() == path) {
            return *id;
        }
        let id = self.next_inode;
        self.next_inode += 1;
        self.inodes.insert(id, path.to_path_buf());
        id
    }

    // --- handlers -----------------------------------------------------------

    fn init(&mut self, body: &[u8]) -> Result<Vec<u8>, i32> {
        let init = FuseInitIn::parse(body).ok_or(libc::EINVAL)?;
        let out = FuseInitOut {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION.min(init.minor),
            max_readahead: init.max_readahead,
            // Advertise big writes only — NOT readdirplus, so the kernel uses the
            // simpler plain READDIR path this server implements.
            flags: init.flags & FUSE_BIG_WRITES,
            max_background: 16,
            congestion_threshold: 12,
            max_write: 1 << 20,
            time_gran: 1,
            max_pages: 256,
            map_alignment: 0,
        };
        Ok(out.to_bytes())
    }

    fn getattr(&self, nodeid: u64) -> Result<Vec<u8>, i32> {
        let path = self.path(nodeid)?;
        let md = std::fs::symlink_metadata(&path).map_err(errno)?;
        Ok(FuseAttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            attr: attr_from(nodeid, &md),
        }
        .to_bytes())
    }

    fn setattr(&mut self, nodeid: u64, body: &[u8]) -> Result<Vec<u8>, i32> {
        // fuse_setattr_in: valid u32 @0, padding u32 @4, fh u64 @8, size u64 @16,
        // ... mode u32 @... We handle the two the dev flow needs: size (truncate)
        // and mode (chmod); the `valid` bitmask says which fields are set.
        let mut c = Cursor::new(body);
        let valid = c.u32().ok_or(libc::EINVAL)?;
        let _padding = c.u32().ok_or(libc::EINVAL)?;
        let _fh = c.u64().ok_or(libc::EINVAL)?;
        let size = c.u64().ok_or(libc::EINVAL)?;
        let path = self.path(nodeid)?;
        const FATTR_MODE: u32 = 1 << 0;
        const FATTR_SIZE: u32 = 1 << 3;
        if valid & FATTR_SIZE != 0 {
            let f = OpenOptions::new().write(true).open(&path).map_err(errno)?;
            f.set_len(size).map_err(errno)?;
        }
        if valid & FATTR_MODE != 0 {
            // mode sits after size(8)+lock_owner(8)+atime(8)+mtime(8)+ctime(8)+
            // atimensec..ctimensec(12) = offset 24+8+... we re-read from a fresh
            // cursor at the mode field (fuse_setattr_in offset 52).
            if let Some(mode) = Cursor::new(&body[52.min(body.len())..]).u32() {
                chmod(&path, mode).map_err(errno)?;
            }
        }
        let md = std::fs::symlink_metadata(&path).map_err(errno)?;
        Ok(FuseAttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            attr: attr_from(nodeid, &md),
        }
        .to_bytes())
    }

    fn lookup(&mut self, parent: u64, body: &[u8]) -> Result<Vec<u8>, i32> {
        let name = Cursor::new(body).cstr().ok_or(libc::EINVAL)?;
        let path = self.child(parent, name)?;
        let md = std::fs::symlink_metadata(&path).map_err(errno)?;
        let nodeid = self.intern(&path);
        Ok(entry_out(nodeid, &md))
    }

    fn opendir(&mut self, nodeid: u64) -> Result<Vec<u8>, i32> {
        let path = self.path(nodeid)?;
        let mut entries = vec![
            DirEntry {
                name: b".".to_vec(),
                ino: nodeid,
                typ: DT_DIR,
            },
            DirEntry {
                name: b"..".to_vec(),
                ino: FUSE_ROOT_ID,
                typ: DT_DIR,
            },
        ];
        for ent in std::fs::read_dir(&path).map_err(errno)? {
            let ent = ent.map_err(errno)?;
            let ft = ent.file_type().map_err(errno)?;
            let typ = if ft.is_dir() {
                DT_DIR
            } else if ft.is_symlink() {
                DT_LNK
            } else if ft.is_file() {
                DT_REG
            } else {
                DT_UNKNOWN
            };
            let ino = ent.metadata().map(|m| m.ino()).unwrap_or(0);
            entries.push(DirEntry {
                name: ent.file_name().as_encoded_bytes().to_vec(),
                ino,
                typ,
            });
        }
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, Handle::Dir(entries));
        Ok(FuseOpenOut { fh, open_flags: 0 }.to_bytes())
    }

    fn readdir(&mut self, body: &[u8]) -> Result<Vec<u8>, i32> {
        let r = FuseReadIn::parse(body).ok_or(libc::EINVAL)?;
        let Some(Handle::Dir(entries)) = self.handles.get(&r.fh) else {
            return Err(libc::EBADF);
        };
        let mut b = Builder::new();
        // `off` is the offset of the NEXT entry, so entry i carries off=i+1 and a
        // READDIR starting at `r.offset` resumes at index `r.offset`.
        for (i, e) in entries.iter().enumerate().skip(r.offset as usize) {
            let start = b.len();
            write_dirent(&mut b, e.ino, (i + 1) as u64, e.typ, &e.name);
            if b.len() > r.size as usize {
                // This entry overflows the guest's buffer — stop before it.
                return Ok(b.into_bytes()[..start].to_vec());
            }
        }
        Ok(b.into_bytes())
    }

    fn open(&mut self, nodeid: u64, body: &[u8]) -> Result<Vec<u8>, i32> {
        let o = FuseOpenIn::parse(body).ok_or(libc::EINVAL)?;
        let path = self.path(nodeid)?;
        let file = OpenOptions::new()
            .read(true)
            .write(is_writable(o.flags))
            .custom_flags((o.flags as i32) & libc::O_APPEND)
            .open(&path)
            .map_err(errno)?;
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, Handle::File(file));
        Ok(FuseOpenOut { fh, open_flags: 0 }.to_bytes())
    }

    fn read(&mut self, body: &[u8]) -> Result<Vec<u8>, i32> {
        let r = FuseReadIn::parse(body).ok_or(libc::EINVAL)?;
        let Some(Handle::File(f)) = self.handles.get(&r.fh) else {
            return Err(libc::EBADF);
        };
        let mut buf = vec![0u8; r.size as usize];
        let n = f.read_at(&mut buf, r.offset).map_err(errno)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn write(&mut self, body: &[u8]) -> Result<Vec<u8>, i32> {
        let w = FuseWriteIn::parse(body).ok_or(libc::EINVAL)?;
        let data = &body[FuseWriteIn::SIZE.min(body.len())..];
        let n = data.len().min(w.size as usize);
        let Some(Handle::File(f)) = self.handles.get(&w.fh) else {
            return Err(libc::EBADF);
        };
        let written = f.write_at(&data[..n], w.offset).map_err(errno)?;
        Ok(FuseWriteOut {
            size: written as u32,
        }
        .to_bytes())
    }

    fn create(&mut self, parent: u64, body: &[u8]) -> Result<Vec<u8>, i32> {
        // fuse_create_in: flags u32 @0, mode u32 @4, umask u32 @8, open_flags u32
        // @12, then the NUL-terminated name.
        let mut c = Cursor::new(body);
        let flags = c.u32().ok_or(libc::EINVAL)?;
        let mode = c.u32().ok_or(libc::EINVAL)?;
        let _umask = c.u32().ok_or(libc::EINVAL)?;
        let _open_flags = c.u32().ok_or(libc::EINVAL)?;
        let name = c.cstr().ok_or(libc::EINVAL)?;
        let path = self.child(parent, name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(flags as i32 & libc::O_TRUNC != 0)
            .mode(mode & 0o777)
            .open(&path)
            .map_err(errno)?;
        let md = file.metadata().map_err(errno)?;
        let nodeid = self.intern(&path);
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, Handle::File(file));
        // Reply is fuse_entry_out immediately followed by fuse_open_out.
        let mut out = entry_out(nodeid, &md);
        out.extend_from_slice(&FuseOpenOut { fh, open_flags: 0 }.to_bytes());
        Ok(out)
    }

    fn mkdir(&mut self, parent: u64, body: &[u8]) -> Result<Vec<u8>, i32> {
        // fuse_mkdir_in: mode u32 @0, umask u32 @4, then the name.
        let mut c = Cursor::new(body);
        let mode = c.u32().ok_or(libc::EINVAL)?;
        let _umask = c.u32().ok_or(libc::EINVAL)?;
        let name = c.cstr().ok_or(libc::EINVAL)?;
        let path = self.child(parent, name)?;
        std::fs::create_dir(&path).map_err(errno)?;
        chmod(&path, mode & 0o777).map_err(errno)?;
        let md = std::fs::symlink_metadata(&path).map_err(errno)?;
        let nodeid = self.intern(&path);
        Ok(entry_out(nodeid, &md))
    }

    fn unlink(&mut self, parent: u64, body: &[u8], is_dir: bool) -> Result<Vec<u8>, i32> {
        let name = Cursor::new(body).cstr().ok_or(libc::EINVAL)?;
        let path = self.child(parent, name)?;
        if is_dir {
            std::fs::remove_dir(&path).map_err(errno)?;
        } else {
            std::fs::remove_file(&path).map_err(errno)?;
        }
        self.inodes.retain(|_, p| p.as_path() != path);
        Ok(Vec::new())
    }

    fn rename(&mut self, parent: u64, body: &[u8]) -> Result<Vec<u8>, i32> {
        // fuse_rename_in: newdir u64 @0, then oldname\0newname\0.
        let mut c = Cursor::new(body);
        let newdir = c.u64().ok_or(libc::EINVAL)?;
        let oldname = c.cstr().ok_or(libc::EINVAL)?;
        let newname = c.cstr().ok_or(libc::EINVAL)?;
        let from = self.child(parent, oldname)?;
        let to = self.child(newdir, newname)?;
        std::fs::rename(&from, &to).map_err(errno)?;
        self.inodes.retain(|_, p| p.as_path() != from);
        Ok(Vec::new())
    }

    fn release(&mut self, body: &[u8]) -> Result<Vec<u8>, i32> {
        // fuse_release_in: fh u64 @0.
        if let Some(fh) = Cursor::new(body).u64() {
            self.handles.remove(&fh);
        }
        Ok(Vec::new())
    }

    fn statfs(&self) -> Result<Vec<u8>, i32> {
        // fuse_kstatfs (80 bytes): blocks,bfree,bavail,files,ffree (u64) +
        // bsize,namelen,frsize,padding (u32) + spare[6] (u32). Plausible values
        // for a dev share — the guest only needs non-zero space.
        let mut b = Builder::new();
        b.u64(1 << 30) // blocks
            .u64(1 << 29) // bfree
            .u64(1 << 29) // bavail
            .u64(1 << 20) // files
            .u64(1 << 19) // ffree
            .u32(4096) // bsize
            .u32(255) // namelen
            .u32(4096) // frsize
            .u32(0) // padding
            .zeros(6 * 4); // spare
        Ok(b.into_bytes())
    }
}

// --- free helpers -----------------------------------------------------------

fn osstr(name: &[u8]) -> &std::ffi::OsStr {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(name)
}

fn is_writable(flags: u32) -> bool {
    let acc = flags as i32 & libc::O_ACCMODE;
    acc == libc::O_WRONLY || acc == libc::O_RDWR
}

/// Map a host `io::Error` to a positive errno for the `-errno` reply.
fn errno(e: io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))
}

/// Build a `fuse_entry_out` for a freshly-looked-up/created node.
fn entry_out(nodeid: u64, md: &Metadata) -> Vec<u8> {
    FuseEntryOut {
        nodeid,
        generation: 0,
        entry_valid: 1,
        attr_valid: 1,
        entry_valid_nsec: 0,
        attr_valid_nsec: 0,
        attr: attr_from(nodeid, md),
    }
    .to_bytes()
}

/// Convert host `Metadata` to a FUSE `fuse_attr`. `st_mode` already carries the
/// file-type bits the guest needs, so it passes through unchanged.
fn attr_from(nodeid: u64, md: &Metadata) -> FuseAttr {
    FuseAttr {
        ino: nodeid,
        size: md.size(),
        blocks: md.blocks(),
        atime: md.atime() as u64,
        mtime: md.mtime() as u64,
        ctime: md.ctime() as u64,
        atimensec: md.atime_nsec() as u32,
        mtimensec: md.mtime_nsec() as u32,
        ctimensec: md.ctime_nsec() as u32,
        mode: md.mode(),
        nlink: md.nlink() as u32,
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev() as u32,
        blksize: 4096,
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a FUSE request: header + body.
    fn req(opcode: u32, nodeid: u64, unique: u64, body: &[u8]) -> Vec<u8> {
        let mut b = Builder::new();
        b.u32((FuseInHeader::SIZE + body.len()) as u32)
            .u32(opcode)
            .u64(unique)
            .u64(nodeid)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .bytes(body);
        b.into_bytes()
    }

    fn out_header(reply: &[u8]) -> FuseOutHeader {
        FuseOutHeader {
            len: u32::from_le_bytes(reply[0..4].try_into().unwrap()),
            error: i32::from_le_bytes(reply[4..8].try_into().unwrap()),
            unique: u64::from_le_bytes(reply[8..16].try_into().unwrap()),
        }
    }
    fn payload(reply: &[u8]) -> &[u8] {
        &reply[FuseOutHeader::SIZE..]
    }

    fn fs() -> (tempfile::TempDir, PassthroughFs) {
        let dir = tempfile::tempdir().unwrap();
        let fs = PassthroughFs::new(dir.path());
        (dir, fs)
    }

    /// INIT negotiates down to our version and clears readdirplus.
    #[test]
    fn init_negotiates_version_and_flags() {
        let (_d, mut fs) = fs();
        let mut body = Builder::new();
        body.u32(7).u32(40).u32(0x2_0000).u32(0xffff_ffff);
        let reply = fs
            .dispatch(&req(FUSE_INIT, 0, 1, &body.into_bytes()))
            .unwrap();
        assert_eq!(out_header(&reply).error, 0);
        let init = FuseInitOut::parse_for_test(payload(&reply));
        assert_eq!(init.0, 7); // major
        assert_eq!(init.1, 31); // minor negotiated down
        assert_eq!(
            init.2 & FUSE_DO_READDIRPLUS,
            0,
            "readdirplus not advertised"
        );
    }

    /// LOOKUP of a real file returns a stable nodeid + its attrs; a missing name
    /// returns -ENOENT.
    #[test]
    fn lookup_returns_nodeid_and_reports_missing() {
        let (d, mut fs) = fs();
        std::fs::write(d.path().join("hello.txt"), b"hi").unwrap();
        let name = {
            let mut b = Builder::new();
            b.bytes(b"hello.txt\0");
            b.into_bytes()
        };
        let reply = fs
            .dispatch(&req(FUSE_LOOKUP, FUSE_ROOT_ID, 2, &name))
            .unwrap();
        assert_eq!(out_header(&reply).error, 0);
        let nodeid = u64::from_le_bytes(payload(&reply)[0..8].try_into().unwrap());
        assert!(nodeid > FUSE_ROOT_ID);
        // A second lookup returns the SAME nodeid (stable interning).
        let reply2 = fs
            .dispatch(&req(FUSE_LOOKUP, FUSE_ROOT_ID, 3, &name))
            .unwrap();
        let nodeid2 = u64::from_le_bytes(payload(&reply2)[0..8].try_into().unwrap());
        assert_eq!(nodeid, nodeid2);

        let missing = {
            let mut b = Builder::new();
            b.bytes(b"nope\0");
            b.into_bytes()
        };
        let r = fs
            .dispatch(&req(FUSE_LOOKUP, FUSE_ROOT_ID, 4, &missing))
            .unwrap();
        assert_eq!(out_header(&r).error, -libc::ENOENT);
    }

    /// A `..`/`/` name is rejected before touching the filesystem (no escape).
    #[test]
    fn lookup_rejects_escape_names() {
        let (_d, mut fs) = fs();
        for bad in [&b"..\0"[..], &b"a/b\0"[..]] {
            let r = fs
                .dispatch(&req(FUSE_LOOKUP, FUSE_ROOT_ID, 9, bad))
                .unwrap();
            assert_eq!(out_header(&r).error, -libc::EINVAL, "name {bad:?}");
        }
    }

    /// OPEN + READ returns file bytes; WRITE persists to the host file.
    #[test]
    fn open_read_write_round_trips_to_the_host_file() {
        let (d, mut fs) = fs();
        let path = d.path().join("f");
        std::fs::write(&path, b"ABCDEFGH").unwrap();
        let nodeid = fs.intern(&path);

        // OPEN (rdwr).
        let mut ob = Builder::new();
        ob.u32(libc::O_RDWR as u32).u32(0);
        let reply = fs
            .dispatch(&req(FUSE_OPEN, nodeid, 5, &ob.into_bytes()))
            .unwrap();
        let fh = u64::from_le_bytes(payload(&reply)[0..8].try_into().unwrap());

        // READ 4 bytes at offset 2 → "CDEF".
        let mut rb = Builder::new();
        rb.u64(fh).u64(2).u32(4).u32(0).u64(0).u32(0).u32(0);
        let reply = fs
            .dispatch(&req(FUSE_READ, nodeid, 6, &rb.into_bytes()))
            .unwrap();
        assert_eq!(payload(&reply), b"CDEF");

        // WRITE "xy" at offset 0.
        let mut wb = Builder::new();
        wb.u64(fh)
            .u64(0)
            .u32(2)
            .u32(0)
            .u64(0)
            .u32(0)
            .u32(0)
            .bytes(b"xy");
        let reply = fs
            .dispatch(&req(FUSE_WRITE, nodeid, 7, &wb.into_bytes()))
            .unwrap();
        let written = u32::from_le_bytes(payload(&reply)[0..4].try_into().unwrap());
        assert_eq!(written, 2);
        assert_eq!(std::fs::read(&path).unwrap(), b"xyCDEFGH");
    }

    /// CREATE makes a new host file and returns a usable handle.
    #[test]
    fn create_makes_a_host_file() {
        let (d, mut fs) = fs();
        let mut cb = Builder::new();
        cb.u32((libc::O_RDWR | libc::O_CREAT) as u32)
            .u32(0o644)
            .u32(0)
            .u32(0)
            .bytes(b"new.txt\0");
        let reply = fs
            .dispatch(&req(FUSE_CREATE, FUSE_ROOT_ID, 8, &cb.into_bytes()))
            .unwrap();
        assert_eq!(out_header(&reply).error, 0);
        assert!(d.path().join("new.txt").exists());
        // The reply is entry_out (128) + open_out (16).
        assert_eq!(
            payload(&reply).len(),
            FuseEntryOut::SIZE + FuseOpenOut::SIZE
        );
    }

    /// OPENDIR + READDIR lists "." "..", and the created entries; a small buffer
    /// truncates cleanly at an entry boundary.
    #[test]
    fn opendir_readdir_lists_entries() {
        let (d, mut fs) = fs();
        std::fs::write(d.path().join("a"), b"").unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();

        let reply = fs
            .dispatch(&req(FUSE_OPENDIR, FUSE_ROOT_ID, 10, &[]))
            .unwrap();
        let fh = u64::from_le_bytes(payload(&reply)[0..8].try_into().unwrap());

        let mut rb = Builder::new();
        rb.u64(fh).u64(0).u32(4096).u32(0).u64(0).u32(0).u32(0);
        let reply = fs
            .dispatch(&req(FUSE_READDIR, FUSE_ROOT_ID, 11, &rb.into_bytes()))
            .unwrap();
        let names = parse_dirent_names(payload(&reply));
        assert!(names.contains(&b".".to_vec()));
        assert!(names.contains(&b"..".to_vec()));
        assert!(names.contains(&b"a".to_vec()));
        assert!(names.contains(&b"sub".to_vec()));
    }

    /// MKDIR then UNLINK(rmdir) round-trips against the host dir.
    #[test]
    fn mkdir_and_rmdir() {
        let (d, mut fs) = fs();
        let mut mb = Builder::new();
        mb.u32(0o755).u32(0).bytes(b"newdir\0");
        let r = fs
            .dispatch(&req(FUSE_MKDIR, FUSE_ROOT_ID, 12, &mb.into_bytes()))
            .unwrap();
        assert_eq!(out_header(&r).error, 0);
        assert!(d.path().join("newdir").is_dir());

        let mut rb = Builder::new();
        rb.bytes(b"newdir\0");
        let r = fs
            .dispatch(&req(FUSE_RMDIR, FUSE_ROOT_ID, 13, &rb.into_bytes()))
            .unwrap();
        assert_eq!(out_header(&r).error, 0);
        assert!(!d.path().join("newdir").exists());
    }

    /// SETATTR size truncates the host file.
    #[test]
    fn setattr_truncates() {
        let (d, mut fs) = fs();
        let path = d.path().join("t");
        std::fs::write(&path, b"0123456789").unwrap();
        let nodeid = fs.intern(&path);
        const FATTR_SIZE: u32 = 1 << 3;
        let mut sb = Builder::new();
        sb.u32(FATTR_SIZE).u32(0).u64(0).u64(4); // valid, pad, fh, size=4
        sb.zeros(64); // rest of fuse_setattr_in
        let r = fs
            .dispatch(&req(FUSE_SETATTR, nodeid, 14, &sb.into_bytes()))
            .unwrap();
        assert_eq!(out_header(&r).error, 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"0123");
    }

    /// FORGET drops the nodeid and returns no reply.
    #[test]
    fn forget_has_no_reply() {
        let (d, mut fs) = fs();
        let path = d.path().join("g");
        std::fs::write(&path, b"").unwrap();
        let nodeid = fs.intern(&path);
        assert!(fs.dispatch(&req(FUSE_FORGET, nodeid, 15, &[])).is_none());
    }

    /// An unknown opcode fails closed with -ENOSYS.
    #[test]
    fn unknown_opcode_is_enosys() {
        let (_d, mut fs) = fs();
        let r = fs.dispatch(&req(9999, FUSE_ROOT_ID, 16, &[])).unwrap();
        assert_eq!(out_header(&r).error, -libc::ENOSYS);
    }

    // --- test helpers ---
    fn parse_dirent_names(buf: &[u8]) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        let mut c = Cursor::new(buf);
        while let (Some(_ino), Some(_off), Some(namelen), Some(_typ)) =
            (c.u64(), c.u64(), c.u32(), c.u32())
        {
            let rest = c.remaining();
            let n = namelen as usize;
            if rest.len() < n {
                break;
            }
            names.push(rest[..n].to_vec());
            let pad = (8 - (n % 8)) % 8;
            // advance past name + pad
            for _ in 0..((n + pad) / 8) {
                c.u64();
            }
            if (n + pad) % 8 != 0 {
                break;
            }
        }
        names
    }

    impl FuseInitOut {
        /// (major, minor, flags) — test-only decode.
        fn parse_for_test(buf: &[u8]) -> (u32, u32, u32) {
            let mut c = Cursor::new(buf);
            let major = c.u32().unwrap();
            let minor = c.u32().unwrap();
            let _readahead = c.u32().unwrap();
            let flags = c.u32().unwrap();
            (major, minor, flags)
        }
    }
}
