//! FUSE wire ABI (little-endian) for the in-house virtio-fs device.
//!
//! virtio-fs carries the Linux **FUSE** protocol over a virtqueue: each request
//! descriptor chain is a `fuse_in_header` + an opcode-specific struct (+ data),
//! and the device replies with a `fuse_out_header` + payload. These structs
//! mirror `include/uapi/linux/fuse.h` byte-for-byte — the guest kernel's fuse
//! driver reads them by C layout, so field order/size/padding are ABI and must
//! not drift. We encode/decode explicitly (little-endian, the only endianness the
//! guest+host share here) rather than transmuting `#[repr(C)]`, matching the rest
//! of the device model and keeping every field boundary test-visible.

/// Protocol version we implement. The guest sends its own (usually newer) version
/// in `FUSE_INIT`; we reply with `min(theirs, ours)` and the guest adapts.
pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

// Opcodes (subset we service; others get -ENOSYS).
pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2; // no reply
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_SETATTR: u32 = 4;
pub const FUSE_MKDIR: u32 = 9;
pub const FUSE_UNLINK: u32 = 10;
pub const FUSE_RMDIR: u32 = 11;
pub const FUSE_RENAME: u32 = 12;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_WRITE: u32 = 16;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_FSYNC: u32 = 20;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_ACCESS: u32 = 34;
pub const FUSE_CREATE: u32 = 35;
pub const FUSE_LSEEK: u32 = 46;

/// The well-known root inode id (the shared directory itself).
pub const FUSE_ROOT_ID: u64 = 1;

/// FUSE_INIT flag: the guest supports the `fuse_attr.flags`/`fuse_open_out` big
/// writes etc. We negotiate a conservative flag set (see `FuseInitOut`).
pub const FUSE_BIG_WRITES: u32 = 1 << 5;
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;

/// A little-endian byte cursor for decoding request payloads. Every read is
/// bounds-checked; a short buffer yields `None` so a malformed guest request
/// fails closed (→ `-EINVAL`) rather than reading past the end.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    /// A NUL-terminated name (as FUSE encodes `LOOKUP`/`CREATE`/… names).
    pub fn cstr(&mut self) -> Option<&'a [u8]> {
        let rest = self.remaining();
        let nul = rest.iter().position(|&b| b == 0)?;
        self.pos += nul + 1;
        Some(&rest[..nul])
    }
}

/// A little-endian byte builder for response payloads.
#[derive(Default)]
pub struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn zeros(&mut self, n: usize) -> &mut Self {
        self.buf.resize(self.buf.len() + n, 0);
        self
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// `struct fuse_in_header` (40 bytes) — prefixes every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

impl FuseInHeader {
    pub const SIZE: usize = 40;
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(buf);
        Some(Self {
            len: c.u32()?,
            opcode: c.u32()?,
            unique: c.u64()?,
            nodeid: c.u64()?,
            uid: c.u32()?,
            gid: c.u32()?,
            pid: c.u32()?,
            padding: c.u32()?,
        })
    }
}

/// `struct fuse_out_header` (16 bytes) — prefixes every reply. `error` is 0 on
/// success or a negative errno (e.g. `-libc::ENOENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

impl FuseOutHeader {
    pub const SIZE: usize = 16;
    /// Build the full reply bytes: header (with `len` = header+payload) + payload.
    pub fn reply(unique: u64, error: i32, payload: &[u8]) -> Vec<u8> {
        let len = (Self::SIZE + payload.len()) as u32;
        let mut b = Builder::new();
        b.u32(len).i32(error).u64(unique).bytes(payload);
        b.into_bytes()
    }
}

/// `struct fuse_init_in` — the guest's negotiated version/flags.
#[derive(Debug, Clone, Copy)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

impl FuseInitIn {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(buf);
        Some(Self {
            major: c.u32()?,
            minor: c.u32()?,
            max_readahead: c.u32()?,
            flags: c.u32()?,
        })
    }
}

/// `struct fuse_init_out` — our negotiated reply. We reply with a v7.31 layout
/// (major/minor/max_readahead/flags/max_background/congestion/max_write/
/// time_gran/max_pages/map_alignment/flags2/unused[7]) = 64 bytes.
#[derive(Debug, Clone, Copy)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
}

impl FuseInitOut {
    pub const SIZE: usize = 64;
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Builder::new();
        b.u32(self.major)
            .u32(self.minor)
            .u32(self.max_readahead)
            .u32(self.flags)
            .u16(self.max_background)
            .u16(self.congestion_threshold)
            .u32(self.max_write)
            .u32(self.time_gran)
            .u16(self.max_pages)
            .u16(self.map_alignment)
            .u32(0) // flags2
            .zeros(7 * 4); // unused[7]
        debug_assert_eq!(b.len(), Self::SIZE);
        b.into_bytes()
    }
}

/// `struct fuse_attr` (88 bytes) — a stat result in FUSE wire form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

impl FuseAttr {
    pub const SIZE: usize = 88;
    pub fn write(&self, b: &mut Builder) {
        b.u64(self.ino)
            .u64(self.size)
            .u64(self.blocks)
            .u64(self.atime)
            .u64(self.mtime)
            .u64(self.ctime)
            .u32(self.atimensec)
            .u32(self.mtimensec)
            .u32(self.ctimensec)
            .u32(self.mode)
            .u32(self.nlink)
            .u32(self.uid)
            .u32(self.gid)
            .u32(self.rdev)
            .u32(self.blksize)
            .u32(self.flags);
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Builder::new();
        self.write(&mut b);
        b.into_bytes()
    }
}

/// `struct fuse_entry_out` (128 bytes) — a `LOOKUP`/`CREATE`/`MKDIR` result:
/// the new nodeid + its attributes + cache-validity timeouts.
#[derive(Debug, Clone, Copy)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

impl FuseEntryOut {
    pub const SIZE: usize = 40 + FuseAttr::SIZE;
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Builder::new();
        b.u64(self.nodeid)
            .u64(self.generation)
            .u64(self.entry_valid)
            .u64(self.attr_valid)
            .u32(self.entry_valid_nsec)
            .u32(self.attr_valid_nsec);
        self.attr.write(&mut b);
        debug_assert_eq!(b.len(), Self::SIZE);
        b.into_bytes()
    }
}

/// `struct fuse_attr_out` (104 bytes) — a `GETATTR`/`SETATTR` result.
#[derive(Debug, Clone, Copy)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

impl FuseAttrOut {
    pub const SIZE: usize = 16 + FuseAttr::SIZE;
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Builder::new();
        b.u64(self.attr_valid).u32(self.attr_valid_nsec).u32(0);
        self.attr.write(&mut b);
        debug_assert_eq!(b.len(), Self::SIZE);
        b.into_bytes()
    }
}

/// `struct fuse_open_in` (8 bytes).
#[derive(Debug, Clone, Copy)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub open_flags: u32,
}
impl FuseOpenIn {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(buf);
        Some(Self {
            flags: c.u32()?,
            open_flags: c.u32()?,
        })
    }
}

/// `struct fuse_open_out` (16 bytes).
#[derive(Debug, Clone, Copy)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
}
impl FuseOpenOut {
    pub const SIZE: usize = 16;
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Builder::new();
        b.u64(self.fh).u32(self.open_flags).u32(0);
        b.into_bytes()
    }
}

/// `struct fuse_read_in` (40 bytes).
#[derive(Debug, Clone, Copy)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}
impl FuseReadIn {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(buf);
        Some(Self {
            fh: c.u64()?,
            offset: c.u64()?,
            size: c.u32()?,
            read_flags: c.u32()?,
            lock_owner: c.u64()?,
            flags: c.u32()?,
            padding: c.u32()?,
        })
    }
}

/// `struct fuse_write_in` (40 bytes) — followed by `size` data bytes.
#[derive(Debug, Clone, Copy)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}
impl FuseWriteIn {
    pub const SIZE: usize = 40;
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(buf);
        Some(Self {
            fh: c.u64()?,
            offset: c.u64()?,
            size: c.u32()?,
            write_flags: c.u32()?,
            lock_owner: c.u64()?,
            flags: c.u32()?,
            padding: c.u32()?,
        })
    }
}

/// `struct fuse_write_out` (8 bytes).
#[derive(Debug, Clone, Copy)]
pub struct FuseWriteOut {
    pub size: u32,
}
impl FuseWriteOut {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Builder::new();
        b.u32(self.size).u32(0);
        b.into_bytes()
    }
}

/// Encode one `struct fuse_dirent` into `b`, 8-byte aligned (as the guest
/// expects when walking a `READDIR` buffer). `typ` is a `DT_*` value.
pub fn write_dirent(b: &mut Builder, ino: u64, off: u64, typ: u32, name: &[u8]) {
    b.u64(ino)
        .u64(off)
        .u32(name.len() as u32)
        .u32(typ)
        .bytes(name);
    let pad = (8 - (name.len() % 8)) % 8;
    b.zeros(pad);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_header_roundtrips_and_is_40_bytes() {
        let mut b = Builder::new();
        b.u32(40)
            .u32(FUSE_LOOKUP)
            .u64(0xdead_beef)
            .u64(FUSE_ROOT_ID)
            .u32(501)
            .u32(20)
            .u32(999)
            .u32(0);
        let bytes = b.into_bytes();
        assert_eq!(bytes.len(), FuseInHeader::SIZE);
        let h = FuseInHeader::parse(&bytes).unwrap();
        assert_eq!(h.opcode, FUSE_LOOKUP);
        assert_eq!(h.unique, 0xdead_beef);
        assert_eq!(h.nodeid, FUSE_ROOT_ID);
        assert_eq!(h.uid, 501);
    }

    #[test]
    fn out_header_reply_prefixes_len_and_error() {
        let r = FuseOutHeader::reply(7, -libc::ENOENT, b"body");
        assert_eq!(&r[0..4], &((FuseOutHeader::SIZE + 4) as u32).to_le_bytes());
        assert_eq!(&r[4..8], &(-libc::ENOENT).to_le_bytes());
        assert_eq!(&r[8..16], &7u64.to_le_bytes());
        assert_eq!(&r[16..], b"body");
    }

    #[test]
    fn fixed_struct_sizes_match_the_fuse_abi() {
        assert_eq!(FuseInHeader::SIZE, 40);
        assert_eq!(FuseOutHeader::SIZE, 16);
        assert_eq!(FuseAttr::SIZE, 88);
        assert_eq!(FuseAttr::default().to_bytes().len(), 88);
        assert_eq!(FuseEntryOut::SIZE, 128);
        assert_eq!(FuseAttrOut::SIZE, 104);
        assert_eq!(FuseInitOut::SIZE, 64);
        assert_eq!(FuseOpenOut::SIZE, 16);
    }

    #[test]
    fn init_out_encodes_the_v731_layout() {
        let out = FuseInitOut {
            major: 7,
            minor: 31,
            max_readahead: 0x2_0000,
            flags: FUSE_BIG_WRITES,
            max_background: 16,
            congestion_threshold: 12,
            max_write: 1 << 20,
            time_gran: 1,
            max_pages: 256,
            map_alignment: 0,
        };
        let b = out.to_bytes();
        assert_eq!(b.len(), 64);
        assert_eq!(&b[0..4], &7u32.to_le_bytes());
        assert_eq!(&b[4..8], &31u32.to_le_bytes());
        assert_eq!(&b[12..16], &FUSE_BIG_WRITES.to_le_bytes());
    }

    #[test]
    fn entry_out_places_attr_after_the_40_byte_prefix() {
        let e = FuseEntryOut {
            nodeid: 42,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: FuseAttr {
                ino: 42,
                mode: 0o40_755,
                ..Default::default()
            },
        };
        let b = e.to_bytes();
        assert_eq!(b.len(), 128);
        assert_eq!(&b[0..8], &42u64.to_le_bytes());
        // attr.ino sits at offset 40 (start of the embedded fuse_attr).
        assert_eq!(&b[40..48], &42u64.to_le_bytes());
    }

    #[test]
    fn cursor_reads_cstr_names_and_fails_closed_on_short_input() {
        let mut c = Cursor::new(b"hello\0rest");
        assert_eq!(c.cstr().unwrap(), b"hello");
        assert_eq!(c.remaining(), b"rest");
        // A truncated fixed field yields None (fail-closed → -EINVAL upstream).
        let mut short = Cursor::new(&[1u8, 2, 3]);
        assert!(short.u32().is_none());
    }

    #[test]
    fn dirent_is_8_byte_aligned() {
        let mut b = Builder::new();
        write_dirent(&mut b, 2, 1, 4 /* DT_DIR */, b"abc");
        // 24-byte fixed header + 3-byte name + 5 pad = 32 (8-aligned).
        assert_eq!(b.len(), 32);
        let mut b2 = Builder::new();
        write_dirent(&mut b2, 2, 1, 8 /* DT_REG */, b"12345678");
        // name already 8-aligned → no pad: 24 + 8 = 32.
        assert_eq!(b2.len(), 32);
    }
}
