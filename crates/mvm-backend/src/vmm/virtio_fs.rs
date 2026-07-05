//! virtio-fs (virtio device id 26): carries the Linux FUSE protocol over a
//! virtqueue so the guest mounts a host directory as a live filesystem — the dev
//! VM's `/work` share.
//!
//! Same virtio-mmio (modern / v2) transport as [`super::virtio::VirtioBlk`], but
//! each descriptor chain is a FUSE request rather than a block request: the
//! readable descriptors hold `fuse_in_header` + payload, the writable descriptors
//! receive `fuse_out_header` + reply. This device only does the transport — it
//! gathers the request, hands it to the transport-free [`PassthroughFs`], and
//! scatters the reply. The filesystem logic + its tests live in [`super::fuse`].
//!
//! Two virtqueues per the virtio-fs spec: queue 0 (hiprio, `FORGET`) and queue 1
//! (requests) for `num_request_queues == 1`. Both drain through the same path;
//! the server handles a reply-less `FORGET`.

use std::path::Path;

use super::fuse::PassthroughFs;
use super::guest_mem::GuestMem;

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_VERSION: u32 = 2;
const VIRTIO_ID_FS: u32 = 26;
const VIRTIO_VENDOR: u32 = 0x4d56_4d76; // "vMVM"

// virtio-mmio register offsets (v2) — identical to the block device's map.
const R_MAGIC: u64 = 0x000;
const R_VERSION: u64 = 0x004;
const R_DEVICE_ID: u64 = 0x008;
const R_VENDOR_ID: u64 = 0x00c;
const R_DEVICE_FEATURES: u64 = 0x010;
const R_DEVICE_FEATURES_SEL: u64 = 0x014;
const R_DRIVER_FEATURES: u64 = 0x020;
const R_DRIVER_FEATURES_SEL: u64 = 0x024;
const R_QUEUE_SEL: u64 = 0x030;
const R_QUEUE_NUM_MAX: u64 = 0x034;
const R_QUEUE_NUM: u64 = 0x038;
const R_QUEUE_READY: u64 = 0x044;
const R_QUEUE_NOTIFY: u64 = 0x050;
const R_INTERRUPT_STATUS: u64 = 0x060;
const R_INTERRUPT_ACK: u64 = 0x064;
const R_STATUS: u64 = 0x070;
const R_QUEUE_DESC_LO: u64 = 0x080;
const R_QUEUE_DESC_HI: u64 = 0x084;
const R_QUEUE_DRIVER_LO: u64 = 0x090;
const R_QUEUE_DRIVER_HI: u64 = 0x094;
const R_QUEUE_DEVICE_LO: u64 = 0x0a0;
const R_QUEUE_DEVICE_HI: u64 = 0x0a4;
/// virtio_fs_config: `u8 tag[36]` at +0, `__le32 num_request_queues` at +36.
const R_CONFIG: u64 = 0x100;

const MMIO_LEN: u64 = 0x200;
const QUEUE_SIZE_MAX: u32 = 256;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// virtio-fs config tag length (fixed 36 bytes, NUL-padded).
const TAG_LEN: usize = 36;
/// Queue count: 1 hiprio + 1 request queue (`num_request_queues == 1`).
const NUM_QUEUES: usize = 2;
const NUM_REQUEST_QUEUES: u32 = 1;

/// Per-queue split-virtqueue state.
#[derive(Default, Clone, Copy)]
struct VirtQueue {
    num: u32,
    ready: u32,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
}

/// A virtio-mmio virtio-fs device backed by a [`PassthroughFs`].
pub struct VirtioFs {
    base: u64,
    irq: u32,
    mem: GuestMem,
    fs: PassthroughFs,
    tag: [u8; TAG_LEN],

    device_features_sel: u32,
    driver_features_sel: u32,
    status: u32,
    queue_sel: u32,
    queues: [VirtQueue; NUM_QUEUES],
    interrupt_status: u32,
}

impl VirtioFs {
    /// # Safety
    /// `ram` must point to `ram_size` bytes mapped as guest RAM at `ram_base`,
    /// valid for the device's lifetime.
    pub unsafe fn new(
        base: u64,
        irq: u32,
        ram: *mut u8,
        ram_base: u64,
        ram_size: usize,
        tag: &str,
        share_root: &Path,
    ) -> Self {
        let mut tag_buf = [0u8; TAG_LEN];
        let bytes = tag.as_bytes();
        let n = bytes.len().min(TAG_LEN);
        tag_buf[..n].copy_from_slice(&bytes[..n]);
        Self {
            base,
            irq,
            // SAFETY: forwarded from this fn's contract.
            mem: unsafe { GuestMem::new(ram, ram_base, ram_size) },
            fs: PassthroughFs::new(share_root),
            tag: tag_buf,
            device_features_sel: 0,
            driver_features_sel: 0,
            status: 0,
            queue_sel: 0,
            queues: [VirtQueue::default(); NUM_QUEUES],
            interrupt_status: 0,
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + MMIO_LEN
    }
    pub fn irq(&self) -> u32 {
        self.irq
    }

    fn config_u32(&self, off: u64) -> u32 {
        // 40-byte config: tag[36] then num_request_queues (LE u32).
        let mut cfg = [0u8; TAG_LEN + 4];
        cfg[..TAG_LEN].copy_from_slice(&self.tag);
        cfg[TAG_LEN..].copy_from_slice(&NUM_REQUEST_QUEUES.to_le_bytes());
        let o = off as usize;
        let mut word = [0u8; 4];
        for (i, b) in word.iter_mut().enumerate() {
            if let Some(v) = cfg.get(o + i) {
                *b = *v;
            }
        }
        u32::from_le_bytes(word)
    }

    /// Handle an MMIO read at `offset` from the device base.
    pub fn read(&self, offset: u64) -> u64 {
        u64::from(match offset {
            R_MAGIC => VIRTIO_MAGIC,
            R_VERSION => VIRTIO_VERSION,
            R_DEVICE_ID => VIRTIO_ID_FS,
            R_VENDOR_ID => VIRTIO_VENDOR,
            // High word (bit 32): VIRTIO_F_VERSION_1. No low-word features.
            R_DEVICE_FEATURES if self.device_features_sel == 1 => 1,
            R_DEVICE_FEATURES => 0,
            R_QUEUE_NUM_MAX => QUEUE_SIZE_MAX,
            R_QUEUE_READY => self.queue(self.queue_sel).ready,
            R_INTERRUPT_STATUS => self.interrupt_status,
            R_STATUS => self.status,
            o if (R_CONFIG..R_CONFIG + (TAG_LEN as u64) + 4).contains(&o) => {
                let v = self.config_u32(o - R_CONFIG);
                if std::env::var_os("MVM_HVF_VIRTIO_DEBUG").is_some() {
                    eprintln!(
                        "virtio-fs: config read off={:#x} -> {:#010x}",
                        o - R_CONFIG,
                        v
                    );
                }
                v
            }
            _ => 0,
        })
    }

    /// Handle an MMIO write at `offset`. Returns `true` if a queue was serviced
    /// (the guest needs an interrupt).
    pub fn write(&mut self, offset: u64, value: u64) -> bool {
        let v = value as u32;
        match offset {
            R_DEVICE_FEATURES_SEL => self.device_features_sel = v,
            R_DRIVER_FEATURES_SEL => self.driver_features_sel = v,
            R_DRIVER_FEATURES => {}
            R_QUEUE_SEL => self.queue_sel = v,
            R_QUEUE_NUM => self.queue_mut().num = v,
            R_QUEUE_READY => self.queue_mut().ready = v,
            R_STATUS => self.status = v,
            R_INTERRUPT_ACK => self.interrupt_status &= !v,
            R_QUEUE_DESC_LO => {
                let q = self.queue_mut();
                q.desc = (q.desc & !0xffff_ffff) | u64::from(v);
            }
            R_QUEUE_DESC_HI => {
                let q = self.queue_mut();
                q.desc = (q.desc & 0xffff_ffff) | (u64::from(v) << 32);
            }
            R_QUEUE_DRIVER_LO => {
                let q = self.queue_mut();
                q.avail = (q.avail & !0xffff_ffff) | u64::from(v);
            }
            R_QUEUE_DRIVER_HI => {
                let q = self.queue_mut();
                q.avail = (q.avail & 0xffff_ffff) | (u64::from(v) << 32);
            }
            R_QUEUE_DEVICE_LO => {
                let q = self.queue_mut();
                q.used = (q.used & !0xffff_ffff) | u64::from(v);
            }
            R_QUEUE_DEVICE_HI => {
                let q = self.queue_mut();
                q.used = (q.used & 0xffff_ffff) | (u64::from(v) << 32);
            }
            R_QUEUE_NOTIFY => return self.process_queue(v as usize),
            _ => {}
        }
        false
    }

    fn queue(&self, sel: u32) -> &VirtQueue {
        &self.queues[(sel as usize).min(NUM_QUEUES - 1)]
    }
    fn queue_mut(&mut self) -> &mut VirtQueue {
        let i = (self.queue_sel as usize).min(NUM_QUEUES - 1);
        &mut self.queues[i]
    }

    /// Drain the available ring for queue `qi`, servicing each FUSE request.
    /// Returns whether any request completed (→ interrupt).
    fn process_queue(&mut self, qi: usize) -> bool {
        if qi >= NUM_QUEUES {
            return false;
        }
        let q = self.queues[qi];
        if q.ready == 0 || q.num == 0 {
            return false;
        }
        let qsz = q.num as u16;
        let avail_idx = self.mem.rd_u16(q.avail + 2);
        let mut serviced = false;
        // `last_avail` is read live from `self.queues[qi]` each iteration so the
        // loop sees its own increments; `q` is only an immutable snapshot of the
        // queue's ring addresses.
        while self.queues[qi].last_avail != avail_idx {
            let last = self.queues[qi].last_avail;
            let slot = last % qsz;
            let head = self.mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            let written = self.service_request(&q, head, qsz);

            let used_idx = self.mem.rd_u16(q.used + 2);
            let uslot = u64::from(used_idx % qsz);
            self.mem.wr_u16(q.used + 4 + uslot * 8, head);
            self.mem.wr_u16(q.used + 6 + uslot * 8, 0);
            self.mem.wr_u16(q.used + 8 + uslot * 8, written as u16);
            self.mem
                .wr_u16(q.used + 10 + uslot * 8, (written >> 16) as u16);
            self.mem.wr_u16(q.used + 2, used_idx.wrapping_add(1));
            self.queues[qi].last_avail = last.wrapping_add(1);
            serviced = true;
        }
        if serviced {
            self.interrupt_status |= 1;
        }
        serviced
    }

    /// Service one descriptor chain: gather the readable descriptors into the FUSE
    /// request, dispatch it, and scatter the reply across the writable
    /// descriptors. Returns bytes written into device-writable buffers.
    fn service_request(&mut self, q: &VirtQueue, head: u16, qsz: u16) -> u32 {
        let desc_at = |i: u16| q.desc + u64::from(i) * 16;

        // Walk the chain once, splitting readable (request) from writable (reply).
        let mut req = Vec::new();
        let mut writable: Vec<(u64, u32)> = Vec::new();
        let mut idx = head;
        let mut guard = 0u32;
        loop {
            let da = desc_at(idx);
            let addr = self.mem.rd_u64(da);
            let len = self.mem.rd_u32(da + 8);
            let flags = self.mem.rd_u16(da + 12);
            if flags & VIRTQ_DESC_F_WRITE != 0 {
                writable.push((addr, len));
            } else {
                req.extend_from_slice(&self.mem.read_bytes(addr, len as usize));
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            let next = self.mem.rd_u16(da + 14);
            if next >= qsz {
                break;
            }
            idx = next;
            guard += 1;
            if guard > qsz as u32 {
                break;
            }
        }

        if std::env::var_os("MVM_HVF_VIRTIO_DEBUG").is_some() {
            let op = if req.len() >= 8 {
                u32::from_le_bytes(req[4..8].try_into().unwrap())
            } else {
                0
            };
            eprintln!(
                "virtio-fs: req len={} opcode={op} writable_descs={}",
                req.len(),
                writable.len()
            );
        }
        let Some(reply) = self.fs.dispatch(&req) else {
            // FORGET and friends have no reply.
            return 0;
        };
        scatter(&self.mem, &writable, &reply)
    }
}

/// Copy `reply` across the writable descriptors in order, returning bytes written
/// (the used-ring `len`). A reply larger than the guest's buffers is truncated —
/// the guest sizes replies from the negotiated `max_write`, so this is a guard.
fn scatter(mem: &GuestMem, writable: &[(u64, u32)], reply: &[u8]) -> u32 {
    let mut off = 0usize;
    for &(addr, len) in writable {
        if off >= reply.len() {
            break;
        }
        let n = (len as usize).min(reply.len() - off);
        mem.write_bytes(addr, &reply[off..off + n]);
        off += n;
    }
    off as u32
}

#[cfg(test)]
mod tests {
    use super::super::fuse::abi::*;
    use super::*;

    const BASE: u64 = 0x4000_0000;

    /// Drive one FUSE request through the split virtqueue against a temp share and
    /// return the reply bytes the device scattered into the writable descriptor.
    struct Harness {
        ram: Vec<u8>,
    }
    impl Harness {
        fn new() -> Self {
            Self {
                ram: vec![0u8; 0x20000],
            }
        }
        fn put(&mut self, gpa: u64, bytes: &[u8]) {
            let off = (gpa - BASE) as usize;
            self.ram[off..off + bytes.len()].copy_from_slice(bytes);
        }
        fn get(&self, gpa: u64, len: usize) -> Vec<u8> {
            let off = (gpa - BASE) as usize;
            self.ram[off..off + len].to_vec()
        }
    }

    fn mk_desc(addr: u64, len: u32, flags: u16, next: u16) -> [u8; 16] {
        let mut d = [0u8; 16];
        d[0..8].copy_from_slice(&addr.to_le_bytes());
        d[8..12].copy_from_slice(&len.to_le_bytes());
        d[12..14].copy_from_slice(&flags.to_le_bytes());
        d[14..16].copy_from_slice(&next.to_le_bytes());
        d
    }

    /// A full request/reply round-trip through the device: readable request
    /// descriptor + writable reply descriptor, INIT then LOOKUP of a real file.
    #[test]
    fn services_a_fuse_request_through_the_split_virtqueue() {
        let share = tempfile::tempdir().unwrap();
        std::fs::write(share.path().join("hello.txt"), b"hi").unwrap();

        let mut h = Harness::new();
        let (desc, avail, used) = (BASE + 0x1000, BASE + 0x2000, BASE + 0x3000);
        let (reqbuf, replybuf) = (BASE + 0x4000, BASE + 0x5000);

        // Descriptor chain: request(RO, ->1), reply(WO).
        h.put(desc, &mk_desc(reqbuf, 512, VIRTQ_DESC_F_NEXT, 1));
        h.put(desc + 16, &mk_desc(replybuf, 4096, VIRTQ_DESC_F_WRITE, 0));
        // avail: idx=1, ring[0]=head 0.
        h.put(avail + 2, &1u16.to_le_bytes());
        h.put(avail + 4, &0u16.to_le_bytes());

        let mut dev = unsafe {
            VirtioFs::new(
                0x0a00_0000,
                50,
                h.ram.as_mut_ptr(),
                BASE,
                h.ram.len(),
                "work",
                share.path(),
            )
        };
        // Identity + config tag.
        assert_eq!(dev.read(R_DEVICE_ID) as u32, VIRTIO_ID_FS);
        let tag = dev.config_u32(0).to_le_bytes();
        assert_eq!(&tag, b"work");

        // Bring the request queue (1) online.
        dev.write(R_QUEUE_SEL, 1);
        dev.write(R_QUEUE_NUM, 4);
        dev.write(R_QUEUE_DESC_LO, desc & 0xffff_ffff);
        dev.write(R_QUEUE_DRIVER_LO, avail & 0xffff_ffff);
        dev.write(R_QUEUE_DEVICE_LO, used & 0xffff_ffff);
        dev.write(R_QUEUE_READY, 1);

        // 1) FUSE_INIT.
        let mut init = Builder::new();
        let init_body = {
            let mut b = Builder::new();
            b.u32(7).u32(31).u32(0x2_0000).u32(0);
            b.into_bytes()
        };
        init.u32((FuseInHeader::SIZE + init_body.len()) as u32)
            .u32(FUSE_INIT)
            .u64(1)
            .u64(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .bytes(&init_body);
        h.put(reqbuf, &init.into_bytes());
        assert!(dev.write(R_QUEUE_NOTIFY, 1), "notify services the queue");
        let reply = h.get(replybuf, 16 + FuseInitOut::SIZE);
        let err = i32::from_le_bytes(reply[4..8].try_into().unwrap());
        assert_eq!(err, 0, "INIT ok");

        // 2) FUSE_LOOKUP hello.txt (advance avail to idx=2; ring[1] = head desc 0).
        h.put(avail + 6, &0u16.to_le_bytes());
        h.put(avail + 2, &2u16.to_le_bytes());
        let mut look = Builder::new();
        look.u32((FuseInHeader::SIZE + 10) as u32)
            .u32(FUSE_LOOKUP)
            .u64(2)
            .u64(FUSE_ROOT_ID)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .bytes(b"hello.txt\0");
        h.put(reqbuf, &look.into_bytes());
        // clear the reply area
        h.put(replybuf, &[0u8; 256]);
        assert!(dev.write(R_QUEUE_NOTIFY, 1));
        let reply = h.get(replybuf, 16 + FuseEntryOut::SIZE);
        let err = i32::from_le_bytes(reply[4..8].try_into().unwrap());
        assert_eq!(err, 0, "LOOKUP ok");
        let nodeid = u64::from_le_bytes(reply[16..24].try_into().unwrap());
        assert!(nodeid > FUSE_ROOT_ID, "LOOKUP returned a fresh nodeid");
    }

    #[test]
    fn identity_and_config_report_fs_id_and_tag() {
        let share = tempfile::tempdir().unwrap();
        let mut ram = vec![0u8; 0x1000];
        let dev = unsafe {
            VirtioFs::new(
                0x0a00_0000,
                50,
                ram.as_mut_ptr(),
                0x4000_0000,
                ram.len(),
                "work",
                share.path(),
            )
        };
        assert_eq!(dev.read(R_MAGIC) as u32, VIRTIO_MAGIC);
        assert_eq!(dev.read(R_DEVICE_ID) as u32, VIRTIO_ID_FS);
        // num_request_queues sits right after the 36-byte tag.
        assert_eq!(dev.config_u32(TAG_LEN as u64), NUM_REQUEST_QUEUES);
        assert!(dev.contains(0x0a00_0000));
        assert!(!dev.contains(0x0a00_0200));
    }

    #[test]
    fn version_1_feature_in_high_word() {
        let share = tempfile::tempdir().unwrap();
        let mut ram = vec![0u8; 0x1000];
        let mut dev = unsafe {
            VirtioFs::new(
                0,
                1,
                ram.as_mut_ptr(),
                0x4000_0000,
                ram.len(),
                "work",
                share.path(),
            )
        };
        dev.write(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(dev.read(R_DEVICE_FEATURES) as u32, 0);
        dev.write(R_DEVICE_FEATURES_SEL, 1);
        assert_eq!(dev.read(R_DEVICE_FEATURES) as u32, 1);
    }
}
