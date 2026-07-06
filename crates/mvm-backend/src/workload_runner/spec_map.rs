//! Pure `VmStartConfig` → `VmmSpec` field mappings. Each function here is a
//! small, driver-independent unit so the workload role's translation of an
//! admitted launch config into a physical `VmmSpec` is testable without a VM.

use std::path::{Path, PathBuf};

use mvm_core::config::vsock_socket_filename;
use mvm_core::vm_backend::{VmStartConfig, VmVolumeKind};
use mvm_guest::vsock::{EGRESS_PORT, GUEST_AGENT_PORT, WORKLOAD_EXIT_PORT, dev_console_data_ports};

use crate::driver::{
    BlockDev, ConsoleCapture, DirShare, KernelImage, VmmSpec, VsockDirection, VsockPort,
};

/// The ordered virtio-blk list for a sealed workload: the read-only rootfs at
/// `/dev/vda` (slot 0), its dm-verity Merkle sidecar at `/dev/vdb` (slot 1) when
/// the image was built with verified boot, and — only when the full runtime
/// overlay triple (image + verity sidecar + roothash) is present — the overlay
/// at `/dev/vdc` (slot 2) and its verity sidecar at `/dev/vdd` (slot 3).
///
/// Every device is read-only: a workload rootfs is sealed, and the verity
/// sidecars are integrity data the guest only reads. The all-three-or-none
/// overlay rule mirrors `VmStartConfig`'s own contract — a partial overlay set
/// is treated as no overlay rather than a half-configured boot.
///
/// An empty `rootfs_path` yields no disks at all — an initramfs-only guest boots
/// entirely from RAM (matching the in-house driver's own empty-path skip). The verity
/// and overlay disks presuppose a rootfs, so they are dropped with it.
pub fn workload_blocks(config: &VmStartConfig) -> Vec<BlockDev> {
    let ro = |source: &str, slot: u8| BlockDev {
        source: source.into(),
        read_only: true,
        // Read-only blocks are file-served (hypervisor-enforced RO), never RAM-backed.
        ephemeral: false,
        slot,
    };

    if config.rootfs_path.is_empty() {
        return Vec::new();
    }

    // The rootfs is read-only by default (a sealed workload; verity-checked).
    // The dev VM opts into a writable root — it boots `rw` and must replay its
    // ext4 journal — via `writable_rootfs`.
    let mut blocks = vec![BlockDev {
        source: config.rootfs_path.clone().into(),
        read_only: !config.writable_rootfs,
        ephemeral: false,
        slot: 0,
    }];

    if let Some(verity) = &config.verity_path {
        blocks.push(ro(verity, 1));
    }

    if let (Some(overlay), Some(overlay_verity), Some(_roothash)) = (
        &config.runtime_overlay_path,
        &config.runtime_overlay_verity_path,
        &config.runtime_overlay_roothash,
    ) {
        blocks.push(ro(overlay, 2));
        blocks.push(ro(overlay_verity, 3));
    }

    // Extra writable `Disk` volumes (beyond the rootfs/verity/overlay) ride as
    // additional virtio-blk devices in slot order — e.g. the dev VM's persistent
    // nix-store overlay. Writable + non-ephemeral so writes hit the host file.
    let mut slot = blocks.len() as u8;
    for v in &config.volumes {
        if matches!(v.kind, VmVolumeKind::Disk) && !v.host.is_empty() {
            blocks.push(BlockDev {
                source: v.host.clone().into(),
                read_only: v.read_only,
                ephemeral: false,
                slot,
            });
            slot += 1;
        }
    }

    blocks
}

/// Directory-share volumes (`VmVolumeKind::DirShare`) → virtio-fs shares. Each
/// device advertises the `uvol{idx}` tag [`encode_user_volumes_cmdline`] wrote
/// onto the guest cmdline (same `mvm_core::vm_backend::uvol_tag` source of
/// truth), so the tag the guest `/init` mounts matches the tag the device
/// advertises. `idx` is the position in the full `volumes` list (disks and
/// shares alike) so it lines up with the encoder's indexing. Empty for a plain
/// workload that declares no shares (the common case).
pub fn workload_dir_shares(config: &VmStartConfig) -> Vec<DirShare> {
    config
        .volumes
        .iter()
        .enumerate()
        .filter(|(_, v)| matches!(v.kind, VmVolumeKind::DirShare) && !v.host.is_empty())
        .map(|(idx, v)| DirShare {
            tag: mvm_core::vm_backend::uvol_tag(idx),
            host_path: v.host.clone().into(),
        })
        .collect()
}

/// The host-side unix sockets a workload's standing vsock channels bind to.
pub struct WorkloadSockets<'a> {
    /// Agent RPC: the host dials the guest agent listening on `GUEST_AGENT_PORT`.
    pub agent: &'a Path,
    /// Egress gateway: the guest dials `EGRESS_PORT`; the host-side bridge
    /// (claim-10 gate + substitution) listens here — the sole path off the box.
    pub egress_gateway: &'a Path,
    /// Workload exit: the guest dials `WORKLOAD_EXIT_PORT` to report its exit code.
    pub exit: &'a Path,
    /// Dev-only interactive console data ports: one host UDS per port in
    /// `dev_console_data_ports()`, pre-opened so a PTY can attach. Empty for
    /// sealed prod boots (`dev_console = false` in `VmStartConfig`).
    pub console_data: Vec<(u32, PathBuf)>,
}

/// The standing vsock ports every workload VM carries: the agent RPC channel the
/// host dials, the two channels the guest dials (egress + exit), and — only when
/// `dev_console` is set — the pre-opened interactive console data ports.
pub fn workload_vsock_ports(socks: &WorkloadSockets) -> Vec<VsockPort> {
    let mut ports = vec![
        VsockPort {
            guest_port: GUEST_AGENT_PORT,
            host_uds: socks.agent.into(),
            direction: VsockDirection::HostDials,
        },
        VsockPort {
            guest_port: EGRESS_PORT,
            host_uds: socks.egress_gateway.into(),
            direction: VsockDirection::GuestDials,
        },
        VsockPort {
            guest_port: WORKLOAD_EXIT_PORT,
            host_uds: socks.exit.into(),
            direction: VsockDirection::GuestDials,
        },
    ];
    // The guest agent allocates `CONSOLE_PORT_BASE + session_id` per ConsoleOpen
    // and listens there; the host dials in to fetch the PTY stream. Pre-open only
    // when `dev_console` is true — a sealed prod boot carries none (claim 15).
    for (port, path) in &socks.console_data {
        ports.push(VsockPort {
            guest_port: *port,
            host_uds: path.clone(),
            direction: VsockDirection::HostDials,
        });
    }
    ports
}

/// Build the per-port (port, host-UDS) list for the interactive console data
/// range, rooted under `<state_dir>/vsock/` to match the Vz socket convention.
/// Returns an empty vec when `dev_console` is false (claim 15: sealed prod
/// boots carry no console listeners).
pub fn console_data_sockets(state_dir: &Path, dev_console: bool) -> Vec<(u32, PathBuf)> {
    if !dev_console {
        return Vec::new();
    }
    let vsock_dir = state_dir.join("vsock");
    dev_console_data_ports()
        .map(|port| {
            let path = vsock_dir.join(vsock_socket_filename(port));
            (port, path)
        })
        .collect()
}

/// Everything the workload role resolves before it can build a `VmmSpec`: the
/// admitted config, the host sockets its vsock channels bind to, the assembled
/// kernel cmdline, and the write-only console capture path.
pub struct WorkloadSpecInputs<'a> {
    pub config: &'a VmStartConfig,
    pub sockets: WorkloadSockets<'a>,
    /// The kernel cmdline the role assembled (roothash, overlay args, console).
    pub cmdline: String,
    /// Write-only host capture of the guest console.
    pub console_log: PathBuf,
}

/// Compose a `VmmSpec` from an admitted `VmStartConfig` and the runtime paths the
/// role resolved. The driver-agnostic translation: sealed rootfs + verity/overlay
/// disks, the three standing vsock channels, the kernel, and the write-only
/// console — no NIC, no policy (those live in the role above and the bridge it
/// spawns, never in the spec the driver boots).
pub fn workload_spec(inputs: &WorkloadSpecInputs) -> VmmSpec {
    let config = inputs.config;
    let kernel = match &config.kernel_path {
        Some(path) if !path.is_empty() => KernelImage::Path(path.into()),
        _ => KernelImage::Bundled,
    };
    VmmSpec {
        name: config.name.clone(),
        kernel,
        initramfs: config
            .initrd_path
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        cmdline: inputs.cmdline.clone(),
        vcpus: config.cpus,
        memory_mib: config.memory_mib,
        mem_initial_mib: config.mem_initial_mib,
        blocks: workload_blocks(config),
        vsock: workload_vsock_ports(&inputs.sockets),
        dir_shares: workload_dir_shares(config),
        // The `mvm.uvols=` cmdline the guest `/init` reads to mount the shares
        // (and note disk volumes) at their guest paths — carries the guest path
        // that `dir_shares` (tag + host only) drops. `None` when no user volumes.
        uvols_cmdline: mvm_core::vm_backend::encode_user_volumes_cmdline(&config.volumes),
        console: ConsoleCapture {
            log_path: inputs.console_log.clone(),
        },
        // A workload is untrusted: it must route egress through the gated endpoint.
        trusted_builder: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn base() -> VmStartConfig {
        VmStartConfig {
            name: "w".into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    fn nodes(blocks: &[BlockDev]) -> Vec<String> {
        blocks.iter().map(BlockDev::device_node).collect()
    }

    #[test]
    fn rootfs_only_maps_to_a_single_read_only_vda() {
        let blocks = workload_blocks(&base());
        assert_eq!(nodes(&blocks), vec!["/dev/vda"]);
        assert_eq!(blocks[0].source, PathBuf::from("/img/rootfs.ext4"));
        assert!(blocks[0].read_only);
    }

    #[test]
    fn writable_rootfs_presents_vda_read_write() {
        // The dev VM boots `root=/dev/vda rw` and must replay its ext4 journal;
        // `writable_rootfs` flips slot 0 writable. A read-only vda panics the
        // kernel on root mount (EROFS) when the fs needs recovery.
        let cfg = VmStartConfig {
            writable_rootfs: true,
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(nodes(&blocks), vec!["/dev/vda"]);
        assert!(!blocks[0].read_only, "writable_rootfs presents vda rw");
    }

    fn vol(host: &str, guest: &str, kind: VmVolumeKind) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only: false,
            kind,
            encrypted: false,
        }
    }

    #[test]
    fn extra_disk_volume_rides_after_the_base_blocks() {
        // A writable `Disk` volume (e.g. the dev VM's nix-store overlay) lands in
        // the slot after the rootfs, writable and non-ephemeral so it persists.
        let cfg = VmStartConfig {
            volumes: vec![vol("/host/nix-store.img", "/nix", VmVolumeKind::Disk)],
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(nodes(&blocks), vec!["/dev/vda", "/dev/vdb"]);
        assert_eq!(blocks[1].source, PathBuf::from("/host/nix-store.img"));
        assert!(!blocks[1].read_only, "extra disk volume is writable");
        assert!(
            !blocks[1].ephemeral,
            "extra disk volume persists to the host"
        );
    }

    #[test]
    fn dir_share_device_tag_matches_the_uvols_cmdline_tag() {
        // The device tag MUST equal the `uvol{idx}` tag the cmdline carries
        // (full-list index), or the guest mounts a tag no device advertises.
        let cfg = VmStartConfig {
            volumes: vec![
                vol("/host/nix-store.img", "/nix", VmVolumeKind::Disk), // idx 0
                vol("/host/project", "/work", VmVolumeKind::DirShare),  // idx 1
            ],
            ..base()
        };
        // A `DirShare` never becomes a block; only the `Disk` does.
        assert_eq!(nodes(&workload_blocks(&cfg)), vec!["/dev/vda", "/dev/vdb"]);
        let shares = workload_dir_shares(&cfg);
        assert_eq!(shares.len(), 1);
        // The share is the 2nd volume (index 1) → tag `uvol1`, matching the
        // cmdline the guest reads.
        assert_eq!(shares[0].tag, mvm_core::vm_backend::uvol_tag(1));
        assert_eq!(shares[0].tag, "uvol1");
        assert_eq!(shares[0].host_path, PathBuf::from("/host/project"));
        let uvols = mvm_core::vm_backend::encode_user_volumes_cmdline(&cfg.volumes).unwrap();
        assert!(
            uvols.contains("uvol1:"),
            "cmdline tags the share uvol1: {uvols}"
        );
    }

    #[test]
    fn dir_share_volume_populates_the_uvols_cmdline() {
        // The virtio-fs share must ride the `mvm.uvols=` cmdline so the guest
        // `/init` mounts it — the device alone (dir_shares) isn't enough, the
        // guest needs the tag→path mapping the cmdline carries.
        let cfg = VmStartConfig {
            volumes: vec![vol("/host/project", "/work", VmVolumeKind::DirShare)],
            ..base()
        };
        let uvols = mvm_core::vm_backend::encode_user_volumes_cmdline(&cfg.volumes)
            .expect("a DirShare volume yields a uvols cmdline");
        assert!(uvols.starts_with("mvm.uvols="), "got: {uvols}");
        // No user volumes → no uvols cmdline (the plain-workload common case).
        assert!(mvm_core::vm_backend::encode_user_volumes_cmdline(&base().volumes).is_none());
    }

    #[test]
    fn empty_host_volumes_are_skipped() {
        let cfg = VmStartConfig {
            volumes: vec![
                vol("", "/work", VmVolumeKind::DirShare),
                vol("", "/nix", VmVolumeKind::Disk),
            ],
            ..base()
        };
        assert_eq!(nodes(&workload_blocks(&cfg)), vec!["/dev/vda"]);
        assert!(workload_dir_shares(&cfg).is_empty());
    }

    #[test]
    fn empty_rootfs_yields_no_blocks() {
        // An initramfs-only guest boots from RAM: no rootfs disk, and the verity /
        // overlay disks (which presuppose a rootfs) are dropped with it.
        let cfg = VmStartConfig {
            rootfs_path: String::new(),
            verity_path: Some("/img/rootfs.verity".into()),
            ..base()
        };
        assert!(workload_blocks(&cfg).is_empty());
    }

    #[test]
    fn verity_sidecar_lands_at_vdb() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(nodes(&blocks), vec!["/dev/vda", "/dev/vdb"]);
        assert_eq!(blocks[1].source, PathBuf::from("/img/rootfs.verity"));
    }

    #[test]
    fn full_overlay_triple_adds_vdc_and_vdd() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(
            nodes(&blocks),
            vec!["/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd"]
        );
        assert!(blocks.iter().all(|b| b.read_only));
    }

    #[test]
    fn partial_overlay_set_is_treated_as_no_overlay() {
        // Overlay image + verity present but roothash missing: the all-three-or-none
        // rule drops the overlay rather than booting a half-configured second target.
        let cfg = VmStartConfig {
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: None,
            ..base()
        };
        assert_eq!(nodes(&workload_blocks(&cfg)), vec!["/dev/vda"]);
    }

    #[test]
    fn workload_vsock_ports_wire_the_three_standing_channels_with_correct_direction() {
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            console_data: Vec::new(),
        };
        let ports = workload_vsock_ports(&socks);

        // Agent: host dials the guest; egress + exit: the guest dials the host.
        let by_port: std::collections::HashMap<u32, &VsockPort> =
            ports.iter().map(|p| (p.guest_port, p)).collect();

        let agent = by_port[&GUEST_AGENT_PORT];
        assert_eq!(agent.direction, VsockDirection::HostDials);
        assert_eq!(agent.host_uds, PathBuf::from("/run/agent.sock"));

        let egress = by_port[&EGRESS_PORT];
        assert_eq!(egress.direction, VsockDirection::GuestDials);
        assert_eq!(egress.host_uds, PathBuf::from("/run/egress.sock"));

        let exit = by_port[&WORKLOAD_EXIT_PORT];
        assert_eq!(exit.direction, VsockDirection::GuestDials);
        assert_eq!(exit.host_uds, PathBuf::from("/run/workload.exit"));
    }

    fn sample_sockets() -> WorkloadSockets<'static> {
        WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            console_data: Vec::new(),
        }
    }

    #[test]
    fn workload_spec_composes_kernel_blocks_vsock_and_console() {
        let cfg = VmStartConfig {
            kernel_path: Some("/img/Image".into()),
            verity_path: Some("/img/rootfs.verity".into()),
            cpus: 2,
            memory_mib: 512,
            ..base()
        };
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &cfg,
            sockets: sample_sockets(),
            cmdline: "console=ttyAMA0 root=/dev/vda".into(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.name, "w");
        assert_eq!(spec.kernel, KernelImage::Path(PathBuf::from("/img/Image")));
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.memory_mib, 512);
        assert_eq!(nodes(&spec.blocks), vec!["/dev/vda", "/dev/vdb"]);
        assert_eq!(spec.vsock.len(), 3);
        assert_eq!(spec.console.log_path, PathBuf::from("/run/console.log"));
    }

    #[test]
    fn workload_spec_maps_initrd_path_to_initramfs() {
        let cfg = VmStartConfig {
            initrd_path: Some("/img/initrd.cpio".into()),
            ..base()
        };
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &cfg,
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.initramfs, Some(PathBuf::from("/img/initrd.cpio")));
    }

    #[test]
    fn workload_spec_without_initrd_has_no_initramfs() {
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.initramfs, None);
    }

    #[test]
    fn workload_spec_falls_back_to_bundled_kernel_without_a_path() {
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.kernel, KernelImage::Bundled);
    }

    // --- console_data_sockets / dev_console gating ---

    #[test]
    fn console_data_sockets_returns_empty_when_dev_console_is_false() {
        let sockets = console_data_sockets(Path::new("/state/w"), false);
        assert!(
            sockets.is_empty(),
            "sealed prod boot must carry no console listeners"
        );
    }

    #[test]
    fn console_data_sockets_returns_128_entries_when_dev_console_is_true() {
        let sockets = console_data_sockets(Path::new("/state/w"), true);
        assert_eq!(
            sockets.len(),
            128,
            "pre-open all 128 console data ports when dev_console is set"
        );
    }

    #[test]
    fn console_data_sockets_paths_follow_vz_convention() {
        use mvm_guest::vsock::CONSOLE_PORT_BASE;
        let state_dir = Path::new("/state/myvm");
        let sockets = console_data_sockets(state_dir, true);

        // First port: CONSOLE_PORT_BASE + 1 = 20001
        let (port, path) = &sockets[0];
        assert_eq!(*port, CONSOLE_PORT_BASE + 1);
        assert_eq!(
            path,
            &PathBuf::from("/state/myvm/vsock/vsock-20001.sock"),
            "path must be <state_dir>/vsock/vsock-<port>.sock"
        );

        // Last port: CONSOLE_PORT_BASE + 128 = 20128
        let (last_port, last_path) = &sockets[127];
        assert_eq!(*last_port, CONSOLE_PORT_BASE + 128);
        assert_eq!(
            last_path,
            &PathBuf::from("/state/myvm/vsock/vsock-20128.sock")
        );
    }

    #[test]
    fn workload_vsock_ports_with_dev_console_carries_128_console_ports() {
        use mvm_guest::vsock::CONSOLE_PORT_BASE;
        let state_dir = Path::new("/state/w");
        let console_data = console_data_sockets(state_dir, true);
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            console_data,
        };
        let ports = workload_vsock_ports(&socks);

        // 3 standing + 128 console = 131
        assert_eq!(ports.len(), 131);

        // All console ports are HostDials and land in the expected range.
        let console_ports: Vec<_> = ports
            .iter()
            .filter(|p| p.guest_port > CONSOLE_PORT_BASE)
            .collect();
        assert_eq!(console_ports.len(), 128);
        assert!(
            console_ports
                .iter()
                .all(|p| p.direction == VsockDirection::HostDials),
            "host dials the guest-side console listener"
        );
    }

    #[test]
    fn workload_vsock_ports_without_dev_console_carries_only_three_ports() {
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            console_data: Vec::new(),
        };
        let ports = workload_vsock_ports(&socks);
        assert_eq!(ports.len(), 3, "no console ports on a sealed prod boot");
    }

    #[test]
    fn workload_spec_with_dev_console_carries_131_vsock_entries() {
        let state_dir = Path::new("/state/w");
        let console_data = console_data_sockets(state_dir, true);
        let cfg = VmStartConfig {
            dev_console: true,
            ..base()
        };
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &cfg,
            sockets: WorkloadSockets {
                agent: Path::new("/run/agent.sock"),
                egress_gateway: Path::new("/run/egress.sock"),
                exit: Path::new("/run/workload.exit"),
                console_data,
            },
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.vsock.len(), 131);
    }

    #[test]
    fn workload_spec_without_dev_console_carries_three_vsock_entries() {
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.vsock.len(), 3);
    }
}
