//! The in-house virtio-fs server: the FUSE wire ABI and a passthrough filesystem
//! that serves a host directory into the guest.
//!
//! virtio-fs (`crate::vmm::virtio_fs`) owns the transport — draining the request
//! virtqueue and scattering replies. This module owns the *protocol*: parsing a
//! FUSE request, executing it against a host directory (the dev VM's `/work`
//! share), and encoding the reply. Kept transport-free so it is unit-testable
//! against a real temp directory with no VM.

pub mod abi;
