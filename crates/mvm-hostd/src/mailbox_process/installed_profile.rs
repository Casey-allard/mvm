//! Trusted installation configuration. The pair names restrict provisioning;
//! each VM still requires its own canonical signed plan and fresh reservation.
use crate::broker::mailbox_workers::WorkerLimits;
use crate::mailbox_service::MailboxLimits;
use std::{ffi::OsString, io};

#[derive(Clone, Debug)]
pub struct MailboxPair([String; 2]);

impl MailboxPair {
    pub fn new(names: [&str; 2]) -> io::Result<Self> {
        for name in names {
            mvm_core::naming::validate_vm_name(name)
                .map_err(|_| io::Error::other("invalid installed mailbox VM name"))?;
        }
        if names[0] == names[1] {
            return Err(io::Error::other("paired mailbox requires distinct VMs"));
        }
        Ok(Self(names.map(str::to_owned)))
    }

    pub fn index(&self, vm: &str) -> io::Result<usize> {
        self.0
            .iter()
            .position(|name| name == vm)
            .ok_or_else(|| io::Error::other("VM outside installed mailbox pair"))
    }
}

#[derive(Clone, Debug)]
pub enum InstalledMailboxProfile {
    Single,
    Pair(MailboxPair),
    OriginalCast(MailboxPair),
}

pub const CAST_QUALIFIER: &str = "--immutable-cast-v1";
pub const CAST_HELPER_FLAG: &str = "--owned-original-cast-v1";
pub const PAIR_HELPER_FLAG: &str = "--owned-pair-slot-v1";
const SINGLE_FLAG: &str = "--owned-mailbox-v1";
const PAIR_FLAG: &str = "--owned-mailbox-pair-v1";

// Per original, pre-reserved in the one coordinator ledger. Two paths (guest
// dial and host consumer) each process one frame synchronously. Workspace
// covers their framing/encoding buffers; these are protocol credits, not RSS.
pub const PAIR_FRAME_BYTES: usize = 8 * 1024;
pub const PAIR_DEPTH: usize = 4;
pub const PAIR_REPLAY_ENTRIES: u64 = 64;
const WORKER_CONTROL_BYTES: usize =
    mvm_contract::protocol::mailbox_worker::MAX_WORKER_CONTROL_BYTES;
const PAIR_QUEUE_BYTES: usize = PAIR_FRAME_BYTES * PAIR_DEPTH;
const PAIR_FRAME_WORKSPACE: usize = 2 * 8 * PAIR_FRAME_BYTES;
const PAIR_REPLAY_RESERVATION: usize = PAIR_REPLAY_ENTRIES as usize * 512;
const SHARED_BYTES: usize = 1024 * 1024;

impl InstalledMailboxProfile {
    pub fn parse(args: &[OsString]) -> io::Result<Option<Self>> {
        match args {
            [] => Ok(None),
            [mode] if mode == SINGLE_FLAG => Ok(Some(Self::Single)),
            [mode,a,b,profile] if mode == PAIR_FLAG && profile==CAST_QUALIFIER => {
                let a=a.to_str().ok_or_else(||io::Error::other("invalid VM name"))?;
                let b=b.to_str().ok_or_else(||io::Error::other("invalid VM name"))?;
                Ok(Some(Self::OriginalCast(MailboxPair::new([a,b])?)))
            }
            [mode, a, b] if mode == PAIR_FLAG => {
                let a = a
                    .to_str()
                    .ok_or_else(|| io::Error::other("invalid mailbox VM name"))?;
                let b = b
                    .to_str()
                    .ok_or_else(|| io::Error::other("invalid mailbox VM name"))?;
                Ok(Some(Self::Pair(MailboxPair::new([a, b])?)))
            }
            _ => Err(io::Error::other("unknown host-agent startup mode")),
        }
    }

    pub fn arguments(&self) -> Vec<&str> {
        match self {
            Self::Single => vec![SINGLE_FLAG],
            Self::Pair(pair) => vec![PAIR_FLAG, &pair.0[0], &pair.0[1]],
            Self::OriginalCast(pair) => vec![PAIR_FLAG, &pair.0[0], &pair.0[1],CAST_QUALIFIER],
        }
    }

    pub(crate) fn check_grant(&self, request:&mvm_contract::protocol::mailbox_worker::MailboxWorkerRequest)->io::Result<()> {
        use mvm_contract::protocol::{mailbox::local_service::MailboxLocalServiceGrant,mailbox_worker::MailboxWorkerBackend};
        match self {
            Self::OriginalCast(pair)=>{
                pair.index(&request.vm_id)?;
                if request.backend!=MailboxWorkerBackend::Firecracker || request.mailbox_grant.local_service!=Some(MailboxLocalServiceGrant::original_cast_v1()) {
                    return Err(io::Error::other("signed compact Firecracker original grant required"));
                }
                Ok(())
            }
            Self::Pair(pair)=>{pair.index(&request.vm_id)?;request.mailbox_grant.require_implemented_local_service().map_err(io::Error::other)}
            Self::Single=>request.mailbox_grant.require_implemented_local_service().map_err(io::Error::other),
        }
    }
    pub fn worker_limits(&self) -> WorkerLimits {
        let (workers, bytes_per_worker) = match self {
            Self::Single => (1, WORKER_CONTROL_BYTES),
            Self::OriginalCast(p) => return development_cast_capacity(p).worker,
            Self::Pair(_) => (
                2,
                WORKER_CONTROL_BYTES
                    + PAIR_QUEUE_BYTES
                    + PAIR_FRAME_WORKSPACE
                    + PAIR_REPLAY_RESERVATION,
            ),
        };
        WorkerLimits {
            host_workers: workers,
            tenant_workers: workers,
            host_bytes: SHARED_BYTES,
            tenant_bytes: SHARED_BYTES,
            bytes_per_worker,
        }
    }
}

/// Development-only A→B capacity proposal. The full 8 KiB worker frame still
/// covers a capped envelope plus the peer's signed credential and prefix.
/// A two-entry queue per worker frees one 32 KiB source generation reservation
/// inside the same 1 MiB aggregate. The explicit immutable Cast qualifier selects this capacity.
pub struct DevelopmentCastCapacity {
    pub worker: WorkerLimits,
    pub queue: MailboxLimits,
}
pub fn development_cast_capacity(pair: &MailboxPair) -> DevelopmentCastCapacity {
    let mut worker = InstalledMailboxProfile::Pair(pair.clone()).worker_limits();
    let queue = MailboxLimits {
        max_depth: 2,
        max_frame_bytes: PAIR_FRAME_BYTES,
    };
    worker.bytes_per_worker -= PAIR_FRAME_BYTES * (PAIR_DEPTH - queue.max_depth);
    DevelopmentCastCapacity { worker, queue }
}

pub fn pair_queue_limits() -> MailboxLimits {
    MailboxLimits {
        max_depth: PAIR_DEPTH,
        max_frame_bytes: PAIR_FRAME_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pair_names_and_launch_arguments_are_explicit_and_roundtrip() {
        assert!(MailboxPair::new(["alpha", "alpha"]).is_err());
        assert!(MailboxPair::new(["alpha", "../beta"]).is_err());
        let profile = InstalledMailboxProfile::Pair(MailboxPair::new(["alpha", "beta"]).unwrap());
        let args: Vec<OsString> = profile.arguments().into_iter().map(Into::into).collect();
        let recovered = InstalledMailboxProfile::parse(&args).unwrap().unwrap();
        assert_eq!(recovered.arguments(), profile.arguments());
        assert!(InstalledMailboxProfile::parse(&args[..2]).is_err());
        assert!(InstalledMailboxProfile::parse(&[]).unwrap().is_none());
        assert_eq!(
            InstalledMailboxProfile::Single.worker_limits().host_workers,
            1
        );
        assert_eq!(
            recovered.worker_limits().host_bytes,
            InstalledMailboxProfile::Single.worker_limits().host_bytes
        );
    }
}
