//! Backend-agnostic VMM driver seam.
//!
//! The `VmmDriver` trait, `RunningVm` handle, and the backend-agnostic boot
//! recipe (`VmmSpec`) live here so concrete backends can be implemented in a
//! downstream crate without a dependency cycle with the workload lifecycle
//! orchestration in `mvm-runtime`.

#[cfg(target_os = "linux")]
mod original_entrypoint;
#[cfg(unix)]
pub mod prepared_disks;
#[cfg(unix)]
pub mod readonly_data;
pub mod spec;
pub mod traits;

#[cfg(target_os = "linux")]
pub use original_entrypoint::{OriginalEntrypointChannel, OriginalEntrypointIdentity};
pub use traits::{
    ChildForkRequest, DuplexStream, LateVolumeAttach, OriginalWorkloadReport, RunningVm,
    RunningVmStopTiming, StandbyParentSpawn, VmmDriver,
};
