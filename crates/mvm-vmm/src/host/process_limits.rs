//! Kernel ceilings for original helper processes, independent of their service.
//!
//! A ceiling is not a parent reservation, authorization, RSS measurement or
//! retirement proof. The caller must retain those owners separately.

use std::process::Command;

#[cfg(target_os = "linux")]
#[path = "process_limits/platforms/linux.rs"]
mod platform;
#[cfg(not(target_os = "linux"))]
#[path = "process_limits/platforms/unsupported.rs"]
mod platform;

/// Bound this child and all its threads before the loader or user code runs.
/// Preserve any stricter inherited soft or hard ceiling; never change the parent.
///
/// The command must directly execute the intended child, without a privileged
/// intermediary capable of raising the inherited hard limit. Its caller owns
/// resource admission and collection of the original child.
///
/// # Errors
/// Refuses a zero ceiling or unavailable platform enforcement. A later spawn
/// fails if installing the kernel limit fails, before executing the program.
pub fn limit_original_address_space(command: &mut Command, bytes: u64) -> anyhow::Result<()> {
    anyhow::ensure!(bytes > 0, "original process address space is unfunded");
    platform::limit_address_space(command, bytes)
}
