//! `mvm-mailbox` binary: the per-VM guest mailbox host process.
//!
//! Spawn contract:
//!
//! 1. The launch path spawns it only for a plan that carries a mailbox grant.
//! 2. It writes a JSON `MailboxProcessConfig` to stdin and closes it. The
//!    config holds keys derived for this one mailbox, never the host signing
//!    seed; nothing is passed in argv or the environment.
//! 3. The process dials the guest's mailbox port, serves it, and exits when
//!    its launcher and its VM are both gone.

use anyhow::{Context, Result};
use mvm_hostd::mailbox_process::{parse, serve};

fn main() -> Result<()> {
    // First statement in the process: a panic before this line would print
    // its payload unredacted.
    mvm_hostd::panic_hook::install("mailbox");
    let mut args = std::env::args_os().skip(1);
    if let Some(mode) = args.next() {
        anyhow::ensure!(
            mode == "--owned-v1" && args.next().is_none(),
            "invalid mailbox helper mode"
        );
        // SAFETY: the installed launcher hands unowned descriptors to this
        // single-threaded process. No threads or descendants have started.
        let lease = unsafe { mvm_vmm::host::installed_owner::receive_resource_lease_at_startup() }?
            .context("owned mailbox requires an installation resource lease")?;
        return mvm_hostd::mailbox_process::owned::run(lease)
            .context("owned mailbox helper failed");
    }
    let raw = mvm_hostd::read_launch_config("mvm-mailbox")?;
    let config = parse(&raw).context("mvm-mailbox config parse failed")?;
    std::process::exit(serve(config));
}
