use std::{os::unix::process::CommandExt, process::Command};

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

pub(super) fn limit_address_space(command: &mut Command, bytes: u64) -> anyhow::Result<()> {
    // SAFETY: after fork the closure reads and sets only kernel rlimits,
    // using copied integers. It does not allocate, log, or acquire a lock.
    unsafe {
        command.pre_exec(move || {
            let inherited = getrlimit(Resource::As);
            let limit = [Some(bytes), inherited.current, inherited.maximum]
                .into_iter()
                .flatten()
                .min();
            setrlimit(
                Resource::As,
                Rlimit {
                    current: limit,
                    maximum: limit,
                },
            )?;
            Ok(())
        });
    }
    Ok(())
}
