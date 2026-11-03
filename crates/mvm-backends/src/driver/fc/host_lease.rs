//! Local process-lifetime custody through the existing Linux FC launcher.
//! This is resource exclusion, not permission to boot a guest.

use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

use anyhow::{Context, Result, ensure};

/// Trusted current-state expectation supplied by the installation owner.
/// These names and bytes are not accepted from guest or network messages.
pub struct HostLeaseExpectation {
    pub state_name: String,
    pub state_bytes: u16,
    pub state_sha256: [u8; 32],
    pub absent_names: [String; 2],
}

/// Owns the exact source descriptions until privileged reopen completes.
/// A reopened description must independently acquire SH before it can launch.
pub struct PreparedHostLifetimeLease {
    directory: File,
    holder: File,
    expected: HostLeaseExpectation,
    directory_id: (u64, u64),
    holder_id: (u64, u64),
    uid: u32,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn close_on_exec(file: &File) -> Result<()> {
    // SAFETY: borrowed live descriptor; preserve its other descriptor flags.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    ensure!(flags >= 0, "host lease descriptor flags unavailable");
    // SAFETY: setting CLOEXEC on the owned source, not on an inherited lease.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    ensure!(result == 0, "host lease descriptor CLOEXEC failed");
    Ok(())
}

impl PreparedHostLifetimeLease {
    pub fn bind(directory: File, holder: File, expected: HostLeaseExpectation) -> Result<Self> {
        ensure!(
            valid_name(&expected.state_name)
                && expected.absent_names.iter().all(|name| valid_name(name))
                && expected.absent_names[0] != expected.absent_names[1]
                && expected
                    .absent_names
                    .iter()
                    .all(|name| name != &expected.state_name)
                && (1..=4096).contains(&expected.state_bytes),
            "invalid host lease expectation"
        );
        let directory_meta = directory
            .metadata()
            .context("host lease directory metadata")?;
        let holder_meta = holder.metadata().context("host lease holder metadata")?;
        // SAFETY: geteuid has no inputs and changes no process credentials.
        let uid = unsafe { libc::geteuid() };
        ensure!(
            directory_meta.is_dir()
                && directory_meta.uid() == uid
                && directory_meta.mode() & 0o7777 == 0o700
                && holder_meta.is_file()
                && holder_meta.uid() == uid
                && holder_meta.mode() & 0o7777 == 0o600
                && holder_meta.nlink() == 1,
            "host lease requires private original directory and regular holder"
        );
        close_on_exec(&directory)?;
        close_on_exec(&holder)?;
        // SAFETY: live owned description; nonblocking SH is retained by File.
        let result = unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("host lifetime lease SH refused");
        }
        Ok(Self {
            directory,
            holder,
            expected,
            uid,
            directory_id: (directory_meta.dev(), directory_meta.ino()),
            holder_id: (holder_meta.dev(), holder_meta.ino()),
        })
    }

    /// Fixed bash, used before both outer launch mutations and privileged exec.
    /// Bash dynamically allocates free descriptors, including when disk handoff
    /// has populated higher numbers. The timeout bounds only the preflight.
    pub(crate) fn preflight(&self) -> String {
        let hash: String = self
            .expected
            .state_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            r#"
set -euo pipefail
export LC_ALL=C
exec {{mvm_host_directory}}< /proc/{pid}/fd/{directory}
exec {{mvm_host_holder}}<> /proc/{pid}/fd/{holder}
[[ "$mvm_host_directory" -le 65535 && "$mvm_host_holder" -le 65535 ]]
/usr/bin/timeout --signal=KILL 1 /bin/bash -euo pipefail -c '
d=$1
h=$2
[[ -d "/proc/self/fd/$d" && -f "/proc/self/fd/$h" ]]
[[ "$(/usr/bin/stat -Lc "%d:%i:%u:%a" -- "/proc/self/fd/$d")" == "{dd}:{di}:{uid}:700" ]]
[[ "$(/usr/bin/stat -Lc "%d:%i:%u:%a:%h" -- "/proc/self/fd/$h")" == "{hd}:{hi}:{uid}:600:1" ]]
/usr/bin/flock --shared --nonblock "$h"
s="/proc/self/fd/$d/{state}"
[[ ! -L "$s" && -f "$s" ]]
[[ "$(/usr/bin/stat -c "%u:%a:%h:%s" -- "$s")" == "{uid}:600:1:{length}" ]]
[[ ! -e "/proc/self/fd/$d/{absent0}" && ! -L "/proc/self/fd/$d/{absent0}" ]]
[[ ! -e "/proc/self/fd/$d/{absent1}" && ! -L "/proc/self/fd/$d/{absent1}" ]]
sum=$(/usr/bin/head -c {read_limit} -- "$s" | /usr/bin/sha256sum)
[[ "${{sum%% *}}" == "{hash}" ]]
' mvm-host-lifetime "$mvm_host_directory" "$mvm_host_holder"
exec {{mvm_host_directory}}<&-
"#,
            pid = std::process::id(),
            directory = self.directory.as_raw_fd(),
            holder = self.holder.as_raw_fd(),
            dd = self.directory_id.0,
            di = self.directory_id.1,
            hd = self.holder_id.0,
            hi = self.holder_id.1,
            uid = self.uid,
            state = self.expected.state_name,
            length = self.expected.state_bytes,
            absent0 = self.expected.absent_names[0],
            absent1 = self.expected.absent_names[1],
            read_limit = u32::from(self.expected.state_bytes) + 1,
        )
    }
}

#[cfg(test)]
#[path = "host_lease/tests.rs"]
mod tests;
