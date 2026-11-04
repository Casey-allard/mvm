//! Fixed privileged renderer for original common host-lifetime custody.

pub use mvm_core::host_lifetime::{HostLeaseExpectation, PreparedHostLifetimeLease};
use std::os::fd::AsRawFd;

pub(crate) fn preflight(lease: &PreparedHostLifetimeLease) -> String {
    let hash: String = lease
        .expectation()
        .state_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        r#"
set -euo pipefail
export LC_ALL=C
exec {{mvm_host_directory}}< /proc/{pid}/fd/{directory} || exit 1
exec {{mvm_host_holder}}<> /proc/{pid}/fd/{holder} || exit 1
[[ "$mvm_host_directory" -le 65535 && "$mvm_host_holder" -le 65535 ]] || exit 1
/usr/bin/timeout --signal=KILL 1 /bin/bash -euo pipefail -c '
d=$1
h=$2
[[ -d "/proc/self/fd/$d" && -f "/proc/self/fd/$h" ]] || exit 1
[[ "$(/usr/bin/stat -Lc "%d:%i:%u:%a" -- "/proc/self/fd/$d")" == "{dd}:{di}:{uid}:700" ]] || exit 1
[[ "$(/usr/bin/stat -Lc "%d:%i:%u:%a:%h" -- "/proc/self/fd/$h")" == "{hd}:{hi}:{uid}:600:1" ]] || exit 1
/usr/bin/flock --shared --nonblock "$h" || exit 1
s="/proc/self/fd/$d/{state}"
[[ ! -L "$s" && -f "$s" ]] || exit 1
[[ "$(/usr/bin/stat -c "%u:%a:%h:%s" -- "$s")" == "{uid}:600:1:{length}" ]] || exit 1
markers=$(/usr/bin/find -H "/proc/self/fd/$d" -mindepth 1 -maxdepth 1 \( -name "{absent0}" -o -name "{absent1}" \) -print -quit) || exit 1
[[ -z "$markers" ]] || exit 1
sum=$(/usr/bin/head -c {read_limit} -- "$s" | /usr/bin/sha256sum) || exit 1
[[ "${{sum%% *}}" == "{hash}" ]] || exit 1
' mvm-host-lifetime "$mvm_host_directory" "$mvm_host_holder" || exit 1
exec {{mvm_host_directory}}<&- || exit 1
"#,
        pid = std::process::id(),
        directory = lease.directory().as_raw_fd(),
        holder = lease.holder().as_raw_fd(),
        dd = lease.directory_object_id().0,
        di = lease.directory_object_id().1,
        hd = lease.holder_object_id().0,
        hi = lease.holder_object_id().1,
        uid = lease.owner_uid(),
        state = lease.expectation().state_name,
        length = lease.expectation().state_bytes,
        absent0 = lease.expectation().absent_names[0],
        absent1 = lease.expectation().absent_names[1],
        read_limit = u32::from(lease.expectation().state_bytes) + 1,
    )
}

#[cfg(test)]
#[path = "host_lease/tests.rs"]
mod tests;
