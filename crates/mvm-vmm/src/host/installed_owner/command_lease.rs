//! Exact-descriptor resource lifetime transfer across a local exec.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Child, Command};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    File, HolderLease, InstallationKey, OwnerError, Phase, RECORD_BYTES, Storage, check_private,
    object_id,
};

const MARKER: &str = "MVM_RESOURCE_LEASE_V1";
const MAX_METADATA_BYTES: usize = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u8,
    root: PathBuf,
    installation: [u8; 32],
    profile: [u8; 32],
    generation: u64,
    directory_fd: i32,
    holder_fd: i32,
    state_bytes: u16,
    state_sha256: [u8; 32],
}

fn owner_error(error: OwnerError) -> io::Error {
    match error {
        OwnerError::Io(error) => error,
        error => io::Error::other(error),
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid inherited resource lease",
    )
}

/// Spawn once while retaining the original parent's independent resource lease.
///
/// The child receives only exact resource descriptors and bounded provisioning
/// metadata, never authority keys or boot permission. Its startup must consume
/// the descriptors before spawning descendants. The caller owns the original
/// Child and must retain the returned parent lease through actual collection.
/// All fallible handoff preparation precedes spawn; no post-spawn failure loses
/// the original Child. The consumed Command cannot outlive its descriptor guard.
pub fn spawn_with_resource_lease(
    command: Command,
    lease: HolderLease,
) -> io::Result<(Child, HolderLease)> {
    spawn_with_channel(command, lease, None)
}
/// Inherit the original lease and a private FD 3 in one exec.
pub fn spawn_with_resource_lease_and_control(
    command: Command,
    lease: HolderLease,
    control: &std::os::unix::net::UnixStream,
) -> io::Result<(Child, HolderLease)> {
    if control.as_raw_fd() >= 3 {
        return spawn_with_channel(command, lease, Some(control));
    }
    // Command installs child stdio before pre_exec. Preserve a control socket
    // allocated in a previously vacant parent stdin/out/err slot.
    let fd = unsafe { libc::fcntl(control.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let retained = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    spawn_with_channel(command, lease, Some(&retained))
}
fn spawn_with_channel(
    mut command: Command,
    lease: HolderLease,
    control: Option<&std::os::unix::net::UnixStream>,
) -> io::Result<(Child, HolderLease)> {
    let mut handoff = lease.prepare_handoff().map_err(owner_error)?;
    if let Some(control) = control {
        use std::os::unix::process::CommandExt;
        for file in [&mut handoff.directory, &mut handoff.holder] {
            if file.as_raw_fd() < 4 {
                let dup = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
                if dup < 0 {
                    return Err(io::Error::last_os_error());
                }
                *file = unsafe { File::from_raw_fd(dup) };
            }
        }
        let fd = control.as_raw_fd();
        // Only async-signal-safe descriptor operations in the forked child.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) != 3 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let metadata = Metadata {
        version: 1,
        root: lease._storage.root.clone(),
        installation: lease._storage.key.installation,
        profile: lease._storage.key.profile,
        generation: lease.generation,
        directory_fd: handoff.directory.as_raw_fd(),
        holder_fd: handoff.holder.as_raw_fd(),
        state_bytes: handoff.state_bytes,
        state_sha256: handoff.state_sha256,
    };
    let encoded = serde_json::to_string(&metadata).map_err(|_| invalid())?;
    if encoded.len() > MAX_METADATA_BYTES {
        return Err(invalid());
    }
    command.env(MARKER, encoded);
    crate::host::restore_image::inherit_descriptors(
        &mut command,
        vec![metadata.directory_fd, metadata.holder_fd],
    );
    let child = command.spawn()?;
    drop(handoff);
    Ok((child, lease))
}

fn private_inherited_pair(metadata: &Metadata) -> io::Result<(File, File)> {
    let fds = [metadata.directory_fd, metadata.holder_fd];
    if fds[0] < 3 || fds[1] < 3 || fds[0] == fds[1] {
        return Err(invalid());
    }
    for fd in fds {
        // SAFETY: fcntl validates the numeric descriptor without taking ownership.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(invalid());
        }
        // SAFETY: the validated inherited descriptor is process-local; restoring
        // CLOEXEC prevents it reaching any later exec of a VM or helper.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: startup's caller guarantees these distinct inherited descriptors
    // have no Rust owners and have never previously been consumed.
    let directory = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: the second validated descriptor is distinct and exclusively owned.
    let holder = unsafe { File::from_raw_fd(fds[1]) };
    check_private(&directory, true).map_err(owner_error)?;
    check_private(&holder, false).map_err(owner_error)?;
    Ok((directory, holder))
}

/// Consume an optional local resource handoff at the process entry boundary.
///
/// Restore CLOEXEC, validate the exact descriptors/current record, acquire a
/// fresh independent SH lease, then close inherited aliases without unlocking.
/// Missing metadata means no handoff; malformed metadata is a fatal startup
/// error. Returned provisioning identity is not permission to perform any job.
///
/// # Safety
///
/// Call once at process startup, before any descendant spawn. No other thread
/// may access the process environment during this call. Descriptors named by the
/// launcher's private environment must be inherited, unowned descriptors in
/// this fresh process. On error the process must refuse its operation. The
/// returned lease must outlive all work belonging to this resource.
pub unsafe fn receive_resource_lease_at_startup() -> io::Result<Option<HolderLease>> {
    let Some(raw) = std::env::var_os(MARKER) else {
        return Ok(None);
    };
    // SAFETY: the caller guarantees the single-threaded environment boundary.
    unsafe { std::env::remove_var(MARKER) };
    let raw = raw.to_str().ok_or_else(invalid)?;
    if raw.len() > MAX_METADATA_BYTES {
        return Err(invalid());
    }
    let metadata: Metadata = serde_json::from_str(raw).map_err(|_| invalid())?;
    if metadata.version != 1
        || usize::from(metadata.state_bytes) != RECORD_BYTES
        || metadata.generation == 0
    {
        return Err(invalid());
    }
    let (directory, holder) = private_inherited_pair(&metadata)?;
    let key = InstallationKey {
        installation: metadata.installation,
        profile: metadata.profile,
    };
    let (storage, _unlocked_owner) = Storage::open(&metadata.root, key).map_err(owner_error)?;
    if object_id(&directory).map_err(owner_error)? != storage.ids[0]
        || object_id(&holder).map_err(owner_error)? != storage.ids[2]
    {
        return Err(invalid());
    }
    let record = storage.read().map_err(owner_error)?;
    let expected_hash: [u8; 32] = Sha256::digest(record.encode()).into();
    if record.phase != Phase::Active
        || record.generation != metadata.generation
        || expected_hash != metadata.state_sha256
    {
        return Err(invalid());
    }
    let lease = HolderLease::from_storage(storage, metadata.generation).map_err(owner_error)?;
    drop(holder);
    drop(directory);
    Ok(Some(lease))
}
