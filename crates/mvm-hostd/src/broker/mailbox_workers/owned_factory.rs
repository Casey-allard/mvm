//! Trusted per-VM provisioning for the canonical mailbox binary.
use super::*;
use crate::mailbox_process::{
    MAILBOX_BIN,
    owned_wire::{PrepareOwnedV1, write_prepare},
};
use mvm_contract::protocol::mailbox::MAILBOX_PORT;
use mvm_core::vm_backend::HostDialRoute;
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::host::installed_owner::{
    HolderLease, InstallationBinding, spawn_with_resource_lease_and_control,
};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// One original admitted VM. The caller supplies trusted installation inputs;
/// no signed control frame may select a program, route, or state directory.
pub struct OwnedMailboxWorkerFactory {
    binary: File,
    binding: Arc<InstallationBinding>,
    context: [u8; 32],
    state_dir: PathBuf,
    route: HostDialRoute,
}
impl OwnedMailboxWorkerFactory {
    pub fn new(
        binary: &Path,
        binding: Arc<InstallationBinding>,
        admitted: &MailboxWorkerRequest,
        state_dir: &Path,
    ) -> io::Result<Self> {
        if !matches!(admitted.operation, MailboxWorkerOperation::Acquire)
            || !state_dir.is_absolute()
            || state_dir.file_name() != Some(admitted.vm_id.as_ref())
            || !std::fs::symlink_metadata(state_dir)?.is_dir()
            || !binary.is_absolute()
            || binary.file_name() != Some(MAILBOX_BIN.as_ref())
        {
            return Err(refused("invalid owned mailbox provisioning"));
        }
        admitted
            .mailbox_grant
            .require_implemented_local_service()
            .map_err(|_| refused("unsupported owned mailbox service"))?;
        let backend = AnyBackend::from_hypervisor(match admitted.backend {
            MailboxWorkerBackend::Firecracker => "firecracker",
            MailboxWorkerBackend::Hvf => "hvf",
        });
        let route = backend
            .host_dial_route(state_dir, MAILBOX_PORT)
            .ok_or_else(|| refused("admitted mailbox backend lacks a host dial route"))?;
        let binary = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(binary)?;
        let meta = binary.metadata()?;
        if !meta.is_file()
            || meta.mode() & 0o111 == 0
            || meta.mode() & 0o6022 != 0
            || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() })
        {
            return Err(refused("untrusted owned mailbox executable"));
        }
        // Pin the provisioned executable inode and keep FD 3 available for
        // the control channel. Do not resolve a filesystem name again at exec.
        let fd = unsafe { libc::fcntl(binary.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let binary = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            binary,
            binding,
            context: context_commitment(admitted)
                .map_err(|_| refused("invalid admitted mailbox context"))?,
            state_dir: state_dir.to_owned(),
            route,
        })
    }
    pub fn route(&self) -> &HostDialRoute {
        &self.route
    }
}
impl MailboxWorkerFactory for OwnedMailboxWorkerFactory {
    fn admit(&self, request: &MailboxWorkerRequest) -> io::Result<()> {
        if context_commitment(request).map_err(|_| refused("invalid mailbox context"))?
            != self.context
        {
            return Err(refused("mailbox request differs from admitted context"));
        }
        Ok(())
    }
    fn spawn(
        &self,
        request: &MailboxWorkerRequest,
        owner: &MailboxWorkerOwner,
    ) -> io::Result<SpawnedMailboxWorker> {
        self.admit(request)?;
        if owner.context_commitment != self.context {
            return Err(refused("mailbox owner context mismatch"));
        }
        let lease = HolderLease::acquire(
            &self.binding.root,
            self.binding.key,
            self.binding.generation,
        )
        .map_err(io::Error::other)?;
        let (control, helper) = UnixStream::pair()?;
        // Queue the small bounded frame before spawn so every failure after
        // a Child exists reaches the broker's original collection machinery.
        write_prepare(
            &control,
            &PrepareOwnedV1 {
                owner: owner.clone(),
                grant: request.mailbox_grant,
                socket: mvm_core::config::vm_mailbox_socket_at(&self.state_dir),
                route: self.route.clone(),
                vm_state_dir: self.state_dir.clone(),
                expected_parent: std::process::id(),
            },
            Instant::now() + std::time::Duration::from_millis(MAX_WORKER_OPERATION_MS),
        )?;
        #[cfg(target_os = "linux")]
        let fd_dir = "/proc/self/fd";
        #[cfg(not(target_os = "linux"))]
        let fd_dir = "/dev/fd";
        let image = Path::new(fd_dir).join(self.binary.as_raw_fd().to_string());
        let mut cmd = mvm_core::env_hygiene::helper_command(image);
        cmd.env_clear()
            .arg("--owned-v1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let (child, parent_lease) = spawn_with_resource_lease_and_control(cmd, lease, &helper)?;
        Ok(SpawnedMailboxWorker {
            child,
            control,
            parent_lease: Some(parent_lease),
        })
    }
}
