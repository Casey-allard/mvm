//! The private Prepare record binds inherited original-process observations.
//! Public metadata never constructs this capability.
use super::*;
use crate::host::host_agent_spawn::{PreparedEndpointAudit, require_live_event};
use std::os::fd::AsFd;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditProjection {
    version: u8,
    socket: PathBuf,
    signer_pid: u32,
    tenant: String,
    vm: String,
    signer_event: i32,
    daemon_event: i32,
}
impl AuditProjection {
    pub(super) fn descriptors(&self) -> [i32; 2] {
        [self.signer_event, self.daemon_event]
    }
    /// Validate the complete borrowed mapping before any inherited fd is owned.
    pub(super) fn preflight(&self, existing: &[i32], vm: &str) -> Result<()> {
        self.check_shape()?;
        if self.vm != vm || self.signer_event == self.daemon_event {
            bail!("installed audit descriptor identity differs")
        }
        for fd in self.descriptors() {
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: metadata query only, before borrowing or adopting the fd.
            if fd <= 2 || existing.contains(&fd) || unsafe { libc::fstat(fd, &mut metadata) } != 0 {
                bail!("installed audit inherited descriptor aliases")
            }
            // SAFETY: the successful fstat established a live inherited fd;
            // this borrow does not adopt, close, signal or consume its event.
            let event = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            require_live_event(event)?;
        }
        Ok(())
    }
    pub(super) fn tenant(&self) -> &str {
        &self.tenant
    }

    #[cfg(target_os = "linux")]
    pub(super) fn check_linux_processes(&self, original_parent: i32) -> Result<()> {
        let signer = live_pidfd_target(self.signer_event)?;
        let daemon = live_pidfd_target(self.daemon_event)?;
        if signer != self.signer_pid
            || signer == daemon
            || [signer, daemon].contains(&u32::try_from(original_parent)?)
            || [signer, daemon].contains(&std::process::id())
        {
            bail!("installed audit process identity differs")
        }
        Ok(())
    }

    pub(super) fn from_original(original: &PreparedEndpointAudit) -> Result<Self> {
        original.check_current()?;
        let [signer, daemon] = original.event_descriptors();
        let projection = Self {
            #[cfg(target_os = "macos")]
            version: 2,
            #[cfg(not(target_os = "macos"))]
            version: 1,
            socket: original.socket().to_owned(),
            signer_pid: original.signer_pid(),
            tenant: original.tenant().to_owned(),
            vm: original.vm().to_owned(),
            signer_event: signer.as_raw_fd(),
            daemon_event: daemon.as_raw_fd(),
        };
        projection.check_shape()?;
        Ok(projection)
    }
    fn check_shape(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        let expected_version = 1;
        #[cfg(target_os = "macos")]
        let expected_version = 2;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let expected_version = 0;
        if expected_version == 0
            || self.version != expected_version
            || self.signer_pid <= 1
            || !self.socket.is_absolute()
            || self.socket.as_os_str().len() > 4096
            || self.tenant.is_empty()
            || self.tenant.len() > 128
            || self.vm.len() > 64
        {
            bail!("installed audit original metadata refused")
        }
        mvm_core::naming::validate_vm_name(&self.vm)?;
        Ok(())
    }
}

pub(super) struct ChildAudit {
    projection: AuditProjection,
    signer: File,
    daemon: File,
}
impl ChildAudit {
    pub(super) fn adopt(projection: AuditProjection, existing: &[i32], vm: &str) -> Result<Self> {
        projection.preflight(existing, vm)?;
        // SAFETY: these are the distinct, live, exclusively inherited numbers
        // bound by the original private Prepare record, adopted once only.
        let signer = unsafe { File::from_raw_fd(projection.signer_event) };
        // SAFETY: same complete preflight and original exec whitelist contract.
        let daemon = unsafe { File::from_raw_fd(projection.daemon_event) };
        for fd in [signer.as_fd(), daemon.as_fd()] {
            rustix::io::fcntl_setfd(
                fd,
                rustix::io::fcntl_getfd(fd)? | rustix::io::FdFlags::CLOEXEC,
            )?;
        }
        let audit = Self {
            projection,
            signer,
            daemon,
        };
        audit.check_current()?;
        Ok(audit)
    }
    pub(super) fn check_current(&self) -> Result<()> {
        require_live_event(&self.signer)?;
        require_live_event(&self.daemon)?;
        Ok(())
    }
}

/// Original child audit capability. Only the private original Prepare path
/// constructs it; cloning retains the same authority and both event handles.
#[derive(Clone)]
pub struct InstalledEndpointAudit {
    lease: InstalledEndpointLease,
}
impl InstalledEndpointAudit {
    pub(super) fn require(lease: &InstalledEndpointLease) -> Result<Self> {
        lease.check_current()?;
        lease
            .authority
            .audit
            .as_ref()
            .context("original audit capability missing")?;
        Ok(Self {
            lease: lease.clone(),
        })
    }
    pub fn check_current(&self) -> Result<()> {
        self.lease.check_current()
    }
    /// Monotonic close only: it creates no admission or cleanup authority.
    pub fn fence(&self) {
        self.lease.authority.fenced.store(true, Ordering::Release);
    }
    /// Original capability continuity only; copied projection facts cannot
    /// substitute for the same private child authority.
    pub fn same_endpoint(&self, lease: &InstalledEndpointLease) -> bool {
        Arc::ptr_eq(&self.lease.authority, &lease.authority)
    }
    fn projection(&self) -> &AuditProjection {
        &self
            .lease
            .authority
            .audit
            .as_ref()
            .expect("private audit construction")
            .projection
    }
    pub fn socket(&self) -> &Path {
        &self.projection().socket
    }
    pub fn signer_pid(&self) -> u32 {
        self.projection().signer_pid
    }
    pub fn tenant(&self) -> &str {
        &self.projection().tenant
    }
    pub fn vm(&self) -> &str {
        &self.projection().vm
    }
    pub fn session(&self) -> &[u8; 32] {
        &self.lease.projection().session
    }
}

#[cfg(target_os = "linux")]
fn live_pidfd_target(fd: i32) -> Result<u32> {
    // Read kernel-produced identity before confinement. Older Linux pidfds
    // can share the anonymous inode, so stat identity alone is insufficient.
    let mut info = String::new();
    File::open(format!("/proc/self/fdinfo/{fd}"))?
        .take(512)
        .read_to_string(&mut info)?;
    info.lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .and_then(|pid| pid.parse::<u32>().ok())
        .filter(|&pid| pid > 1)
        .context("installed audit live pidfd identity unavailable")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        os::fd::IntoRawFd,
        process::{Child, Command, Stdio},
    };

    struct OriginalChild(Child);
    impl Drop for OriginalChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn original() -> OriginalChild {
        OriginalChild(
            Command::new("/bin/sh")
                .args(["-c", "read item"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn event(child: &OriginalChild) -> std::os::fd::OwnedFd {
        let observer = ProcessExitObserver::arm(child.0.id().try_into().unwrap()).unwrap();
        observer.duplicate_event_descriptor().unwrap().unwrap()
    }
    fn projection(signer: i32, daemon: i32) -> AuditProjection {
        AuditProjection {
            version: 1,
            socket: "/tmp/owned-audit-fixture.sock".into(),
            signer_pid: 42,
            tenant: "local".into(),
            vm: "vm-1".into(),
            signer_event: signer,
            daemon_event: daemon,
        }
    }

    #[test]
    fn original_signer_or_daemon_exit_stays_observable_without_consuming_events() {
        for stop_signer in [true, false] {
            let mut signer = original();
            let mut daemon = original();
            let signer_event = event(&signer);
            let daemon_event = event(&daemon);
            let audit = ChildAudit::adopt(
                projection(signer_event.into_raw_fd(), daemon_event.into_raw_fd()),
                &[],
                "vm-1",
            )
            .unwrap();
            audit.check_current().unwrap();
            let stopped = if stop_signer {
                &mut signer
            } else {
                &mut daemon
            };
            drop(stopped.0.stdin.take());
            stopped.0.wait().unwrap();
            assert!(audit.check_current().is_err());
            assert!(
                audit.check_current().is_err(),
                "readiness was never drained"
            );
        }
    }

    #[test]
    fn linux_process_identity_refuses_the_same_target_and_wrong_signer() {
        let signer = original();
        let daemon = original();
        let signer_event = event(&signer);
        let daemon_event = event(&daemon);
        let duplicate = event(&signer);
        let parent = std::process::id().try_into().unwrap();
        let mut facts = projection(signer_event.as_raw_fd(), daemon_event.as_raw_fd());
        facts.signer_pid = signer.0.id();
        facts.check_linux_processes(parent).unwrap();
        facts.daemon_event = duplicate.as_raw_fd();
        assert!(facts.check_linux_processes(parent).is_err());
        facts.daemon_event = daemon_event.as_raw_fd();
        facts.signer_pid = daemon.0.id();
        assert!(facts.check_linux_processes(parent).is_err());
    }

    #[test]
    fn audit_adoption_refuses_descriptor_aliases_and_foreign_vm_before_ownership_transfer() {
        let signer = original();
        let daemon = original();
        let signer_event = event(&signer);
        let daemon_event = event(&daemon);
        let a = signer_event.as_raw_fd();
        let b = daemon_event.as_raw_fd();
        assert!(ChildAudit::adopt(projection(a, a), &[], "vm-1").is_err());
        assert!(ChildAudit::adopt(projection(a, b), &[b], "vm-1").is_err());
        assert!(ChildAudit::adopt(projection(a, b), &[], "vm-2").is_err());
        // Refusal occurs before adoption, so the caller still owns both fds.
        require_live_event(&signer_event).unwrap();
        require_live_event(&daemon_event).unwrap();
    }
}
