use super::*;
use anyhow::ensure;
use rustix::fs::{AtFlags, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

const JOURNAL_CAP: usize = 64 * 1024;

/// Owned-only bind: guard exists before any chmod/capture can fail.
pub fn bind_owned_signer_listener(
    path: &Path,
    admission: &Arc<crate::owned_resources::registered::RegistrationAdmission>,
) -> Result<crate::owned_resources::registered::RegisteredListener> {
    OwnedEntry::prepare_absent(path)?;
    let listener = admission.listener(|| UnixListener::bind(path))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity(u64, u64);

fn number<T: TryInto<u64>>(value: T) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("file identity is out of range"))
}

struct Directory {
    file: File,
    path: PathBuf,
    id: Identity,
}
impl Directory {
    fn open(path: &Path) -> Result<Self> {
        let file = File::from(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let meta = file.metadata()?;
        ensure!(
            meta.is_dir()
                && meta.uid() == rustix::process::geteuid().as_raw()
                && meta.mode() & 0o7777 == 0o700,
            "owned helper requires private directory"
        );
        let result = Self {
            file,
            path: path.into(),
            id: Identity(meta.dev(), meta.ino()),
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        let meta = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            meta.is_dir()
                && Identity(meta.dev(), meta.ino()) == self.id
                && meta.uid() == rustix::process::geteuid().as_raw()
                && meta.mode() & 0o7777 == 0o700,
            "owned helper directory changed"
        );
        Ok(())
    }
    fn identity(&self, name: &std::ffi::OsStr) -> Result<Option<Identity>> {
        self.check()?;
        match rustix::fs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(meta) => Ok(Some(Identity(number(meta.st_dev)?, number(meta.st_ino)?))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(error).context("inspect owned helper entry"),
        }
    }
}

pub(crate) struct OwnedEntry {
    directory: Directory,
    name: std::ffi::OsString,
    id: Identity,
    removed: bool,
}
impl OwnedEntry {
    pub(crate) fn prepare_absent(path: &Path) -> Result<()> {
        let parent = path.parent().context("owned entry parent")?;
        mvm_core::private_fs::create_owned_private_dir(parent)?;
        let directory = Directory::open(parent)?;
        let name = path.file_name().context("owned entry name")?;
        ensure!(
            directory.identity(name)?.is_none(),
            "refusing preexisting owned helper entry"
        );
        Ok(())
    }
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        use std::os::unix::fs::FileTypeExt;
        let directory = Directory::open(path.parent().context("owned entry parent")?)?;
        let name = path.file_name().context("owned entry name")?.to_owned();
        let id = directory
            .identity(&name)?
            .context("owned helper entry absent")?;
        let meta = std::fs::symlink_metadata(path)?;
        ensure!(
            meta.file_type().is_socket()
                && meta.uid() == rustix::process::geteuid().as_raw()
                && Identity(meta.dev(), meta.ino()) == id,
            "owned socket identity or owner changed"
        );
        Ok(Self {
            directory,
            name,
            id,
            removed: false,
        })
    }
    pub(crate) fn remove(&mut self) -> Result<()> {
        if !self.removed {
            ensure!(
                self.directory.identity(&self.name)? == Some(self.id),
                "owned helper entry replaced"
            );
            rustix::fs::unlinkat(&self.directory.file, &self.name, AtFlags::empty())?;
            self.removed = true;
        }
        ensure!(
            self.directory.identity(&self.name)?.is_none(),
            "owned entry replaced after removal"
        );
        self.directory.check()?;
        self.directory.file.sync_all()?;
        Ok(())
    }
}

pub(super) struct OwnedJournal {
    directory: Directory,
    name: std::ffi::OsString,
    last: StdMutex<Option<Identity>>,
}
struct BoundedBytes(Vec<u8>);
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > JOURNAL_CAP.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("owned journal byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl OwnedJournal {
    fn new(path: &Path) -> Result<Self> {
        OwnedEntry::prepare_absent(path)?;
        Ok(Self {
            directory: Directory::open(path.parent().context("journal parent")?)?,
            name: path.file_name().context("journal name")?.into(),
            last: StdMutex::new(None),
        })
    }
    pub(super) fn store<'a>(
        &self,
        registrations: impl IntoIterator<Item = &'a RegisterVm>,
    ) -> Result<()> {
        let mut entries = Vec::with_capacity(2);
        for registration in registrations {
            ensure!(entries.len() < 2, "owned journal registration limit");
            entries.push(registration);
        }
        entries.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));
        let mut bytes = BoundedBytes(Vec::with_capacity(JOURNAL_CAP));
        serde_json::to_writer(&mut bytes, &entries)?;
        let expected = *self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("owned journal state poisoned"))?;
        ensure!(
            self.directory.identity(&self.name)? == expected,
            "owned journal replaced"
        );
        let temporary = format!("owned-journal-{}.tmp", std::process::id());
        let fd = rustix::fs::openat(
            &self.directory.file,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(fd);
        file.write_all(&bytes.0)?;
        file.sync_all()?;
        let meta = file.metadata()?;
        self.directory.check()?;
        ensure!(
            self.directory.identity(&self.name)? == expected,
            "owned journal replaced before commit"
        );
        rustix::fs::renameat(
            &self.directory.file,
            temporary.as_str(),
            &self.directory.file,
            &self.name,
        )?;
        *self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("owned journal state poisoned"))? =
            Some(Identity(meta.dev(), meta.ino()));
        self.directory.file.sync_all()?;
        Ok(())
    }
    fn remove_empty(&self) -> Result<()> {
        self.store(std::iter::empty())?;
        let expected = self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("owned journal state poisoned"))?
            .context("owned journal not committed")?;
        let fd = rustix::fs::openat(
            &self.directory.file,
            &self.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut file = File::from(fd);
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && Identity(meta.dev(), meta.ino()) == expected
                && meta.len() == 2,
            "owned journal identity or size changed"
        );
        let mut bytes = [0; 2];
        file.read_exact(&mut bytes)?;
        ensure!(
            &bytes == b"[]" && self.directory.identity(&self.name)? == Some(expected),
            "owned journal is not verified empty"
        );
        rustix::fs::unlinkat(&self.directory.file, &self.name, AtFlags::empty())?;
        self.directory.file.sync_all()?;
        Ok(())
    }
}

impl VmHandle {
    async fn stop_owned(&mut self) -> Result<()> {
        if let Some(success) = self.joined {
            ensure!(success, "owned broker task previously failed");
            return Ok(());
        }
        if let Some(stop) = self.owned_stop.take() {
            let _ = stop.send(());
        }
        let joined = tokio::time::timeout(Duration::from_secs(1), &mut self.serve_task)
            .await
            .context("owned broker task stop timed out")?;
        let result = joined
            .context("join owned broker task")
            .and_then(|result| result);
        self.joined = Some(result.is_ok());
        result
    }
}

impl HostAgentDaemon {
    /// Serve the installed direct-child mode and reap its original signer.
    pub async fn run_owned(
        cfg: HostAgentConfig,
        nonce: [u8; 16],
        mut signer: tokio::process::Child,
    ) -> Result<()> {
        let setup = (|| -> Result<_> {
            let bytes = crate::owned_resources::read_key(&cfg.host_signer_public_key_path)?;
            let key = VerifyingKey::from_bytes(&bytes)?;
            let daemon = Self::new(cfg.tenant_id.clone(), key, cfg.max_frame_bytes)
                .with_signer_helper(cfg.signer_helper_uds_path.clone())
                .with_registration_journal(cfg.registration_journal_path()?)
                .with_owned_lifecycle(signer.id().context("original signer child ID missing")?)?;
            OwnedEntry::prepare_absent(&cfg.control_socket)?;
            let listener = daemon
                .owned_admission
                .as_ref()
                .context("owned I/O admission absent")?
                .listener(|| UnixListener::bind(&cfg.control_socket))?;
            std::fs::set_permissions(&cfg.control_socket, std::fs::Permissions::from_mode(0o700))?;
            let control = OwnedEntry::capture(&cfg.control_socket)?;
            let helper = OwnedEntry::capture(&cfg.signer_helper_uds_path)?;
            ensure!(
                signer.try_wait()?.is_none(),
                "original signer exited before owned readiness"
            );
            let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
            let flags = rustix::fs::fcntl_getfl(&fd)?;
            rustix::fs::fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
            // SAFETY: AsyncFd owns this exclusive duplicate until its drop;
            // OwnedFd keeps one stable live descriptor for that whole interval.
            let owner = unsafe { tokio::io::unix::AsyncFd::register(fd) }?;
            let ready =
                serde_json::to_vec(&serde_json::json!({"nonce":nonce,"pid":std::process::id()}))?;
            ensure!(ready.len() <= 256, "owned ready limit");
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&u32::try_from(ready.len())?.to_be_bytes())?;
            stdout.write_all(&ready)?;
            stdout.flush()?;
            Ok((daemon, listener, control, helper, owner))
        })();
        match setup {
            Ok((mut daemon, listener, mut control, mut helper, owner)) => {
                let serving = daemon.serve_owned_control(listener, &owner).await;
                let closed = daemon.close_owned().await;
                daemon
                    .owned_admission
                    .as_ref()
                    .context("owned I/O admission absent")?
                    .fence();
                let stopped = stop_signer(&mut signer).await;
                serving.and(closed).and(stopped)?;
                daemon.remove_owned_journal()?;
                control.remove()?;
                helper.remove()?;
                Ok(())
            }
            Err(error) => {
                let stopped = stop_signer(&mut signer).await;
                stopped?;
                Err(error)
            }
        }
    }

    async fn serve_owned_control(
        &mut self,
        listener: crate::owned_resources::registered::RegisteredListener,
        owner: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        let workspaces =
            crate::owned_resources::WorkspacePool::new(crate::owned_resources::CONTROL_WORKSPACES)?;
        let admission = self
            .owned_admission
            .clone()
            .context("owned I/O admission absent")?;
        loop {
            let mut stream = tokio::select! {
                _ = admission.closed() => bail!("owned I/O admission fenced"),
                closed = owner_closed(owner) => { closed?; return Ok(()); }
                accepted = listener.accept() => accepted.context("owned control accept")?,
            };
            let _workspace = workspaces.acquire().await?;
            let signed = tokio::time::timeout(
                Duration::from_secs(1),
                crate::framing::read_json_frame_checked::<_, SignedControl>(
                    &mut stream,
                    CONTROL_MAX_FRAME_BYTES,
                    crate::owned_resources::validate_shape,
                ),
            )
            .await;
            let response = match signed {
                Ok(Ok(signed)) => match broker_control::verify(&signed, &self.verifying_key) {
                    Ok(request) => match self.apply_owned(request).await {
                        Ok(()) => ControlResponse::Ok,
                        Err(error) => ControlResponse::Err {
                            message: error.to_string(),
                        },
                    },
                    Err(_) => ControlResponse::Err {
                        message: "control signature rejected".into(),
                    },
                },
                Ok(Err(_)) | Err(_) => continue,
            };
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                crate::framing::write_json_frame_bounded(
                    &mut stream,
                    &response,
                    CONTROL_MAX_FRAME_BYTES,
                ),
            )
            .await;
        }
    }

    pub(crate) fn with_owned_lifecycle(mut self, signer: u32) -> Result<Self> {
        mvm_core::naming::validate_vm_name(&self.tenant_id)?;
        ensure!(
            (1..=JOURNAL_CAP).contains(&self.max_frame_bytes),
            "owned broker frame limit"
        );
        let path = &self
            .registration_journal
            .as_ref()
            .context("owned journal required")?
            .path;
        self.owned_journal = Some(OwnedJournal::new(path)?);
        self.owned_signer = Some(signer);
        self.owned_admission = Some(Arc::new(
            crate::owned_resources::registered::RegistrationAdmission::new(),
        ));
        self.owned_workspaces = Some(crate::owned_resources::WorkspacePool::new(
            crate::owned_resources::SERVICE_WORKSPACES,
        )?);
        Ok(self)
    }
    pub(crate) async fn apply_owned(&mut self, request: &ControlRequest) -> Result<()> {
        match request {
            ControlRequest::Register(registration) => {
                tokio::task::block_in_place(|| self.register(registration))
            }
            ControlRequest::Deregister(request) => {
                validate_vm_id(&request.vm_id)?;
                if self.vms.contains_key(&request.vm_id)
                    || self.owned_paths.contains_key(&request.vm_id)
                    || self.registrations.contains_key(&request.vm_id)
                {
                    self.owned_closing.insert(request.vm_id.clone());
                }
                let outcome: Result<()> = async {
                    if let Some(handle) = self.vms.get_mut(&request.vm_id) {
                        handle.stop_owned().await?;
                    }
                    tokio::task::block_in_place(|| self.deregister_helper_vm(&request.vm_id))?;
                    if let Some(path) = self.owned_paths.get_mut(&request.vm_id) {
                        path.remove()?;
                    }
                    self.registrations.remove(&request.vm_id);
                    // Keep the closing path/handle until the empty commit is durable.
                    tokio::task::block_in_place(|| self.persist_registrations())?;
                    self.vms.remove(&request.vm_id);
                    self.owned_paths.remove(&request.vm_id);
                    self.owned_closing.remove(&request.vm_id);
                    Ok(())
                }
                .await;
                if outcome.is_err() {
                    self.owned_registration_fenced = true;
                }
                outcome
            }
            ControlRequest::HvfInstanceV1(_) => {
                bail!("owned agent does not accept instance control")
            }
        }
    }
    pub(crate) async fn close_owned(&mut self) -> Result<()> {
        // Stop both queues before awaiting either one. Ordinary owner EOF is
        // not an invented I/O fatal; actual retirement failure still fences.
        for handle in self.vms.values_mut() {
            if let Some(stop) = handle.owned_stop.take() {
                let _ = stop.send(());
            }
        }
        let names: Vec<_> = self.owned_paths.keys().cloned().collect();
        for vm_id in names {
            self.apply_owned(&ControlRequest::Deregister(
                super::super::control::DeregisterVm { vm_id },
            ))
            .await?;
        }
        ensure!(
            self.vms.is_empty() && self.owned_paths.is_empty() && self.registrations.is_empty(),
            "owned daemon has unfinished registrations"
        );
        Ok(())
    }
    pub(crate) fn remove_owned_journal(&self) -> Result<()> {
        self.owned_journal
            .as_ref()
            .context("owned journal missing")?
            .remove_empty()
    }
}

async fn owner_closed(owner: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>) -> Result<()> {
    loop {
        let mut ready = owner.readable().await?;
        match ready
            .try_io(|fd| rustix::io::read(fd.get_ref(), &mut [0; 1]).map_err(std::io::Error::from))
        {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => bail!("unexpected owned lifetime pipe data"),
            Ok(Err(error)) => return Err(error).context("owned lifetime pipe"),
            Err(_) => continue,
        }
    }
}

async fn stop_signer(signer: &mut tokio::process::Child) -> Result<()> {
    ensure!(
        signer.try_wait()?.is_none(),
        "original signer exited unexpectedly"
    );
    signer.start_kill().context("stop original signer child")?;
    let status = tokio::time::timeout(Duration::from_secs(2), signer.wait())
        .await
        .context("original signer child exit timed out")??;
    use std::os::unix::process::ExitStatusExt;
    ensure!(
        status.success() || status.signal() == Some(libc::SIGKILL),
        "original signer exit was not collected intentional termination"
    );
    Ok(())
}

#[cfg(test)]
mod bounded_closing_tests {
    use super::*;

    fn private_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn daemon(directory: &Path, tenant: &str) -> Result<HostAgentDaemon> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        HostAgentDaemon::new(tenant, key, 65536)
            .with_registration_journal(directory.join("registrations.json"))
            .with_owned_lifecycle(1)
    }

    #[test]
    fn owned_child_refuses_unbounded_tenant_before_service_clones() {
        let directory = private_directory();
        assert!(daemon(directory.path(), &"t".repeat(64)).is_err());
        assert!(!directory.path().join("registrations.json").exists());
        assert!(daemon(directory.path(), &"t".repeat(63)).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_registration_refuses_repeated_service_expansion_before_binding() {
        let directory = private_directory();
        let mut daemon = daemon(directory.path(), "local").unwrap();
        let mut registration =
            super::super::tests::register(directory.path(), "vm-1", "local", None);
        let socket = PathBuf::from(&registration.broker_listen_socket);
        registration.services_bindings =
            vec![mvm_core::protocol::broker::ServiceId::parse("host.audit.v1").unwrap(); 3];
        assert!(daemon.register(&registration).is_err());
        assert!(!socket.exists(), "shape refusal precedes listener effects");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_registration_refuses_large_capability_key_before_binding() {
        use mvm_contract::protocol::agent_capability::{CapabilityBinding, CapabilityId};
        let directory = private_directory();
        let mut daemon = daemon(directory.path(), "local").unwrap();
        let mut registration =
            super::super::tests::register(directory.path(), "vm-1", "local", None);
        let socket = PathBuf::from(&registration.broker_listen_socket);
        registration.capability_bindings = vec![CapabilityBinding {
            capability: CapabilityId::new(
                mvm_core::protocol::broker::ServiceId::parse(format!(
                    "host.{}.v1",
                    "a".repeat(100)
                ))
                .unwrap(),
                "v".repeat(40),
            )
            .unwrap(),
            descriptor_digest: [1; 32],
        }];
        assert!(daemon.register(&registration).is_err());
        assert!(!socket.exists(), "shape refusal precedes listener effects");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_deregister_failures_do_not_accumulate_closing_names() {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let journal = directory.path().join("registrations.json");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        // State-layer regression: no helper is configured and no successful
        // cleanup/authority claim is made. Real signer effects have separate
        // original-Child process coverage.
        let mut daemon = HostAgentDaemon::new("local", key, 65536)
            .with_registration_journal(&journal)
            .with_owned_lifecycle(1)
            .unwrap();
        std::fs::write(&journal, b"foreign evidence").unwrap();
        for index in 0..16 {
            assert!(
                daemon
                    .apply_owned(&ControlRequest::Deregister(
                        super::super::super::control::DeregisterVm {
                            vm_id: format!("vm-fault-{index}")
                        }
                    ))
                    .await
                    .is_err()
            );
        }
        assert_eq!(std::fs::read(&journal).unwrap(), b"foreign evidence");
        assert_eq!(
            daemon.owned_closing.len(),
            0,
            "unknown input must not allocate persistent names"
        );
        assert!(daemon.owned_registration_fenced);
    }
}
