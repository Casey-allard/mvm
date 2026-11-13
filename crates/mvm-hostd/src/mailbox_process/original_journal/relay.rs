//! Original SDK process relaying one *sealed* canonical mailbox request. Only
//! the actual A and B mailbox helpers receive or produce plaintext.
use super::{
    OriginalJournalDestination,
    authorization::{JournalCredentials, PairedJournalAdmission},
};
use crate::mailbox_service::directed_journal::PairedSourceMaterial;
use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::mailbox::{EncryptionContext, MailboxRoutingFrame};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::frame::{Refusal, decode_frame, encode_frame};
use mvm_core::plan::ExecutionPlan;
use mvm_vmm::host::uds_peer::connected_peer_pid;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::time::Instant;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceConfiguration {
    pub(super) parent: u32,
    pub(crate) destination_name: String,
    pub(crate) grants: JournalCredentials,
    commitment: [u8; 32],
    key: [u8; 32],
    encryption: EncryptionContext,
    routing: MailboxRoutingFrame,
}
impl Drop for SourceConfiguration {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}
impl SourceConfiguration {
    pub(crate) fn material(&self) -> PairedSourceMaterial {
        PairedSourceMaterial::from_enrollment(
            self.commitment,
            Key::from_bytes(self.key),
            self.encryption.clone(),
            self.routing.clone(),
        )
    }
    /// getppid is the original launcher and remains unchanged while that
    /// process lives; an orphan reparented to init cannot adopt a replacement.
    pub(crate) fn connect(
        &self,
        source_state: &Path,
        until: Instant,
    ) -> Result<UnixStream, Refusal> {
        // SAFETY: getppid takes no arguments and returns the calling process's current parent PID.
        let original_parent = || unsafe { libc::getppid() } as u32;
        if self.parent <= 1 || original_parent() != self.parent {
            return Err(Refusal::NotAuthorized);
        }
        let stream = mvm_agentd::vsock::connect_unix_before(&path(source_state), until)
            .map_err(|_| Refusal::Unavailable)?;
        if connected_peer_pid(&stream).ok().map(|v| v as u32) != Some(self.parent)
            || original_parent() != self.parent
        {
            return Err(Refusal::NotAuthorized);
        }
        Ok(stream)
    }
}

fn path(source_state: &Path) -> PathBuf {
    mvm_core::config::vm_socket_dir_at(source_state).join("j1.sock")
}

struct OwnedListener {
    path: PathBuf,
    socket: UnixListener,
    inode: (u64, u64),
}
impl OwnedListener {
    fn bind(state: &Path) -> Result<Self> {
        let path = path(state);
        let socket =
            UnixListener::bind(&path).context("bind exclusive original A journal relay")?;
        let m = std::fs::symlink_metadata(&path)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            path,
            socket,
            inode: (m.dev(), m.ino()),
        })
    }
}
impl Drop for OwnedListener {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.inode) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The caller can service one original A guest transaction at a time. A
/// transport error or missing reply leaves A's retained intent untouched.
pub struct OriginalJournalSourceHost {
    pub(super) source: Child,
    pub(super) readiness: Option<String>,
    pub(super) restart: super::reconnect::RestartInput,
    pub(super) stop: super::stop::StopCustody,
    pub(super) boot: mvm_core::mailbox::reader::MailboxReaderBootBinding,
    pub(super) _guard: std::sync::Arc<super::LaunchClaim>,
    pub(super) marker: super::OriginalMarker,
    listener: OwnedListener,
    pub(super) destination: std::sync::Arc<std::sync::Mutex<OriginalJournalDestination>>,
    pub(super) plan: ExecutionPlan,
    pub(super) grants: std::sync::Arc<JournalCredentials>,
}

#[derive(Clone, Copy, Debug)]
pub struct CompletedRelayIo {
    /// Exact userspace bytes read from A and written to B.
    pub sealed_to_destination: usize,
    /// Exact reply bytes read from B through EOF and written to A.
    pub reply_to_source: usize,
}

impl OriginalJournalSourceHost {
    pub(super) fn require_original_relay(&self) -> Result<()> {
        let named = std::fs::symlink_metadata(&self.listener.path)?;
        ensure!(
            (named.dev(), named.ino()) == self.listener.inode && named.nlink() == 1,
            "original A relay socket changed"
        );
        Ok(())
    }
    pub fn require_ready(&self) -> Result<()> {
        if let Some(e) = &self.readiness {
            anyhow::bail!("original A did not become ready: {e}");
        }
        Ok(())
    }

    pub fn try_collect(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.stop.observe_helper(&mut self.marker, &mut self.source)
    }

    /// Request termination through the retained original Child. The caller
    /// must first confirm VM stop and separately report assisted teardown.
    /// Only try_collect can clear this helper's persistent ownership record.
    pub fn request_original_exit_after_vm_stop(&mut self) -> std::io::Result<()> {
        super::request_original_exit(&mut self.source)
    }

    /// Nonblocking on an idle listener. One shared action deadline for all
    /// socket traffic and revocation sampling once A has connected.
    pub fn forward_once(&mut self, until: Instant) -> Result<bool> {
        Ok(self.forward_once_with_counts(until)?.is_some())
    }

    pub fn forward_once_with_counts(&mut self, until: Instant) -> Result<Option<CompletedRelayIo>> {
        self.forward_once_observed(until, |_, _| {})
    }

    /// Observe the original public envelope and exact verdict only after both
    /// original helper exchanges have completed. The observer cannot alter them.
    /// An observed verdict still requires signature, binding and outcome checks.
    pub fn forward_once_observed(
        &mut self,
        until: Instant,
        observe: impl FnOnce(&mvm_contract::protocol::mailbox::MailboxEnvelope, &[u8]),
    ) -> Result<Option<CompletedRelayIo>> {
        self.require_ready()?;
        let d = self
            .plan
            .mailbox
            .as_ref()
            .and_then(|g| g.outbound_journal_v1.as_ref())
            .context("missing enrolled A direction")?;
        let now = super::authorization::now_ms()?;
        ensure!(
            (d.not_before_unix_ms..d.expires_at_unix_ms).contains(&now),
            "original A direction expired"
        );
        let window = std::time::Duration::from_millis((d.expires_at_unix_ms - now) as u64)
            .min(std::time::Duration::from_secs(12));
        let until = until.min(Instant::now() + window);
        ensure!(
            Instant::now() < until && self.source.try_wait()?.is_none(),
            "original A helper unavailable"
        );
        let (a, _) = match self.listener.socket.accept() {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        ensure!(
            connected_peer_pid(&a)? as u32 == self.source.id() && self.source.try_wait()?.is_none(),
            "accepted connection is not the original A helper"
        );
        let mut dest = self
            .destination
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original B helper is busy"))?;
        let mut a = crate::mailbox_service::durable::GuestDeadline::new(a, until)?;
        let body = crate::mailbox_service::read_frame(
            crate::mailbox_service::MAX_SOURCE_INTENT_BYTES,
            &mut a,
        )
        .map_err(|e| anyhow::anyhow!("invalid original A journal frame: {e:?}"))?;
        let (send, envelope) =
            decode_frame(&body).map_err(|_| anyhow::anyhow!("invalid canonical journal frame"))?;
        ensure!(
            send == self.grants.destination_send
                && encode_frame(&send, &envelope).ok().as_ref() == Some(&body),
            "A ciphertext did not carry the original canonical Send credential"
        );
        let b = dest.connect_for_proposal(&self.plan, &self.grants, until)?;
        let mut b = crate::mailbox_service::durable::GuestDeadline::new(b, until)?;
        b.write_all(&u32::try_from(body.len())?.to_be_bytes())?;
        b.write_all(&body)?;
        let mut verdict = Vec::new();
        b.take(mvm_core::mailbox::frame::MAX_VERDICT_BYTES + 1)
            .read_to_end(&mut verdict)?;
        ensure!(
            !verdict.is_empty()
                && verdict.len() as u64 <= mvm_core::mailbox::frame::MAX_VERDICT_BYTES,
            "incomplete or oversized B journal reply"
        );
        a.write_all(&verdict)?;
        observe(&envelope, &verdict);
        Ok(Some(CompletedRelayIo {
            sealed_to_destination: 4 + body.len(),
            reply_to_source: verdict.len(),
        }))
    }
}

impl PairedJournalAdmission {
    pub fn launch_original_source(
        &self,
        plan: &ExecutionPlan,
        backend: &mvm_runtime::backend::AnyBackend,
        name: &str,
        posture: &super::MailboxLaunchPosture,
    ) -> Result<OriginalJournalSourceHost> {
        let owner = self.launch_custodied_source(plan, backend, name, posture)?;
        if let Err(error) = owner.require_ready() {
            return Err(super::IncompleteJournalStart::new(error, owner).into());
        }
        Ok(owner)
    }

    pub fn launch_custodied_source(
        &self,
        plan: &ExecutionPlan,
        backend: &mvm_runtime::backend::AnyBackend,
        name: &str,
        posture: &super::MailboxLaunchPosture,
    ) -> Result<OriginalJournalSourceHost> {
        ensure!(
            posture.variant() == mvm_core::plan::Variant::Prod,
            "paired source requires production posture"
        );
        self.verify(plan)?;
        super::super::spawn_with_original(
            plan,
            backend,
            name,
            Some(posture),
            true,
            |config, plan, guard| {
                let setup = (|| -> Result<_> {
                    let stop = super::stop::StopCustody::capture(config, backend, name)?;
                    let boot = config.reader_boot.as_ref().context("absent A boot")?;
                    let mut dest = self
                        .original
                        .try_lock()
                        .map_err(|_| anyhow::anyhow!("original B busy"))?;
                    ensure!(
                        config.vm_state_dir == dest.peer_state(name)?
                            && config.keys_dir == dest.keys_dir,
                        "A and B require the same original installed authority"
                    );
                    let material =
                        dest.source_material(plan, posture, boot, &self.grants, self.deadline)?;
                    ensure!(
                        material.commitment
                            == mvm_core::mailbox::outbound::journal_direction_commitment(boot)?,
                        "source data key belongs to a different original boot"
                    );

                    if boot
                        .outbound_journal_v1
                        .is_some_and(|d| d.sender_settlement.is_some())
                    {
                        crate::mailbox_service::sender_window::SenderWindow::provision(
                            &config.vm_state_dir,
                            material.commitment,
                        )?;
                    }
                    let delegated = SourceConfiguration {
                        parent: std::process::id(),
                        destination_name: dest.name.clone(),
                        grants: (*self.grants).clone(),
                        commitment: material.commitment,
                        key: *material.key.expose_bytes(),
                        encryption: material.encryption,
                        routing: material.routing,
                    };
                    config.keys.outbound_source = Some(delegated);
                    let listener = OwnedListener::bind(&config.vm_state_dir)?;
                    let (source, marker, readiness, restart) =
                        stop.spawn_helper(config, &guard.owner_dir)?;
                    Ok(OriginalJournalSourceHost {
                        source,
                        restart,
                        boot: boot.clone(),
                        readiness,
                        stop,
                        _guard: guard,
                        marker,
                        listener,
                        destination: self.original.clone(),
                        plan: plan.clone(),
                        grants: self.grants.clone(),
                    })
                })();
                setup.map_err(std::io::Error::other)
            },
        )?
        .context("no admitted source mailbox")
    }
}
