//! Passive lifetime proof for the original guest mailbox bridge. No signing or stop capability.
use super::{
    ConnectedInstance, OwnedInstance, ProcessExitObserver, ProcessExitWait, require_bridge_peer,
    wire,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::{hvf_control::HvfInstance, mailbox::MAILBOX_PORT};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};

/// Public fields for the launcher's private worker bootstrap. A deserialized record
/// alone establishes no process identity or mailbox authorization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalMailboxTarget {
    instance: HvfInstance,
    child_pid: u32,
    root: [u8; 32],
}

impl OwnedInstance {
    /// The original opaque cold owner supplies the incarnation and public control root.
    pub fn mailbox_target(&self) -> Result<OriginalMailboxTarget> {
        super::require_owned_child_custody()?;
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("original HVF child poisoned"))?;
        ensure!(child.try_wait()?.is_none(), "original HVF child exited");
        Ok(OriginalMailboxTarget {
            instance: self.instance.clone(),
            child_pid: child.id(),
            root: self.root.to_bytes(),
        })
    }
}

impl OriginalMailboxTarget {
    pub fn matches_operator(&self, key: &[u8; 32]) -> bool {
        &self.root == key
    }
    pub fn instance(&self) -> &HvfInstance {
        &self.instance
    }
    pub fn child_pid(&self) -> u32 {
        self.child_pid
    }

    /// Called separately by each worker under authenticated original launch input.
    /// A fresh challenge is generated only after arming this worker's kernel observer.
    pub fn observe_at(&self, home: &Path, until: Instant) -> Result<OriginalMailboxObservation> {
        let deadline = until.min(Instant::now() + wire::CONNECTION_BUDGET);
        ensure!(home.is_absolute(), "original home is not absolute");
        mvm_core::naming::validate_vm_name(&self.instance.vm_id)?;
        let state = mvm_core::config::vm_state_dir_at(home, &self.instance.vm_id);
        self.check_current(&state)?;
        let path = mvm_core::config::vm_socket_dir_at(&state).join(wire::SOCKET_FILE);
        let stream = mvm_agentd::vsock::connect_unix_before(&path, deadline)?;
        let observer = self.arm_connected(stream, deadline, state)?;
        observer.require_current()?;
        Ok(observer)
    }
    fn check_current(&self, state: &Path) -> Result<()> {
        use std::{
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let f = std::fs::File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(state.join(wire::INSTANCE_FILE))?;
        let meta = f.metadata()?;
        mvm_core::private_fs::require_current_owner(&meta)?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.mode() & 0o022 == 0
                && meta.len() <= wire::MAX_FRAME_BYTES as u64,
            "invalid original HVF instance record"
        );
        let mut bytes = Vec::new();
        f.take(wire::MAX_FRAME_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= wire::MAX_FRAME_BYTES,
            "oversized original HVF instance record"
        );
        ensure!(
            serde_json::from_slice::<HvfInstance>(&bytes)? == self.instance,
            "HVF mailbox generation changed"
        );
        Ok(())
    }
    fn arm_connected(
        &self,
        mut stream: UnixStream,
        deadline: Instant,
        state: PathBuf,
    ) -> Result<OriginalMailboxObservation> {
        let key = VerifyingKey::from_bytes(&self.root)?;
        let (observer, _) = ConnectedInstance::prove_connected(
            &mut stream,
            &self.instance,
            Some(self.child_pid),
            &key,
            deadline,
        )?;
        let proof = OriginalMailboxObservation::from_proven_peer(self.clone(), observer, state);
        proof.require_process_live()?;
        Ok(proof)
    }
}

/// This worker owns an independently armed exit observer. The first observed
/// exit or observation failure remains terminal even on one-shot EVFILT_PROC.
pub struct OriginalMailboxObservation {
    target: OriginalMailboxTarget,
    observer: Mutex<Option<ProcessExitObserver>>,
    state: PathBuf,
}
impl OriginalMailboxObservation {
    fn from_proven_peer(
        target: OriginalMailboxTarget,
        observer: ProcessExitObserver,
        state: PathBuf,
    ) -> Self {
        Self {
            target,
            observer: Mutex::new(Some(observer)),
            state,
        }
    }
    fn require_process_live(&self) -> Result<()> {
        let mut slot = self
            .observer
            .lock()
            .map_err(|_| anyhow::anyhow!("worker lifetime observer poisoned"))?;
        let observer = slot
            .as_ref()
            .context("original HVF supervisor no longer live")?;
        match observer.wait_event(Instant::now()) {
            Ok(ProcessExitWait::TimedOut) => Ok(()),
            result => {
                *slot = None;
                result?;
                anyhow::bail!("original HVF supervisor exited")
            }
        }
    }
    pub fn require_current(&self) -> Result<()> {
        self.require_process_live()?;
        if let Err(error) = self.target.check_current(&self.state) {
            // A later replacement of the public file cannot revive an observed retired generation.
            *self
                .observer
                .lock()
                .map_err(|_| anyhow::anyhow!("worker lifetime observer poisoned"))? = None;
            return Err(error);
        }
        self.require_process_live()
    }
    /// The OS connects precisely port 5257's canonical bridge. Its peer must be
    /// the already-proven original supervisor, and its generation must stay current.
    pub fn open_mailbox(&self, until: Instant) -> Result<UnixStream> {
        let deadline = until.min(Instant::now() + wire::CONNECTION_BUDGET);
        self.require_current()?;
        let path = mvm_core::config::vm_hvf_vsock_port_socket_at(&self.state, MAILBOX_PORT);
        let stream = mvm_agentd::vsock::connect_unix_before(&path, deadline)?;
        require_bridge_peer(&stream, self.target.child_pid)?;
        self.require_current()?;
        ensure!(
            Instant::now() < deadline,
            "original HVF mailbox connection deadline"
        );
        Ok(stream)
    }
}

#[cfg(test)]
mod tests;
