//! Linear evidence for a helper construction that never crossed exec.
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalStartDisposition {
    NoExec,
    ChildOwned,
    Uncertain,
}

pub struct JournalStartAttempt {
    disposition: JournalStartDisposition,
    original: Option<NoHelperStart>,
}

impl Default for JournalStartAttempt {
    fn default() -> Self {
        Self::new()
    }
}
impl JournalStartAttempt {
    pub fn new() -> Self {
        Self {
            disposition: JournalStartDisposition::Uncertain,
            original: None,
        }
    }
    pub fn disposition(&self) -> JournalStartDisposition {
        self.disposition
    }
    pub fn fence_uncertain(&mut self) {
        self.disposition = JournalStartDisposition::Uncertain;
    }
    pub fn child_owned(&mut self) -> Result<()> {
        ensure!(
            self.original.is_some() && self.disposition == JournalStartDisposition::Uncertain,
            "original helper construction phase differs"
        );
        self.disposition = JournalStartDisposition::ChildOwned;
        Ok(())
    }
    pub fn take_no_exec(&mut self) -> Result<NoHelperStart> {
        ensure!(
            self.disposition == JournalStartDisposition::NoExec,
            "helper no-exec proof unavailable"
        );
        self.disposition = JournalStartDisposition::Uncertain;
        self.original
            .take()
            .context("original helper construction custody missing")
    }
    pub(in crate::mailbox_process) fn arm(
        &mut self,
        plan: &ExecutionPlan,
        state: &Path,
        claim: Arc<LaunchClaim>,
    ) -> Result<()> {
        ensure!(self.original.is_none(), "helper construction already armed");
        let open = |path: &Path| -> Result<File> {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)?;
            let meta = file.metadata()?;
            mvm_core::private_fs::require_current_owner(&meta)?;
            ensure!(
                meta.is_dir() && meta.mode() & 0o022 == 0,
                "unsafe original helper directory"
            );
            Ok(file)
        };
        let boot = MailboxReaderBootBinding::load(state)?;
        boot.check_plan(plan)?;
        self.original = Some(NoHelperStart {
            name: plan.image.name.clone(),
            state: open(state)?,
            owner: open(&claim.owner_dir)?,
            boot,
            claim,
        });
        self.disposition = JournalStartDisposition::NoExec;
        Ok(())
    }
    pub(crate) fn exec_failed(&mut self) {
        self.disposition = JournalStartDisposition::NoExec;
    }
}

#[must_use = "retain original no-exec custody through parent retirement publication"]
pub struct NoHelperStart {
    name: String,
    state: File,
    owner: File,
    boot: MailboxReaderBootBinding,
    claim: Arc<LaunchClaim>,
}
impl NoHelperStart {
    pub fn check_original(&self, plan: &ExecutionPlan) -> Result<()> {
        ensure!(
            plan.image.name == self.name,
            "different no-helper admission"
        );
        self.boot.check_plan(plan)?;
        let state = mvm_core::config::vm_state_dir(&self.name);
        let owner = mvm_core::config::vm_mailbox_original_owner_at(
            &mvm_core::config::mvm_keys_dir(),
            &self.name,
        );
        ensure!(
            owner == self.claim.owner_dir,
            "different no-helper installation"
        );
        for (held, path) in [(&self.state, &state), (&self.owner, &owner)] {
            let original = held.metadata()?;
            let named = std::fs::symlink_metadata(path)?;
            ensure!(
                named.is_dir() && (original.dev(), original.ino()) == (named.dev(), named.ino()),
                "original no-helper directory replaced"
            );
        }
        ensure!(
            MailboxReaderBootBinding::load(&state)? == self.boot,
            "original no-helper boot replaced"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
