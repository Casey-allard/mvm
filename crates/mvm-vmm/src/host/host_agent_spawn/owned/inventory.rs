//! Authenticated read-only file inventory for the original funded audit chain.
use super::*;
use mvm_core::protocol::audit_inventory::verify;
use mvm_core::protocol::audit_signer::{AuditInventory, AuditInventoryPhase, SignedAuditInventory};
use std::ffi::{OsStr, OsString};

pub struct RegisteredAuditFile {
    parent: File,
    directory_path: PathBuf,
    file: File,
    name: OsString,
    registration: SignedAuditInventory,
    opened: AuditInventory,
    terminal: Option<(AuditInventory, SignedAuditInventory)>,
}

impl RegisteredAuditFile {
    pub(super) fn capture(
        request: &RegisterVm,
        signed: &SignedAuditInventory,
        limit: u64,
    ) -> Result<Self> {
        // The key is enrolled exactly once on the private connection to the
        // original daemon, which verified its original signer's connected PID.
        let opened = verify(signed, &signed.key)?;
        ensure!(
            opened.phase == AuditInventoryPhase::Registered
                && opened.tenant == request.tenant_id
                && opened.vm == request.vm_id
                && Some(&opened.workload) == request.workload_id.as_ref()
                && opened.length <= limit,
            "signed original audit registration differs"
        );
        let path = Path::new(&request.workload_chain_path);
        let directory_path = path.parent().context("missing audit parent")?.to_path_buf();
        let parent = crate::host::restore_image::open_trusted_dir(&directory_path)?;
        let name = path
            .file_name()
            .context("missing audit filename")?
            .to_owned();
        let file = Self::open_reader(&parent, &name)?;
        let result = Self {
            parent,
            directory_path,
            file,
            name,
            registration: signed.clone(),
            opened,
            terminal: None,
        };
        result.check_file(&result.opened, limit)?;
        Ok(result)
    }

    fn open_reader(parent: &File, name: &OsStr) -> Result<File> {
        use rustix::fs::{Mode, OFlags, openat};
        Ok(openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?
        .into())
    }

    fn check_file(&self, facts: &AuditInventory, limit: u64) -> Result<()> {
        let current =
            crate::host::restore_image::open_trusted_dir(&self.directory_path)?.metadata()?;
        let parent = self.parent.metadata()?;
        ensure!(
            (current.dev(), current.ino()) == (parent.dev(), parent.ino()),
            "original audit directory changed"
        );
        let held = self.file.metadata()?;
        let named = Self::open_reader(&self.parent, &self.name)?.metadata()?;
        ensure!(
            (named.dev(), named.ino()) == (held.dev(), held.ino())
                && (held.dev(), held.ino()) == (facts.dev, facts.ino)
                && held.is_file()
                && held.nlink() == 1
                && held.uid() == self.parent.metadata()?.uid()
                && held.mode() & 0o077 == 0
                && held.len() == facts.length
                && held.len() <= limit,
            "original funded audit file changed"
        );
        Ok(())
    }

    pub(super) fn close(&mut self, signed: &SignedAuditInventory, limit: u64) -> Result<()> {
        let end = verify(signed, &self.registration.key)?;
        ensure!(
            end.phase == AuditInventoryPhase::Deregistered
                && self.opened.same_registration(&end)
                && end.length >= self.opened.length,
            "original audit terminal differs"
        );
        self.check_file(&end, limit)?;
        self.file.sync_all()?;
        self.parent.sync_all()?;
        self.check_file(&end, limit)?;
        self.terminal = Some((end, signed.clone()));
        Ok(())
    }

    pub(super) fn check_terminal(&self, limit: u64) -> Result<()> {
        self.check_file(
            self.terminal()
                .context("missing original terminal receipt")?,
            limit,
        )
    }

    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn directory(&self) -> &File {
        &self.parent
    }
    pub fn name(&self) -> &OsStr {
        &self.name
    }
    pub fn verifying_key(&self) -> [u8; 32] {
        self.registration.key
    }
    /// Original signer envelope retained for independent archive verification.
    pub fn signed_registered(&self) -> &SignedAuditInventory {
        &self.registration
    }
    /// Original signed closing envelope, available only after the held file is synced.
    pub fn signed_terminal(&self) -> Option<&SignedAuditInventory> {
        self.terminal.as_ref().map(|(_, signed)| signed)
    }
    pub fn registered(&self) -> &AuditInventory {
        &self.opened
    }
    pub fn terminal(&self) -> Option<&AuditInventory> {
        self.terminal.as_ref().map(|(facts, _)| facts)
    }
}
