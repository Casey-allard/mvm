use super::{
    AnyResult, MAILBOX_READER_BOOT_FILE, MAX_MAILBOX_READER_BOOT_BYTES, MailboxReaderBootBinding,
    Path,
};
use anyhow::Context as _;

pub(super) fn load_guest_original() -> AnyResult<MailboxReaderBootBinding> {
    use std::os::unix::fs::MetadataExt as _;
    let dir = Path::new("/run/mvm");
    for ancestor in dir.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted original boot directory"
        );
    }
    load_binding(dir, true)
}

pub(super) fn load_binding(
    state_dir: &Path,
    guest_original: bool,
) -> AnyResult<MailboxReaderBootBinding> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let path = state_dir.join(MAILBOX_READER_BOOT_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && (!guest_original || (metadata.uid() == 0 && metadata.mode() & 0o222 == 0))
            && metadata.nlink() == 1
            && metadata.len() <= MAX_MAILBOX_READER_BOOT_BYTES,
        "mailbox reader boot binding is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_MAILBOX_READER_BOOT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_MAILBOX_READER_BOOT_BYTES,
        "mailbox reader boot binding exceeds the encoded bound"
    );
    serde_json::from_slice(&bytes).context("decode mailbox reader boot binding")
}
