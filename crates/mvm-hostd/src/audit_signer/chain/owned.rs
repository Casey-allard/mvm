use super::*;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

const LINE_BYTES: usize = 256 * 1024;
const HEAD_BYTES: usize = 256;

pub(super) fn recover_head(file: &File, secondary: &Path) -> Result<String> {
    // The original readable O_APPEND file holds the sole-writer lock. Cloning
    // preserves that identity, rather than reopening the mutable JSONL path.
    let mut source = file.try_clone()?;
    source.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::with_capacity(8192, source);
    let mut line = Vec::with_capacity(LINE_BYTES + 1);
    let mut last = Vec::with_capacity(LINE_BYTES);
    loop {
        line.clear();
        let count = (&mut reader)
            .take((LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        anyhow::ensure!(count <= LINE_BYTES, "owned audit line limit");
        if count == 0 {
            break;
        }
        let text = std::str::from_utf8(&line)?;
        if !text.trim().is_empty() {
            last.clear();
            last.extend_from_slice(&line);
        }
    }
    let head = if last.is_empty() {
        CanonicalEntry::genesis_prev_hash()
    } else {
        let entry: OnDiskEntry = serde_json::from_slice(&last)?;
        anyhow::ensure!(
            entry.entry_hash.len() == 64
                && entry
                    .entry_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "owned audit head shape"
        );
        entry.entry_hash
    };
    let prior = bounded_head(secondary)?;
    if prior.as_deref() != Some(head.as_str()) && head != CanonicalEntry::genesis_prev_hash() {
        write_head(secondary, &head)?;
    }
    Ok(head)
}

pub(super) fn write_head(path: &Path, head: &str) -> Result<()> {
    anyhow::ensure!(
        head.len() == 64 && head.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "owned head shape"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    anyhow::ensure!(file.metadata()?.is_file(), "owned secondary head type");
    file.write_all(head.as_bytes())?;
    Ok(())
}

fn bounded_head(path: &Path) -> Result<Option<String>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= HEAD_BYTES as u64,
        "owned head size/type"
    );
    let mut bytes = Vec::with_capacity(HEAD_BYTES + 1);
    file.take((HEAD_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= HEAD_BYTES, "owned head changed size");
    let text = std::str::from_utf8(&bytes)?.trim();
    Ok((!text.is_empty()).then(|| text.to_owned()))
}
