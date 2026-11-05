//! Explicit installed-profile input/workspace boundary, never a credential.

use super::*;

/// Source-reviewed candidate requested workspace; caller retains actual credit.
pub fn owned_config_workspace_requirement(input_bytes: usize, max_bytes: usize) -> Result<u64> {
    anyhow::ensure!(
        (1..=65_536).contains(&max_bytes) && input_bytes <= max_bytes,
        "owned host config input limit unsupported"
    );
    let fixed = u64::try_from(max_bytes)
        .ok()
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_add(65_536));
    u64::try_from(input_bytes)
        .ok()
        .and_then(|n| n.checked_mul(1024))
        .and_then(|n| fixed.and_then(|fixed| fixed.checked_add(n)))
        .ok_or_else(|| anyhow::anyhow!("owned host config workspace overflow"))
}

/// Read one regular canonical config file within the original held workspace.
/// Workspace numbers are checked input facts, not a grant or reservation.
pub fn load_strict_bounded(
    override_dir: Option<&Path>,
    max_bytes: usize,
    workspace_bytes: u64,
) -> Result<MvmConfig> {
    use std::io::Read;
    let fixed = owned_config_workspace_requirement(0, max_bytes)?;
    anyhow::ensure!(
        workspace_bytes >= fixed,
        "owned host config read credit missing"
    );
    if let Some(directory) = override_dir {
        anyhow::ensure!(
            directory.as_os_str().len() <= 4096,
            "owned host config path unsupported"
        );
    }
    let path = config_path_at(&config_dir(override_dir));
    anyhow::ensure!(
        path.as_os_str().len() <= 4096,
        "owned host config path unsupported"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Opening an unexpected FIFO must not block before the type check.
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MvmConfig::default());
        }
        Err(_) => anyhow::bail!("host config could not be read; check config/config.toml"),
    };
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("owned host config metadata unavailable"))?;
    anyhow::ensure!(
        metadata.is_file(),
        "owned host config is not a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= u64::try_from(max_bytes)?,
        "owned host config exceeds input bound"
    );
    let limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("owned host config input overflow"))?;
    let mut bytes = Vec::with_capacity(limit);
    file.take(u64::try_from(limit)?)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("host config could not be read; check config/config.toml"))?;
    anyhow::ensure!(
        bytes.len() <= max_bytes,
        "owned host config exceeds input bound"
    );
    anyhow::ensure!(
        workspace_bytes >= owned_config_workspace_requirement(bytes.len(), max_bytes)?,
        "owned host config parser credit missing"
    );
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("host config is invalid; check config/config.toml"))?;
    parse(&text)
}
