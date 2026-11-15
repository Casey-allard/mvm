use super::{AnyResult, MailboxReaderBootBinding, Path};

pub(super) fn load_guest_original() -> AnyResult<MailboxReaderBootBinding> {
    Err(crate::private_fs::unsupported_platform_error(Path::new("/run/mvm")).into())
}

pub(super) fn load_binding(
    state_dir: &Path,
    _guest_original: bool,
) -> AnyResult<MailboxReaderBootBinding> {
    Err(crate::private_fs::unsupported_platform_error(state_dir).into())
}
