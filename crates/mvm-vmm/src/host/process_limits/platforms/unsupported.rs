use std::{io, process::Command};

pub(super) fn limit_address_space(_command: &mut Command, _bytes: u64) -> anyhow::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "original process address-space enforcement unavailable",
    )
    .into())
}
