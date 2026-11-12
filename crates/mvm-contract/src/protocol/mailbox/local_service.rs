//! Signed local service selection. A recognized contract is not runtime support.

use serde::{Deserialize, Serialize};

/// Version of the opt-in local mailbox service, independent of envelope v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub enum MailboxLocalServiceVersion {
    ReliableV1,
}

impl TryFrom<u16> for MailboxLocalServiceVersion {
    type Error = MailboxLocalServiceError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ReliableV1),
            _ => Err(MailboxLocalServiceError::UnsupportedVersion),
        }
    }
}

impl From<MailboxLocalServiceVersion> for u16 {
    fn from(value: MailboxLocalServiceVersion) -> Self {
        match value {
            MailboxLocalServiceVersion::ReliableV1 => 1,
        }
    }
}

/// Per-mailbox ceilings within the original shared host and guest budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxLocalLimits {
    pub payload_bytes: u32,
    pub spooled_requests: u16,
    pub retained_guest_bytes: u64,
    pub queued_messages: u16,
    pub active_calls: u16,
    pub max_frame_bytes: u32,
    pub retained_host_bytes: u64,
    pub max_connections: u8,
}

impl MailboxLocalLimits {
    /// Check the conservative contract ceilings and room for bounded local headers.
    pub fn validate(self) -> Result<(), MailboxLocalServiceError> {
        let valid = (1..=16 * 1024).contains(&self.payload_bytes)
            && (1..=256).contains(&self.spooled_requests)
            && (1..=1024 * 1024).contains(&self.retained_guest_bytes)
            && (1..=8).contains(&self.queued_messages)
            && (1..=4).contains(&self.active_calls)
            && self.active_calls <= self.queued_messages
            && self.max_frame_bytes <= 65_536
            && self.max_frame_bytes >= self.payload_bytes.saturating_add(1024)
            && self.retained_guest_bytes >= u64::from(self.max_frame_bytes) + 1024
            && (1..=512 * 1024).contains(&self.retained_host_bytes)
            && self.retained_host_bytes >= 2 * u64::from(self.max_frame_bytes) + 1024
            && self.max_connections == 3;
        if valid {
            Ok(())
        } else {
            Err(MailboxLocalServiceError::InvalidLimits)
        }
    }
}

/// Explicit signed selection. Its absence preserves the legacy grant encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "GrantWire")]
pub struct MailboxLocalServiceGrant {
    pub version: MailboxLocalServiceVersion,
    pub limits: MailboxLocalLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantWire {
    version: MailboxLocalServiceVersion,
    limits: MailboxLocalLimits,
}

impl TryFrom<GrantWire> for MailboxLocalServiceGrant {
    type Error = MailboxLocalServiceError;

    fn try_from(value: GrantWire) -> Result<Self, Self::Error> {
        let grant = Self {
            version: value.version,
            limits: value.limits,
        };
        grant.validate()?;
        Ok(grant)
    }
}

impl MailboxLocalServiceGrant {
    /// Conservative initial limits. This constructor does not enable a runtime.
    #[must_use]
    pub const fn reliable_v1() -> Self {
        Self {
            version: MailboxLocalServiceVersion::ReliableV1,
            limits: MailboxLocalLimits {
                payload_bytes: 16 * 1024,
                spooled_requests: 256,
                retained_guest_bytes: 1024 * 1024,
                queued_messages: 8,
                active_calls: 4,
                max_frame_bytes: 65_536,
                retained_host_bytes: 512 * 1024,
                max_connections: 3,
            },
        }
    }

    /// Compact shape for a single explicitly enrolled original pair. Selecting
    /// this grant alone does not activate a runtime.
    pub const fn original_cast_v1() -> Self {
        let mut service = Self::reliable_v1();
        service.limits.payload_bytes = 1024;
        service.limits.max_frame_bytes = 4096;
        service.limits.spooled_requests = 1;
        service.limits.queued_messages = 1;
        service.limits.active_calls = 1;
        service.limits.retained_guest_bytes = 8192;
        // Both signed participants cover source preparation and the routed
        // turn. The installed coordinator debits one shared ledger for both.
        service.limits.retained_host_bytes = 65_536;
        service
    }

    pub fn validate(self) -> Result<(), MailboxLocalServiceError> {
        self.limits.validate()
    }

    /// Reliable runtime support must land before any launch can select it.
    pub fn require_implemented(self) -> Result<(), MailboxLocalServiceError> {
        self.validate()?;
        Err(MailboxLocalServiceError::Unimplemented)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailboxLocalServiceError {
    #[error("unsupported mailbox local service version")]
    UnsupportedVersion,
    #[error("invalid mailbox local service limits")]
    InvalidLimits,
    #[error("ambiguous or invalid mailbox service cmdline")]
    InvalidCmdline,
    #[error("reliable mailbox service is not implemented")]
    Unimplemented,
}

/// Strictly parsed boot selection, before checking actual runtime support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxGuestService {
    Disabled,
    Legacy,
    ReliableV1,
}

impl MailboxGuestService {
    pub fn require_implemented(self) -> Result<(), MailboxLocalServiceError> {
        match self {
            Self::Disabled | Self::Legacy => Ok(()),
            Self::ReliableV1 => Err(MailboxLocalServiceError::Unimplemented),
        }
    }
}

/// Parse exact service keys once. Unknown versions and duplicate assertions fail.
pub fn parse_mailbox_service_cmdline(
    input: &str,
) -> Result<MailboxGuestService, MailboxLocalServiceError> {
    let mut mailbox = None;
    let mut service = None;
    for token in input.split_ascii_whitespace() {
        if matches!(token, "mvm.mailbox" | "mvm.mailbox.service") {
            return Err(MailboxLocalServiceError::InvalidCmdline);
        }
        if let Some(value) = token.strip_prefix("mvm.mailbox=") {
            if mailbox.replace(value).is_some() || !matches!(value, "0" | "1") {
                return Err(MailboxLocalServiceError::InvalidCmdline);
            }
        } else if let Some(value) = token.strip_prefix("mvm.mailbox.service=")
            && (service.replace(value).is_some() || value != "1")
        {
            return Err(MailboxLocalServiceError::InvalidCmdline);
        }
    }
    match (mailbox, service) {
        (None | Some("0"), None) => Ok(MailboxGuestService::Disabled),
        (Some("1"), None) => Ok(MailboxGuestService::Legacy),
        (Some("1"), Some("1")) => Ok(MailboxGuestService::ReliableV1),
        _ => Err(MailboxLocalServiceError::InvalidCmdline),
    }
}
