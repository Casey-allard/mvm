//! Parent-issued static endpoint partition. A projection never grants quota.

use super::*;

/// Immutable location data. Only the retained original guard owns disk credit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointStoreLocator {
    pub version: u16,
    pub path: std::path::PathBuf,
    pub device: u64,
    pub inode: u64,
    pub reservation_serial: u64,
    /// Installed managed tenant tag, not the canonical tenant-name encoding.
    pub tenant: [u8; 32],
    pub session: [u8; 32],
}
impl EndpointStoreLocator {
    fn validate(&self, session: [u8; 32]) -> Result<()> {
        let bytes = self.path.as_os_str().as_encoded_bytes();
        ensure!(
            self.version == 1
                && self.path.is_absolute()
                && bytes.len() <= 4096
                && !bytes.contains(&0)
                && !bytes
                    .split(|byte| *byte == b'/')
                    .any(|part| matches!(part, b"." | b".."))
                && self.reservation_serial > 0
                && self.session != [0; 32]
                && self.session == session,
            "invalid endpoint store locator"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPartitionProjection {
    pub version: u16,
    pub binding: HostLaunchBinding,
    pub admitted_plan_id: String,
    pub session: [u8; 32],
    pub partition_serial: u64,
    pub profile: u16,
    pub store: Option<EndpointStoreLocator>,
    pub limits: EndpointPartitionLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPartitionLimits {
    pub host_plaintext_bytes: u64,
    pub host_codec_bytes: u64,
    pub host_carrier_bytes: u64,
    pub host_metadata_bytes: u64,
    pub host_stack_bytes: u64,
    pub cache_disk_bytes: u64,
    pub staging_disk_bytes: u64,
    pub workers: u32,
    pub max_streams: u16,
}
impl EndpointPartitionLimits {
    /// Managed host memory only. Guest VM RAM is a separate parent domain.
    pub fn host_resident_bytes(&self) -> Result<u64> {
        [
            self.host_plaintext_bytes,
            self.host_codec_bytes,
            self.host_carrier_bytes,
            self.host_metadata_bytes,
            self.host_stack_bytes,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, value| {
            sum.checked_add(value)
                .context("endpoint host memory sum overflow")
        })
    }
}

/// Trusted installed DI must retain the actual pre-reserved parent lease and
/// check its original epoch/slot. Implementing this from a quota DTO is invalid.
pub trait EndpointPartitionGuard: Send + Sync {
    fn check_current(&self, projection: &EndpointPartitionProjection) -> Result<()>;

    /// Bind retained telemetry to this original owner before writer effects.
    ///
    /// Implementations must compare the borrowed directory to the original
    /// registered state pin and retain actual parent storage credit. A path,
    /// projection or successful callback alone is not deletion authority.
    ///
    /// # Errors
    /// The default refuses unsupported providers without performing effects.
    fn prepare_retained_telemetry(
        &self,
        _projection: &EndpointPartitionProjection,
        _state_path: &std::path::Path,
        _state_directory: &File,
    ) -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "original retained telemetry owner unavailable",
        )
        .into())
    }

    /// Retain the actual records/key files under this original preparation.
    ///
    /// The provider must verify its existing state pin and creation intent,
    /// fixed names and file identities, and retain the actual files/credit
    /// before accepting binding. This callback grants no creation or deletion.
    ///
    /// # Errors
    /// The default refuses unsupported providers without performing effects.
    fn bind_retained_telemetry_files(
        &self,
        _projection: &EndpointPartitionProjection,
        _state_path: &std::path::Path,
        _state_directory: &File,
        _records_file: &File,
        _wrapped_key_file: &File,
    ) -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "original retained telemetry file owner unavailable",
        )
        .into())
    }
}

/// Linear partition owner, not serializable or cloneable. Moving it never
/// releases/reacquires its actual original parent reservation.
#[must_use = "retain the actual partition until endpoint workers have joined"]
pub struct PreparedEndpointPartition {
    projection: EndpointPartitionProjection,
    guard: Arc<dyn EndpointPartitionGuard>,
}
impl PreparedEndpointPartition {
    pub fn new(
        projection: EndpointPartitionProjection,
        guard: Arc<dyn EndpointPartitionGuard>,
    ) -> Result<Self> {
        crate::naming::validate_vm_name(&projection.binding.vm_name)?;
        ensure!(
            projection.version == 1
                && projection.binding.generation > 0
                && projection.binding.grant_serial > 0
                && projection.binding.cpus > 0
                && projection.binding.memory_mib > 0
                && projection.partition_serial > 0
                && projection.profile > 0
                && projection.session != [0; 32]
                && !projection.admitted_plan_id.is_empty()
                && projection.admitted_plan_id.len() <= 256
                && projection.limits.workers > 0
                && projection.limits.max_streams > 0
                && projection.limits.host_resident_bytes()? > 0,
            "invalid endpoint partition projection"
        );
        projection
            .limits
            .cache_disk_bytes
            .checked_add(projection.limits.staging_disk_bytes)
            .context("endpoint disk sum overflow")?;
        if let Some(store) = &projection.store {
            store.validate(projection.session)?;
        } else {
            ensure!(
                projection.profile != 2,
                "codec endpoint original store missing"
            );
        }
        guard.check_current(&projection)?;
        Ok(Self { projection, guard })
    }

    pub fn projection(&self) -> &EndpointPartitionProjection {
        &self.projection
    }

    pub fn check_current(&self) -> Result<()> {
        self.guard.check_current(&self.projection)
    }

    /// Cleanup identity only: equal projection fields do not own this guard.
    pub fn retains_guard(&self, guard: &Arc<dyn EndpointPartitionGuard>) -> bool {
        Arc::ptr_eq(&self.guard, guard)
    }
}
impl fmt::Debug for PreparedEndpointPartition {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("PreparedEndpointPartition")
            .field("projection", &self.projection)
            .finish_non_exhaustive()
    }
}

/// The original partition, SH descriptions and installation anchor move as one
/// owner. There is no constructor from separately selected files or a DTO.
#[must_use = "retain original endpoint custody until positive worker exit"]
pub struct PreparedEndpointHandoff {
    pub(super) partition: PreparedEndpointPartition,
    pub(super) holder: PreparedHostLifetimeLease,
    pub(super) anchor: Arc<HostLifetimeAnchor>,
}
impl PreparedEndpointHandoff {
    pub fn partition(&self) -> &PreparedEndpointPartition {
        &self.partition
    }
    pub fn holder(&self) -> &PreparedHostLifetimeLease {
        &self.holder
    }

    /// Ask only the same original guard to bind retained telemetry storage.
    ///
    /// Fresh holder, current-parent and partition checks surround a successful
    /// callback. No descriptor is duplicated and no replacement guard, cap or
    /// serialized authority is accepted. The provider retains any effects on
    /// error; callers must not interpret refusal as a no-effects certificate.
    ///
    /// # Errors
    /// Refuses stale original custody, an unsupported provider, or any failure
    /// from the original storage owner, including a post-callback revocation.
    pub fn prepare_retained_telemetry(
        &self,
        state_path: &std::path::Path,
        state_directory: &File,
    ) -> Result<()> {
        self.check_current()?;
        self.partition.guard.prepare_retained_telemetry(
            self.partition.projection(),
            state_path,
            state_directory,
        )?;
        self.check_current()
    }

    /// Bind original files through only this handoff's retained owner.
    ///
    /// The writer must subsequently consume the same verified records File,
    /// rather than reopening its path. Fresh original-custody checks surround
    /// a successful callback; a late refusal does not undo the provider's file
    /// retention or certify that no effects occurred.
    ///
    /// # Errors
    /// Refuses stale custody, missing original preparation, unsupported file
    /// binding or any provider failure. No metadata is a replacement authority.
    pub fn bind_retained_telemetry_files(
        &self,
        state_path: &std::path::Path,
        state_directory: &File,
        records_file: &File,
        wrapped_key_file: &File,
    ) -> Result<()> {
        self.check_current()?;
        self.partition.guard.bind_retained_telemetry_files(
            self.partition.projection(),
            state_path,
            state_directory,
            records_file,
            wrapped_key_file,
        )?;
        self.check_current()
    }

    pub fn check_current(&self) -> Result<()> {
        self.anchor.verify_current()?;
        let parent = self
            .anchor
            .current_parent
            .lock()
            .map_err(|_| anyhow::anyhow!("host parent binding poisoned"))?
            .as_ref()
            .cloned()
            .context("original parent resource permit missing")?;
        parent.check_current(self.anchor.binding())?;
        self.partition.check_current()
    }
}
impl fmt::Debug for PreparedEndpointHandoff {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("PreparedEndpointHandoff")
            .field("projection", self.partition.projection())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "endpoint_retained_tests.rs"]
mod retained_telemetry_tests;
