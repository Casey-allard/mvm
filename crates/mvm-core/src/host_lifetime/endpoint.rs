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
