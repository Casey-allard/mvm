//! Heap declaration from the already debited original installed store permit.
use super::{PayloadResourcePermit, invalid};
use spiralcore_transfer::resource_profile::ResourceProfile;
use std::io;

impl PayloadResourcePermit {
    pub(super) fn owned_store_heap_bytes(&self) -> io::Result<u64> {
        self.check_current()?;
        let work = self.store_work.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "installed store workspace not booked",
            )
        })?;
        if self.profile != Some(ResourceProfile::SmallV1) {
            return Err(invalid("installed store profile differs"));
        }
        let charged = ResourceProfile::SmallV1
            .operation_charge()
            .map_err(invalid)?
            .checked_add(work.workspace_bytes)
            .ok_or_else(|| invalid("installed store workspace charge overflow"))?;
        if self.charge.resident_bytes < charged {
            return Err(invalid("installed store workspace debit missing"));
        }
        Ok(work.workspace_bytes)
    }
}
