use super::*;

#[test]
fn host_lifetime_entry_requires_disk_custody_and_prepared_lease_together() {
    type Boot = fn(
        &FcDriver,
        &VmmSpec,
        Option<&mvm_vmm::host::restore_image::VerifiedRestoreFile>,
        mvm_vmm::driver::prepared_disks::PreparedWritableDisks,
        PreparedHostLifetimeLease,
    ) -> Result<Box<dyn RunningVm>>;
    let _: Boot = FcDriver::boot_custodied_with_host_lease;
}
