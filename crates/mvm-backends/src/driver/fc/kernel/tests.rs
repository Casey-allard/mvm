use super::*;
use mvm_vmm::{
    driver::{prepared_disks::PreparedWorkloadRoot, spec::BlockDev},
    host::restore_image::{VerifiedRestoreFile, inherit_descriptors},
};
use std::{
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    process::Stdio,
};

#[test]
fn the_original_root_recipe_reads_exact_bytes_in_the_inheriting_child_after_path_replacement() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let private = root.path().join("held");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let source = root.path().join("root.img");
    let bytes = b"exact original workload bytes\0\0\xff\0";
    std::fs::write(&source, bytes).unwrap();
    let spec = super::super::tests::spec_with(
        KernelImage::Bundled,
        vec![],
        vec![BlockDev {
            source: source.clone(),
            read_only: true,
            ephemeral: false,
            slot: 0,
        }],
    );
    let sealed = VerifiedRestoreFile::prepare(
        &source,
        &private,
        &mvm_core::plan::bundle::sha256_hex(bytes),
    )
    .unwrap();
    let original = PreparedWorkloadRoot::bind(&spec, &source, sealed).unwrap();
    let recipe = fc_root_recipe(&spec, &original).unwrap();
    std::fs::write(&source, b"replacement must not be loaded").unwrap();
    assert_eq!(
        recipe.blocks[0].source,
        PathBuf::from(format!("/proc/self/fd/{}", original.file().as_raw_fd()))
    );
    let mut command = mvm_core::env_hygiene::helper_command("/bin/cat");
    command.arg(&recipe.blocks[0].source).stdin(Stdio::null());
    inherit_descriptors(&mut command, vec![original.file().as_raw_fd()]);
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, bytes);
    let mut command = mvm_core::env_hygiene::helper_command("/bin/cat");
    command.arg(&recipe.blocks[0].source).stdin(Stdio::null());
    assert!(!command.output().unwrap().status.success());
    let mut wrong = spec.clone();
    wrong.blocks[0].source = root.path().join("other.img");
    assert!(fc_root_recipe(&wrong, &original).is_err());
    wrong = spec;
    wrong.blocks[0].read_only = false;
    assert!(fc_root_recipe(&wrong, &original).is_err());
}
