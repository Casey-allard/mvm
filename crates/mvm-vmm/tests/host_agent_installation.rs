#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;

use mvm_vmm::host::host_agent_installation::{
    HomePreparation, create_new_home_and_provision, descriptor, prepare_home,
};
use mvm_vmm::host::installed_owner::{HolderLease, InstallationOwner, Phase};

#[test]
fn fresh_provisioning_preserves_original_identity_and_refuses_reinitialization() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let home = parent.path().canonicalize().unwrap().join("fresh-home");
    let provisioned = create_new_home_and_provision(&home, "local").unwrap();
    assert_eq!(provisioned.home(), home.as_path());
    provisioned.verify().unwrap();
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let installation = descriptor(&home, "local").unwrap();
    assert_eq!(
        installation.root,
        mvm_core::config::host_agent_dir_at(&home, "local").join("resource-owner-v1")
    );
    let mut original = InstallationOwner::open(&installation.root, installation.key).unwrap();
    assert_eq!(original.snapshot().unwrap().phase, Phase::Clean);
    assert_eq!(original.snapshot().unwrap().epoch, 0);
    let epoch = original.begin().unwrap();
    let holder =
        HolderLease::acquire(&installation.root, installation.key, epoch.generation()).unwrap();
    let record = installation.root.join("state.bin");
    let active_bytes = fs::read(&record).unwrap();
    assert!(create_new_home_and_provision(&home, "local").is_err());
    assert_eq!(fs::read(&record).unwrap(), active_bytes);
    assert_eq!(original.snapshot().unwrap().phase, Phase::Active);
    drop(holder);
    original.finish(epoch).unwrap();
    provisioned.verify().unwrap();

    let preserved = parent.path().join("preserved-home");
    fs::rename(&home, &preserved).unwrap();
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        provisioned.verify().is_err(),
        "a new pathname occupant cannot replace the original held home"
    );
    assert!(
        preserved
            .join("host-agent/local/resource-owner-v1/state.bin")
            .is_file()
    );
}

#[test]
fn invalid_tenants_refuse_before_creating_any_home() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let home = parent.path().canonicalize().unwrap().join("fresh-home");
    let oversized = "x".repeat(513);
    for tenant in [
        "",
        ".",
        "..",
        "../escape",
        "/absolute",
        "line\nbreak",
        &oversized,
    ] {
        assert!(create_new_home_and_provision(&home, tenant).is_err());
        assert!(!home.exists(), "invalid tenant created a partial home");
    }
}

#[test]
fn existing_empty_partial_and_symlink_homes_are_not_adopted_or_repaired() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = parent.path().canonicalize().unwrap();
    for name in ["empty", "partial"] {
        let home = parent.join(name);
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
        if name == "partial" {
            fs::write(home.join("retained"), b"synthetic partial initialization").unwrap();
        }
        assert!(create_new_home_and_provision(&home, "local").is_err());
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o755
        );
        if name == "partial" {
            assert_eq!(
                fs::read(home.join("retained")).unwrap(),
                b"synthetic partial initialization"
            );
        }
    }
    let target = parent.join("empty");
    let link = parent.join("home-link");
    symlink(&target, &link).unwrap();
    assert!(create_new_home_and_provision(&link, "local").is_err());
    assert!(descriptor(&link, "local").is_err());
    assert!(!target.join("host-agent").exists());
    let nested = link.join("child-home");
    assert!(create_new_home_and_provision(&nested, "local").is_err());
    assert!(!target.join("child-home").exists());
}

#[test]
fn home_preparation_distinguishes_fresh_from_live_owned_existing_storage() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let home = parent.path().canonicalize().unwrap().join("fresh-home");
    let prepared = prepare_home(&home, "local").unwrap();
    assert!(matches!(&prepared, HomePreparation::Fresh(_)));
    prepared.verify().unwrap();
    assert_eq!(prepared.home(), home);
    let labels = descriptor(&home, "local").unwrap();
    let mut owner = InstallationOwner::open(&labels.root, labels.key).unwrap();
    let epoch = owner.begin().unwrap();
    let record = labels.root.join("state.bin");
    let original = fs::read(&record).unwrap();

    let existing = prepare_home(&home, "local").unwrap();
    assert!(matches!(&existing, HomePreparation::ExistingUnverified(_)));
    existing.verify().unwrap();
    assert_eq!(fs::read(record).unwrap(), original);
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Active);
    owner.finish(epoch).unwrap();
}

#[test]
fn existing_home_preparation_preserves_unverified_state_and_refuses_intent_or_replacement() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = parent.path().canonicalize().unwrap();
    let home = parent.join("existing-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(home.join("retained"), b"existing unverified storage").unwrap();
    let prepared = prepare_home(&home, "local").unwrap();
    assert!(matches!(&prepared, HomePreparation::ExistingUnverified(_)));
    prepared.verify().unwrap();
    assert!(!home.join("host-agent").exists());
    assert_eq!(
        fs::read(home.join("retained")).unwrap(),
        b"existing unverified storage"
    );

    let intent = home.join(".host-agent-provisioning.intent");
    fs::write(&intent, b"retained incomplete initialization").unwrap();
    assert!(prepare_home(&home, "local").is_err());
    assert!(prepared.verify().is_err());
    fs::remove_file(intent).unwrap();
    let preserved = parent.join("preserved-home");
    fs::rename(&home, &preserved).unwrap();
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(prepared.verify().is_err());
    assert_eq!(
        fs::read(preserved.join("retained")).unwrap(),
        b"existing unverified storage"
    );
    assert!(!home.join("host-agent").exists());
}
