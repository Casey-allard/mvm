use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

fn original() -> (tempfile::TempDir, File, File) {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = crate::host::restore_image::open_trusted_dir(root.path()).unwrap();
    let records = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(
            root.path()
                .join(crate::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE),
        )
        .unwrap();
    (root, state, records)
}

#[test]
fn borrowed_original_records_preflight_preserves_descriptor_custody() {
    let (root, state, mut records) = original();
    let projection = RecordsProjection::from_original(root.path(), &state, &state, &records).unwrap();
    projection.preflight(&[]).unwrap();
    assert!(projection.preflight(&[records.as_raw_fd()]).is_err());
    records.write_all(b"retained-original\n").unwrap();
    projection.preflight(&[]).unwrap();
    assert_eq!(
        std::fs::read(
            root.path()
                .join(crate::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE)
        )
        .unwrap(),
        b"retained-original\n"
    );
}

#[test]
fn records_require_original_private_read_append_file_and_exact_name() {
    let (root, state, records) = original();
    let path = root
        .path()
        .join(crate::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE);
    let readonly = File::open(&path).unwrap();
    assert!(RecordsProjection::from_original(root.path(), &state, &state, &readonly).is_err());
    let write_only = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    assert!(RecordsProjection::from_original(root.path(), &state, &state, &write_only).is_err());
    let not_append = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(RecordsProjection::from_original(root.path(), &state, &state, &not_append).is_err());
    let projection = RecordsProjection::from_original(root.path(), &state, &state, &records).unwrap();
    std::fs::rename(&path, root.path().join("retained-original")).unwrap();
    let replacement = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    assert!(projection.preflight(&[]).is_err());
    assert_eq!(records.metadata().unwrap().len(), 0);
    drop(replacement);
}

#[test]
fn records_refuse_extra_links_permissions_and_closed_numbers_without_adoption() {
    let (root, state, mut records) = original();
    let path = root
        .path()
        .join(crate::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE);
    std::fs::hard_link(&path, root.path().join("extra-link")).unwrap();
    assert!(RecordsProjection::from_original(root.path(), &state, &state, &records).is_err());
    std::fs::remove_file(root.path().join("extra-link")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(RecordsProjection::from_original(root.path(), &state, &state, &records).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut projection = RecordsProjection::from_original(root.path(), &state, &state, &records).unwrap();
    projection.descriptor = -1;
    assert!(projection.preflight(&[]).is_err());
    records.write_all(b"still-owned\n").unwrap();
}

#[test]
fn split_socket_directory_must_remain_the_original_registered_object() {
    let (root, state, records) = original();
    let sockets = root.path().join("socket-directory");
    std::fs::DirBuilder::new().mode(0o700).create(&sockets).unwrap();
    let original_socket = crate::host::restore_image::open_trusted_dir(&sockets).unwrap();
    let projection = RecordsProjection::from_original(
        root.path(), &state, &original_socket, &records,
    ).unwrap();
    projection.open_registered_socket_at(&sockets).unwrap();
    std::fs::rename(&sockets, root.path().join("first")).unwrap();
    std::fs::DirBuilder::new().mode(0o700).create(&sockets).unwrap();
    assert!(projection.open_registered_socket_at(&sockets).is_err());
}
