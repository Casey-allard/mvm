use mvm_core::user_config::{load_strict, load_strict_bounded, owned_config_workspace_requirement};

#[test]
fn oversized_valid_operator_config_is_refused_without_changing_legacy_loading() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("config.toml");
    let text = format!("#{}", "x".repeat(65_536));
    std::fs::write(&path, &text).unwrap();
    assert!(
        load_strict(Some(root.path())).is_ok(),
        "legacy remains unchanged"
    );
    assert!(load_strict_bounded(Some(root.path()), 65_536, u64::MAX).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
}

#[test]
fn bounded_loader_uses_canonical_proxy_precedence_and_static_private_errors() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("config.toml");
    let valid = "[egress_proxy]\nhttps='http://proxy.example:8080'\n";
    std::fs::write(&path, valid).unwrap();
    let required = owned_config_workspace_requirement(valid.len(), 65_536).unwrap();
    assert!(load_strict_bounded(Some(root.path()), 65_536, required - 1).is_err());
    let config = load_strict_bounded(Some(root.path()), 65_536, required).unwrap();
    assert_eq!(
        config.egress_proxy.unwrap().https.as_deref(),
        Some("http://proxy.example:8080")
    );
    std::fs::write(
        &path,
        "[egress_proxy]\nhttps=['SYNTHETIC_PRIVATE_TOML_VALUE']\n",
    )
    .unwrap();
    let error = load_strict_bounded(Some(root.path()), 65_536, u64::MAX).unwrap_err();
    assert!(!format!("{error:#}").contains("SYNTHETIC_PRIVATE_TOML_VALUE"));
}

#[test]
fn missing_file_and_invalid_local_limits_have_no_filesystem_mutation() {
    let root = tempfile::tempdir().unwrap();
    assert!(load_strict_bounded(Some(root.path()), 65_536, u64::MAX).is_ok());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    for limit in [0, usize::MAX] {
        assert!(load_strict_bounded(Some(root.path()), limit, u64::MAX).is_err());
    }
    assert!(owned_config_workspace_requirement(usize::MAX, 65_536).is_err());
    assert!(load_strict_bounded(Some(root.path()), 65_536, 0).is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn exact_profile_input_cap_is_accepted_and_nonregular_file_is_refused() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("config.toml"),
        format!("#{}", "x".repeat(65_535)),
    )
    .unwrap();
    assert!(load_strict_bounded(Some(root.path()), 65_536, u64::MAX).is_ok());
    std::fs::remove_file(root.path().join("config.toml")).unwrap();
    std::fs::create_dir(root.path().join("config.toml")).unwrap();
    assert!(load_strict_bounded(Some(root.path()), 65_536, u64::MAX).is_err());
}
