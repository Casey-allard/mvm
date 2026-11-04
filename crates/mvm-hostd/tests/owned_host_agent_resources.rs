#![cfg(unix)]

use mvm_hostd::owned_resources::{WorkspacePool, validate_shape};

#[tokio::test]
async fn shared_workspaces_refuse_third_without_allocating_another_operation() {
    let pool = WorkspacePool::new(2).unwrap();
    let first = pool.try_acquire().unwrap();
    let second = pool.try_acquire().unwrap();
    assert!(pool.try_acquire().is_err());
    drop(first);
    let third = pool.try_acquire().unwrap();
    assert!(pool.try_acquire().is_err());
    drop((second, third));
    assert!(pool.try_acquire().is_ok());
}

#[tokio::test]
async fn saturated_service_workspaces_do_not_consume_cleanup_control_credit() {
    let service = WorkspacePool::new(2).unwrap();
    let cleanup = WorkspacePool::new(1).unwrap();
    let first = service.try_acquire().unwrap();
    let second = service.try_acquire().unwrap();
    assert!(service.try_acquire().is_err());
    let control = cleanup.try_acquire().unwrap();
    assert!(cleanup.try_acquire().is_err());
    drop((first, second, control));
}

#[test]
fn owned_shape_refuses_valid_json_before_typed_tree_with_too_many_nodes() {
    let bytes = serde_json::to_vec(&vec![true; 1024]).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_ok());
    assert!(validate_shape(&bytes).is_err());
    let boundary = serde_json::to_vec(&vec![true; 1023]).unwrap();
    assert!(validate_shape(&boundary).is_ok());
}

#[test]
fn owned_shape_counts_keys_and_nested_depth_and_checks_complete_document() {
    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(serde_json::from_str::<serde_json::Value>(&deep).is_ok());
    assert!(validate_shape(deep.as_bytes()).is_err());
    let boundary = format!("{}0{}", "[".repeat(32), "]".repeat(32));
    assert!(validate_shape(boundary.as_bytes()).is_ok());
    assert!(validate_shape(br#"{"key":"\u0061","array":[1,null,true]}"#).is_ok());
    assert!(validate_shape(b"{} false").is_err());
    assert!(validate_shape(b"{not-json}").is_err());
}

#[test]
fn owned_shape_refuses_oversize_body_and_zero_capacity_pool() {
    assert!(WorkspacePool::new(0).is_err());
    let bytes = serde_json::to_vec(&"x".repeat(65536)).unwrap();
    assert!(serde_json::from_slice::<String>(&bytes).is_ok());
    assert!(validate_shape(&bytes).is_err());
}

#[test]
fn owned_chain_recovers_exact_existing_head_with_bounded_tail_storage() {
    use mvm_hostd::audit_signer::{canonical::CanonicalEntry, chain::Chain};
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.jsonl");
    let head = directory.path().join("head");
    let key = directory.path().join("key");
    std::fs::write(&key, [9u8; 32]).unwrap();
    let mut chain = Chain::open(&path, &head, Some(&key)).unwrap();
    let expected = chain
        .append(CanonicalEntry {
            category: "workload_audit".into(),
            correlation_id: "original".into(),
            fields: serde_json::json!({"event":"retained"}),
            prev_hash: CanonicalEntry::genesis_prev_hash(),
            session_id: "session".into(),
            tenant_id: "local".into(),
            ts: "2026-11-03T00:00:00Z".into(),
            workload_id: "vm-1".into(),
        })
        .unwrap();
    drop(chain);
    let original = std::fs::read(&path).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    for _ in 0..20000 {
        file.write_all(&original).unwrap();
    }
    file.write_all(b"\n \t\r\n").unwrap();
    drop(file);
    assert!(path.metadata().unwrap().len() > 8 * 1024 * 1024);
    let reopened = Chain::open_owned(&path, &head, Some(&key)).unwrap();
    assert_eq!(reopened.head(), expected);
}

#[test]
fn owned_key_and_chain_tail_refuse_oversize_before_unbounded_reads() {
    use mvm_hostd::{audit_signer::chain::Chain, host_signer::keystore::Keystore};
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    let file = std::fs::File::create(&key).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    drop(file);
    assert!(Keystore::load_from_file_bounded(&key).is_err());
    std::fs::write(&key, [9u8; 32]).unwrap();
    assert!(Keystore::load_from_file_bounded(&key).is_ok());
    let path = directory.path().join("chain.jsonl");
    std::fs::write(&path, vec![b'x'; 256 * 1024 + 1]).unwrap();
    assert!(Chain::open_owned(&path, &directory.path().join("head"), Some(&key)).is_err());
}

#[tokio::test]
async fn bounded_output_matches_canonical_bytes_and_writes_nothing_on_oversize() {
    let value = serde_json::json!({"exact":"canonical","array":[1,true,null]});
    let mut canonical = Vec::new();
    mvm_hostd::framing::write_json_frame(&mut canonical, &value)
        .await
        .unwrap();
    let mut bounded = Vec::new();
    mvm_hostd::framing::write_json_frame_bounded(&mut bounded, &value, 65536)
        .await
        .unwrap();
    assert_eq!(bounded, canonical);
    let mut refused = Vec::new();
    assert!(
        mvm_hostd::framing::write_json_frame_bounded(&mut refused, &"x".repeat(65536), 65536)
            .await
            .is_err()
    );
    assert!(
        refused.is_empty(),
        "no prefix or partial body before size qualification"
    );
}

#[tokio::test]
async fn shape_is_checked_on_real_socket_before_typed_deserialize() {
    use tokio::io::AsyncWriteExt;
    struct Never;
    impl<'de> serde::Deserialize<'de> for Never {
        fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            panic!("typed allocation/deserializer reached before shape refusal");
        }
    }
    let bytes = serde_json::to_vec(&vec![true; 1024]).unwrap();
    let (mut sender, mut receiver) = tokio::net::UnixStream::pair().unwrap();
    let writer = tokio::spawn(async move {
        sender
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        sender.write_all(&bytes).await.unwrap();
    });
    let outcome = mvm_hostd::framing::read_json_frame_checked::<_, Never>(
        &mut receiver,
        65536,
        validate_shape,
    )
    .await;
    assert!(outcome.is_err());
    writer.await.unwrap();
}
