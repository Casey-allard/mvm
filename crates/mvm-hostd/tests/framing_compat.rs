//! The legacy hostd path remains the same framing API as core.

use mvm_core::framing as core;
use mvm_hostd::framing as hostd;

const WIRE: &[u8] = b"\0\0\0\x017";

#[tokio::test]
async fn both_paths_exchange_the_same_wire_bytes() {
    assert_eq!(hostd::FRAME_LEN_BYTES, core::FRAME_LEN_BYTES);
    assert_eq!(
        hostd::DEFAULT_MAX_FRAME_BYTES,
        core::DEFAULT_MAX_FRAME_BYTES
    );

    let mut bytes = Vec::new();
    hostd::write_json_frame(&mut bytes, &7u8).await.unwrap();
    assert_eq!(bytes, WIRE);
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(
        core::read_json_frame::<_, u8>(&mut reader, 1)
            .await
            .unwrap(),
        7
    );

    let mut bytes = Vec::new();
    core::write_json_frame(&mut bytes, &7u8).await.unwrap();
    assert_eq!(bytes, WIRE);
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(
        hostd::read_json_frame::<_, u8>(&mut reader, 1)
            .await
            .unwrap(),
        7
    );
}

#[tokio::test]
async fn facade_preserves_error_identity_and_caller_cap() {
    let mut reader = std::io::Cursor::new(WIRE);
    let error: core::FrameError = hostd::read_json_frame::<_, u8>(&mut reader, 0)
        .await
        .unwrap_err();
    let error: hostd::FrameError = error;
    assert!(matches!(
        error,
        core::FrameError::TooLarge { size: 1, cap: 0 }
    ));
    assert_eq!(reader.position(), 4);
}

#[tokio::test]
async fn bounded_writer_keeps_wire_and_refuses_before_any_output() {
    let mut bytes = Vec::new();
    hostd::write_json_frame_bounded(&mut bytes, &7u8, 1)
        .await
        .unwrap();
    assert_eq!(bytes, WIRE);
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(
        core::read_json_frame_checked::<_, u8>(&mut reader, 1, |body| {
            assert_eq!(body, b"7");
            Ok(())
        })
        .await
        .unwrap(),
        7
    );
    let mut bytes = Vec::new();
    assert!(matches!(
        core::write_json_frame_bounded(&mut bytes, &[7u8, 8], 1).await,
        Err(hostd::FrameError::Encode(_))
    ));
    assert!(bytes.is_empty());
    assert!(matches!(
        hostd::write_json_frame_bounded(&mut bytes, &7u8, 0).await,
        Err(core::FrameError::LengthOverflow)
    ));
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn checked_reader_keeps_validation_and_cap_before_typed_parse() {
    let mut reader = std::io::Cursor::new(WIRE);
    let mut checked = false;
    let error = hostd::read_json_frame_checked::<_, bool>(&mut reader, 1, |body| {
        checked = true;
        assert_eq!(body, b"7");
        Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fixture validation refusal",
        )))
    })
    .await
    .unwrap_err();
    assert!(checked);
    match error {
        core::FrameError::Decode(error) => {
            assert_eq!(error.to_string(), "fixture validation refusal");
        }
        error => panic!("validation failure changed: {error}"),
    }
    assert_eq!(reader.position(), WIRE.len() as u64);

    let mut reader = std::io::Cursor::new(WIRE);
    let error = core::read_json_frame_checked::<_, u8>(&mut reader, 0, |_| {
        panic!("oversize input must not reach validation")
    })
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        hostd::FrameError::TooLarge { size: 1, cap: 0 }
    ));
    assert_eq!(reader.position(), 4);
}
