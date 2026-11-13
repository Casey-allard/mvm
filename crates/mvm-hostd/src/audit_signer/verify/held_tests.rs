use super::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

#[test]
fn original_signed_workload_fd_verifies_final_scope_without_moving_its_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = super::tests::build(&dir, 3);
    let mut file = File::open(&path).unwrap();
    file.seek(SeekFrom::Start(8)).unwrap();
    let metadata = file.metadata().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let head = std::fs::read_to_string(dir.path().join("HEAD")).unwrap();
    let original = WorkloadChainExpectation {
        tenant: "t-1",
        workload: "wl-1",
        head: &head,
        length: metadata.len(),
        cap: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    std::fs::rename(&path, dir.path().join("held")).unwrap();
    std::fs::write(&path, []).unwrap();
    let verify = |expected: &WorkloadChainExpectation<'_>| {
        verify_original_workload_chain(&file, &key.verifying_key(), expected)
    };
    let report = verify(&original).unwrap();
    assert_eq!(report.entries, 3);
    assert_eq!(report.length, bytes.len() as u64);
    assert_eq!(report.sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
    assert_eq!(report.head, head);
    assert!(
        verify(&WorkloadChainExpectation {
            tenant: "other",
            ..original
        })
        .is_err()
    );
    assert!(
        verify(&WorkloadChainExpectation {
            workload: "other",
            ..original
        })
        .is_err()
    );
    assert!(
        verify(&WorkloadChainExpectation {
            head: &"0".repeat(64),
            ..original
        })
        .is_err()
    );
    assert!(
        verify(&WorkloadChainExpectation {
            cap: original.length - 1,
            ..original
        })
        .is_err()
    );
    assert!(
        verify(&WorkloadChainExpectation {
            length: original.length - 1,
            ..original
        })
        .is_err()
    );
    assert!(
        verify(&WorkloadChainExpectation {
            inode: original.inode.wrapping_add(1),
            ..original
        })
        .is_err()
    );
    assert_eq!(file.stream_position().unwrap(), 8);
}

#[test]
fn authenticated_empty_genesis_and_unterminated_or_oversized_rows_are_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let (path, key) = super::tests::build(&dir, 0);
    let file = File::open(&path).unwrap();
    let meta = file.metadata().unwrap();
    let genesis = CanonicalEntry::genesis_prev_hash();
    let expected = WorkloadChainExpectation {
        tenant: "t-1",
        workload: "wl-1",
        head: &genesis,
        length: 0,
        cap: 1 << 20,
        device: meta.dev(),
        inode: meta.ino(),
    };
    let verify = |e: &WorkloadChainExpectation<'_>| {
        verify_original_workload_chain(&file, &key.verifying_key(), e)
    };
    assert_eq!(verify(&expected).unwrap().entries, 0);
    assert!(
        verify(&WorkloadChainExpectation {
            head: "",
            ..expected
        })
        .is_err()
    );
    for bytes in [b" ".to_vec(), vec![b' '; 256 * 1024 + 2], b"\n".to_vec()] {
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            verify(&WorkloadChainExpectation {
                length: bytes.len() as u64,
                ..expected
            })
            .is_err()
        );
    }
}
