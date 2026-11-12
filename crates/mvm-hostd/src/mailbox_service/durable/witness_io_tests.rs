use super::*;
use std::io::{Cursor, Read, Write};

#[test]
fn aborted_exchange_preserves_successful_prefix_and_never_records_payload() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report");
    let recorder = Recorder::create(&report).unwrap();
    let input = Cursor::new(vec![0; 8]);
    let result: io::Result<()> = recorder.observe(input, |io, _| {
        let mut input = [0_u8; 10];
        io.read_exact(&mut input)
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    let file = std::fs::read_to_string(&report).unwrap();
    assert_eq!(file.lines().last(), Some("end 1 8 0 0 0 false"));
    assert!(Recorder::create(&report).is_err());
}

#[test]
fn report_marks_overflow_once_and_continues_serving_original_io() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report");
    let recorder = Recorder::create(&path).unwrap();
    for _ in 0..(MAX_EXCHANGES + 3) {
        recorder
            .observe(Cursor::new(Vec::new()), |io, _| {
                io.write_all(b"synthetic private data")
            })
            .unwrap();
    }
    let file = std::fs::read_to_string(path).unwrap();
    assert_eq!(file.lines().count(), 1 + 2 * MAX_EXCHANGES + 1);
    assert_eq!(file.lines().last(), Some("overflow"));
    assert!(file.lines().any(|line| line == "end 1 0 22 0 0 false"));
    assert!(!file.contains("synthetic"));
}

#[test]
fn records_protocol_progress_before_an_exchange_returns() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("report");
    let recorder = Recorder::create(&file).unwrap();
    recorder.observe(Cursor::new(Vec::<u8>::new()), |_, mark| {
        mark("challenge_written");
        let recorded = std::fs::read_to_string(&file).unwrap();
        assert_eq!(recorded.lines().last(), Some("phase 1 challenge_written"));
    });
}
