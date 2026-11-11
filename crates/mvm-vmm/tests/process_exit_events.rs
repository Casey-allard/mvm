#![cfg(any(target_os = "linux", target_os = "macos"))]
use mvm_vmm::host::process_exit::{ProcessExitObserver, wait_process_exit_events};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn multiplexed_exit_and_wakeup_keep_original_child_collection_separate() {
    let mut child = Command::new("/bin/cat")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let observer = ProcessExitObserver::arm(child.id().try_into().unwrap()).unwrap();
    let (mut wake, mut sender) = UnixStream::pair().unwrap();
    let idle = wait_process_exit_events(
        &[&observer],
        Some(wake.as_fd()),
        Some(Instant::now() + Duration::from_millis(20)),
    )
    .unwrap();
    assert!(idle.timed_out);
    assert!(!idle.wake_ready);
    assert!(idle.exited.is_empty());
    sender.write_all(&[1]).unwrap();
    let woke = wait_process_exit_events(
        &[&observer],
        Some(wake.as_fd()),
        Some(Instant::now() + Duration::from_secs(2)),
    )
    .unwrap();
    assert!(woke.wake_ready);
    assert!(woke.exited.is_empty());
    wake.read_exact(&mut [0]).unwrap();
    drop(child.stdin.take());
    let exited = wait_process_exit_events(
        &[&observer],
        Some(wake.as_fd()),
        Some(Instant::now() + Duration::from_secs(2)),
    )
    .unwrap();
    assert_eq!(exited.exited, vec![0]);
    assert!(child.wait().unwrap().success()); // This test owns that exact Child.
}

#[test]
fn disconnected_wakeup_is_reported_without_inventing_process_exit() {
    let (wake, sender) = UnixStream::pair().unwrap();
    drop(sender);
    let events = wait_process_exit_events(
        &[],
        Some(wake.as_fd()),
        Some(Instant::now() + Duration::from_secs(1)),
    )
    .unwrap();
    assert!(events.wake_ready);
    assert!(!events.timed_out);
    assert!(events.exited.is_empty());
}

#[test]
fn retained_observer_remains_bound_after_original_child_collection() {
    let mut child = Command::new("/bin/cat")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let observer = ProcessExitObserver::arm(child.id().try_into().unwrap()).unwrap();
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    let (wake, _sender) = UnixStream::pair().unwrap();
    let events = wait_process_exit_events(
        &[&observer],
        Some(wake.as_fd()),
        Some(Instant::now() + Duration::from_secs(2)),
    )
    .unwrap();
    assert_eq!(events.exited, vec![0]);
    assert!(!events.timed_out);
}
