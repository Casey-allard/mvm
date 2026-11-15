//! Actual-child custody controls; no workload or native retirement is fabricated.
use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    panic::{AssertUnwindSafe, catch_unwind, panic_any},
    sync::atomic::{AtomicBool, Ordering},
};

fn configured_original(configure: impl FnOnce(&mut Child) -> Result<()>) -> Result<()> {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = mvm_core::env_hygiene::helper_command("/bin/sh");
    command.args(["-c", "exit 17"]);
    let (mut child, mut marker) = super::super::spawn_claimed(root.path(), command).unwrap();
    let original_pid = child.id();
    let result = catch_unwind(AssertUnwindSafe(|| {
        configure_held_helper(&mut child, configure)
    }));
    assert_eq!(child.id(), original_pid);
    marker.require_original().unwrap();
    assert!(super::super::OriginalMarker::claim(root.path()).is_err());
    assert_eq!(child.wait().unwrap().code(), Some(17));
    marker.require_original().unwrap();
    marker.clear_original().unwrap();
    assert!(!marker.path.exists());
    match result {
        Ok(readiness) => readiness,
        Err(payload) => {
            // Reap the original first, even on the intentionally failing control.
            std::mem::forget(payload);
            panic!("configuration unwind escaped original-child custody");
        }
    }
}

#[test]
fn successful_configuration_keeps_the_original_until_collection() {
    configured_original(|_| Ok(())).unwrap();
}

#[test]
fn failed_configuration_keeps_its_error_and_original_child() {
    let error =
        configured_original(|_| anyhow::bail!("fixture configuration refusal")).unwrap_err();
    assert_eq!(error.to_string(), "fixture configuration refusal");
}

#[test]
fn configuration_unwind_returns_failed_readiness_with_the_original_child() {
    let error = configured_original(|_| panic!("fixture private panic text")).unwrap_err();
    assert_eq!(error.to_string(), "original helper configuration unwound");
}

struct PanickingPayload(Arc<AtomicBool>);
impl Drop for PanickingPayload {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        panic!("fixture payload drop must not abandon custody");
    }
}

#[test]
fn panicking_payload_drop_cannot_unwind_again_and_lose_the_child() {
    let dropped = Arc::new(AtomicBool::new(false));
    let payload_flag = Arc::clone(&dropped);
    let error = configured_original(|_| panic_any(PanickingPayload(payload_flag))).unwrap_err();
    assert_eq!(error.to_string(), "original helper configuration unwound");
    assert!(!dropped.load(Ordering::SeqCst));
}
