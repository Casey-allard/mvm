use super::*;
use std::os::unix::fs::PermissionsExt;

struct Pending(Option<Child>);
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

#[test]
fn scope_watch_timeout_preserves_original_child_custody() {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("systemd-run");
    std::fs::write(&program, b"#!/bin/sh\nread -r owned_scope_input\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(&program);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut bound = BoundCommand {
        command,
        unit: Some("owned-fixture.scope".into()),
        machine_id: "owned-scope-fixture".into(),
        creation_timeout: Duration::from_millis(25),
    };
    let mut pending = Pending(None);
    let result = bound.spawn_custodied(&mut pending.0);
    assert!(
        result.is_err(),
        "the deliberately waiting scope must time out"
    );
    let child = pending
        .0
        .as_mut()
        .expect("scope error discarded the original Child");
    assert!(
        child.try_wait().unwrap().is_none(),
        "only the caller owns cleanup after the scope error"
    );
}
