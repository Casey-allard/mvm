use super::*;

fn original_command(command: Command) -> BoundCommand {
    BoundCommand {
        command,
        unit: None,
        machine_id: "retained-spawn-fixture".into(),
        creation_timeout: Duration::from_secs(1),
    }
}

fn waiting_child() -> BoundCommand {
    let mut command = crate::env_hygiene::helper_command("/bin/cat");
    command.stdin(Stdio::piped()).stdout(Stdio::null());
    original_command(command)
}

#[test]
fn a_spawn_refusal_never_invokes_the_original_observer() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = original_command(crate::env_hygiene::helper_command(
        dir.path().join("absent-executable"),
    ));
    let failure = command
        .spawn_retained::<()>(|_| panic!("observer before successful spawn"))
        .unwrap_err();
    assert!(matches!(failure, RetainedSpawnFailure::NotSpawned(_)));
}

#[test]
fn a_failed_observer_returns_the_same_live_child_for_collection() {
    let mut command = waiting_child();
    let mut captured = None;
    let failure = command
        .spawn_retained::<()>(|child| {
            captured = Some(child.id());
            anyhow::bail!("fixture observer refusal")
        })
        .unwrap_err();
    let RetainedSpawnFailure::Spawned {
        mut child,
        observation,
        error,
    } = failure
    else {
        panic!("original child lost after observer refusal")
    };
    let still_live = child.try_wait().unwrap().is_none();
    let original_id = child.id();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert!(still_live);
    assert_eq!(captured, Some(original_id));
    assert!(observation.is_none());
    assert!(error.to_string().contains("fixture observer refusal"));
    assert!(status.success());
}

#[test]
fn a_successful_observer_and_original_child_are_returned_together() {
    let (mut child, original_id) = waiting_child()
        .spawn_retained(|child| Ok(child.id()))
        .unwrap();
    let still_live = child.try_wait().unwrap().is_none();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert!(still_live);
    assert_eq!(child.id(), original_id);
    assert!(status.success());
}

#[test]
fn an_unwinding_observer_returns_its_original_child() {
    let mut captured = None;
    let failure = waiting_child()
        .spawn_retained::<()>(|child| {
            captured = Some(child.id());
            panic!("synthetic observer failure details");
        })
        .unwrap_err();
    let RetainedSpawnFailure::Spawned {
        mut child,
        observation,
        error,
    } = failure
    else {
        panic!("lost original spawned child on observer unwind")
    };
    let same_process = Some(child.id()) == captured;
    let still_running = child.try_wait().unwrap().is_none();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert!(same_process && still_running && status.success());
    assert!(observation.is_none());
    assert_eq!(error.to_string(), "original child observer panicked");
}
