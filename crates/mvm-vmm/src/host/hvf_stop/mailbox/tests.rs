use super::*;
use crate::host::hvf_control_transport as wire;
use ed25519_dalek::SigningKey;
use mvm_core::protocol::{
    broker_control::{self, ControlRequest},
    hvf_control::{HvfInstance, HvfInstanceControl},
};
use std::{
    io::Read,
    os::unix::net::UnixStream,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn target(pid: u32) -> OriginalMailboxTarget {
    OriginalMailboxTarget {
        instance: HvfInstance {
            vm_id: "mailbox-test".into(),
            boot_nonce: [1; 32],
        },
        child_pid: pid,
        root: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    }
}

fn signed_pair(
    identity: OriginalMailboxTarget,
    served_nonce: [u8; 32],
) -> anyhow::Result<OriginalMailboxObservation> {
    let (client, mut server) = UnixStream::pair()?;
    let until = Instant::now() + Duration::from_secs(2);
    std::thread::scope(|scope| {
        let mut served = identity.instance.clone();
        served.boot_nonce = served_nonce;
        let responder = scope.spawn(move || -> anyhow::Result<()> {
            let mut nonce = [0; 32];
            if server.read_exact(&mut nonce).is_err() {
                return Ok(());
            }
            let challenge = broker_control::sign(
                ControlRequest::HvfInstanceV1(HvfInstanceControl::Challenge {
                    instance: served,
                    client_nonce: nonce,
                    connection_nonce: [2; 32],
                }),
                &[7; 32],
            )?;
            wire::write_frame(&mut server, &challenge, until)
        });
        let result = identity.arm_connected(client, until, std::path::PathBuf::new());
        responder.join().unwrap()?;
        result
    })
}

#[test]
fn worker_observation_requires_original_process_and_signed_instance() {
    let id = target(std::process::id());
    signed_pair(id.clone(), [1; 32])
        .unwrap()
        .require_process_live()
        .unwrap();
    assert!(signed_pair(id, [3; 32]).is_err());
    assert!(signed_pair(target(std::process::id() + 1), [1; 32]).is_err());
}

#[test]
fn independent_workers_both_latch_exit_of_the_same_original() {
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let id = target(child.id());
    let observations: Vec<_> = (0..2)
        .map(|_| {
            OriginalMailboxObservation::from_proven_peer(
                id.clone(),
                crate::host::process_exit::ProcessExitObserver::arm(child.id() as i32).unwrap(),
                std::path::PathBuf::new(),
            )
        })
        .collect();
    for obs in &observations {
        obs.require_process_live().unwrap();
    }
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    for obs in &observations {
        assert!(obs.require_process_live().is_err());
        assert!(obs.require_process_live().is_err());
    }
}

#[test]
fn original_mailbox_opens_only_5257_and_rejects_generation_change_with_same_pid() {
    use std::{io::Write, os::unix::net::UnixListener};
    let id = target(std::process::id());
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let state = mvm_core::config::vm_state_dir_at(home.path(), &id.instance.vm_id);
    let controls = mvm_core::config::vm_socket_dir_at(&state);
    let port = mvm_core::config::vm_hvf_vsock_port_socket_at(&state, 5257);
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&controls).unwrap();
    std::fs::create_dir_all(port.parent().unwrap()).unwrap();
    let record = state.join(wire::INSTANCE_FILE);
    std::fs::write(&record, serde_json::to_vec(&id.instance).unwrap()).unwrap();
    let control = UnixListener::bind(controls.join(wire::SOCKET_FILE)).unwrap();
    let mailbox = UnixListener::bind(port).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    std::thread::scope(|scope| {
        let instance = id.instance.clone();
        let server = scope.spawn(move || {
            let (mut s, _) = control.accept().unwrap();
            let mut nonce = [0; 32];
            s.read_exact(&mut nonce).unwrap();
            let response = broker_control::sign(
                ControlRequest::HvfInstanceV1(HvfInstanceControl::Challenge {
                    instance,
                    client_nonce: nonce,
                    connection_nonce: [8; 32],
                }),
                &[7; 32],
            )
            .unwrap();
            wire::write_frame(&mut s, &response, until).unwrap();
            drop(s);
        });
        let observed = id.observe_at(home.path(), until).unwrap();
        server.join().unwrap();
        let mut link = observed.open_mailbox(until).unwrap();
        let (mut other, _) = mailbox.accept().unwrap();
        let original = b"mailbox\0\0";
        link.write_all(original).unwrap();
        let mut received = [0; 9];
        other.read_exact(&mut received).unwrap();
        assert_eq!(&received, original);
        let mut changed = id.instance.clone();
        changed.boot_nonce = [3; 32];
        std::fs::write(&record, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(observed.require_current().is_err());
        std::fs::write(&record, serde_json::to_vec(&id.instance).unwrap()).unwrap();
        assert!(observed.open_mailbox(until).is_err());
    });
}
