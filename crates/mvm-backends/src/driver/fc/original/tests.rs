use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

const CHILD: &str = "driver::fc::original::tests::api_fixture";
#[test]
#[ignore = "spawned only by the original-stream test"]
fn api_fixture() {
    let path = std::env::var_os("MVM_COMPONENT_SOCKET").unwrap();
    let listener = UnixListener::bind(path).unwrap();
    let (mut client, _) = listener.accept().unwrap();
    client.write_all(b"ready\n").unwrap();
    let mut done = String::new();
    BufReader::new(client).read_line(&mut done).unwrap();
}
#[test]
fn live_config_session_carries_only_its_original_process() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.socket");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", CHILD])
        .env("MVM_COMPONENT_SOCKET", &path)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let mut stream = loop {
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(stream) => break stream,
            Err(_) if start.elapsed() < std::time::Duration::from_secs(3) => {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fixture failed: {e}")
            }
        }
    };
    let mut ready = String::new();
    BufReader::new(&stream).read_line(&mut ready).unwrap();
    assert_eq!(ready, "ready\n");
    let owner = ConfigSessionOwner::capture(&stream).unwrap();
    assert_eq!(owner.pid(), child.id());
    owner.require_live().unwrap();
    std::fs::remove_file(&path).unwrap();
    let second = UnixListener::bind(&path).unwrap();
    let replacement = std::os::unix::net::UnixStream::connect(&path).unwrap();
    assert_ne!(
        ConfigSessionOwner::capture(&replacement).unwrap().pid(),
        owner.pid()
    );
    stream.write_all(b"done\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(owner.require_live().is_err());
    drop(second);
}
