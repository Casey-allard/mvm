#![cfg(target_os = "linux")]

use super::*;
use crate::driver::fc::{HostLeaseExpectation, PreparedHostLifetimeLease};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{DirBuilderExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "mvm-lease-launch-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let mut state = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(root.join("state.bin"))
            .unwrap();
        state.write_all(b"abc").unwrap();
        drop(
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(root.join("holders.lock"))
                .unwrap(),
        );
        Self { root }
    }
    fn lease(&self) -> PreparedHostLifetimeLease {
        PreparedHostLifetimeLease::bind(
            File::open(&self.root).unwrap(),
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.root.join("holders.lock"))
                .unwrap(),
            HostLeaseExpectation {
                state_name: "state.bin".into(),
                state_bytes: 3,
                state_sha256: [
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ],
                absent_names: [".state.intent".into(), ".state.next".into()],
            },
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn leased_launch_accepts_the_existing_writable_disk_reopen_composition() {
    let fixture = Fixture::new();
    let lease = fixture.lease();
    let vm = fixture.root.join("vm");
    let socket = vm.join("fc.socket");
    let base = firecracker_launch_script_as(vm.to_str().unwrap(), socket.to_str().unwrap(), "", 0);
    let leased = reopen_host_lease_script(&base, &lease).expect("typed lease composition");
    reopen_handoff_script(&leased, std::process::id(), 1000, 1001)
        .expect("the leased bash launcher must still accept writable disk custody");
}

struct Shell {
    child: Child,
    input: ChildStdin,
    events: mpsc::Receiver<String>,
    reader: Option<JoinHandle<()>>,
    reaped: bool,
}
impl Shell {
    fn spawn(mut command: Command, fill_low_fds: bool) -> Self {
        let null = File::open("/dev/null").unwrap();
        if fill_low_fds {
            let source = null.as_raw_fd();
            // SAFETY: only async-signal-safe dup2 is used between fork/exec.
            // All changes are confined to the owned child descriptor table.
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(source, 9) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    for fd in 10..1000 {
                        if libc::dup2(9, fd) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (send, events) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if send.try_send(line).is_err() {
                    return;
                }
            }
            let _ = send.try_send("EOF".into());
        });
        Self {
            child,
            input,
            events,
            reader: Some(reader),
            reaped: false,
        }
    }
    fn event(&self, expected: &str) {
        assert_eq!(
            self.events
                .recv_timeout(Duration::from_secs(5))
                .expect("owned shell watchdog"),
            expected
        );
    }
    fn send(&mut self, command: &[u8]) {
        self.input.write_all(command).unwrap();
        self.input.flush().unwrap();
    }
    fn finish(mut self, success: bool) {
        self.event("EOF");
        let status = self.child.wait().unwrap();
        self.reaped = true;
        assert_eq!(status.success(), success, "owned shell exit {status}");
        self.reader.take().unwrap().join().unwrap();
    }
}
impl Drop for Shell {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn high_disk(fixture: &Fixture, name: &str, bytes: &[u8], minimum: i32) -> File {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(fixture.root.join(name))
        .unwrap();
    file.write_all(bytes).unwrap();
    // SAFETY: duplicate a live owned fixture FD; no unrelated FD is replaced.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(fd >= minimum);
    // SAFETY: the successful duplicate is a fresh exclusively owned FD.
    unsafe { File::from_raw_fd(fd) }
}

#[test]
fn privileged_disk_and_lease_fds_coexist_through_actual_foreground_exec() {
    let fixture = Fixture::new();
    let lease = fixture.lease();
    let original = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.root.join("holders.lock"))
        .unwrap();
    let backing = high_disk(&fixture, "backing", b"disk", 1000);
    let sidecar = high_disk(&fixture, "sidecar", b"meta", 1001);
    assert_eq!((backing.as_raw_fd(), sidecar.as_raw_fd()), (1000, 1001));
    let vm = fixture.root.join("vm");
    fs::DirBuilder::new().mode(0o700).create(&vm).unwrap();
    let pid_path = vm.join("fc.pid");
    let socket = vm.join("fc.socket");
    let base = firecracker_launch_script_as(vm.to_str().unwrap(), socket.to_str().unwrap(), "", 0);
    let leased = reopen_host_lease_script(&base, &lease).unwrap();
    let composed = reopen_handoff_script(&leased, std::process::id(), 1000, 1001).unwrap();
    let inner = composed
        .split_once("<<'MVM_LAUNCH_SCRIPT_EOF'\n")
        .unwrap()
        .1
        .split_once("MVM_LAUNCH_SCRIPT_EOF")
        .unwrap()
        .0;
    let target = format!(
        r#"set -euo pipefail
[[ "$(/usr/bin/head -c 4 /proc/self/fd/1000)" == disk ]] || exit 1
[[ "$(/usr/bin/head -c 4 /proc/self/fd/1001)" == meta ]] || exit 1
printf 'READY\n'
IFS= read -r command
[[ "$command" == probe ]] || exit 1
set +e
/usr/bin/flock --exclusive --nonblock /proc/{}/fd/{} /usr/bin/true
code=$?
set -e
[[ "$code" -eq 1 ]] || exit 1
printf 'HELD\n'
IFS= read -r command
[[ "$command" == exit ]] || exit 1
printf 'EXIT\n'
"#,
        std::process::id(),
        original.as_raw_fd()
    );
    let fake_exec = format!("exec /bin/bash -c {}", shell_quote(&target));
    let exec = "exec firecracker --api-sock \"$2\"";
    assert_eq!(inner.matches(exec).count(), 1);
    let body = inner.replacen(exec, &fake_exec, 1);
    let mut command = Command::new("/bin/bash");
    command
        .arg("-c")
        .arg(body)
        .arg("leased-inner")
        .arg(&pid_path)
        .arg(&socket);
    let mut shell = Shell::spawn(command, true);
    shell.event("READY");
    drop(lease);
    shell.send(b"probe\n");
    shell.event("HELD");
    shell.send(b"exit\n");
    shell.event("EXIT");
    shell.finish(true);
    // SAFETY: independent original holder FD, nonblocking final-close probe.
    assert_eq!(
        unsafe { libc::flock(original.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert!(pid_path.is_file());
}

#[test]
fn stale_outer_lease_refuses_before_mkdir_rm_or_target_exec() {
    let fixture = Fixture::new();
    let lease = fixture.lease();
    fs::write(fixture.root.join("state.bin"), b"abd").unwrap();
    let vm = fixture.root.join("must-not-create");
    let socket_dir = fixture.root.join("sockets");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&socket_dir)
        .unwrap();
    let socket = socket_dir.join("fc.socket");
    fs::write(&socket, b"must-not-remove").unwrap();
    let target = fixture.root.join("must-not-execute");
    let base = firecracker_launch_script_as(vm.to_str().unwrap(), socket.to_str().unwrap(), "", 0);
    let leased = reopen_host_lease_script(&base, &lease).unwrap();
    // Keep real outer mutations. Replace only eventual exec and detachment so
    // even a broken gate cannot launch a VM or leave a background process.
    let script = leased
        .replacen(
            "exec firecracker --api-sock \"$2\"",
            &format!(
                "exec /usr/bin/touch {}",
                shell_quote(target.to_str().unwrap())
            ),
            1,
        )
        .replacen("setsid nohup bash ", "/bin/bash ", 1)
        .replacen("/firecracker.log &\n", "/firecracker.log\n", 1);
    let mut command = Command::new("/bin/bash");
    command.arg("-c").arg(script);
    Shell::spawn(command, false).finish(false);
    assert!(!vm.exists());
    assert_eq!(fs::read(&socket).unwrap(), b"must-not-remove");
    assert!(!target.exists());
}
