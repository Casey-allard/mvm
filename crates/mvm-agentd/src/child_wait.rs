//! One waiter for every child process in the guest.
//!
//! When the agent is PID 1 it must reap orphans re-parented to it, or the
//! guest accumulates zombies. But `waitpid(-1, …)` reaps *any* child,
//! including one that some other part of the agent spawned and is polling
//! with [`std::process::Child::try_wait`]. Whichever waiter gets there
//! first consumes the status; the loser sees `ECHILD` and has no way to
//! learn what the process actually did.
//!
//! That is not hypothetical. With a `SIGCHLD` handler reaping in the
//! background, `stream_exec` lost every workload exit status: a command
//! that exited 0, one that exited 3, and one that exited 7 all surfaced
//! as `-1`, and the host reported 255 for all three. Unit tests could not
//! see it, because a test process is never PID 1 and so never installed
//! the reaper.
//!
//! So there is exactly one waiter here, and it publishes.
//!
//! - Code that spawns a child registers it with [`OwnedChild`], an RAII
//!   token that deregisters on drop.
//! - [`install_orphan_reaper`] starts a polling thread. It reaps
//!   everything, records the status of *registered* pids in a table, and
//!   discards the rest — those are the orphans it exists to clean up.
//! - Owners call [`try_wait`] / [`wait`] instead of the inherent `Child`
//!   methods. Those consult the table when the kernel says `ECHILD`.
//!
//! The reaper's `waitpid` + publish, and an owner's `try_wait` + lookup,
//! each run under the same mutex. So an owner either wins the race and
//! reads the status from the kernel, or loses it and finds the status
//! already in the table — there is no interleaving where the status is
//! observable by neither, and therefore no retry loop. Original worker and hook launches also hold the mutex across spawn
//! so a failed exec can be collected by the standard library before a sweep.
//! Waiting for a live child never holds that mutex.
//!
//! Everything degrades to the plain `Child` methods when no reaper is
//! installed, which is every unit test and every non-PID-1 process.

use std::collections::{HashMap, HashSet};
use std::io;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// How often the orphan reaper sweeps. Zombie orphans are harmless while
/// they wait — they hold a pid table slot and nothing else — so this
/// trades a little latency for not needing an async-signal-safe handler.
const REAP_INTERVAL: Duration = Duration::from_millis(200);

/// First poll gap for [`wait`] once a reaper is running and the kernel may
/// not be the one to hand us the status. Short so a quick command returns
/// promptly.
const WAIT_POLL_MIN: Duration = Duration::from_millis(1);

/// Ceiling the [`wait`] poll gap backs off to. A workload can run for
/// hours; polling it at the initial cadence the whole time would burn a
/// core for nothing.
const WAIT_POLL_MAX: Duration = Duration::from_millis(50);

/// Set once [`install_orphan_reaper`] has started the sweeper. Until then
/// every entry point here delegates straight to the inherent `Child`
/// methods, so nothing changes for a process that is not PID 1.
static REAPER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Pids some part of the agent owns and intends to wait on, plus the exit
/// statuses the reaper collected on their behalf.
///
/// One mutex covers both so that "is this pid owned?" and "record its
/// status" are a single atomic step against an owner's own wait.
#[derive(Default)]
struct Registry {
    // This form registers at spawn, before another thread can reap. Each
    // generation owns its own status even after the kernel reuses the PID.
    originals: HashMap<i32, Arc<Generation>>,
    owned: HashSet<i32>,
    reaped: HashMap<i32, i32>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}

struct Generation {
    status: OnceLock<ExitStatus>,
    // Only set for a worker launched as the leader of a fresh process group.
    process_group: bool,
}

/// Original status and signal authority for one supervised process.
#[derive(Clone)]
pub(crate) struct OriginalProcess {
    pid: i32,
    generation: Arc<Generation>,
}

impl OriginalProcess {
    /// Check the original generation while holding the reaper lock. An exit
    /// between this check and kill remains a zombie, so the PID cannot have
    /// been recycled under our feet.
    pub(crate) fn signal(&self, signal: i32) -> io::Result<()> {
        let reg = registry()
            .lock()
            .map_err(|_| io::Error::other("child registry poisoned"))?;
        if self.generation.status.get().is_some() {
            return Ok(());
        }
        if !reg
            .originals
            .get(&self.pid)
            .is_some_and(|v| Arc::ptr_eq(v, &self.generation))
        {
            return Err(io::Error::other("original child identity unavailable"));
        }
        let target = if self.generation.process_group {
            -self.pid
        } else {
            self.pid
        };
        // SAFETY: kill has no pointer arguments. Only the still-held original
        // child (or its group created at spawn) can be targeted.
        if unsafe { libc::kill(target, signal) } < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err);
            }
        }
        Ok(())
    }
}

pub(crate) struct OriginalChild {
    pub(crate) child: Child,
    pub(crate) original: OriginalProcess,
}

impl OriginalChild {
    /// std may wait for its own failed-exec child *inside* Command::spawn.
    /// Cover that interval too, then publish the successful original before
    /// the PID-1 reaper can consume its exit. Waiting for a running child is
    /// always outside this critical section.
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        Self::spawn_registered(command, false)
    }

    pub(crate) fn spawn_group(command: &mut Command) -> io::Result<Self> {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        Self::spawn_registered(command, true)
    }

    fn spawn_registered(command: &mut Command, process_group: bool) -> io::Result<Self> {
        let mut reg = registry()
            .lock()
            .map_err(|_| io::Error::other("child registry poisoned"))?;
        let child = command.spawn()?;
        let original = OriginalProcess {
            pid: child.id() as i32,
            generation: Arc::new(Generation {
                status: OnceLock::new(),
                process_group,
            }),
        };
        reg.originals
            .insert(original.pid, original.generation.clone());
        Ok(Self { child, original })
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let mut reg = registry()
            .lock()
            .map_err(|_| io::Error::other("child registry poisoned"))?;
        if let Some(status) = self.original.generation.status.get() {
            return Ok(Some(*status));
        }
        if !reg
            .originals
            .get(&self.original.pid)
            .is_some_and(|v| Arc::ptr_eq(v, &self.original.generation))
        {
            return Err(io::Error::other("original child status unavailable"));
        }
        if self.original.generation.process_group {
            if peek_exit(libc::P_PID, self.original.pid as libc::id_t)?.is_none() {
                return Ok(None);
            }
            terminate_exited_group(self.original.pid)?;
        }
        if let Some(status) = self.child.try_wait()? {
            let _ = self.original.generation.status.set(status);
            reg.originals.remove(&self.original.pid);
            return Ok(Some(status));
        }
        Ok(None)
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        let mut gap = WAIT_POLL_MIN;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            std::thread::sleep(gap);
            gap = (gap * 2).min(WAIT_POLL_MAX);
        }
    }
}

impl Drop for OriginalChild {
    fn drop(&mut self) {
        if let Ok(mut reg) = registry().lock() {
            if reg
                .originals
                .get(&self.original.pid)
                .is_some_and(|v| Arc::ptr_eq(v, &self.original.generation))
            {
                reg.originals.remove(&self.original.pid);
            }
        }
    }
}

/// Registration token for a child this process spawned and will wait on.
///
/// Hold it from just after spawn until the last [`try_wait`] / [`wait`]
/// call for that child. While it is alive the reaper records the child's
/// status instead of discarding it; on drop the pid and any unread status
/// are forgotten, so the table cannot grow without bound.
pub struct OwnedChild {
    pid: i32,
}

impl OwnedChild {
    /// Register `pid` as owned. Cheap and safe to call when no reaper is
    /// running — the registry simply goes unread.
    pub fn new(pid: u32) -> Self {
        let pid = pid as i32;
        register_in(registry(), pid);
        Self { pid }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        deregister_in(registry(), self.pid);
    }
}

/// Non-blocking wait, safe against a concurrently running orphan reaper.
///
/// Same contract as [`Child::try_wait`]: `Ok(None)` means still running.
/// The difference is that a status already collected by the reaper is
/// returned here rather than lost to `ECHILD`.
pub fn try_wait(child: &mut Child) -> io::Result<Option<ExitStatus>> {
    if !REAPER_RUNNING.load(Ordering::Acquire) {
        return child.try_wait();
    }
    try_wait_in(registry(), child)
}

/// Non-blocking wait on a raw pid, for a child forked without
/// [`std::process::Command`] (the console's PTY shell).
///
/// Returns the raw `waitpid` status once the child has exited, `Ok(None)`
/// while it runs. Like [`try_wait`], a status the orphan reaper collected
/// first is recovered from the table rather than lost to `ECHILD`, which is
/// why the pid must be registered with an [`OwnedChild`] for as long as it is
/// polled.
pub fn try_wait_pid(pid: i32) -> io::Result<Option<i32>> {
    if !REAPER_RUNNING.load(Ordering::Acquire) {
        return waitpid_nohang(pid);
    }
    try_wait_pid_in(registry(), pid, waitpid_nohang)
}

fn waitpid_nohang(pid: i32) -> io::Result<Option<i32>> {
    let mut raw = 0;
    // SAFETY: `waitpid` writes only through `raw`, a live local `i32`, and
    // `WNOHANG` makes it return immediately.
    let rc = unsafe { libc::waitpid(pid, &mut raw, libc::WNOHANG) };
    match rc {
        0 => Ok(None),
        rc if rc == pid => Ok(Some(raw)),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Blocking wait, safe against a concurrently running orphan reaper.
///
/// With a reaper installed this polls [`try_wait`] rather than blocking in
/// the kernel, because the reaper may be the one that actually collects
/// the status. Without a reaper it is a straight [`Child::wait`].
pub fn wait(child: &mut Child) -> io::Result<ExitStatus> {
    if !REAPER_RUNNING.load(Ordering::Acquire) {
        return child.wait();
    }
    let mut gap = WAIT_POLL_MIN;
    loop {
        match try_wait_in(registry(), child)? {
            Some(status) => return Ok(status),
            None => {
                std::thread::sleep(gap);
                gap = (gap * 2).min(WAIT_POLL_MAX);
            }
        }
    }
}

/// Start the orphan reaper. Call once, from PID 1, before anything spawns
/// a child.
///
/// Replaces the `SIGCHLD` handler this agent used to install: a handler
/// must be async-signal-safe, so it could not take a lock, so it could not
/// publish what it reaped — which is precisely how it destroyed owned
/// children's exit statuses. A plain thread can lock, so it can publish.
pub fn install_orphan_reaper() {
    if REAPER_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("mvm-orphan-reaper".to_string())
        .spawn(|| {
            loop {
                reap_with(registry(), waitpid_any);
                std::thread::sleep(REAP_INTERVAL);
            }
        });
    if let Err(e) = spawned {
        // Let a later call retry; orphans stay unreaped until one succeeds.
        REAPER_RUNNING.store(false, Ordering::Release);
        tracing::error!(error = %e, "could not start the orphan reaper thread");
    }
}

// ---------------------------------------------------------------------------
// Registry operations, parameterised over the registry and the reap syscall
// so they can be exercised without touching process-global state or the real
// `waitpid(-1)` — which in a threaded test binary would steal other tests'
// children.
// ---------------------------------------------------------------------------

fn register_in(reg: &Mutex<Registry>, pid: i32) {
    if let Ok(mut reg) = reg.lock() {
        reg.owned.insert(pid);
    }
}

fn deregister_in(reg: &Mutex<Registry>, pid: i32) {
    if let Ok(mut reg) = reg.lock() {
        reg.owned.remove(&pid);
        reg.reaped.remove(&pid);
    }
}

fn try_wait_in(reg: &Mutex<Registry>, child: &mut Child) -> io::Result<Option<ExitStatus>> {
    let pid = child.id() as i32;
    let Ok(mut reg) = reg.lock() else {
        return child.try_wait();
    };
    // A status the reaper already collected settles it — the kernel has
    // nothing left to tell us about this pid.
    if let Some(raw) = reg.reaped.remove(&pid) {
        return Ok(Some(exit_status_from_raw(raw)));
    }
    match child.try_wait() {
        Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
            // The reaper cannot have published between the lookup above and
            // here — it takes this same lock to publish. So ECHILD means the
            // status was consumed by something that never recorded it, and
            // there is genuinely nothing left to report.
            Ok(reg.reaped.remove(&pid).map(exit_status_from_raw))
        }
        other => other,
    }
}

fn try_wait_pid_in(
    reg: &Mutex<Registry>,
    pid: i32,
    waitpid: impl FnOnce(i32) -> io::Result<Option<i32>>,
) -> io::Result<Option<i32>> {
    let Ok(mut reg) = reg.lock() else {
        return waitpid(pid);
    };
    if let Some(raw) = reg.reaped.remove(&pid) {
        return Ok(Some(raw));
    }
    match waitpid(pid) {
        // Same reasoning as `try_wait_in`: the reaper publishes under this
        // lock, so ECHILD here means the status is in the table or gone.
        Err(e) if e.raw_os_error() == Some(libc::ECHILD) => Ok(reg.reaped.remove(&pid)),
        other => other,
    }
}

/// Drain every exited child through `waitpid`, recording the ones an
/// [`OwnedChild`] claims and discarding the rest.
///
/// `waitpid` writes the raw status through its out-param and returns the
/// reaped pid, `0` when children exist but none have exited, or a negative
/// value when there are none at all — i.e. `waitpid(-1, …, WNOHANG)`.
#[cfg(test)]
fn reap_in(reg: &Mutex<Registry>, mut waitpid: impl FnMut(&mut i32) -> i32) {
    reap_with(reg, |_, raw| waitpid(raw))
}

fn reap_with(reg: &Mutex<Registry>, mut waitpid: impl FnMut(&Registry, &mut i32) -> i32) {
    let Ok(mut reg) = reg.lock() else {
        return;
    };
    loop {
        let mut raw = 0;
        let pid = waitpid(&reg, &mut raw);
        if pid <= 0 {
            return;
        }
        if let Some(exit) = reg.originals.remove(&pid) {
            let _ = exit.status.set(exit_status_from_raw(raw));
        } else if reg.owned.contains(&pid) {
            reg.reaped.insert(pid, raw);
        }
    }
}

/// WNOWAIT leaves an exited leader in the kernel until we collect its status.
/// While holding the registry lock its PID (and therefore its original group
/// ID) cannot be reused by another managed worker.
fn peek_exit(kind: libc::idtype_t, id: libc::id_t) -> io::Result<Option<i32>> {
    // SAFETY: zero is valid for siginfo_t. POSIX permits the no-event case
    // to leave this struct unchanged; a zero si_pid means no pending exit.
    let mut event: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: event is a writable siginfo_t. All wait options are valid
        // for this selector; WNOHANG makes the operation nonblocking.
        let rc = unsafe {
            libc::waitid(
                kind,
                id,
                &mut event,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            // SAFETY: waitid supplies the child PID on an exit notification.
            let pid = unsafe { event.si_pid() };
            return Ok((pid > 0).then_some(pid));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn terminate_exited_group(pid: i32) -> io::Result<()> {
    // SAFETY: this function is called only under the original registry lock
    // after WNOWAIT identified its unreaped group leader. A same-group
    // descendant can keep the pipes open even though the leader exited.
    if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    if e.raw_os_error() == Some(libc::EPERM) {
        // Darwin returns EPERM for a group containing only an unreaped
        // zombie. Accept that case only after the kernel reports exactly
        // the original leader. A second member or an incomplete result
        // leaves the group unresolved. No enumeration outside this group.
        const PROC_PGRP_ONLY: u32 = 2;
        let mut members = [0i32; 2];
        // SAFETY: proc_listpids writes at most the supplied byte count.
        let bytes = unsafe {
            libc::proc_listpids(
                PROC_PGRP_ONLY,
                pid as u32,
                members.as_mut_ptr().cast(),
                std::mem::size_of_val(&members) as libc::c_int,
            )
        };
        if bytes == std::mem::size_of_val(&members[0]) as i32 && members[0] == pid {
            return Ok(());
        }
    }
    Err(e)
}

fn waitpid_any(reg: &Registry, raw: &mut i32) -> i32 {
    let Ok(Some(pid)) = peek_exit(libc::P_ALL, 0) else {
        return 0;
    };
    if reg.originals.get(&pid).is_some_and(|g| g.process_group)
        && terminate_exited_group(pid).is_err()
    {
        return 0;
    }
    // SAFETY: raw is a writable i32, targeted at the child we just observed.
    unsafe { libc::waitpid(pid, raw, libc::WNOHANG) }
}

fn exit_status_from_raw(raw: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// A private registry per test. The process-global one is deliberately
    /// untouched here: these tests run as threads under `cargo test`, and
    /// mutating shared reaper state would make them race each other.
    fn fresh_registry() -> Mutex<Registry> {
        Mutex::default()
    }

    fn spawn_exiting_with(code: i32) -> Child {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("exit {code}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn")
    }

    /// Play the sweeper against one specific pid until it collects the
    /// status, so the test never touches `waitpid(-1)` — which in this
    /// threaded test binary would steal other tests' children.
    ///
    /// A zombie is still a live pid as far as `kill(pid, 0)` is concerned,
    /// so polling for the process to "disappear" would hang forever; the
    /// reap itself is the only thing that reports exit.
    fn reap_until_collected(reg: &Mutex<Registry>, pid: i32) {
        for _ in 0..500 {
            reap_in(reg, |raw| {
                // SAFETY: writes only through `raw`; targeted at our own child.
                unsafe { libc::waitpid(pid, raw, libc::WNOHANG) }
            });
            if reg.lock().unwrap().reaped.contains_key(&pid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("child {pid} was never collected");
    }

    #[test]
    fn the_global_entry_points_are_plain_child_waits_until_a_reaper_runs() {
        assert!(
            !REAPER_RUNNING.load(Ordering::Acquire),
            "a unit test is never PID 1, so it must never install the reaper"
        );
        let mut child = spawn_exiting_with(3);
        assert_eq!(wait(&mut child).expect("wait").code(), Some(3));
    }

    #[test]
    fn an_owner_recovers_the_exit_code_the_reaper_collected() {
        // The exact loss this module exists to prevent, against the real
        // kernel: the reaper gets to the child first, so the owner's
        // `try_wait` sees ECHILD — and must still report the true code.
        let reg = fresh_registry();
        let mut child = spawn_exiting_with(7);
        let pid = child.id() as i32;
        register_in(&reg, pid);
        reap_until_collected(&reg, pid);

        assert!(
            child.try_wait().is_err(),
            "precondition: the kernel must now answer ECHILD for this pid"
        );
        let status = try_wait_in(&reg, &mut child).expect("try_wait after reap");
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(7),
            "the owner must recover the exit code the reaper collected"
        );
    }

    #[test]
    fn a_recovered_status_is_handed_out_once() {
        // The table is drained on read, so a second poll cannot resurrect a
        // stale status and report the same exit twice.
        let reg = fresh_registry();
        let mut child = spawn_exiting_with(4);
        let pid = child.id() as i32;
        register_in(&reg, pid);
        reap_until_collected(&reg, pid);

        assert_eq!(
            try_wait_in(&reg, &mut child)
                .unwrap()
                .and_then(|s| s.code()),
            Some(4)
        );
        assert_eq!(
            try_wait_in(&reg, &mut child).unwrap(),
            None,
            "a drained status must not be replayed"
        );
    }

    #[test]
    fn an_unowned_pid_is_discarded_rather_than_accumulated() {
        // Orphans are what the reaper exists for, but nobody will ever ask
        // for their status, so keeping it would leak the table.
        let reg = fresh_registry();
        let mut scripted = vec![(4242, 0), (4243, 1 << 8)].into_iter();
        reap_in(&reg, |raw| match scripted.next() {
            Some((pid, status)) => {
                *raw = status;
                pid
            }
            None => 0,
        });
        assert!(reg.lock().unwrap().reaped.is_empty());
    }

    #[test]
    fn reaping_stops_at_the_first_non_positive_answer() {
        // `0` means "children exist, none exited". Treating it as anything
        // but a stop condition would spin the reaper thread hot.
        let reg = fresh_registry();
        register_in(&reg, 4242);
        let mut calls = 0;
        let mut scripted = vec![4242, 0, 4243].into_iter();
        reap_in(&reg, |raw| {
            calls += 1;
            *raw = 0;
            scripted.next().unwrap_or(-1)
        });
        assert_eq!(calls, 2, "must stop at the 0, not keep draining");
        let reg = reg.lock().unwrap();
        assert!(reg.reaped.contains_key(&4242));
        assert!(!reg.reaped.contains_key(&4243));
    }

    #[test]
    fn only_owned_pids_are_recorded() {
        let reg = fresh_registry();
        register_in(&reg, 4242);
        let mut scripted = vec![(4242, 3 << 8), (9999, 5 << 8)].into_iter();
        reap_in(&reg, |raw| match scripted.next() {
            Some((pid, status)) => {
                *raw = status;
                pid
            }
            None => 0,
        });
        let reg = reg.lock().unwrap();
        assert_eq!(reg.reaped.get(&4242), Some(&(3 << 8)));
        assert!(!reg.reaped.contains_key(&9999));
    }

    #[test]
    fn a_raw_pid_owner_recovers_the_status_the_reaper_collected() {
        // The console forks its shell directly, so it has a pid and no
        // `Child`. It must get the same protection as a `Child` owner.
        let reg = fresh_registry();
        let mut child = spawn_exiting_with(6);
        let pid = child.id() as i32;
        register_in(&reg, pid);
        reap_until_collected(&reg, pid);

        let raw = try_wait_pid_in(&reg, pid, waitpid_nohang)
            .expect("wait after reap")
            .expect("the reaper's status must be handed to the owner");
        assert!(libc::WIFEXITED(raw));
        assert_eq!(libc::WEXITSTATUS(raw), 6);
        assert_eq!(
            try_wait_pid_in(&reg, pid, waitpid_nohang).unwrap(),
            None,
            "a drained status must not be replayed"
        );
        // Already reaped above; this only settles the `Child` handle, and the
        // ECHILD it answers is expected.
        let _ = child.wait();
    }

    #[test]
    fn a_raw_pid_wait_reports_a_running_child_as_running() {
        let reg = fresh_registry();
        assert_eq!(try_wait_pid_in(&reg, 4242, |_| Ok(None)).unwrap(), None);
    }

    #[test]
    fn deregistering_forgets_the_pid_and_any_unread_status() {
        let reg = fresh_registry();
        register_in(&reg, 4242);
        reg.lock().unwrap().reaped.insert(4242, 0);
        deregister_in(&reg, 4242);
        let reg = reg.lock().unwrap();
        assert!(!reg.owned.contains(&4242));
        assert!(
            !reg.reaped.contains_key(&4242),
            "an unread status must not outlive its owner, or the table grows forever"
        );
    }

    #[test]
    fn the_owned_token_registers_and_deregisters_in_the_global_registry() {
        // The RAII wiring itself, on a pid no real child can hold.
        let pid = 0x7f00_0001u32;
        {
            let _owned = OwnedChild::new(pid);
            assert!(registry().lock().unwrap().owned.contains(&(pid as i32)));
        }
        assert!(!registry().lock().unwrap().owned.contains(&(pid as i32)));
    }

    #[test]
    fn raw_status_decoding_matches_the_kernel_encoding() {
        // wait(2) packs a normal exit as `code << 8`.
        assert_eq!(exit_status_from_raw(3 << 8).code(), Some(3));
        assert_eq!(exit_status_from_raw(0).code(), Some(0));
    }
}
