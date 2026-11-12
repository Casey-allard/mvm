//! Development-profile warm OCI workload. Its ordinary call stdin goes to the
//! original signed receiver. Reply with the local, ephemeral message identifier.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use mvm_agentd::{mailbox_cast::submit::submit_original_workload, worker_protocol::*};
    let start = std::time::Instant::now();
    let cpu = || -> std::io::Result<u64> {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut t) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64)
    };
    let before = cpu()?;
    let request = read_pipe_frame::<_, WorkerCallRequest>(&mut std::io::stdin().lock())?;
    let admitted = submit_original_workload(&request.stdin)?;
    write_pipe_frame(
        &mut std::io::stdout().lock(),
        &WorkerCallResponse {
            stdout: admitted.message_id.as_bytes().to_vec(),
            stderr: serde_json::to_vec(
                &serde_json::json!({"workload_cpu_ns":cpu()?-before,"workload_wall_ns":u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)}),
            )?,
            controls: vec![],
            outcome: WorkerOutcome::Exit { code: 0 },
        },
    )
}
#[cfg(not(target_os = "linux"))]
fn main() {}
