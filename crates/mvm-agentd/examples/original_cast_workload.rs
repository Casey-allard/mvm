//! Reference for an opted-in Linux OCI warm worker. Echo one exact Cast along
//! with the ordinary call's stdin and report the workload's CPU in its result.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use mvm_agentd::{mailbox_cast::exec::original_workload_reader, worker_protocol::*};
    use std::io::{stdin, stdout};
    let start = std::time::Instant::now();
    let cpu = || -> u64 {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut t) },
            0
        );
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    };
    let begin = cpu();
    let mut reader = original_workload_reader()?;
    let request = read_pipe_frame::<_, WorkerCallRequest>(&mut stdin().lock())?;
    let mut response = Vec::new();
    if !reader.receive_with(|delivery| {
        response.extend_from_slice(&delivery.body);
        Ok(())
    })? {
        return Err(std::io::Error::other("no original Cast"));
    }
    response.extend_from_slice(&request.stdin);
    eprintln!("original workload stderr available");
    let metrics = serde_json::to_vec(
        &serde_json::json!({"workload_cpu_ns":cpu()-begin,"workload_wall_ns":start.elapsed().as_nanos() as u64}),
    )?;
    write_pipe_frame(
        &mut stdout().lock(),
        &WorkerCallResponse {
            stdout: response,
            stderr: metrics,
            controls: Vec::new(),
            outcome: WorkerOutcome::Exit { code: 0 },
        },
    )
}
#[cfg(not(target_os = "linux"))]
fn main() {}
