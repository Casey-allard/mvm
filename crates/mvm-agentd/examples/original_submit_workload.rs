//! Development-profile warm OCI workload. Its ordinary call stdin goes to the
//! original signed receiver. Reply with the local, ephemeral message identifier.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use mvm_agentd::{mailbox_cast::submit::submit_original_workload, worker_protocol::*};
    let request = read_pipe_frame::<_, WorkerCallRequest>(&mut std::io::stdin().lock())?;
    let admitted = submit_original_workload(&request.stdin)?;
    write_pipe_frame(
        &mut std::io::stdout().lock(),
        &WorkerCallResponse {
            stdout: admitted.message_id.as_bytes().to_vec(),
            stderr: vec![],
            controls: vec![],
            outcome: WorkerOutcome::Exit { code: 0 },
        },
    )
}
#[cfg(not(target_os = "linux"))]
fn main() {}
