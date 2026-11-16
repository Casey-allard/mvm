use super::*;
use std::future::{Future, poll_fn};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::task::Poll;
use std::time::{Duration, Instant};

struct Release(Arc<AtomicBool>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn blocked_owned_dispatch_preserves_original_partial_frame_deadline() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(mvm_vmm::host::host_agent_spawn::OWNED_ASYNC_WORKERS_PER_PROCESS)
        .max_blocking_threads(mvm_vmm::host::host_agent_spawn::OWNED_BLOCKING_WORKERS_PER_PROCESS)
        .enable_all()
        .build()?;
    let directory = tempfile::Builder::new()
        .permissions({
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o700)
        })
        .tempdir()?;
    let path = directory.path().join("signer.sock");
    let admission = Arc::new(crate::owned_resources::registered::RegistrationAdmission::new());
    let workspaces =
        crate::owned_resources::WorkspacePool::new(crate::owned_resources::SIGNER_WORKSPACES)?;
    let released = Arc::new(AtomicBool::new(false));
    let dispatch_active = Arc::new(AtomicBool::new(false));
    let release_on_drop = Release(released.clone());
    let (entered, waiting) = mpsc::channel();
    let (expired, observed) = mpsc::channel();
    let mut helper = SignerHelper::new("local", None).with_owned_resource_limits();
    helper.owned_dispatch_hook = Some(Arc::new({
        let released = released.clone();
        let dispatch_active = dispatch_active.clone();
        move || {
            dispatch_active.store(true, Ordering::Release);
            entered.send(()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !released.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "test dispatch release deadline");
                std::thread::sleep(Duration::from_millis(1));
            }
            dispatch_active.store(false, Ordering::Release);
        }
    }));
    let helper = Arc::new(Mutex::new(helper));
    let (listener, partial_client, mut client, partial, dispatch) = runtime.block_on(async {
        let listener = crate::broker::daemon::bind_owned_signer_listener(&path, &admission)?;
        let mut partial_client = UnixStream::connect(&path).await?;
        let partial_stream = listener.accept().await?;
        partial_client.write_all(&1024u32.to_be_bytes()).await?;
        partial_client.write_all(b"{").await?;
        let mut partial = Box::pin(handle_owned_connection(
            partial_stream,
            helper.clone(),
            65536,
            workspaces.clone(),
        ));
        // Poll the actual partial handler to Pending BEFORE starting dispatch:
        // its original one-second parse timeout and read are now armed.
        poll_fn(|cx| {
            assert!(partial.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let completion_dispatch = dispatch_active.clone();
        let completion_release = released.clone();
        let partial = tokio::spawn(async move {
            let result = partial.await;
            expired
                .send((
                    result.as_ref().err().map(|e| format!("{e:#}")),
                    completion_dispatch.load(Ordering::Acquire)
                        && !completion_release.load(Ordering::Acquire),
                ))
                .unwrap();
            result
        });
        let mut client = UnixStream::connect(&path).await?;
        let stream = listener.accept().await?;
        crate::framing::write_json_frame_bounded(
            &mut client,
            &SignerHelperRequest::Probe {
                request_id: "held-dispatch".into(),
            },
            65536,
        )
        .await?;
        let dispatch = tokio::spawn(handle_owned_connection(stream, helper, 65536, workspaces));
        Ok::<_, anyhow::Error>((listener, partial_client, client, partial, dispatch))
    })?;
    let entered = waiting.recv_timeout(Duration::from_secs(2));
    // A native observer cannot be starved by the Tokio scheduler under test.
    // This is observation allowance; the production parse timeout remains 1s.
    let timely = if entered.is_ok() {
        observed.recv_timeout(Duration::from_millis(1500))
    } else {
        Err(mpsc::RecvTimeoutError::Timeout)
    };
    let remained_held = !released.load(Ordering::Acquire);
    drop(release_on_drop);
    let (partial, dispatch, response) = runtime.block_on(async {
        let (partial, dispatch) = tokio::join!(partial, dispatch);
        let response =
            crate::framing::read_json_frame::<_, SignerHelperResponse>(&mut client, 65536).await;
        (partial, dispatch, response)
    });
    drop((listener, partial_client, client));
    drop(runtime);
    let expected_timeout = matches!(&timely, Ok((Some(message), true)) if message.contains("owned signer parse deadline"));
    anyhow::ensure!(
        entered.is_ok()
            && expected_timeout
            && remained_held
            && matches!(&partial, Ok(Err(error)) if error.to_string().contains("owned signer parse deadline"))
            && matches!(&dispatch, Ok(Ok(())))
            && matches!(&response, Ok(SignerHelperResponse::Pong { request_id }) if request_id=="held-dispatch"),
        "entered={entered:?}; timely_partial={timely:?}; held={remained_held}; partial={partial:?}; dispatch={dispatch:?}; response={response:?}"
    );
    Ok(())
}

#[test]
fn owned_signer_refuses_current_thread_runtime_before_requests() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let directory = tempfile::tempdir()?;
    runtime.block_on(async {
        let admission = Arc::new(crate::owned_resources::registered::RegistrationAdmission::new());
        let listener = crate::broker::daemon::bind_owned_signer_listener(&directory.path().join("signer.sock"), &admission)?;
        let helper = Arc::new(Mutex::new(SignerHelper::new("local", None).with_owned_resource_limits()));
        let result = serve_owned_on_listener(listener, helper.clone(), 65536, admission).await;
        anyhow::ensure!(matches!(result, Err(ref error) if error.to_string().contains("owned signer requires a multithread runtime")));
        anyhow::ensure!(helper.lock().await.registration_count() == 0);
        Ok(())
    })
}
