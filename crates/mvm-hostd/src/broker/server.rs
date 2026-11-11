//! UDS server loop — accepts `ServiceCall` envelopes from the supervisor
//! proxy, dispatches via [`Registry`], writes back the [`ServiceResponse`].
//!
//! Currently the UDS server only; vsock 5300 wiring is separate (the
//! supervisor sets up the backend-specific listener and hands an FD; this
//! crate consumes the FD via [`serve_on_listener`]).
//!
//! Frame format: 4-byte big-endian length prefix + JSON `ServiceCall`.
//! Response: 4-byte big-endian length prefix + JSON `ServiceResponse`.
//! The max-frame-bytes gate is enforced *before* the parse so a malformed
//! length prefix cannot provoke an unbounded allocation.

use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceResponse};
use mvm_core::protocol::handler::ServiceCallCtx;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::broker::registry::{CancellationToken, Registry};

/// Accept loop. Each accepted UDS connection runs to completion in its
/// own `tokio::spawn`; one connection per supervisor-proxy call.
pub async fn serve(
    listener: UnixListener,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    info!(
        workload_id = %workload_id,
        max_frame_bytes,
        "mvm-broker accept loop started"
    );
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("mvm-broker UDS accept failed")?;
        let registry = registry.clone();
        let workload_id = workload_id.clone();
        let tenant_id = tenant_id.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, registry, workload_id, tenant_id, max_frame_bytes).await
            {
                warn!(error = %e, "mvm-broker connection terminated with error");
            }
        });
    }
}

/// Variant of [`serve`] for tests + cases where the caller already has a
/// `UnixListener` (e.g., from a tempdir-bound test fixture). The
/// supervisor's spawn path calls this once it sets up the listener at
/// the per-VM UDS path from `SubprocessConfig::uds_path`.
pub async fn serve_on_listener(
    listener: UnixListener,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    serve(listener, registry, workload_id, tenant_id, max_frame_bytes).await
}

const MAX_RETAINED_CONNECTIONS: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListenerPhase {
    Preparing,
    Running,
    Stopped,
}

struct IngressState {
    stopped: bool,
    failed: bool,
    listener: ListenerPhase,
}

type ConnectionTasks = tokio::task::JoinSet<Result<()>>;

/// Inner service-task custody. The original daemon cell/map retains this owner
/// BEFORE any listener/task is created; this type is not a replacement owner.
/// A canceled drain borrows its stable set and cannot drop/abort that set.
pub(crate) struct ServiceConnectionOwner {
    tasks: Arc<tokio::sync::Mutex<ConnectionTasks>>,
    ingress: Arc<std::sync::Mutex<IngressState>>,
    stopped: tokio::sync::watch::Sender<bool>,
    slots: Arc<tokio::sync::Semaphore>,
    admission_taken: bool,
    drained: bool,
}

/// One original listener turn. Connection tasks never capture this value, its
/// set Arc, or an owner Sender; they carry only separate ingress state and Rx.
pub(crate) struct ServiceConnectionAdmission {
    tasks: Arc<tokio::sync::Mutex<ConnectionTasks>>,
    ingress: Arc<std::sync::Mutex<IngressState>>,
    stopped: tokio::sync::watch::Receiver<bool>,
    slots: Arc<tokio::sync::Semaphore>,
}

/// Actual connection-task joins only. The LiveVmHandle separately retains and
/// joins its original listener; this receipt grants no admission or authority.
pub(crate) struct ServiceConnectionDrainReceipt {
    _private: (),
}

impl ServiceConnectionOwner {
    pub(crate) fn new(slots: Arc<tokio::sync::Semaphore>) -> Self {
        let (stopped, _) = tokio::sync::watch::channel(false);
        Self {
            tasks: Arc::new(tokio::sync::Mutex::new(ConnectionTasks::new())),
            ingress: Arc::new(std::sync::Mutex::new(IngressState {
                stopped: false,
                failed: false,
                listener: ListenerPhase::Preparing,
            })),
            stopped,
            slots,
            admission_taken: false,
            drained: false,
        }
    }

    pub(crate) fn take_listener_admission(&mut self) -> Result<ServiceConnectionAdmission> {
        anyhow::ensure!(
            !self.admission_taken && !self.drained,
            "original listener admission already consumed"
        );
        let ingress = self
            .ingress
            .lock()
            .map_err(|_| anyhow::anyhow!("original ingress state poisoned"))?;
        anyhow::ensure!(
            !ingress.stopped && !ingress.failed && !self.slots.is_closed(),
            "original service admission stopped"
        );
        self.admission_taken = true;
        Ok(ServiceConnectionAdmission {
            tasks: self.tasks.clone(),
            ingress: self.ingress.clone(),
            stopped: self.stopped.subscribe(),
            slots: self.slots.clone(),
        })
    }

    pub(crate) fn request_stop(&self) {
        // Per-VM retirement closes only its local admission, not the tenant's
        // shared semaphore. Whole-daemon stop closes that original budget.
        match self.ingress.lock() {
            Ok(mut state) => {
                state.stopped = true;
                if state.listener == ListenerPhase::Preparing {
                    state.listener = ListenerPhase::Stopped;
                }
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.stopped = true;
                state.failed = true;
            }
        }
        self.stopped.send_replace(true);
    }

    pub(crate) async fn drain(&mut self) -> Result<ServiceConnectionDrainReceipt> {
        self.request_stop();
        if !self.drained {
            {
                let state = self
                    .ingress
                    .lock()
                    .map_err(|_| anyhow::anyhow!("original ingress state poisoned"))?;
                anyhow::ensure!(
                    state.listener == ListenerPhase::Stopped,
                    "original listener has not stopped; retain its join owner"
                );
            }
            let mut tasks = self.tasks.lock().await;
            while let Some(result) = tasks.join_next().await {
                record_connection_join(&self.ingress, result);
            }
            let state = self
                .ingress
                .lock()
                .map_err(|_| anyhow::anyhow!("original ingress state poisoned"))?;
            anyhow::ensure!(!state.failed, "original connection task outcome unresolved");
            self.drained = true;
        }
        Ok(ServiceConnectionDrainReceipt { _private: () })
    }
}

impl Drop for ServiceConnectionOwner {
    fn drop(&mut self) {
        // The outer original cell remains the owner until actual drain. Its
        // borrowed guards retain this entire value on cancellation/unwind.
        // No abort/JoinSet replacement or final-Arc leak is performed here.
        self.request_stop();
    }
}

fn record_connection_join(
    ingress: &std::sync::Mutex<IngressState>,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => warn!("retained broker connection completed with a protocol error"),
        Err(_) => {
            let mut state = ingress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.failed = true;
            state.stopped = true;
        }
    }
}

struct OriginalListenerTurn {
    ingress: Arc<std::sync::Mutex<IngressState>>,
    completed: bool,
}

impl Drop for OriginalListenerTurn {
    fn drop(&mut self) {
        let mut state = self
            .ingress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.listener = ListenerPhase::Stopped;
        state.failed |= !self.completed;
    }
}

fn service_stop_requested(stopped: &tokio::sync::watch::Receiver<bool>) -> bool {
    *stopped.borrow() || stopped.has_changed().is_err()
}

async fn service_stopped(stopped: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if service_stop_requested(stopped) || stopped.changed().await.is_err() {
            return;
        }
    }
}

/// Retained variant for the original daemon map. No set is owned solely by
/// this async frame, and the caller must join this original listener task before
/// borrowing ServiceConnectionOwner::drain for all admitted connection work.
pub(crate) async fn serve_on_listener_owned(
    listener: UnixListener,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
    mut admission: ServiceConnectionAdmission,
) -> Result<()> {
    {
        let mut state = admission
            .ingress
            .lock()
            .map_err(|_| anyhow::anyhow!("original ingress state poisoned"))?;
        if state.stopped || admission.slots.is_closed() {
            state.listener = ListenerPhase::Stopped;
            return Ok(());
        }
        anyhow::ensure!(
            state.listener == ListenerPhase::Preparing,
            "original listener already started"
        );
        state.listener = ListenerPhase::Running;
    }
    let mut original = OriginalListenerTurn {
        ingress: admission.ingress.clone(),
        completed: false,
    };
    // Re-register the SAME original listener descriptor as AsyncFd so readiness
    // is observed before reserving a tenant slot. Idle listeners cannot hoard
    // the entire shared capacity; no unbudgeted accepted FD is created first.
    let listener = listener.into_std()?;
    // SAFETY: this exclusively owned std UnixListener keeps the same open
    // descriptor/file description for its entire AsyncFd lifetime. No raw close,
    // replacement, get_mut, or competing owner is exposed; into_std deregistered
    // the previous Tokio listener before this same descriptor is registered.
    let listener = unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(listener, tokio::io::Interest::READABLE)
    }?;
    loop {
        {
            let mut tasks = admission.tasks.lock().await;
            while let Some(result) = tasks.try_join_next() {
                record_connection_join(&admission.ingress, result);
            }
        }
        let stopping = {
            let state = admission
                .ingress
                .lock()
                .map_err(|_| anyhow::anyhow!("original ingress state poisoned"))?;
            state.stopped || state.failed
        };
        if stopping || service_stop_requested(&admission.stopped) || admission.slots.is_closed() {
            break;
        }
        let at_limit = { admission.tasks.lock().await.len() >= MAX_RETAINED_CONNECTIONS };
        if at_limit {
            let joined = tokio::select! {
                biased;
                () = service_stopped(&mut admission.stopped) => break,
                joined = async { admission.tasks.lock().await.join_next().await } => joined,
            };
            if let Some(result) = joined {
                record_connection_join(&admission.ingress, result);
            }
            continue;
        }
        let mut ready = tokio::select! {
            biased;
            () = service_stopped(&mut admission.stopped) => break,
            ready = listener.readable() => ready?,
        };
        let permit = tokio::select! {
            biased;
            () = service_stopped(&mut admission.stopped) => break,
            permit = admission.slots.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let stream = match ready.try_io(|listener| listener.get_ref().accept()) {
            Ok(Ok((stream, _))) => stream,
            Ok(Err(error)) => return Err(error).context("original service accept failed"),
            Err(_) => continue,
        };
        stream.set_nonblocking(true)?;
        let stream = UnixStream::from_std(stream)?;
        let state = admission.ingress.clone();
        let stopped = admission.stopped.clone();
        let slots = admission.slots.clone();
        let registry = registry.clone();
        let workload_id = workload_id.clone();
        let tenant_id = tenant_id.clone();
        admission.tasks.lock().await.spawn(async move {
            let _original_permit = permit;
            handle_owned_connection(OwnedConnection {
                stream,
                registry,
                workload_id,
                tenant_id,
                max_frame_bytes,
                ingress: state,
                stopped,
                slots,
            })
            .await
        });
    }
    original.completed = true;
    Ok(())
}

struct OwnedConnection {
    stream: UnixStream,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
    ingress: Arc<std::sync::Mutex<IngressState>>,
    stopped: tokio::sync::watch::Receiver<bool>,
    slots: Arc<tokio::sync::Semaphore>,
}

async fn handle_owned_connection(connection: OwnedConnection) -> Result<()> {
    let OwnedConnection {
        mut stream,
        registry,
        workload_id,
        tenant_id,
        max_frame_bytes,
        ingress,
        mut stopped,
        slots,
    } = connection;
    let call = tokio::select! {
        biased;
        () = service_stopped(&mut stopped) => return Ok(()),
        call = read_frame::<ServiceCall>(&mut stream, max_frame_bytes) => call?,
    };
    {
        // Serialize local stop against DispatchStarted bookkeeping. Registry
        // remains the sole canonical capability/admission enforcement path.
        let state = ingress
            .lock()
            .map_err(|_| anyhow::anyhow!("original ingress state poisoned"))?;
        if state.stopped || state.failed || slots.is_closed() {
            return Ok(());
        }
    }
    // No stop-select around original dispatch: a canceled waiter cannot turn
    // an admitted handler into an apparent completion or refund its permit.
    let response = dispatch_call(call, registry, workload_id, tenant_id).await;
    tokio::select! {
        biased;
        () = service_stopped(&mut stopped) => return Ok(()),
        written = write_frame(&mut stream, &response) => written?,
    }
    tokio::select! {
        biased;
        () = service_stopped(&mut stopped) => Ok(()),
        result = stream.shutdown() => result.context("original service shutdown failed"),
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    let call = read_frame::<ServiceCall>(&mut stream, max_frame_bytes).await?;
    let response = dispatch_call(call, registry, workload_id, tenant_id).await;

    write_frame(&mut stream, &response).await?;
    stream
        .shutdown()
        .await
        .context("mvm-broker UDS shutdown failed")?;
    Ok(())
}

async fn dispatch_call(
    call: ServiceCall,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
) -> ServiceResponse {
    // Reassign a server-authoritative correlation id at ingress: the
    // guest-supplied `call.correlation_id` is NEVER trusted — a workload could
    // otherwise choose an id that collides with or impersonates another entry
    // in the chain-signed audit log. The reassigned id flows into the ctx
    // (hence the audit entry) and the response. The guest does not match on it
    // (one call per connection), so reassignment is transparent to it.
    let correlation_id = mint_correlation_id();
    debug!(
        service = %call.service,
        verb = %call.verb,
        client_correlation_id = %call.correlation_id,
        correlation_id = %correlation_id,
        "mvm-broker received call (correlation id reassigned)"
    );

    // The registration's workload identity is also this broker connection's
    // server-derived session lookup key. A guest cannot choose it: each VM has
    // a separately bound listener carrying its admitted registration context.
    let ctx = ServiceCallCtx {
        workload_id: workload_id.clone(),
        tenant_id: tenant_id.clone(),
        correlation_id: correlation_id.clone(),
        session_id: workload_id.clone(),
        profile: AgentProfile::default(),
        composition_depth: 0,
        composition_width: 0,
    };

    let cancellation = CancellationToken::new();
    let result = match call.capability {
        Some(invocation) => {
            registry
                .dispatch_capability(
                    &ctx,
                    &call.service,
                    &call.verb,
                    &invocation,
                    call.payload,
                    &cancellation,
                )
                .await
        }
        None => {
            registry
                .dispatch(&ctx, &call.service, &call.verb, call.payload)
                .await
        }
    };
    match result {
        Ok(payload) => ServiceResponse::Ok {
            correlation_id,
            payload,
        },
        Err(e) => ServiceResponse::Err {
            correlation_id,
            code: e.code,
            message: e.message,
        },
    }
}

/// Mint a fresh, server-authoritative correlation id at frame ingress. Unique
/// per (broker process, call): a process-id prefix + a monotonic counter — the
/// broker is per-VM and serves one call per connection, so this never collides
/// within a workload. No new dependency; the value is opaque (a future change
/// to ULID/Snowflake is a serde-compatible widening since it stays a string).
fn mint_correlation_id() -> CorrelationId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    CorrelationId::new(format!("brk-{}-{:016x}", std::process::id(), n))
}

/// Read a length-prefixed JSON frame. Enforces the max-frame-bytes cap
/// before allocating the body buffer.
// Length-prefixed JSON framing lives in `crate::framing`; these wrappers
// keep the broker error context on the shared transport. The
// cap-before-alloc gate is enforced there.
pub async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<T> {
    crate::framing::read_json_frame(stream, max_frame_bytes)
        .await
        .context("mvm-broker frame read failed")
}

/// Write a length-prefixed JSON frame.
pub async fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    crate::framing::write_json_frame(stream, value)
        .await
        .context("mvm-broker frame write failed")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::time::Duration;

    use mvm_contract::protocol::agent_capability::{
        CapabilityDescriptor, CapabilityId, CapabilityInvocation, CapabilityLimits, SchemaRef,
    };
    use mvm_contract::protocol::agent_session::AgentRequestId;
    use mvm_core::policy::security::AgentProfile;
    use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
    use mvm_core::protocol::handler::{ServiceCallCtx, ServiceDispatchResult, ServiceHandler};
    use tempfile::tempdir;
    use tokio::net::UnixStream as ClientStream;

    use super::*;
    use tokio::io::AsyncReadExt;

    pub(crate) struct HeldDispatch {
        entered: std::sync::atomic::AtomicUsize,
        completed: std::sync::atomic::AtomicUsize,
        changed: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
    }

    impl HeldDispatch {
        pub(crate) fn new() -> Self {
            Self {
                entered: std::sync::atomic::AtomicUsize::new(0),
                completed: std::sync::atomic::AtomicUsize::new(0),
                changed: tokio::sync::Notify::new(),
                release: tokio::sync::Semaphore::new(0),
            }
        }

        pub(crate) fn release_dispatches(&self, count: usize) {
            self.release.add_permits(count);
        }

        pub(crate) fn completed_count(&self) -> usize {
            self.completed.load(std::sync::atomic::Ordering::Acquire)
        }

        pub(crate) async fn entered_at_least(&self, target: usize) {
            loop {
                let changed = self.changed.notified();
                if self.entered.load(std::sync::atomic::Ordering::Acquire) >= target {
                    return;
                }
                changed.await;
            }
        }
    }

    impl ServiceHandler for HeldDispatch {
        fn id(&self) -> ServiceId {
            ServiceId::parse("host.dev.held.v1").unwrap()
        }
        fn profiles(&self) -> &[AgentProfile] {
            &[AgentProfile::Dev]
        }
        fn audit_durability(&self) -> mvm_core::protocol::broker::AuditDurability {
            mvm_core::protocol::broker::AuditDurability::default_batched()
        }
        fn idempotency(&self) -> mvm_core::protocol::broker::Idempotency {
            mvm_core::protocol::broker::Idempotency::MintFresh
        }
        fn call_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }
        fn dispatch<'a>(
            &'a self,
            _ctx: &'a ServiceCallCtx,
            _verb: &'a str,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
            Box::pin(async move {
                self.entered
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                self.changed.notify_one();
                self.release.acquire().await.unwrap().forget();
                self.completed
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                Ok(payload)
            })
        }
    }

    fn held_descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(ServiceId::parse("host.dev.held.v1").unwrap(), "hold").unwrap())
            .description("controlled original dispatch fixture")
            .input_schema(SchemaRef::new("host.dev.held.input.v1", [3; 32]).unwrap())
            .output_schema(SchemaRef::new("host.dev.held.output.v1", [4; 32]).unwrap())
            .limits(CapabilityLimits::new(1024, 1024, 5_000).unwrap())
            .build()
            .unwrap()
    }

    pub(crate) fn held_registry(handler: Arc<HeldDispatch>) -> Arc<Registry> {
        let descriptor = held_descriptor();
        let binding = descriptor.binding();
        let mut registry = Registry::new();
        registry.register_capability(handler, descriptor).unwrap();
        registry.admit_capabilities([binding]).unwrap();
        Arc::new(registry)
    }

    pub(crate) fn held_call() -> ServiceCall {
        static REQUEST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let payload = serde_json::json!({"exact": [0, 1, 255]});
        let request = format!(
            "held-fixture-{}",
            REQUEST.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let invocation = CapabilityInvocation::from_payload(
            held_descriptor().binding(),
            AgentRequestId::parse(request).unwrap(),
            &payload,
        )
        .unwrap();
        ServiceCall {
            service: ServiceId::parse("host.dev.held.v1").unwrap(),
            verb: "hold".into(),
            correlation_id: CorrelationId::new("fixture-owned-dispatch"),
            payload,
            capability: Some(invocation),
        }
    }

    #[tokio::test]
    async fn owned_service_stop_releases_partial_frames_without_dispatch() {
        let directory = tempdir().unwrap();
        let path = uds_path(&directory);
        let listener = UnixListener::bind(&path).unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(256));
        let mut owner = ServiceConnectionOwner::new(slots.clone());
        let admission = owner.take_listener_admission().unwrap();
        let serving = tokio::spawn(serve_on_listener_owned(
            listener,
            Arc::new(Registry::new()),
            "wl".into(),
            "tenant".into(),
            65_536,
            admission,
        ));
        let mut client = ClientStream::connect(&path).await.unwrap();
        client.write_all(&[0]).await.unwrap();
        tokio::task::yield_now().await;
        owner.request_stop();
        tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), owner.drain())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(slots.available_permits(), 256);
    }

    #[tokio::test]
    async fn owned_service_drain_retains_entered_dispatch_across_canceled_wait() {
        let directory = tempdir().unwrap();
        let path = uds_path(&directory);
        let listener = UnixListener::bind(&path).unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(256));
        let mut owner = ServiceConnectionOwner::new(slots.clone());
        let handler = Arc::new(HeldDispatch::new());
        let registry = held_registry(handler.clone());
        let serving = tokio::spawn(serve_on_listener_owned(
            listener,
            registry,
            "wl".into(),
            "tenant".into(),
            65_536,
            owner.take_listener_admission().unwrap(),
        ));
        let mut client = ClientStream::connect(&path).await.unwrap();
        write_call(&mut client, &held_call()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), handler.entered_at_least(1))
            .await
            .unwrap();
        owner.request_stop();
        tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let pending = tokio::time::timeout(Duration::from_millis(20), owner.drain()).await;
        let held = slots.available_permits();
        let completed_before_release = handler.completed.load(std::sync::atomic::Ordering::Acquire);
        // Always release/collect the actual admitted fixture before asserting.
        handler.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), owner.drain())
            .await
            .unwrap()
            .unwrap();
        assert!(
            pending.is_err(),
            "a joined listener is not an original dispatch receipt"
        );
        assert_eq!(
            held, 255,
            "canceling the waiter cannot refund the live task's slot"
        );
        assert_eq!(completed_before_release, 0);
        assert_eq!(
            handler.completed.load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(slots.available_permits(), 256);
    }

    #[tokio::test]
    async fn owned_service_ingress_budget_is_shared_between_listeners() {
        // Two small fixture slots exercise the SAME shared-budget mechanism;
        // production's one per-tenant cap remains 256, never 256 per VM.
        let directory = tempdir().unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(2));
        let handler = Arc::new(HeldDispatch::new());
        let registry = held_registry(handler.clone());
        let mut owners = Vec::new();
        let mut servers = Vec::new();
        let mut clients = Vec::new();
        for index in 0..2 {
            let path = directory.path().join(format!("listener-{index}.sock"));
            let listener = UnixListener::bind(&path).unwrap();
            let mut owner = ServiceConnectionOwner::new(slots.clone());
            servers.push(tokio::spawn(serve_on_listener_owned(
                listener,
                registry.clone(),
                "wl".into(),
                "tenant".into(),
                65_536,
                owner.take_listener_admission().unwrap(),
            )));
            let mut client = ClientStream::connect(&path).await.unwrap();
            write_call(&mut client, &held_call()).await.unwrap();
            owners.push(owner);
            clients.push(client);
        }
        tokio::time::timeout(Duration::from_secs(1), handler.entered_at_least(2))
            .await
            .unwrap();
        let mut third = ClientStream::connect(directory.path().join("listener-0.sock"))
            .await
            .unwrap();
        write_call(&mut third, &held_call()).await.unwrap();
        let third_entered =
            tokio::time::timeout(Duration::from_millis(50), handler.entered_at_least(3)).await;
        let remaining = slots.available_permits();
        for owner in &owners {
            owner.request_stop();
        }
        for server in servers {
            tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        handler
            .release
            .add_permits(handler.entered.load(std::sync::atomic::Ordering::Acquire));
        for owner in &mut owners {
            tokio::time::timeout(Duration::from_secs(1), owner.drain())
                .await
                .unwrap()
                .unwrap();
        }
        assert!(
            third_entered.is_err(),
            "a second listener cannot mint extra ingress capacity"
        );
        assert_eq!(remaining, 0);
        assert_eq!(
            handler.entered.load(std::sync::atomic::Ordering::Acquire),
            2
        );
        assert_eq!(slots.available_permits(), 2);
    }

    async fn write_call(stream: &mut ClientStream, call: &ServiceCall) -> Result<()> {
        let body = serde_json::to_vec(call).unwrap();
        let len: u32 = body.len().try_into().unwrap();
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&body).await?;
        Ok(())
    }

    async fn read_response(stream: &mut ClientStream) -> Result<ServiceResponse> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn uds_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("broker.sock")
    }

    struct TypedEchoHandler;

    impl ServiceHandler for TypedEchoHandler {
        fn id(&self) -> ServiceId {
            ServiceId::parse("host.dev.echo.v1").expect("service id")
        }

        fn profiles(&self) -> &[AgentProfile] {
            &[AgentProfile::Dev]
        }

        fn audit_durability(&self) -> mvm_core::protocol::broker::AuditDurability {
            mvm_core::protocol::broker::AuditDurability::default_batched()
        }

        fn idempotency(&self) -> mvm_core::protocol::broker::Idempotency {
            mvm_core::protocol::broker::Idempotency::MintFresh
        }

        fn call_timeout(&self) -> Duration {
            Duration::from_millis(50)
        }

        fn dispatch<'a>(
            &'a self,
            _ctx: &'a ServiceCallCtx,
            _verb: &'a str,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
            Box::pin(async move { Ok(payload) })
        }
    }

    fn typed_echo_descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.dev.echo.v1").expect("service id"),
                "echo",
            )
            .expect("capability id"))
            .description("echo a bounded test value")
            .input_schema(SchemaRef::new("host.dev.echo.input.v1", [1; 32]).expect("schema"))
            .output_schema(SchemaRef::new("host.dev.echo.output.v1", [2; 32]).expect("schema"))
            .limits(CapabilityLimits::new(1024, 1024, 100).expect("limits"))
            .build()
            .expect("descriptor")
    }

    #[tokio::test]
    async fn round_trips_a_call_and_returns_not_bound_with_empty_registry() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind typed broker test listener: {error}"),
        };
        let registry = Arc::new(Registry::new());

        let server_task = tokio::spawn({
            let registry = registry.clone();
            let path_clone = path.clone();
            async move {
                let _ = serve_on_listener(
                    listener,
                    registry,
                    "wl-test".into(),
                    "t-test".into(),
                    65_536,
                )
                .await;
                drop(path_clone);
            }
        });

        // Give the listener a tick to start.
        tokio::task::yield_now().await;

        let mut client = ClientStream::connect(&path).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.time.v1").unwrap(),
            verb: "now".into(),
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            payload: serde_json::json!({}),
            capability: None,
        };
        write_call(&mut client, &call).await.unwrap();
        let response = read_response(&mut client).await.unwrap();

        match response {
            ServiceResponse::Err {
                correlation_id,
                code,
                message,
            } => {
                // The broker reassigns a server-authoritative correlation id at
                // ingress — the guest-supplied value is never trusted/echoed.
                assert_ne!(correlation_id.as_str(), "01HBROKER0000000000000000");
                assert!(
                    correlation_id.as_str().starts_with("brk-"),
                    "correlation id must be server-minted: {}",
                    correlation_id.as_str()
                );
                assert_eq!(code, ServiceErrorCode::NotBound);
                assert!(message.contains("host.time.v1"));
            }
            other => panic!("expected NotBound err, got {:?}", other),
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn typed_call_round_trips_over_uds_and_replay_is_refused() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind typed broker test listener: {error}"),
        };
        let descriptor = typed_echo_descriptor();
        let binding = descriptor.binding();
        let mut registry = Registry::new();
        registry
            .register_capability(Arc::new(TypedEchoHandler), descriptor)
            .expect("register typed handler");
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit typed binding");
        let registry = Arc::new(registry);
        let server_task = tokio::spawn({
            let registry = registry.clone();
            async move {
                let _ = serve_on_listener(
                    listener,
                    registry,
                    "wl-test".into(),
                    "t-test".into(),
                    65_536,
                )
                .await;
            }
        });
        tokio::task::yield_now().await;

        let payload = serde_json::json!({"value": 7});
        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("uds-request-1").expect("request id"),
            &payload,
        )
        .expect("invocation");
        let call = ServiceCall {
            service: ServiceId::parse("host.dev.echo.v1").expect("service id"),
            verb: "echo".into(),
            correlation_id: CorrelationId::new("guest-correlation"),
            payload: payload.clone(),
            capability: Some(invocation.clone()),
        };
        let mut client = ClientStream::connect(&path).await.unwrap();
        write_call(&mut client, &call).await.unwrap();
        assert!(matches!(
            read_response(&mut client).await.unwrap(),
            ServiceResponse::Ok { payload: response, .. } if response == payload
        ));

        let mut replay_client = ClientStream::connect(&path).await.unwrap();
        write_call(&mut replay_client, &call).await.unwrap();
        let response = read_response(&mut replay_client).await.unwrap();
        assert!(matches!(
            response,
            ServiceResponse::Err {
                code: ServiceErrorCode::CapabilityReplay,
                ..
            }
        ));
        server_task.abort();
    }

    #[tokio::test]
    async fn rejects_frames_above_the_cap() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("failed to bind broker test listener: {err}"),
        };
        let registry = Arc::new(Registry::new());

        let server_task = tokio::spawn({
            let registry = registry.clone();
            let path_clone = path.clone();
            async move {
                let _ = serve_on_listener(
                    listener,
                    registry,
                    "wl-test".into(),
                    "t-test".into(),
                    // Tiny cap so any real envelope blows past it.
                    32,
                )
                .await;
                drop(path_clone);
            }
        });

        tokio::task::yield_now().await;

        let mut client = ClientStream::connect(&path).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.time.v1").unwrap(),
            verb: "now".into(),
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            payload: serde_json::json!({"padding": "x".repeat(256)}),
            capability: None,
        };
        // Manually write the length prefix + body so the test exercises
        // the server-side cap check (the server reads the prefix, sees
        // it's > 32, and closes the connection).
        let body = serde_json::to_vec(&call).unwrap();
        let len: u32 = body.len().try_into().unwrap();
        client.write_all(&len.to_be_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();

        // The server should drop the connection; depending on platform
        // scheduling, the client may observe either EOF or a reset.
        let mut buf = [0u8; 4];
        match client.read(&mut buf).await {
            Ok(0) => {}
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!("expected EOF/reset after oversized frame rejection, got {n} bytes"),
            Err(err) => {
                panic!("expected EOF/reset after oversized frame rejection, got {err}")
            }
        }

        server_task.abort();
    }
}
