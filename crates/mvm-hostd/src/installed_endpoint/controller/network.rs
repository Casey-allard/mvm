//! Selected Object-TCP foreground controller. No legacy serve/runtime fallback.
use super::*;
use anyhow::Context as _;
use crate::installed_endpoint::Component;
use crate::supervisor::{
    flowmux::{
        FlowMuxAccept, FlowMuxSession, FlowMuxVmResources, OwnedTcpRelays, PayloadMappingConfig,
        SpiralCorePayloadFactory, registry::RegistryLimits,
    },
    network_endpoint::{EndpointConfig, ResolverBackend, build_egress_gate},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mvm_vmm::host::network_endpoint_spawn::EndpointTransport;
use std::{
    io::{self, Write},
    net::Shutdown,
    os::{
        fd::AsRawFd,
        unix::net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const SESSION_STACK: u64 = 2 << 20;
// Experimental functional-fixture envelope, prepaid from the SAME ledger.
// It is not a source-closed runtime/FlowMux heap bound or an enabled Root profile.
const EXPERIMENTAL_RUNTIME_SESSION: u64 = 8 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedNetworkRuntimeRequirements {
    pub controller: OwnedEndpointRuntimeRequirements,
    pub session_stack_bytes: u64,
    pub additional_threads: u8,
    pub experimental_runtime_session_bytes: u64,
    pub runtime_session_model_qualified: bool,
}
pub fn owned_network_runtime_requirements() -> Result<OwnedNetworkRuntimeRequirements> {
    Ok(OwnedNetworkRuntimeRequirements {
        controller: owned_endpoint_runtime_requirements()?,
        session_stack_bytes: mvm_core::host_lifetime::native_thread_stack_terms(SESSION_STACK)?
            .known_rust_bytes,
        additional_threads: 1,
        experimental_runtime_session_bytes: EXPERIMENTAL_RUNTIME_SESSION,
        runtime_session_model_qualified: false,
    })
}

/// Reject required services outside this first versioned implementation before
/// listener/collector effects. The complete HTTP/connector profile remains open.
fn selected_config(config: &EndpointConfig) -> Result<&Path> {
    ensure!(
        config.secrets.is_empty()
            && config.tools.is_empty()
            && config.ingress.is_empty()
            && config.tls_intermediate.is_none()
            && config.proxy_http.is_none()
            && config.proxy_https.is_none()
            && config.no_proxy.is_none()
            && config.reversible_replacement == Default::default()
            && matches!(config.resolver, ResolverBackend::Local),
        "installed Object-TCP required service unsupported"
    );
    ensure!(
        config.telemetry.is_some(),
        "installed original collector required"
    );
    let state = &config
        .telemetry
        .as_ref()
        .expect("checked original collector")
        .state_dir;
    // The canonical projection emits these locations even with no selected
    // tools/HTTP service. They remain inert in Object-TCP-only mode; their
    // presence is not permission to create connector/approval workers. Keep
    // their exact canonical origin rather than deleting/reinterpreting fields.
    ensure!(
        config.connector_uds_path.as_deref()
            == Some(
                mvm_core::config::vm_socket_dir_at(state)
                    .join(mvm_vmm::host::network_endpoint_spawn::SUBST_CONNECTOR_SOCKET)
                    .as_path()
            )
            && config.approval_socket.as_deref()
                == Some(mvm_core::config::vm_approval_socket_at(state).as_path()),
        "installed canonical service location differs"
    );
    let EndpointTransport::Uds { path } = &config.transport else {
        anyhow::bail!("installed Object-TCP requires original UDS transport")
    };
    let socket_dir = mvm_core::config::vm_socket_dir_at(state);
    let telemetry = config.telemetry.as_ref().expect("checked original collector");
    ensure!(
        state.is_absolute()
            && state.parent().is_some()
            && path.is_absolute()
            && path.file_name().is_some_and(|name| {
                path.as_path() == state.join(name) || path.as_path() == socket_dir.join(name)
            })
            && config.session_marker.as_deref()
                == Some(state.join(mvm_vmm::host::network_endpoint_spawn::SUBST_SESSION_FILE).as_path())
            && config.session_ready_socket.as_deref()
                == Some(socket_dir.join(mvm_vmm::host::network_endpoint_spawn::SUBST_SESSION_READY_SOCKET).as_path())
            && telemetry.telemetry_sock
                == mvm_core::config::vm_hvf_vsock_port_socket_at(
                    state,
                    mvm_core::protocol::telemetry::TELEMETRY_PORT,
                )
            && telemetry.signer_sock
                == mvm_core::config::host_agent_signer_helper_socket(&config.tenant_id)
            && telemetry.host_anchor_path
                == mvm_core::config::mvm_keys_dir()
                    .join(mvm_vmm::host::broker_services_spawn::HOST_SIGNER_PUB),
        "installed original service paths differ"
    );
    Ok(path)
}

fn bind(path: &Path) -> Result<UnixListener> {
    // Canonical state parents already exist and are held by the parent. Never
    // remove/rebind an unknown socket or create a different state namespace.
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(super) fn run(
    mut child: InstalledEndpointChild,
    resources: InstalledEndpointResources,
) -> Result<()> {
    let config = resources
        .network_config()
        .context("original network config missing")?;
    let path = selected_config(config)?;
    let quote = owned_network_runtime_requirements()?;
    let stack = quote
        .controller
        .main_stack_envelope_bytes
        .checked_add(quote.session_stack_bytes)
        .context("installed controller stack sum overflow")?;
    let metadata = quote
        .controller
        .controller_metadata_bytes
        .checked_add(quote.experimental_runtime_session_bytes)
        .context("installed controller metadata sum overflow")?;
    let controller = Arc::new(resources.claim_component(Component::Controller, stack, metadata)?);
    let session_control =
        crate::installed_endpoint::InstalledSessionControl::new(controller.clone());
    let audit = resources.lease.audit()?;
    let telemetry = config.telemetry.as_ref().context("original collector missing")?;
    ensure!(
        audit.tenant() == config.tenant_id && audit.socket() == telemetry.signer_sock,
        "installed collector audit authority differs"
    );
    // All selected constructors draw on this SAME original Resources before
    // listeners, collector threads, or Ready. No optional audit/key fallback.
    let recorder = Arc::new(resources.build_owned_audit_recorder()?);
    let group = OwnedTcpRelays::from_installed_resources(&resources)?;
    let factory = SpiralCorePayloadFactory::from_installed_resources(&resources)?
        .context("installed original payload factory missing")?;
    let policy = config
        .network_policy
        .as_ref()
        .context("original policy missing")?;
    let mapping = Arc::new(
        PayloadMappingConfig::new(
            policy,
            config
                .admitted_network_plan
                .clone()
                .context("original plan missing")?,
        )?
        .with_factory(Arc::new(factory)),
    );
    let identity = config
        .flowmux_identity
        .as_ref()
        .context("original guest identity missing")?;
    let host_key =
        ed25519_dalek::SigningKey::from_bytes(&decode_key(&identity.host_signing_key_base64)?);
    let guest_key = ed25519_dalek::VerifyingKey::from_bytes(&decode_key(
        &identity.guest_verifying_key_base64,
    )?)?;
    let limits = config.network_limits.validate()?;
    let params = FlowMuxAccept::new_shared(
        &identity.session_id,
        host_key,
        guest_key,
        RegistryLimits::from_network_limits(limits),
        Arc::new(build_egress_gate(policy)),
    )
    .with_vm_resources(Arc::new(FlowMuxVmResources::new(limits)))
    .with_payload_mapping(Some(mapping))
    .with_owned_tcp_relays(Some(group.clone()))
    .with_installed_audit(audit.clone())
    .with_installed_session_control(session_control.clone())
    .with_recorder(Some(recorder));
    // No enable_all, tokio::spawn or spawn_blocking. Actual audit futures use
    // bounded synchronous original std sockets; Handle::block_on needs no driver.
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let marker = config.session_marker.clone();
    let authenticated = Arc::new(AtomicBool::new(false));
    let listener = bind(path)?;
    let readiness = config
        .session_ready_socket
        .as_deref()
        .map(bind)
        .transpose()?;
    #[cfg(target_os = "linux")]
    {
        // Preserve the canonical DNS/TLS path inventory but grant no host key,
        // secret store or unrelated audit directory. Actual signer authority is
        // the original kernel-observed helper and existing guarded std client.
        let mut spec = crate::jailer::ConfinementSpec::network_endpoint(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        );
        spec.readable_paths.retain(|path| path.is_absolute());
        spec.readable_paths.push(telemetry.host_anchor_path.clone());
        spec.read_write_paths.clear();
        for parent in [
            Some(telemetry.state_dir.as_path()),
            telemetry.telemetry_sock.parent(),
            telemetry.signer_sock.parent(),
            audit.socket().parent(),
            path.parent(),
            config
                .session_ready_socket
                .as_deref()
                .and_then(Path::parent),
            marker.as_deref().and_then(Path::parent),
        ]
        .into_iter()
        .flatten()
        {
            if !spec
                .read_write_paths
                .iter()
                .any(|held| parent.starts_with(held))
            {
                spec.read_write_paths.push(parent.to_owned());
            }
        }
        resources.confine(&spec)?;
    }
    let mut collector = resources
        .start_owned_collector(child.startup_deadline())?
        .context("installed original collector missing")?;
    child.send_ready(Default::default(), child.startup_deadline())?;
    let mut pending = Some((params, runtime));
    let mut worker: Option<SessionWorker> = None;
    let mut waiter: Option<UnixStream> = None;
    let serving = (|| -> Result<()> {
        loop {
            // A previously failed worker cannot be erased by later EOF.
            session_control.check_failure()?;
            if child.parent_closed()? {
                return Ok(());
            }
            child.check_parent()?;
            controller.check_current()?;
            audit.check_current()?;
            // At most one accept attempt per control iteration. A full guest
            // queue cannot starve the original EOF/lease checks or readiness.
            if pending.is_some() {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (params, runtime) = pending.take().expect("one original session");
                        worker = Some(SessionWorker::spawn(
                            stream,
                            params,
                            runtime,
                            marker.clone(),
                            authenticated.clone(),
                            controller.clone(),
                            session_control.clone(),
                        )?);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if let Some(readiness) = &readiness
                && waiter.is_none()
            {
                match readiness.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(true)?;
                        waiter = Some(stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if authenticated.load(Ordering::Acquire)
                && let Some(stream) = &mut waiter
            {
                match stream.write(&[1]) {
                    Ok(1) => {
                        waiter.take();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    _ => {
                        waiter.take();
                    }
                }
            }
            let mut fds = [
                libc::pollfd {
                    fd: child.control_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if pending.is_some() {
                        listener.as_raw_fd()
                    } else {
                        -1
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: original owner lifetimes span this bounded poll.
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 25) } < 0
                && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                anyhow::bail!("installed controller poll failed")
            }
        }
    })();
    drop(listener);
    drop(readiness);
    drop(waiter);
    // SAME one cleanup deadline, and original handles/credits remain retained
    // on every timeout/error. No successful Drained after serving failure.
    let cleanup = Instant::now() + Duration::from_secs(2);
    if let Some(worker) = &mut worker {
        worker.request_stop();
        // The session may be inside the mapped carrier's handshake. Wake the
        // same attached upstream socket before waiting for the session.
        group.close_and_wake()?;
        worker.close_and_join(cleanup)?;
    }
    group.close_and_join(cleanup)?;
    collector.close_and_join(cleanup)?;
    let pool = resources.payload_pool().context("original pool missing")?;
    pool.close_admission()?;
    ensure!(pool.drained()?, "installed payload resources not drained");
    serving?;
    session_control.check_failure()?;
    child.send_drained(cleanup)
}

fn decode_key(encoded: &str) -> Result<[u8; 32]> {
    ensure!(encoded.len() == 44, "installed canonical key shape");
    let mut bytes = zeroize::Zeroizing::new([0u8; 33]);
    let len = STANDARD
        .decode_slice(encoded, bytes.as_mut_slice())
        .map_err(|_| anyhow::anyhow!("installed canonical key encoding"))?;
    ensure!(len == 32, "installed canonical key length");
    Ok(bytes[..32].try_into().expect("checked key length"))
}

struct SessionWorker {
    socket: UnixStream,
    handle: Option<JoinHandle<()>>,
    done: mpsc::Receiver<SessionExit>,
    permit: Arc<super::super::InstalledEndpointComponentPermit>,
    control: Arc<crate::installed_endpoint::InstalledSessionControl>,
}
enum SessionExit {
    Completed,
    Stopped,
    Failed,
}
impl SessionWorker {
    fn spawn(
        stream: UnixStream,
        params: FlowMuxAccept,
        runtime: tokio::runtime::Runtime,
        marker: Option<std::path::PathBuf>,
        authenticated: Arc<AtomicBool>,
        permit: Arc<super::super::InstalledEndpointComponentPermit>,
        control: Arc<crate::installed_endpoint::InstalledSessionControl>,
    ) -> Result<Self> {
        // Retain the direct cancellation descriptor BEFORE handshake or worker
        // effects. It does not wait for an installed relay to exist.
        let socket = stream.try_clone()?;
        let (signal, done) = mpsc::sync_channel(1);
        let retained = permit.clone();
        let worker_control = control.clone();
        let handle = std::thread::Builder::new()
            .name("installed-session".into())
            .stack_size(SESSION_STACK as usize)
            .spawn(move || {
                let _retained = retained;
                let _entered = runtime.enter();
                let result = (|| {
                    let mut session = FlowMuxSession::accept_with(stream, params)?;
                    if let Some(path) = marker.as_deref() {
                        std::fs::write(path, b"1")?;
                        std::fs::metadata(path)?;
                    }
                    authenticated.store(true, Ordering::Release);
                    let served = session.serve();
                    if served.is_ok() {
                        worker_control.wait_for_stop()?;
                    }
                    served
                })();
                let exit = match result {
                    Ok(()) => SessionExit::Completed,
                    Err(crate::supervisor::flowmux::FlowMuxError::Transport(error))
                        if worker_control.is_stop_error(&error) =>
                    {
                        SessionExit::Stopped
                    }
                    Err(_) => {
                        worker_control.fail();
                        SessionExit::Failed
                    }
                };
                let _ = signal.send(exit);
            })?;
        Ok(Self {
            socket,
            handle: Some(handle),
            done,
            permit,
            control,
        })
    }
    fn request_stop(&self) {
        self.control.request_stop();
        let _ = self.socket.shutdown(Shutdown::Both);
    }
    fn close_and_join(&mut self, deadline: Instant) -> Result<()> {
        if self.handle.is_none() {
            return Ok(());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("installed session join deadline")?;
        let exit = self
            .done
            .recv_timeout(remaining)
            .context("installed session completion pending")?;
        while !self
            .handle
            .as_ref()
            .expect("original session handle")
            .is_finished()
        {
            ensure!(
                Instant::now() < deadline,
                "installed session native epilogue pending"
            );
            std::thread::park_timeout(Duration::from_millis(1));
        }
        self.handle
            .take()
            .expect("original session handle")
            .join()
            .map_err(|_| anyhow::anyhow!("installed session worker failed"))?;
        ensure!(
            !matches!(exit, SessionExit::Failed),
            "installed session terminal failure"
        );
        self.control.check_failure()?;
        Ok(())
    }
}
impl Drop for SessionWorker {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(handle) = self.handle.take() {
            // Uncertain original completion cannot discard its owner/credit.
            std::mem::forget((handle, self.socket.try_clone().ok(), self.permit.clone()));
        }
    }
}
