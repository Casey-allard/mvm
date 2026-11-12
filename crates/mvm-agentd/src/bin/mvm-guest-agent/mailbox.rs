//! Mailbox listener glue: bind the reserved mailbox vsock port and forward the
//! workload's outbox message to each host connection.
//!
//! Opt-in and launch-asserted, like telemetry: the listener binds only when
//! the kernel cmdline carries `mvm.mailbox=1`, which the host sets only for a
//! signed plan that carries a mailbox grant. Otherwise no thread starts and no
//! port is held. Vsock-only; the container tier has none.

use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::Ordering;

use mvm_agentd::mailbox_outbox::{
    MAILBOX_HOLD, MAILBOX_IO_TIMEOUT, OUTBOX_PATH, bound_socket_io, forward_outbox, peer_gone,
    wait_for_outbox,
};
use mvm_contract::protocol::mailbox::MAILBOX_PORT;
use mvm_contract::protocol::mailbox::local_service::{
    MailboxGuestService, parse_mailbox_service_cmdline,
};

#[cfg(test)]
use mvm_agentd::mailbox_outbox::MAILBOX_CMDLINE_TOKEN;

use crate::globals::SHUTDOWN_REQUESTED;
#[cfg(test)]
use crate::telemetry::cmdline_asserts;
use crate::transport::{accept_vsock, bind_vsock_listener, unix_transport_selected};

#[cfg(target_os = "linux")]
pub(crate) enum OriginalEndpoint {
    Deliver(mvm_agentd::mailbox_cast::GuestCastEndpoint),
    Submit(mvm_agentd::mailbox_cast::submit::GuestSubmitEndpoint),
}
#[cfg(target_os = "linux")]
struct OriginalDelivery {
    endpoint: std::sync::Mutex<Option<OriginalEndpoint>>,
    descriptor: std::sync::Mutex<Option<std::os::fd::OwnedFd>>,
}
#[cfg(target_os = "linux")]
static ORIGINAL: std::sync::OnceLock<OriginalDelivery> = std::sync::OnceLock::new();

/// Check the original boot authority before accepting any mount or starting a
/// worker. The activation message cannot supply a replacement trust anchor.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_delivery(
    env: &mvm_agentd::vsock::ActivateEnvironment,
    boot: &crate::state::AgentBootState,
) -> anyhow::Result<Option<(OriginalEndpoint, std::os::fd::OwnedFd)>> {
    use anyhow::{Context, ensure};
    let (denied, held) = boot.grant_state();
    let delivery = env.cast_delivery_v1.as_ref();
    let submit = env.cast_submit_v1.as_ref();
    ensure!(
        !(delivery.is_some() && submit.is_some()),
        "exactly one original guest mailbox role required"
    );
    if delivery.is_none() && submit.is_none() {
        ensure!(
            held.as_ref()
                .is_none_or(|g| g.cast_delivery_v1.is_none() && g.cast_submit_v1.is_none()),
            "missing committed mailbox role"
        );
        return Ok(None);
    }
    ensure!(!denied, "boot grant authority denied");
    ensure!(
        crate::init::is_pid1()
            && !env.rootfs.in_place
            && env.rootfs.virtiofs_tag.is_none()
            && !env.rootfs.data_dev.is_empty(),
        "expected original PID 1 block-root activation"
    );
    let selected = parse_mailbox_service_cmdline(&std::fs::read_to_string("/proc/cmdline")?)?;
    ensure!(
        selected == MailboxGuestService::ReliableV1,
        "missing signed reliable service selection"
    );
    // Only the signed, original role checked below can activate this subset.
    let held = held.context("missing original boot grant")?;
    let anchor = boot
        .host_signer_key()
        .context("missing original boot anchor")?;
    // The root hash is a digest, not an Ed25519 point.
    let root = env
        .rootfs
        .roothash
        .as_deref()
        .map(|h| {
            ensure!(
                h.len() == 64
                    && h.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid root digest"
            );
            let mut bytes = [0; 32];
            for (i, x) in bytes.iter_mut().enumerate() {
                *x = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)?;
            }
            Ok::<_, anyhow::Error>(bytes)
        })
        .transpose()?;
    let mount = env.cast_mount_commitment()?;
    let now = chrono::Utc::now();
    if let Some(e) = submit {
        let original = e.open_original(
            &held,
            &anchor,
            &held.session_id,
            &held.plan_nonce,
            root,
            mount,
            now,
        )?;
        let (endpoint, fd) =
            mvm_agentd::mailbox_cast::submit::GuestSubmitEndpoint::prepare_original_worker(
                original,
            )?;
        return Ok(Some((OriginalEndpoint::Submit(endpoint), fd)));
    }
    let e = delivery.context("missing original Deliver role")?;
    let channel = e.open_original(
        &held,
        &anchor,
        &held.session_id,
        &held.plan_nonce,
        root,
        mount,
        now,
    )?;
    let (endpoint, fd) =
        mvm_agentd::mailbox_cast::GuestCastEndpoint::prepare_original_worker(channel, e.limits())?;
    Ok(Some((OriginalEndpoint::Deliver(endpoint), fd)))
}

#[cfg(target_os = "linux")]
pub(crate) fn install_delivery(
    pair: Option<(OriginalEndpoint, std::os::fd::OwnedFd)>,
) -> anyhow::Result<()> {
    if let Some((endpoint, fd)) = pair {
        use mvm_agentd::runtime_config::ConcurrencyConfig;
        let runtime = mvm_agentd::runtime_config::load()?
            .ok_or_else(|| anyhow::anyhow!("Cast requires an installed workload runtime"))?;
        anyhow::ensure!(
            matches!(runtime.concurrency,Some(ConcurrencyConfig::WarmProcess(cfg)) if cfg.pool_size==1),
            "one original OCI worker required"
        );
        let entry = mvm_agentd::entrypoint::EntrypointPolicy::production()
            .validate()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(
            !entry.use_resolved_path
                && entry.resolved == std::path::Path::new("/usr/lib/mvm/wrappers/oci-entrypoint"),
            "original Cast requires the validated OCI entrypoint"
        );
        ORIGINAL
            .set(OriginalDelivery {
                endpoint: std::sync::Mutex::new(Some(endpoint)),
                descriptor: std::sync::Mutex::new(Some(fd)),
            })
            .map_err(|_| anyhow::anyhow!("original Deliver already installed"))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn take_original() -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    ORIGINAL
        .get()
        .map(|o| {
            o.descriptor
                .lock()
                .map_err(|_| std::io::Error::other("original descriptor poisoned"))?
                .take()
                .ok_or_else(|| std::io::Error::other("original descriptor already delegated"))
        })
        .transpose()
}
/// A restored original does not inherit this ephemeral mailbox lane. Close its
/// queue and any unclaimed FD before the guest can accept a new restore lineage.
#[cfg(target_os = "linux")]
pub(crate) fn retire_for_restore() -> bool {
    let Some(original) = ORIGINAL.get() else {
        return false;
    };
    original
        .endpoint
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    original
        .descriptor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    true
}

/// Spawn the mailbox listener on a boot that asserts one. Called after PID-1
/// activation; a bind failure is logged and abandoned, never boot-fatal.
pub(crate) fn init_mailbox() {
    let selected = std::fs::read_to_string("/proc/cmdline").and_then(|cmdline| {
        let service = parse_mailbox_service_cmdline(&cmdline).map_err(std::io::Error::other)?;
        #[cfg(target_os = "linux")]
        if service == MailboxGuestService::ReliableV1 {
            let live = ORIGINAL
                .get()
                .and_then(|o| o.endpoint.lock().ok())
                .is_some_and(|slot| slot.is_some());
            if !live {
                return Err(std::io::Error::other("no verified original mailbox role"));
            }
            return Ok(service);
        }
        service
            .require_implemented()
            .map_err(std::io::Error::other)?;
        Ok(service)
    });
    let service = match selected {
        Ok(service) => service,
        Err(error) => {
            eprintln!("mvm-guest-agent: mailbox service selection refused: {error}");
            return;
        }
    };
    if service == MailboxGuestService::Disabled || unix_transport_selected() {
        return;
    }
    let _ =
        mvm_agentd::detached::spawn_named("mailbox-listener", move || {
            match bind_vsock_listener(MAILBOX_PORT) {
                #[cfg(target_os = "linux")]
                Ok(fd) if service == MailboxGuestService::ReliableV1 => {
                    use std::os::fd::{AsRawFd, OwnedFd};
                    let listener = unsafe { OwnedFd::from_raw_fd(fd) };
                    let Some(original) = ORIGINAL.get() else {
                        return;
                    };
                    while !SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
                        if let Some(fd) =
                            accept_vsock(listener.as_raw_fd(), "original mailbox role")
                        {
                            let original_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                            let Ok(mut guard) = original.endpoint.lock() else {
                                return;
                            };
                            let Some(endpoint) = guard.as_mut() else {
                                return;
                            };
                            match endpoint {
                                OriginalEndpoint::Deliver(endpoint) => {
                                    let _ = endpoint.receive_on_host_port(original_fd);
                                    let _ = endpoint.offer_to_workload();
                                }
                                OriginalEndpoint::Submit(endpoint) => {
                                    let _ = endpoint.forward_on_host_port(original_fd);
                                }
                            }
                        }
                    }
                }
                Ok(fd) => accept_loop(fd),
                Err(e) => eprintln!(
                    "mvm-guest-agent: mailbox listener bind failed (port {MAILBOX_PORT}): {e}"
                ),
            }
        });
}

/// The host re-dials an idle guest forever, so only the first few refusals
/// and then one in a hundred are logged.
fn logs_refusal(refused: u32) -> bool {
    refused < 3 || refused.is_multiple_of(100)
}

/// One host connection at a time, each answered from the outbox.
fn accept_loop(listener_fd: RawFd) {
    let mut refused = 0u32;
    while !SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
        let Some(cfd) = accept_vsock(listener_fd, "mailbox") else {
            continue;
        };
        // SAFETY: `cfd` is the just-accepted connection fd, owned here and
        // closed on drop.
        let mut stream = unsafe { std::fs::File::from_raw_fd(cfd) };
        // Hold an idle connection until a message is spooled, the host hangs
        // up, or the hold ends, so an idle guest is dialed once per hold.
        if !wait_for_outbox(
            Path::new(OUTBOX_PATH),
            MAILBOX_HOLD,
            std::time::Duration::from_millis(50),
            || peer_gone(cfd) || SHUTDOWN_REQUESTED.load(Ordering::Acquire),
        ) {
            continue;
        }
        let _ = bound_socket_io(cfd, MAILBOX_IO_TIMEOUT);
        if let Err(refusal) = forward_outbox(&mut stream, Path::new(OUTBOX_PATH)) {
            if logs_refusal(refused) {
                eprintln!("mvm-guest-agent: mailbox frame not delivered: {refusal}");
            }
            refused = refused.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_guest_logs_a_bounded_number_of_refusals() {
        assert_eq!((0..1000).filter(|&n| logs_refusal(n)).count(), 3 + 10 - 1);
    }

    #[test]
    fn only_the_exact_token_asserts_a_mailbox() {
        assert!(cmdline_asserts(
            "console=ttyS0 mvm.mailbox=1",
            MAILBOX_CMDLINE_TOKEN
        ));
        assert!(!cmdline_asserts("mvm.mailbox=0", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("xmvm.mailbox=1", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("console=ttyS0", MAILBOX_CMDLINE_TOKEN));
    }
}
