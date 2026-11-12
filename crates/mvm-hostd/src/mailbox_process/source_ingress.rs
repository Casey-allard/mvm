//! Original A helper. Its original coordinator reserves generation workspace
//! before authorizing a pull on this authenticated per-VM connection.
use super::{
    destination_ingress::{LiveIo, bind, bound_route, fence, next_original},
    owned::BoundCastEndpoint,
    owned_wire::{DeadlineStream, OwnedStatusV1, write_status},
};
use crate::{
    mailbox_launch::cast_pair::development::{
        EndpointRole, InstalledDirection, destination::DestinationRole,
    },
    mailbox_service::{
        GuestSealer,
        guest_io::{GuestStreamCounts, Measured},
    },
};
use mvm_contract::protocol::mailbox::{
    local::{LocalDirection, LocalDisposition, LocalFrame, LocalGreeting, LocalRole},
    local_service::MailboxLocalLimits,
};
use mvm_core::mailbox::frame::{self, cast::source::SourceCastSlot, local::*};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

use crate::mailbox_launch::cast_pair::source_pull::PULL_ONE;
const TIMEOUT: Duration = Duration::from_secs(5);
// Minted only after a pull has arrived on the authenticated original parent's
// connection. The coordinator keeps the real shared-ledger charge until it
// collects this child, including if the connection resets after one byte.
struct OriginalPull;

fn read_submit(
    guest: &mut (impl Read + Write),
    hello: &LocalGreeting,
    limits: &MailboxLocalLimits,
    current: impl Fn() -> io::Result<()>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    current()?;
    let greeting = encode_local_greeting(hello).map_err(io::Error::other)?;
    guest.write_all(&greeting)?;
    guest.flush()?;
    let mut echo = [0; LOCAL_GREETING_BYTES];
    guest.read_exact(&mut echo)?;
    verify_local_greeting_echo(hello, &echo).map_err(io::Error::other)?;
    current()?;
    let mut size = [0; 4];
    guest.read_exact(&mut size)?;
    let n =
        checked_local_body_length(&size, LocalRole::Submit, limits).map_err(io::Error::other)?;
    let mut bytes = Zeroizing::new(vec![0; 4 + n]);
    bytes[..4].copy_from_slice(&size);
    guest.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn exchange<C>(
    peer: &mut (impl Read + Write),
    guest: &mut (impl Read + Write),
    role: &DestinationRole,
    key: &InstalledDirection,
    sealer: &mut GuestSealer,
    slot: &mut SourceCastSlot<C>,
    limits: &MailboxLocalLimits,
    current: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let sample = || {
        current()?;
        role.policies(crate::mailbox_launch::now_unix_ms())
            .map_err(io::Error::other)
    };
    let bytes = read_submit(guest, &role.direction.source_greeting(), limits, || {
        sample().map(|_| ())
    })?;
    let (src, dst) = sample()?;
    let mut lane = sealer
        .enrolled_addressed_source(role.source_for(key), slot)
        .map_err(io::Error::other)?;
    let env = lane.prepare(&bytes, &src, &dst).map_err(io::Error::other)?;
    let frame = frame::encode_frame(role.grants().send, env).map_err(io::Error::other)?;
    if frame.len() > super::installed_profile::PAIR_FRAME_BYTES {
        return Err(io::Error::other(
            "sealed source contribution exceeds installed limit",
        ));
    }
    sample()?;
    // EOF without a complete verdict is deliberately nonterminal. Dropping a
    // wire turn leaves the generation's original request, sequence and envelope.
    let verdict = frame::strict_peer_verdict(peer, &frame)?;
    sample()?;
    let disposition = match verdict {
        Ok(()) => LocalDisposition::AcceptedEphemeral,
        Err(frame::Refusal::QueueFull(_)) => LocalDisposition::Full,
        Err(_) => LocalDisposition::Unavailable,
    };
    let result = lane
        .record_peer_disposition(&bytes, disposition)
        .map_err(io::Error::other)?;
    let reply = encode_local_frame(
        &LocalFrame::SubmitResult(result),
        LocalRole::Submit,
        LocalDirection::HostToGuest,
        limits,
    )
    .map_err(io::Error::other)?;
    guest.write_all(&reply)?;
    guest.flush()
}

pub(super) fn run(
    original: BoundCastEndpoint<'_>,
    mut role: DestinationRole,
    control: &UnixStream,
    parent: u32,
    deadline: Instant,
) -> io::Result<GuestStreamCounts> {
    fence(control, parent)?;
    let listener = bind(&original.config.socket)?;
    let key = original
        .direction
        .installed(&role.direction, EndpointRole::Source, &original.owner)
        .map_err(io::Error::other)?;
    let limits = role
        .channel
        .narrow_guest_limits(
            original
                .config
                .grant
                .local_service
                .ok_or_else(|| io::Error::other("missing original source limits"))?
                .limits,
        )
        .map_err(io::Error::other)?;
    role.policies(crate::mailbox_launch::now_unix_ms())
        .map_err(io::Error::other)?;
    write_status(
        control,
        &OwnedStatusV1::ReadyCastSourceV1 {
            owner: original.owner.clone(),
            direction_commitment: role.direction.commitment(),
        },
        deadline,
    )?;
    let mut counts = GuestStreamCounts::default();
    let mut sealer = original.config.keys.trust().1;
    let mut slot = None;
    while let Some(incoming) = next_original(control, parent, &listener)? {
        let until = Instant::now() + TIMEOUT;
        let mut peer = LiveIo {
            io: DeadlineStream::new(&incoming, until),
            ctrl: control,
            parent,
        };
        let mut trigger = [0];
        if peer.read_exact(&mut trigger).is_err() || trigger != [PULL_ONE] {
            continue;
        }
        fence(control, parent)?;
        if role.policies(crate::mailbox_launch::now_unix_ms()).is_err() {
            continue;
        }
        let held = slot.get_or_insert_with(|| {
            SourceCastSlot::new(
                OriginalPull,
                crate::broker::mailbox_workers::cast_credit::CAST_WORK_BYTES,
            )
        });
        counts.dial();
        let stream = match bound_route(&original.config.route, until) {
            Ok(s) => s,
            Err(_) => {
                counts.failed_dial();
                continue;
            }
        };
        let mut guest = Measured::new(
            LiveIo {
                io: DeadlineStream::new(&stream, until),
                ctrl: control,
                parent,
            },
            &mut counts,
        );
        // A failed turn closes its two streams. Keep its original state for
        // the next authenticated pull; parent death is observed by next_original.
        let _ = exchange(
            &mut peer,
            &mut guest,
            &role,
            key,
            &mut sealer,
            held,
            &limits,
            || fence(control, parent),
        );
    }
    Ok(counts)
}

#[cfg(test)]
pub(crate) fn qualify(
    role: &DestinationRole,
    key: &InstalledDirection,
    keys: &crate::mailbox_launch::DerivedMailboxKeys,
    original: &[u8],
    limits: MailboxLocalLimits,
) -> mvm_contract::protocol::mailbox::MailboxEnvelope {
    use super::destination_ingress::test_meter::{Meter, thread_cpu};
    use mvm_core::mailbox::frame::submit::PreparedSubmit;
    use std::net::Shutdown;
    let mut slot = SourceCastSlot::new(
        (),
        crate::broker::mailbox_workers::cast_credit::CAST_WORK_BYTES,
    );
    let mut sealer = keys.trust().1;
    let mut prior: Option<Vec<u8>> = None;
    for acknowledge in [false, true] {
        let (guest, helper_guest) = UnixStream::pair().unwrap();
        let (relay, helper_relay) = UnixStream::pair().unwrap();
        for io in [&guest, &helper_guest, &relay, &helper_relay] {
            io.set_read_timeout(Some(TIMEOUT)).unwrap();
            io.set_write_timeout(Some(TIMEOUT)).unwrap();
        }
        let meter = |io| Meter {
            io,
            read: 0,
            written: 0,
        };
        let mut guest = meter(guest);
        let mut relay = meter(relay);
        let mut helper_guest = meter(helper_guest);
        let mut helper_relay = meter(helper_relay);
        let submitted = PreparedSubmit::from_claim(original.to_vec(), limits).unwrap();
        let began = Instant::now();
        let frame = std::thread::scope(|s| {
            let client = s.spawn(move || {
                let cpu = thread_cpu();
                let result = submitted.forward_on(
                    &mut guest,
                    &role.direction.source_greeting(),
                    role.direction.sender_boot().as_bytes(),
                    |bytes, receipt| {
                        assert_eq!(bytes, original);
                        assert_ne!(receipt.message_id.as_bytes(), &[0; 32]);
                        Ok(())
                    },
                );
                (result, thread_cpu() - cpu, guest.read, guest.written)
            });
            let router = s.spawn(move || {
                let cpu = thread_cpu();
                let mut header = [0; 4];
                relay.read_exact(&mut header).unwrap();
                let n = u32::from_be_bytes(header) as usize;
                assert!(n > 0 && n <= super::installed_profile::PAIR_FRAME_BYTES);
                let mut frame = vec![0; n];
                relay.read_exact(&mut frame).unwrap();
                if acknowledge {
                    serde_json::to_writer(&mut relay, &Result::<(), frame::Refusal>::Ok(()))
                        .unwrap();
                }
                relay.io.shutdown(Shutdown::Write).unwrap();
                (frame, thread_cpu() - cpu, relay.read, relay.written)
            });
            let cpu = thread_cpu();
            let observed = exchange(
                &mut helper_relay,
                &mut helper_guest,
                role,
                key,
                &mut sealer,
                &mut slot,
                &limits,
                || Ok(()),
            );
            let helper_cpu = thread_cpu() - cpu;
            assert_eq!(observed.is_ok(), acknowledge);
            helper_guest.io.shutdown(Shutdown::Write).unwrap();
            let (result, guest_cpu, g_rx, g_tx) = client.join().unwrap();
            let (frame, relay_cpu, r_rx, r_tx) = router.join().unwrap();
            assert_eq!(result.is_ok(), acknowledge);
            if let Ok(d) = result {
                assert_eq!(d, LocalDisposition::AcceptedEphemeral);
            }
            assert_eq!((r_rx, r_tx), (helper_relay.written, helper_relay.read));
            assert_eq!((g_rx, g_tx), (helper_guest.written, helper_guest.read));
            eprintln!(
                "original_source_turn accepted={acknowledge} helper_to_relay={r_rx} relay_to_helper={r_tx} helper_to_guest={g_rx} guest_to_helper={g_tx} elapsed_ns={} helper_cpu_ns={helper_cpu} guest_cpu_ns={guest_cpu} relay_cpu_ns={relay_cpu}",
                began.elapsed().as_nanos()
            );
            frame
        });
        if let Some(previous) = prior.replace(frame.clone()) {
            assert_eq!(previous, frame);
        }
    }
    let (proof, envelope) = frame::decode_frame(&prior.unwrap()).unwrap();
    assert_eq!(&proof, role.grants().send);
    envelope
}
