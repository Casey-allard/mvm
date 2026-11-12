//! One admitted guest reader and one incoming sealed link share the original local journal.
use super::{WorkerLaunch, carrier};
use crate::mailbox_launch::{LAUNCH_LIMITS, object_pair::EndpointMaterial};
use crate::mailbox_service::{
    await_first_byte,
    durable::{GUEST_EXCHANGE_TIMEOUT, GuestDeadline},
    object_intent::OutboundObject,
    read_frame,
};
use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::mailbox::MAILBOX_PORT;
use mvm_core::mailbox::{
    frame::{MAX_VERDICT_BYTES, Refusal, decode_frame},
    journal::{FileJournalAnchor, JournalError, MailboxJournal},
    object_pair::role::ObjectParticipantRole,
    reader_wire::{
        ObjectSubmissionV1, ReaderRequest, ReaderResponse, read_request, write_response,
    },
};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct StopOnExit<'a>(&'a AtomicBool);

impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Local<'a> {
    owner: &'a WorkerLaunch,
    local: EndpointMaterial,
    journal: Mutex<MailboxJournal>,
    anchor: FileJournalAnchor,
    stop: AtomicBool,
}

fn refusal(e: &anyhow::Error) -> Refusal {
    if let Some(reason) = e.downcast_ref::<Refusal>() {
        return reason.clone();
    }
    if let Some(error) = e.downcast_ref::<JournalError>() {
        return match error {
            JournalError::Full => Refusal::StorageFull,
            JournalError::Busy
            | JournalError::MaintenancePending
            | JournalError::Storage(_)
            | JournalError::Uncertain => Refusal::Unavailable,
            JournalError::Mailbox(mvm_core::mailbox::MailboxError::Expired) => Refusal::Expired,
            _ => Refusal::NotAuthorized,
        };
    }
    if e.downcast_ref::<std::io::Error>().is_some() {
        return Refusal::Unavailable;
    }
    Refusal::NotAuthorized
}

impl Local<'_> {
    fn active(&self) -> bool {
        !self.stop.load(Ordering::Acquire) && self.owner.require_live().is_ok()
    }
    fn current(&self) -> Result<i64> {
        ensure!(self.active(), Refusal::Unavailable);
        Ok(self.owner.config.validate_current()?.now)
    }
    fn lock(&self) -> Result<MutexGuard<'_, MailboxJournal>> {
        self.journal.lock().map_err(|_| Refusal::Unavailable.into())
    }
    fn guest_request(
        &self,
        io: &mut (impl Read + Write),
        out: &carrier::Link,
        until: Instant,
    ) -> Result<ReaderResponse> {
        let request = read_request(io)?;
        let cfg = &self.owner.config;
        let now = self.current()?;
        let binding = &self.local.reader.boot;
        let pair = binding
            .durable_object_pair_sha256_v1
            .context("original pair missing")?;
        match request {
            ReaderRequest::GetObjectRoleV1 {
                pair: requested,
                boot,
            } if requested == pair && boot == binding.boot => Ok(ReaderResponse::ObjectRoleV1 {
                signed: Box::new(cfg.role.clone()),
            }),
            ReaderRequest::ReceiveObjectPairV1 { pair: requested } if requested == pair => {
                let challenge: [u8; 32] = rand::random();
                ensure!(challenge != [0; 32], "guest reader challenge unavailable");
                write_response(
                    io,
                    &ReaderResponse::Challenge {
                        enrollment: Box::new(self.local.reader.enrollment.clone()),
                        capability: Box::new(self.local.reader.capability.clone()),
                        challenge,
                    },
                )?;
                let ReaderRequest::Possession { signature } = read_request(io)? else {
                    return Err(Refusal::NotAuthorized.into());
                };
                self.current()?;
                cfg.lease_original(&mut *self.lock()?, &self.anchor, &challenge, &signature)
            }
            ReaderRequest::AuthorizeObjectCallV1 {
                pair: requested,
                lease,
                challenge,
            } if requested == pair && challenge != [0; 32] => Ok(ReaderResponse::ObjectRoleV1 {
                signed: Box::new(cfg.authorize_call(&*self.lock()?, &lease)?),
            }),
            ReaderRequest::Ack { signed } => {
                cfg.acknowledge_original(&mut *self.lock()?, &self.anchor, &signed)?;
                Ok(ReaderResponse::Acknowledged { ack: signed })
            }
            ReaderRequest::SubmitObjectV1 {
                pair: requested,
                submission,
            } if requested == pair => {
                let held = {
                    let journal = self.lock()?;
                    let original = match submission.as_ref() {
                        ObjectSubmissionV1::Reply { original_call, .. } => {
                            Some(journal.original_object_call(original_call, now)?)
                        }
                        _ => None,
                    };
                    OutboundObject {
                        pair,
                        boot: binding.boot,
                        submission: &submission,
                        original,
                    }
                    .retain(&self.local, &cfg.local_intents, &|| self.current())?
                };
                // Release the journal before waiting for the opposite endpoint.
                held.send(
                    &self.local,
                    until,
                    || self.current(),
                    |turn, end| carrier::submit(out, turn, end),
                )
            }
            _ => Err(Refusal::NotAuthorized.into()),
        }
    }

    fn incoming(&self, incoming: &carrier::Link) -> Result<()> {
        while self.active() {
            if !await_first_byte(&incoming.socket, Duration::from_millis(200), || {
                self.active()
            }) {
                continue;
            }
            incoming.record(Instant::now() + GUEST_EXCHANGE_TIMEOUT, |mut io| {
                let raw = read_frame(LAUNCH_LIMITS.max_frame_bytes, &mut io)?;
                let result = (|| -> Result<_> {
                    self.current()?;
                    let (cap, envelope) = decode_frame(&raw)?;
                    let receipt = self.owner.config.admit_original(
                        &mut *self.lock()?,
                        &self.anchor,
                        &cap,
                        &envelope,
                    )?;
                    self.current()?;
                    Ok(receipt)
                })();
                let verdict: carrier::Verdict = result.map_err(|e| refusal(&e));
                carrier::write_record(
                    &mut io,
                    &serde_json::to_vec(&verdict)?,
                    MAX_VERDICT_BYTES as usize,
                )
            })?;
        }
        Ok(())
    }

    fn guest(
        &self,
        out: &carrier::Link,
        #[cfg(feature = "durable-guest-io-witness")]
        meter: &crate::mailbox_service::durable::witness_io::Recorder,
    ) -> Result<()> {
        while self.active() {
            let stream = match crate::telemetry_collector::dial_route(
                &self.owner.config.route,
                MAILBOX_PORT,
            ) {
                Ok(stream) => stream,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            self.check_guest_peer(&stream)?;
            if !await_first_byte(&stream, Duration::from_secs(150), || self.active()) {
                continue;
            }
            let until = Instant::now() + GUEST_EXCHANGE_TIMEOUT;
            let mut io = GuestDeadline::new(stream, until)?;
            #[cfg(feature = "durable-guest-io-witness")]
            meter.observe(&mut io, |wrapped, _mark| self.answer(wrapped, out, until))?;
            #[cfg(not(feature = "durable-guest-io-witness"))]
            self.answer(&mut io, out, until)?;
        }
        Ok(())
    }
    fn check_guest_peer(&self, stream: &UnixStream) -> Result<()> {
        let cfg = &self.owner.config;
        let vmm = match cfg.role.role.role {
            ObjectParticipantRole::Caller => cfg.caller_vmm,
            ObjectParticipantRole::Callee => cfg.callee_vmm,
        };
        ensure!(
            mvm_vmm::host::uds_peer::connected_peer_pid(stream)? == i32::try_from(vmm.pid)?,
            "guest mux belongs to a different original VMM"
        );
        self.owner.require_live()
    }
    fn answer(
        &self,
        io: &mut (impl Read + Write),
        out: &carrier::Link,
        until: Instant,
    ) -> Result<()> {
        let response = self
            .guest_request(io, out, until)
            .and_then(|answer| {
                self.current()?;
                Ok(answer)
            })
            .unwrap_or_else(|error| ReaderResponse::Refused {
                reason: refusal(&error),
            });
        self.owner.require_live()?;
        // This operation's guest connection can disappear after a durable commit.
        // The next connection can reconcile the same operation and original seal.
        let _ = write_response(io, &response);
        Ok(())
    }
}

pub(super) fn run(owner: WorkerLaunch, [out, incoming]: [UnixStream; 2]) -> Result<()> {
    let _original_dirs = owner.config.hold_original_directories()?;
    let (journal, anchor) = owner.config.open_journal()?;
    let state = owner.config.validate_current()?.local_state;
    let out = carrier::Link::new(out, &state, true)?;
    let incoming = carrier::Link::new(incoming, &state, false)?;
    let local = Local {
        owner: &owner,
        local: owner.config.endpoint_material()?,
        journal: Mutex::new(journal),
        anchor,
        stop: AtomicBool::new(false),
    };
    #[cfg(feature = "durable-guest-io-witness")]
    let meter = {
        use crate::mailbox_service::durable::witness_io::Recorder;
        Recorder::selected_guest(&state.join("object-guest-stream-v1.counts"))?
    };
    std::thread::scope(|scope| -> Result<()> {
        let peer = std::thread::Builder::new()
            .name("original-object-inbound".into())
            .spawn_scoped(scope, || {
                let _stop = StopOnExit(&local.stop);
                local.incoming(&incoming)
            })?;
        let guest = (|| -> Result<()> {
            let _stop = StopOnExit(&local.stop);
            local.current()?;
            (&owner.channel).write_all(b"READY\n")?;
            local.guest(
                &out,
                #[cfg(feature = "durable-guest-io-witness")]
                &meter,
            )
        })();
        let _ = incoming.socket.shutdown(Shutdown::Both);
        let result = peer
            .join()
            .map_err(|_| anyhow::anyhow!("original peer listener panicked"))?;
        guest?;
        // An orderly owner stop may wake an idle reader with EOF.
        if owner.require_live().is_ok() {
            result?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unwinding_either_original_loop_wakes_its_sibling() {
        let stop = AtomicBool::new(false);
        let pair = UnixStream::pair().unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        std::thread::scope(|scope| {
            let wait = scope.spawn(|| {
                while !stop.load(Ordering::Acquire) {
                    assert!(Instant::now() < until);
                    await_first_byte(&pair.0, Duration::from_millis(50), || {
                        !stop.load(Ordering::Acquire)
                    });
                }
            });
            let fail = scope.spawn(|| {
                let _guard = StopOnExit(&stop);
                panic!("injected original worker failure");
            });
            assert!(fail.join().is_err());
            wait.join().unwrap();
        });
    }
}
