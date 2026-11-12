//! Pull one sealed submission from A's already provisioned mailbox helper.
//! Only the original helpers can interpret guest-local submissions or delivery.
use super::{
    AddressedCastGrants, CastCredit, MailboxWorkers, OpenContext, Result, ServingCastMapping,
    development::{DevelopmentDirection, DirectionTurn},
};
use crate::{
    broker::mailbox_workers::cast_credit::CAST_WORK_BYTES,
    mailbox_process::{installed_profile::pair_queue_limits, owned_wire::DeadlineStream},
};
use anyhow::ensure;
use mvm_core::mailbox::frame::{Refusal, decode_frame};
use std::{
    io::{Read, Write},
    net::Shutdown,
    time::{Duration, Instant},
};

/// A private poll on the original per-VM data socket. This byte grants no
/// authority and carries no plaintext, receipt, guest key, or message ID.
pub(crate) const PULL_ONE: u8 = 1;

impl ServingCastMapping {
    /// Return B's transient ingress verdict after relaying it back to A.
    /// On transport error A cannot retire its retained submission. Even a
    /// successful write to A does not prove guest readback or durable commit.
    pub fn forward_one_from_original_source(
        &self,
        workers: &MailboxWorkers,
        direction: &DevelopmentDirection,
        grants: AddressedCastGrants<'_>,
        deadline: Instant,
        mut current: impl FnMut() -> Result<(OpenContext, OpenContext)>,
    ) -> Result<Result<(), Refusal>> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
        let a = (&*self.source_vm, &self.source_owner);
        let b = (&*self.destination_vm, &self.destination_owner);
        let (source, dest) = current()?;
        DirectionTurn::from_serving(direction, self, workers, grants, &source, &dest)?;
        ensure!(
            self.channel.admits_workspace((2 * CAST_WORK_BYTES) as u64),
            "insufficient signed source and forwarding workspace"
        );
        let credit = workers.reserve_cast(a, b)?;
        let socket = mvm_agentd::vsock::connect_unix_before(&self.source_socket, deadline)?;
        workers.retain_original_source(a, b, &socket, direction.commitment())?;
        let (source, dest) = current()?;
        DirectionTurn::from_serving(direction, self, workers, grants, &source, &dest)?;
        let mut io = DeadlineStream::new(&socket, deadline);
        let bytes = pull_frame(&mut io, pair_queue_limits().max_frame_bytes)?;
        let routed = self.admit_source_frame(credit, grants, &bytes, current()?)?;
        drop(bytes);
        let verdict = routed.exchange_at_destination(direction, deadline, current)?;
        let reply = serde_json::to_vec(&verdict)?;
        ensure!(reply.len() <= 4096, "source ingress verdict exceeds limit");
        io.write_all(&reply)?;
        socket.shutdown(Shutdown::Write)?;
        drop(routed); // Retain the forwarding charge through the reply to A.
        Ok(verdict)
    }

    fn admit_source_frame<'a>(
        &'a self,
        credit: CastCredit<'a>,
        grants: AddressedCastGrants<'a>,
        body: &[u8],
        (source, dest): (OpenContext, OpenContext),
    ) -> Result<super::RoutedCast<'a>> {
        let (send, envelope) = decode_frame(body)?;
        ensure!(
            &send == grants.send,
            "source returned another Send credential"
        );
        let routed = self.route_reserved(credit, envelope, grants, &source, &dest)?;
        // decode_frame validated both subfields. Require the exact original
        // canonical envelope, including its outer route and ciphertext bytes.
        let n = u32::from_be_bytes(body[..4].try_into()?) as usize;
        ensure!(
            body[4 + n..] == routed.canonical,
            "noncanonical source envelope"
        );
        Ok(routed)
    }
}

fn pull_frame(stream: &mut (impl Read + Write), limit: usize) -> Result<Vec<u8>> {
    stream.write_all(&[PULL_ONE])?;
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix)?;
    let size = u32::from_be_bytes(prefix) as usize;
    ensure!(
        (1..=limit).contains(&size),
        "source frame outside admitted size"
    );
    let mut body = vec![0; size];
    stream.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[test]
    fn original_pull_is_binary_exact_and_checks_length_before_reading_body() {
        for (size, bytes, accepted) in [
            (0u32, &[][..], false),
            (5, &[0, 1, 255, 42, 0][..], true),
            (6, &[][..], false),
            (3, &[0, 1][..], false),
        ] {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            let result = std::thread::scope(|s| {
                let t = s.spawn(move || {
                    let mut trigger = [0];
                    a.read_exact(&mut trigger).unwrap();
                    assert_eq!(trigger, [PULL_ONE]);
                    a.write_all(&size.to_be_bytes()).unwrap();
                    a.write_all(bytes).unwrap();
                });
                let r = pull_frame(&mut b, 5);
                t.join().unwrap();
                r
            });
            if accepted {
                assert_eq!(result.unwrap(), bytes);
            } else {
                assert!(result.is_err());
            }
        }
    }
}
