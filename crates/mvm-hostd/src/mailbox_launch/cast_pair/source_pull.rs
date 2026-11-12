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
use mvm_core::mailbox::{decode_envelope, frame::Refusal};
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
        let send_bytes = serde_json::to_vec(grants.send)?;
        let original = source_envelope(body, &send_bytes)?;
        let envelope = decode_envelope(original)?;
        let routed = self.route_reserved(credit, envelope, grants, &source, &dest)?;
        ensure!(original == routed.canonical, "noncanonical source envelope");
        routed.credit.admitted()?;
        Ok(routed)
    }
}

fn source_envelope<'a>(body: &'a [u8], expected_send: &[u8]) -> Result<&'a [u8]> {
    // Compare the length and the exact installed credential encoding before
    // decoding the envelope. Equivalent JSON must not change the peer bytes.
    let prefix = u32::try_from(expected_send.len())?.to_be_bytes();
    let rest = body
        .strip_prefix(&prefix[..])
        .and_then(|rest| rest.strip_prefix(expected_send));
    rest.filter(|env| !env.is_empty())
        .ok_or_else(|| anyhow::anyhow!("source Send framing differs from the enrolled credential"))
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
    fn original_pull_requires_byte_identical_credential_before_admission() {
        let cap = br#"{"ok":1}"#;
        let payload = b"\0env\xff";
        for candidate in [cap.as_slice(), br#"{ "ok":1 }"#, br#"{"ok":2}"#] {
            let mut body = (candidate.len() as u32).to_be_bytes().to_vec();
            body.extend_from_slice(candidate);
            body.extend_from_slice(payload);
            if candidate == cap {
                assert_eq!(source_envelope(&body, cap).unwrap(), payload);
            } else {
                assert!(source_envelope(&body, cap).is_err());
            }
        }
        assert!(source_envelope(&[0; 3], cap).is_err());
    }
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
