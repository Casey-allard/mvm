#![cfg(unix)]

use mvm_contract::protocol::mailbox::{
    CausationId, ContentType, CorrelationId, MailboxMessageKind, MessageId, PrincipalId, local::*,
    local_service::MailboxLocalServiceGrant,
};
use mvm_core::mailbox::frame::{
    local::*,
    submit::{PreparedSubmit, reconciles_published_submit},
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn greeting() -> LocalGreeting {
    LocalGreeting {
        role: LocalRole::Submit,
        binding: [1; 32],
        generation: 42,
    }
}

fn request() -> LocalSubmit {
    LocalSubmit {
        originating_binding: [1; 32],
        request_id: 17,
        kind: MailboxMessageKind::Cast,
        recipient: PrincipalId::from_bytes([2; 32]),
        content_type: ContentType::parse("a/b", 1).unwrap(),
        expires_at_unix_ms: 2500,
        timeout_ms: 0,
        correlation: CorrelationId::from_bytes([0; 32]),
        causation: CausationId::from_bytes([0; 32]),
        reply_token: Vec::new(),
        body: vec![0, 255, 0],
    }
}

#[test]
fn lost_or_refused_verdict_preserves_exact_request_until_original_acceptance() {
    let limits = MailboxLocalServiceGrant::reliable_v1().limits;
    let encoded = encode_local_frame(
        &LocalFrame::Submit(Box::new(request())),
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits,
    )
    .unwrap();
    let digest = local_request_digest(&encoded, &limits).unwrap();
    let pending = PreparedSubmit::from_claim(encoded.clone(), limits).unwrap();
    let mut published = 0;
    let mut received_by_host = 0usize;
    let mut written_by_host = 0usize;
    let started = std::time::Instant::now();
    for attempt in 0..6 {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        let expected = encoded.clone();
        let peer = std::thread::spawn(move || {
            let hello = encode_local_greeting(&greeting()).unwrap();
            host.write_all(&hello).unwrap();
            let mut echo = [0; LOCAL_GREETING_BYTES];
            host.read_exact(&mut echo).unwrap();
            assert_eq!(echo, hello);
            let mut actual = vec![0; expected.len()];
            host.read_exact(&mut actual).unwrap();
            assert_eq!(actual, expected);
            let from_guest = echo.len() + actual.len();
            if attempt == 0 {
                return (from_guest, hello.len());
            }
            let disposition = if attempt == 1 {
                LocalDisposition::Full
            } else {
                LocalDisposition::DuplicateEphemeral
            };
            let result = LocalSubmitResult {
                request_id: 17,
                disposition,
                semantic_digest: if attempt == 2 { [8; 32] } else { digest },
                message_id: MessageId::from_bytes(if attempt == 1 { [0; 32] } else { [4; 32] }),
                correlation: CorrelationId::from_bytes([0; 32]),
                service_generation: if attempt == 3 { [7; 32] } else { [3; 32] },
            };
            let frame = encode_local_frame(
                &LocalFrame::SubmitResult(result),
                LocalRole::Submit,
                LocalDirection::HostToGuest,
                &limits,
            )
            .unwrap();
            host.write_all(&frame).unwrap();
            (from_guest, hello.len() + frame.len())
        });
        let outcome = pending.forward_on(&mut guest, &greeting(), &[3; 32], |claim, result| {
            assert_eq!(claim, encoded);
            assert_eq!(result.disposition, LocalDisposition::DuplicateEphemeral);
            if attempt == 4 {
                return Err(std::io::Error::other("injected local publication failure"));
            }
            published += 1;
            Ok(())
        });
        let (inbound, outbound) = peer.join().unwrap();
        received_by_host += inbound;
        written_by_host += outbound;
        match attempt {
            1 => assert_eq!(outcome.unwrap(), LocalDisposition::Full),
            5 => assert_eq!(outcome.unwrap(), LocalDisposition::DuplicateEphemeral),
            _ => assert!(outcome.is_err()),
        }
    }
    assert_eq!(published, 1);
    println!(
        "submit_retry attempts=6 payload_bytes=3 guest_to_host={received_by_host} host_to_guest={written_by_host} exchange_ns={}",
        started.elapsed().as_nanos()
    );
}

/// Read and write halves are independent, as they are on an admitted stream.
struct Fixture {
    input: std::io::Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Read for Fixture {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}
impl Write for Fixture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn fixture(hello: LocalGreeting, reply: &[u8]) -> Fixture {
    let mut input = encode_local_greeting(&hello).unwrap().to_vec();
    input.extend_from_slice(reply);
    Fixture {
        input: std::io::Cursor::new(input),
        output: Vec::new(),
    }
}
fn prepare(s: LocalSubmit) -> (PreparedSubmit, [u8; 32]) {
    let limits = MailboxLocalServiceGrant::reliable_v1().limits;
    let bytes = encode_local_frame(
        &LocalFrame::Submit(Box::new(s)),
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits,
    )
    .unwrap();
    let digest = local_request_digest(&bytes, &limits).unwrap();
    (PreparedSubmit::from_claim(bytes, limits).unwrap(), digest)
}

#[test]
fn wrong_role_binding_or_connection_generation_emits_no_claim() {
    let (pending, _) = prepare(request());
    for bad in [
        LocalGreeting {
            role: LocalRole::Control,
            ..greeting()
        },
        LocalGreeting {
            generation: 43,
            ..greeting()
        },
        LocalGreeting {
            binding: [5; 32],
            ..greeting()
        },
    ] {
        let mut stream = fixture(bad, &[]);
        assert!(
            pending
                .forward_on(&mut stream, &greeting(), &[3; 32], |_, _| panic!())
                .is_err()
        );
        assert!(stream.output.is_empty());
    }
}

#[test]
fn oversized_or_incomplete_response_never_retires() {
    let (pending, _) = prepare(request());
    for reply in [
        &u32::MAX.to_be_bytes()[..],
        &[0, 0, 0, 12, 2][..],
        &[0, 0][..],
        &[0; 4][..],
    ] {
        assert!(
            pending
                .forward_on(
                    &mut fixture(greeting(), reply),
                    &greeting(),
                    &[3; 32],
                    |_, _| panic!()
                )
                .is_err()
        );
    }
}

#[test]
fn positive_results_bind_request_id_and_kind_specific_correlation() {
    use MailboxMessageKind::*;
    for (kind, answer, request_id, accepted) in [
        (Cast, 0, 17, true),
        (Cast, 1, 17, false),
        (Call, 0, 17, false),
        (Call, 1, 17, true),
        (Reply, 2, 17, true),
        (Reply, 1, 17, false),
        (Cast, 0, 18, false),
    ] {
        let mut submit = request();
        submit.kind = kind;
        match kind {
            Call => submit.timeout_ms = 100,
            Reply => {
                submit.correlation = CorrelationId::from_bytes([2; 32]);
                submit.causation = CausationId::from_bytes([1; 32]);
                submit.reply_token.push(7);
            }
            Cast => (),
        }
        let (pending, digest) = prepare(submit);
        let result = LocalSubmitResult {
            request_id,
            disposition: LocalDisposition::AcceptedEphemeral,
            semantic_digest: digest,
            message_id: MessageId::from_bytes([4; 32]),
            correlation: CorrelationId::from_bytes([answer; 32]),
            service_generation: [3; 32],
        };
        let reply = encode_local_frame(
            &LocalFrame::SubmitResult(result),
            LocalRole::Submit,
            LocalDirection::HostToGuest,
            &MailboxLocalServiceGrant::reliable_v1().limits,
        )
        .unwrap();
        let mut published = false;
        let outcome = pending.forward_on(
            &mut fixture(greeting(), &reply),
            &greeting(),
            &[3; 32],
            |_, _| {
                published = true;
                Ok(())
            },
        );
        assert_eq!(outcome.is_ok(), accepted);
        assert_eq!(published, accepted);
    }
}

#[test]
fn publication_survives_unlink_failure_and_rejects_changed_message_identity() {
    let (pending, digest) = prepare(request());
    let limits = MailboxLocalServiceGrant::reliable_v1().limits;
    let mut stored = None;
    let mut retired = false;
    for (step, id) in [4, 5, 4].into_iter().enumerate() {
        let verdict = LocalSubmitResult {
            request_id: 17,
            disposition: if step == 0 {
                LocalDisposition::AcceptedEphemeral
            } else {
                LocalDisposition::DuplicateEphemeral
            },
            semantic_digest: digest,
            message_id: MessageId::from_bytes([id; 32]),
            correlation: CorrelationId::from_bytes([0; 32]),
            service_generation: [3; 32],
        };
        let bytes = encode_local_frame(
            &LocalFrame::SubmitResult(verdict),
            LocalRole::Submit,
            LocalDirection::HostToGuest,
            &limits,
        )
        .unwrap();
        let result = pending.forward_on(
            &mut fixture(greeting(), &bytes),
            &greeting(),
            &[3; 32],
            |_, result| {
                if let Some(first) = stored.as_ref() {
                    if !reconciles_published_submit(first, result) {
                        return Err(std::io::Error::other("conflicting retained result"));
                    }
                    assert!(!reconciles_published_submit(result, first));
                } else {
                    stored = Some(result.clone());
                    return Err(std::io::Error::other(
                        "injected unlink failure after local publication",
                    ));
                }
                retired = true;
                Ok(())
            },
        );
        assert_eq!(retired, step == 2);
        assert_eq!(result.is_ok(), step == 2);
    }
}

#[test]
fn revoked_submit_after_greeting_keeps_claim_bytes_off_stream() {
    use std::cell::Cell;
    let limits = MailboxLocalServiceGrant::reliable_v1().limits;
    let original = encode_local_frame(
        &LocalFrame::Submit(Box::new(request())),
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits,
    )
    .unwrap();
    let pending = PreparedSubmit::from_claim(original, limits).unwrap();
    let (mut host, mut guest) = UnixStream::pair().unwrap();
    let hello = encode_local_greeting(&greeting()).unwrap();
    host.write_all(&hello).unwrap();
    let n = Cell::new(0);
    let err = pending
        .forward_on_current(
            &mut guest,
            &greeting(),
            &[3; 32],
            || {
                n.set(n.get() + 1);
                if n.get() == 1 {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "original grant expired",
                    ))
                }
            },
            |_, _| panic!("must retain the original claim"),
        )
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    drop(guest);
    let mut got = Vec::new();
    host.read_to_end(&mut got).unwrap();
    assert_eq!(got, hello, "only the greeting echo was authorized");
}
