use mvm_contract::protocol::mailbox::{
    CausationId, ContentType, CorrelationId, MailboxMessageKind, MessageId, PrincipalId, local::*,
    local_service::MailboxLocalServiceGrant,
};
use mvm_core::mailbox::frame::{Refusal, local::*};

fn limits() -> mvm_contract::protocol::mailbox::local_service::MailboxLocalLimits {
    MailboxLocalServiceGrant::reliable_v1().limits
}

fn submit() -> LocalFrame {
    LocalFrame::Submit(Box::new(LocalSubmit {
        originating_binding: [1; 32],
        request_id: 1,
        kind: MailboxMessageKind::Call,
        recipient: PrincipalId::from_bytes([0; 32]),
        content_type: ContentType::parse("a/b", 1).unwrap(),
        expires_at_unix_ms: 1000,
        timeout_ms: 100,
        correlation: CorrelationId::from_bytes([0; 32]),
        causation: CausationId::from_bytes([0; 32]),
        reply_token: vec![],
        body: vec![0, 255, 0],
    }))
}

fn fixtures() -> Vec<(LocalFrame, LocalRole, LocalDirection)> {
    vec![
        (submit(), LocalRole::Submit, LocalDirection::GuestToHost),
        (
            LocalFrame::SubmitResult(LocalSubmitResult {
                request_id: 1,
                semantic_digest: [3; 32],
                disposition: LocalDisposition::AcceptedEphemeral,
                message_id: MessageId::from_bytes([2; 32]),
                correlation: CorrelationId::from_bytes([4; 32]),
                service_generation: [5; 32],
            }),
            LocalRole::Submit,
            LocalDirection::HostToGuest,
        ),
        (
            LocalFrame::Deliver(Box::new(LocalDelivery {
                delivery_sequence: 1,
                message_id: MessageId::from_bytes([2; 32]),
                correlation: CorrelationId::from_bytes([3; 32]),
                causation: CausationId::from_bytes([0; 32]),
                sender: PrincipalId::from_bytes([4; 32]),
                recipient: PrincipalId::from_bytes([5; 32]),
                kind: MailboxMessageKind::Call,
                content_type: ContentType::parse("a/b", 1).unwrap(),
                expires_at_unix_ms: 1000,
                reply_token: vec![7],
                body: vec![0, 255, 0],
            })),
            LocalRole::Deliver,
            LocalDirection::HostToGuest,
        ),
        (
            LocalFrame::DeliveryAck(LocalDeliveryAck {
                delivery_sequence: 1,
                message_id: MessageId::from_bytes([2; 32]),
                disposition: LocalInboxDisposition::Accepted,
            }),
            LocalRole::Deliver,
            LocalDirection::GuestToHost,
        ),
        (
            LocalFrame::ControlRequest(LocalControlRequest {
                control_id: 1,
                operation: LocalControlOperation::Query,
                target_request_id: 2,
            }),
            LocalRole::Control,
            LocalDirection::GuestToHost,
        ),
        (
            LocalFrame::ControlResult(LocalControlResult {
                control_id: 1,
                target_request_id: 2,
                disposition: LocalDisposition::Retired,
                message_id: MessageId::from_bytes([0; 32]),
                correlation: CorrelationId::from_bytes([0; 32]),
                service_generation: [5; 32],
            }),
            LocalRole::Control,
            LocalDirection::HostToGuest,
        ),
    ]
}

#[test]
fn fixed_control_vector_and_all_application_frames_are_exact() {
    let vectors: Vec<String> =
        serde_json::from_str(include_str!("fixtures/mailbox_local_frames.json")).unwrap();
    assert_eq!(vectors.len(), fixtures().len());
    for ((frame, role, direction), expected) in fixtures().into_iter().zip(vectors) {
        let bytes = encode_local_frame(&frame, role, direction, &limits()).unwrap();
        assert_eq!(hex::encode(&bytes), expected);
        assert_eq!(
            decode_local_frame(&bytes, role, direction, &limits()).unwrap(),
            frame
        );
        assert_eq!(
            encode_local_frame(
                &decode_local_frame(&bytes, role, direction, &limits()).unwrap(),
                role,
                direction,
                &limits()
            )
            .unwrap(),
            bytes
        );
        if matches!(frame, LocalFrame::ControlRequest(_)) {
            assert_eq!(
                hex::encode(bytes),
                "00000012050000000000000001010000000000000002"
            );
        }
    }
}

#[test]
fn exact_greeting_refuses_unknown_version_role_reserved_and_zero_identity() {
    let greeting = LocalGreeting {
        role: LocalRole::Submit,
        binding: [1; 32],
        generation: 1,
    };
    let bytes = encode_local_greeting(&greeting).unwrap();
    assert_eq!(&bytes[..12], b"MVMBX001\0\x01\x01\0");
    assert_eq!(decode_local_greeting(&bytes).unwrap(), greeting);
    assert!(verify_local_greeting_echo(&greeting, &bytes).is_ok());
    for (offset, value) in [(0, 0), (9, 2), (10, 0), (10, 4), (11, 1), (51, 0)] {
        let mut wrong = bytes;
        wrong[offset] = value;
        assert!(decode_local_greeting(&wrong).is_err(), "offset {offset}");
    }
    let mut wrong_binding = bytes;
    wrong_binding[12..44].fill(0);
    assert!(decode_local_greeting(&wrong_binding).is_err());
    let mut other_binding = bytes;
    other_binding[12] = 9;
    assert!(verify_local_greeting_echo(&greeting, &other_binding).is_err());
    let mut other_generation = bytes;
    other_generation[51] = 2;
    assert!(verify_local_greeting_echo(&greeting, &other_generation).is_err());
}

#[test]
fn truncated_trailing_unknown_and_wrong_role_frames_never_decode() {
    for (frame, role, direction) in fixtures() {
        let bytes = encode_local_frame(&frame, role, direction, &limits()).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_local_frame(&bytes[..end], role, direction, &limits()).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_local_frame(&trailing, role, direction, &limits()).is_err());
        let mut unknown = bytes.clone();
        unknown[4] = 255;
        assert!(decode_local_frame(&unknown, role, direction, &limits()).is_err());
        for other_role in [LocalRole::Submit, LocalRole::Deliver, LocalRole::Control] {
            if other_role != role && !matches!(frame, LocalFrame::DeliveryAck(_)) {
                assert!(encode_local_frame(&frame, other_role, direction, &limits()).is_err());
                assert!(decode_local_frame(&bytes, other_role, direction, &limits()).is_err());
            }
        }
    }
}

#[test]
fn external_lengths_are_checked_before_read_or_allocation() {
    assert!(checked_local_body_length(&[0; 4], LocalRole::Submit, &limits()).is_err());
    assert!(
        checked_local_body_length(&u32::MAX.to_be_bytes(), LocalRole::Submit, &limits()).is_err()
    );
    assert!(
        checked_local_body_length(&4097u32.to_be_bytes(), LocalRole::Control, &limits()).is_err()
    );
    assert_eq!(
        checked_local_body_length(&4096u32.to_be_bytes(), LocalRole::Control, &limits()).unwrap(),
        4096
    );
    let mut invalid = limits();
    invalid.max_frame_bytes = 0;
    assert!(checked_local_body_length(&1u32.to_be_bytes(), LocalRole::Submit, &invalid).is_err());
    let mut bytes = encode_local_frame(
        &submit(),
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits(),
    )
    .unwrap();
    bytes[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        decode_local_frame(
            &bytes,
            LocalRole::Submit,
            LocalDirection::GuestToHost,
            &limits()
        ),
        Err(Refusal::Oversized(_))
    ));
}

#[test]
fn immutable_request_digest_binds_all_bytes_and_length() {
    let bytes = encode_local_frame(
        &submit(),
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits(),
    )
    .unwrap();
    let digest = local_request_digest(&bytes, &limits()).unwrap();
    for offset in [12, 44, 52, 60, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        if let Ok(other) = local_request_digest(&changed, &limits()) {
            assert_ne!(digest, other);
        }
    }
    let mut longer = submit();
    if let LocalFrame::Submit(s) = &mut longer {
        s.body.push(0);
    }
    let longer = encode_local_frame(
        &longer,
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits(),
    )
    .unwrap();
    assert_ne!(digest, local_request_digest(&longer, &limits()).unwrap());
}

#[test]
fn invalid_ids_tokens_kinds_and_payload_limits_refuse() {
    for change in 0..7 {
        let mut f = submit();
        let LocalFrame::Submit(s) = &mut f else {
            unreachable!()
        };
        match change {
            0 => s.request_id = 0,
            1 => s.originating_binding = [0; 32],
            2 => s.timeout_ms = 0,
            3 => s.body.clear(),
            4 => s.body.resize(16385, 0),
            5 => s.reply_token.push(1),
            _ => s.correlation = CorrelationId::from_bytes([3; 32]),
        }
        assert!(
            encode_local_frame(
                &f,
                LocalRole::Submit,
                LocalDirection::GuestToHost,
                &limits()
            )
            .is_err(),
            "change {change}"
        );
    }
    let mut reply = submit();
    let LocalFrame::Submit(s) = &mut reply else {
        unreachable!()
    };
    s.kind = MailboxMessageKind::Reply;
    s.timeout_ms = 0;
    assert!(
        encode_local_frame(
            &reply,
            LocalRole::Submit,
            LocalDirection::GuestToHost,
            &limits()
        )
        .is_err()
    );
    let LocalFrame::Submit(s) = &mut reply else {
        unreachable!()
    };
    s.reply_token = vec![1];
    s.correlation = CorrelationId::from_bytes([2; 32]);
    s.causation = CausationId::from_bytes([3; 32]);
    assert!(
        encode_local_frame(
            &reply,
            LocalRole::Submit,
            LocalDirection::GuestToHost,
            &limits()
        )
        .is_ok()
    );
}

#[test]
fn receipt_carrier_preserves_canonical_bytes_and_requires_separate_verification() {
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, DeliveryId, DeliveryOutcome, DestinationReceipt, ExecutionEpoch,
        MailboxAddress, MailboxId, ProtocolVersion, SignatureAlgorithm, TenantId,
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let signed = mvm_core::mailbox::sign_receipt(
        DestinationReceipt {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            delivery_id: DeliveryId::from_bytes([1; 32]),
            message_id: MessageId::from_bytes([2; 32]),
            address: MailboxAddress {
                tenant: TenantId::from_bytes([3; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([4; 32]),
                mailbox: MailboxId::from_bytes([5; 32]),
                recipient: PrincipalId::from_bytes([6; 32]),
            },
            execution_epoch: ExecutionEpoch::new(1).unwrap(),
            outcome: DeliveryOutcome::AcceptedEphemeral,
            observed_at_unix_ms: 1000,
            ciphertext_commitment: [7; 32],
        },
        &key,
    )
    .unwrap();
    let frame = LocalFrame::DestinationReceipt(Box::new(LocalDestinationReceipt {
        request_id: 1,
        signed: signed.clone(),
    }));
    let bytes = encode_local_frame(
        &frame,
        LocalRole::Control,
        LocalDirection::HostToGuest,
        &limits(),
    )
    .unwrap();
    assert_eq!(bytes[4], 7);
    assert_eq!(&bytes[17..], serde_json::to_vec(&signed).unwrap());
    assert_eq!(
        decode_local_frame(
            &bytes,
            LocalRole::Control,
            LocalDirection::HostToGuest,
            &limits()
        )
        .unwrap(),
        frame
    );
    mvm_core::mailbox::verify_receipt(&signed, &key.verifying_key()).unwrap();
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
    assert!(mvm_core::mailbox::verify_receipt(&signed, &wrong.verifying_key()).is_err());
    let mut noncanonical = bytes.clone();
    noncanonical.push(b' ');
    noncanonical[..4].copy_from_slice(&(u32::try_from(bytes.len() - 3).unwrap()).to_be_bytes());
    noncanonical[13..17].copy_from_slice(&(u32::try_from(bytes.len() - 16).unwrap()).to_be_bytes());
    assert!(
        decode_local_frame(
            &noncanonical,
            LocalRole::Control,
            LocalDirection::HostToGuest,
            &limits()
        )
        .is_err()
    );
    let mut oversized = vec![0u8; 17 + 2049];
    oversized[..4].copy_from_slice(&2062u32.to_be_bytes());
    oversized[4] = 7;
    oversized[12] = 1;
    oversized[13..17].copy_from_slice(&2049u32.to_be_bytes());
    assert_eq!(
        decode_local_frame(
            &oversized,
            LocalRole::Control,
            LocalDirection::HostToGuest,
            &limits()
        ),
        Err(Refusal::Oversized(2048))
    );
}

#[test]
fn decoder_rejects_invalid_enums_nested_lengths_and_unbounded_names() {
    let bytes = encode_local_frame(
        &submit(),
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits(),
    )
    .unwrap();
    for (offset, value) in [(45, 0), (45, 4), (78, 0), (78, 128), (79, 255), (83, 0)] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        assert!(
            decode_local_frame(
                &bad,
                LocalRole::Submit,
                LocalDirection::GuestToHost,
                &limits()
            )
            .is_err(),
            "offset {offset}"
        );
    }
    for offset in [160, 164] {
        let mut bad = bytes.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode_local_frame(
                &bad,
                LocalRole::Submit,
                LocalDirection::GuestToHost,
                &limits()
            ),
            Err(Refusal::Oversized(_))
        ));
    }
    for (frame, role, direction) in fixtures() {
        let bytes = encode_local_frame(&frame, role, direction, &limits()).unwrap();
        let field = match frame {
            LocalFrame::SubmitResult(_) | LocalFrame::DeliveryAck(_) => Some(45),
            LocalFrame::ControlRequest(_) => Some(13),
            LocalFrame::ControlResult(_) => Some(21),
            _ => None,
        };
        if let Some(field) = field {
            for value in [0, 255] {
                let mut bad = bytes.clone();
                bad[field] = value;
                assert!(decode_local_frame(&bad, role, direction, &limits()).is_err());
            }
        }
    }
}

#[test]
fn full_body_bound_and_zero_fidelity_survive_without_debug_disclosure() {
    let mut frame = submit();
    let LocalFrame::Submit(s) = &mut frame else {
        unreachable!()
    };
    s.body = b"private-plaintext-sentinel".to_vec();
    s.body.resize(16384, 0);
    let bytes = encode_local_frame(
        &frame,
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits(),
    )
    .unwrap();
    let decoded = decode_local_frame(
        &bytes,
        LocalRole::Submit,
        LocalDirection::GuestToHost,
        &limits(),
    )
    .unwrap();
    assert_eq!(decoded, frame);
    assert!(!format!("{decoded:?}").contains("private-plaintext-sentinel"));
    assert!(!format!("{decoded:?}").contains("112, 114, 105, 118"));
}
