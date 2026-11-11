#![cfg(feature = "protocol")]

use mvm_contract::protocol::mailbox::{
    ExecutionEpoch, MailboxGrant, MailboxId,
    local_service::{MailboxLocalServiceGrant, MailboxLocalServiceVersion},
};

#[test]
fn legacy_mailbox_grant_keeps_exact_published_json() {
    let original = concat!(
        "{\"mailbox\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],",
        "\"authority_key\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],\"epoch\":1}"
    );
    let grant: MailboxGrant = serde_json::from_str(original).expect("published legacy value");
    assert_eq!(grant.local_service, None);
    assert_eq!(serde_json::to_string(&grant).unwrap(), original);
}

#[test]
fn reliable_service_is_explicit_and_bounded_without_enabling_a_runtime() {
    let grant = MailboxGrant {
        mailbox: MailboxId::from_bytes([7; 32]),
        authority_key: [9; 32],
        epoch: ExecutionEpoch::new(1).unwrap(),
        local_service: Some(MailboxLocalServiceGrant::reliable_v1()),
    };
    let service = grant.local_service.unwrap();
    assert_eq!(service.version, MailboxLocalServiceVersion::ReliableV1);
    assert_eq!(service.limits.payload_bytes, 16 * 1024);
    assert_eq!(service.limits.spooled_requests, 256);
    assert_eq!(service.limits.retained_guest_bytes, 1024 * 1024);
    assert_eq!(service.limits.queued_messages, 8);
    assert_eq!(service.limits.active_calls, 4);
    assert_eq!(service.limits.max_frame_bytes, 65536);
    assert_eq!(service.limits.retained_host_bytes, 512 * 1024);
    assert_eq!(service.limits.max_connections, 3);
    service.validate().unwrap();
    let value = serde_json::to_value(grant).unwrap();
    assert_eq!(value["local_service"]["version"], 1);
    assert_eq!(
        serde_json::from_value::<MailboxGrant>(value).unwrap(),
        grant
    );
}

#[test]
fn unknown_versions_and_invalid_signed_limits_refuse_during_decode() {
    let original = serde_json::to_value(MailboxLocalServiceGrant::reliable_v1()).unwrap();
    let mut unknown = original.clone();
    unknown["version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<MailboxLocalServiceGrant>(unknown).is_err());
    for (field, invalid) in [
        ("payload_bytes", 0),
        ("payload_bytes", 16385),
        ("spooled_requests", 0),
        ("spooled_requests", 257),
        ("retained_guest_bytes", 0),
        ("retained_guest_bytes", 1048577),
        ("queued_messages", 0),
        ("queued_messages", 9),
        ("active_calls", 0),
        ("active_calls", 5),
        ("max_frame_bytes", 0),
        ("max_frame_bytes", 65537),
        ("retained_host_bytes", 0),
        ("retained_host_bytes", 524289),
        ("max_connections", 0),
        ("max_connections", 1),
        ("max_connections", 2),
        ("max_connections", 4),
    ] {
        let mut value = original.clone();
        value["limits"][field] = serde_json::json!(invalid);
        assert!(
            serde_json::from_value::<MailboxLocalServiceGrant>(value).is_err(),
            "{field}={invalid}"
        );
    }
    let mut unknown_field = original;
    unknown_field["unrecognized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<MailboxLocalServiceGrant>(unknown_field).is_err());
}

#[test]
fn inconsistent_frame_and_retention_budgets_refuse() {
    let original = serde_json::to_value(MailboxLocalServiceGrant::reliable_v1()).unwrap();
    for (field, invalid) in [
        ("max_frame_bytes", 16384),
        ("retained_guest_bytes", 16384),
        ("retained_host_bytes", 16384),
        ("queued_messages", 3),
    ] {
        let mut value = original.clone();
        value["limits"][field] = serde_json::json!(invalid);
        assert!(
            serde_json::from_value::<MailboxLocalServiceGrant>(value).is_err(),
            "{field}={invalid}"
        );
    }
}

#[test]
fn guest_cmdline_refuses_ambiguous_or_unknown_mailbox_modes() {
    use mvm_contract::protocol::mailbox::local_service::{
        MailboxGuestService, parse_mailbox_service_cmdline,
    };
    assert_eq!(
        parse_mailbox_service_cmdline("console=ttyS0").unwrap(),
        MailboxGuestService::Disabled
    );
    assert_eq!(
        parse_mailbox_service_cmdline("mvm.mailbox=1").unwrap(),
        MailboxGuestService::Legacy
    );
    assert_eq!(
        parse_mailbox_service_cmdline("mvm.mailbox=0").unwrap(),
        MailboxGuestService::Disabled
    );
    assert_eq!(
        parse_mailbox_service_cmdline("mvm.mailbox=1 mvm.mailbox.service=1").unwrap(),
        MailboxGuestService::ReliableV1
    );
    for input in [
        "mvm.mailbox=1 mvm.mailbox=1",
        "mvm.mailbox=1 mvm.mailbox=0",
        "mvm.mailbox.service=1",
        "mvm.mailbox=1 mvm.mailbox.service=1 mvm.mailbox.service=1",
        "mvm.mailbox=1 mvm.mailbox.service=2",
        "mvm.mailbox=1 mvm.mailbox.service=01",
        "mvm.mailbox=1 mvm.mailbox.service",
        "mvm.mailbox",
    ] {
        assert!(parse_mailbox_service_cmdline(input).is_err(), "{input}");
    }
    assert!(
        MailboxGuestService::ReliableV1
            .require_implemented()
            .is_err()
    );
    MailboxGuestService::Legacy.require_implemented().unwrap();
}
