use super::*;
use crate::audit::host_keypair;
use ed25519_dalek::SigningKey;
use mvm_core::mailbox::{
    reader::{mint_guest_receive_capability, sign_reader_possession, verify_reader_possession},
    sign_capability,
};
use mvm_core::plan::{sign_plan, test_support::PlanFixture};

fn public_grant(dir: &Path, mail: u8) -> MailboxGrant {
    let mailbox = MailboxId::from_bytes([mail; 32]);
    let epoch = ExecutionEpoch::new(1).unwrap();
    MailboxGrant {
        mailbox,
        epoch,
        authority_key: super::super::authority_key_for(dir, &mailbox, epoch)
            .unwrap()
            .to_bytes(),
        report: None,
        retention: Some(MailboxRetentionPolicy::new(60_000).unwrap()),
        incoming_journal_policy_sha256_v1: None,
        outbound_journal_v1: None,
        durable_object_pair_sha256_v1: None,
    }
}

fn flow(
    keys: &Path,
    to: &MailboxGrant,
    from: &MailboxGrant,
    kind: MailboxMessageKind,
    op: MailboxOperation,
    id: u8,
    now: i64,
) -> SignedMailboxCapability {
    let src = super::super::derived_keys(keys, &from.mailbox, from.epoch).unwrap();
    let dst = super::super::derived_keys(keys, &to.mailbox, to.epoch).unwrap();
    let receive = op == MailboxOperation::Receive;
    let address = MailboxAddress {
        tenant: TenantId::from_bytes([1; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
        mailbox: to.mailbox,
        recipient: PrincipalId::from_bytes(dst.sender.verifying_key().to_bytes()),
    };
    sign_capability(
        MailboxCapabilityGrant {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            capability_id: CapabilityId::from_bytes([id; 32]),
            revocation_id: RevocationId::from_bytes([id; 32]),
            issuer: PrincipalId::from_bytes(to.authority_key),
            subject: if receive {
                address.recipient
            } else {
                PrincipalId::from_bytes(src.sender.verifying_key().to_bytes())
            },
            address,
            operations: CapabilityOperations::from_operations(&[op]),
            message_kinds: vec![kind],
            content_types: vec![ContentType::parse("application/spiralcore-object", 1).unwrap()],
            minimum_execution_epoch: to.epoch,
            maximum_execution_epoch: to.epoch,
            policy_epoch: 1,
            not_before_unix_ms: now - 1000,
            expires_at_unix_ms: now + 120_000,
            max_payload_bytes: if kind == MailboxMessageKind::Call {
                4152
            } else {
                88
            },
            max_messages_per_minute: 60,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 8192,
            delegation_depth: 0,
        },
        &dst.authority,
    )
    .unwrap()
}

struct Originals {
    dir: tempfile::TempDir,
    a: MailboxGrant,
    b: MailboxGrant,
    credentials: ObjectPairCredentials,
    now: i64,
}
impl Originals {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        host_keypair::load_or_init_at(dir.path()).unwrap();
        let now = super::super::now_unix_ms();
        let a = public_grant(dir.path(), 31);
        let b = public_grant(dir.path(), 32);
        let credentials = ObjectPairCredentials {
            call: flow(
                dir.path(),
                &b,
                &a,
                MailboxMessageKind::Call,
                MailboxOperation::Send,
                7,
                now,
            ),
            reply: flow(
                dir.path(),
                &a,
                &b,
                MailboxMessageKind::Reply,
                MailboxOperation::Reply,
                8,
                now,
            ),
            receive_at_caller: flow(
                dir.path(),
                &a,
                &b,
                MailboxMessageKind::Reply,
                MailboxOperation::Receive,
                9,
                now,
            ),
            receive_at_callee: flow(
                dir.path(),
                &b,
                &a,
                MailboxMessageKind::Call,
                MailboxOperation::Receive,
                10,
                now,
            ),
        };
        Self {
            dir,
            a,
            b,
            credentials,
            now,
        }
    }
    fn prepare(&self, credentials: ObjectPairCredentials) -> Result<PreparedObjectPair> {
        PreparedObjectPair::prepare_at(
            self.dir.path(),
            &self.a,
            &Nonce::from_bytes([1; 16]),
            &self.b,
            &Nonce::from_bytes([2; 16]),
            credentials,
            self.now,
        )
    }
}

struct BootFixture {
    dir: tempfile::TempDir,
    signed: SignedExecutionPlan,
    boot: MailboxReaderBootBinding,
    posture: MailboxLaunchPosture,
    ack: SigningKey,
}
impl BootFixture {
    fn new(keys: &Path, grant: MailboxGrant, n: u8, now: i64) -> Self {
        let mut plan = PlanFixture::new()
            .workload(format!("vm-{n}"))
            .nonce([n; 16])
            .validity(
                chrono::DateTime::from_timestamp_millis(now - 5000).unwrap(),
                chrono::DateTime::from_timestamp_millis(now + 120000).unwrap(),
            )
            .mailbox(grant)
            .build();
        plan.image.name = format!("vm-{n}");
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let signer = host_keypair::load_or_init_at(keys).unwrap();
        let signed = sign_plan(&plan, &signer.signing, &host_keypair::host_signer_id());
        let ack = SigningKey::from_bytes(&[n + 31; 32]);
        let boot = MailboxReaderBootBinding::mint(
            &plan,
            SigningKey::from_bytes(&[n + 21; 32]).verifying_key(),
            ack.verifying_key().to_bytes(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        boot.persist(dir.path()).unwrap();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Prod);
        Self {
            dir,
            signed,
            boot,
            posture,
            ack,
        }
    }
    fn input(&self) -> BootInput<'_> {
        BootInput {
            plan: &self.signed,
            state: self.dir.path(),
            boot: &self.boot,
            posture: &self.posture,
            current_epoch: ExecutionEpoch::new(1).unwrap(),
        }
    }
}

#[test]
fn original_installation_rejects_an_unissued_or_swapped_return_reader() {
    let f = Originals::new();
    let mut wrong = f.credentials.clone();
    wrong.receive_at_caller = wrong.receive_at_callee.clone();
    assert!(f.prepare(wrong).is_err());
    let mut bad = f.credentials.clone();
    bad.reply.signature[0] ^= 1;
    assert!(f.prepare(bad).is_err());
    let mut too_large = f.credentials.clone();
    let aa = super::super::derived_keys(f.dir.path(), &f.a.mailbox, f.a.epoch).unwrap();
    too_large.receive_at_caller.grant.max_payload_bytes += 1;
    too_large.receive_at_caller =
        sign_capability(too_large.receive_at_caller.grant, &aa.authority).unwrap();
    assert!(f.prepare(too_large).is_err());
    let p = f.prepare(f.credentials.clone()).unwrap();
    let (a, b) = p.selected_grants();
    assert!(a.durable_object_pair_sha256_v1.is_some());
    assert_eq!(
        a.durable_object_pair_sha256_v1,
        b.durable_object_pair_sha256_v1
    );
    assert_eq!(f.a.durable_object_pair_sha256_v1, None);
    assert!(!f.dir.path().join(super::super::ENCRYPTION_ROOT).exists());
}

#[test]
fn independent_direction_keys_and_original_reader_possession_survive_restart() {
    let f = Originals::new();
    let p = f.prepare(f.credentials.clone()).unwrap();
    let (ag, bg) = p.selected_grants();
    let a = BootFixture::new(f.dir.path(), ag, 1, f.now);
    let b = BootFixture::new(f.dir.path(), bg, 2, f.now);
    let auth = super::super::derived_keys(f.dir.path(), &ag.mailbox, ag.epoch)
        .unwrap()
        .authority;
    assert!(
        mint_guest_receive_capability(
            &ag,
            &a.boot,
            &f.credentials.reply,
            f.credentials.reply.grant.address,
            &auth
        )
        .is_err(),
        "canonical own-mailbox mint must refuse Reply as a Send substitute"
    );
    let bind = || p.bind_at(f.dir.path(), a.input(), b.input(), f.now);
    assert!(
        bind().is_err(),
        "missing KEK cannot silently create a different DEK"
    );
    let root = f.dir.path().join(super::super::ENCRYPTION_ROOT);
    Key::load_or_create(&root).unwrap();
    let first = bind().unwrap();
    assert_eq!(
        first.caller.reader.capability,
        f.credentials.receive_at_caller
    );
    assert_eq!(
        first.callee.reader.capability,
        f.credentials.receive_at_callee
    );
    for (original, peer) in [
        (&first.caller, &first.callee),
        (&first.callee, &first.caller),
    ] {
        assert!(original.outbound_key.expose_bytes() == peer.inbound_key.expose_bytes());
        assert!(original.inbound_key.expose_bytes() != original.outbound_key.expose_bytes());
    }
    for (role, material) in [(&a, &first.caller), (&b, &first.callee)] {
        let challenge = [81u8; 32];
        let proof =
            sign_reader_possession(&material.reader.enrollment, &challenge, &role.ack).unwrap();
        verify_reader_possession(
            &material.reader.enrollment,
            &challenge,
            &proof,
            &role.ack.verifying_key(),
        )
        .unwrap();
    }
    let second = bind().unwrap();
    assert_eq!(
        first.caller.reader.enrollment,
        second.caller.reader.enrollment
    );
    assert_eq!(
        first.callee.reader.enrollment,
        second.callee.reader.enrollment
    );
    assert!(first.caller.outbound_key.expose_bytes() == second.callee.inbound_key.expose_bytes());
    let revoke = revocations_path(b.dir.path());
    std::fs::write(
        &revoke,
        serde_json::to_vec(&[f.credentials.receive_at_callee.grant.revocation_id]).unwrap(),
    )
    .unwrap();
    assert!(bind().is_err());
    std::fs::remove_file(&revoke).unwrap();
    std::fs::write(&root, [66u8; 32]).unwrap();
    assert!(
        bind().is_err(),
        "changed retained directional keys must refuse"
    );
}
