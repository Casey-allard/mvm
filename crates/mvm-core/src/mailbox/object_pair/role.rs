//! Host-attested, public role description for the enrolled workload. The guest
//! verifies it against its original boot file. It contains no private key.
use super::{MailboxReaderBootBinding, ObjectPairGrants};
use anyhow::{Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::protocol::mailbox::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectParticipantRole {
    Caller,
    Callee,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRoleV1 {
    pub role: ObjectParticipantRole,
    pub caller: MailboxReaderBootBinding,
    pub callee: MailboxReaderBootBinding,
    pub call: SignedMailboxCapability,
    pub reply: SignedMailboxCapability,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}
impl ObjectRoleV1 {
    pub fn outbound(&self) -> &SignedMailboxCapability {
        match self.role {
            ObjectParticipantRole::Caller => &self.call,
            ObjectParticipantRole::Callee => &self.reply,
        }
    }
    pub fn peer(&self) -> &MailboxReaderBootBinding {
        match self.role {
            ObjectParticipantRole::Caller => &self.callee,
            ObjectParticipantRole::Callee => &self.caller,
        }
    }
    pub fn local(&self) -> &MailboxReaderBootBinding {
        match self.role {
            ObjectParticipantRole::Caller => &self.caller,
            ObjectParticipantRole::Callee => &self.callee,
        }
    }
    fn check(&self, local: &MailboxReaderBootBinding, now: i64) -> Result<()> {
        ensure!(
            self.local() == local
                && self.caller.boot != self.callee.boot
                && self.caller.plan_nonce != self.callee.plan_nonce
                && self.caller.mailbox != self.callee.mailbox
                && self.caller.authority_key != self.callee.authority_key
                && local.outbound_journal_v1.is_none()
                && self.peer().outbound_journal_v1.is_none()
                && (self.not_before_unix_ms..self.expires_at_unix_ms).contains(&now),
            "role is not for this live original"
        );
        let digest = ObjectPairGrants {
            call: &self.call,
            reply: &self.reply,
        }
        .commitment(&self.caller.plan_nonce, &self.callee.plan_nonce)?;
        ensure!(
            local.durable_object_pair_sha256_v1 == Some(digest)
                && self.peer().durable_object_pair_sha256_v1 == Some(digest),
            "original signed pair differs"
        );
        let c = &self.call.grant;
        let r = &self.reply.grant;
        ensure!(
            c.address.tenant == r.address.tenant
                && c.address.authorization_domain == r.address.authorization_domain
                && c.subject == r.address.recipient
                && r.subject == c.address.recipient
                && c.subject != r.subject,
            "role credentials do not form a reciprocal pair"
        );
        for (g, boot, op, kind) in [
            (
                &self.call,
                &self.callee,
                MailboxOperation::Send,
                MailboxMessageKind::Call,
            ),
            (
                &self.reply,
                &self.caller,
                MailboxOperation::Reply,
                MailboxMessageKind::Reply,
            ),
        ] {
            super::verify_capability_signature(g, &VerifyingKey::from_bytes(&boot.authority_key)?)?;
            let g = &g.grant;
            ensure!(
                g.address.mailbox == boot.mailbox
                    && g.issuer.as_bytes() == &boot.authority_key
                    && g.minimum_execution_epoch == boot.execution_epoch
                    && g.maximum_execution_epoch == boot.execution_epoch
                    && g.operations == CapabilityOperations::from_operations(&[op])
                    && g.message_kinds == [kind]
                    && g.content_types == [ContentType::parse("application/spiralcore-object", 1)?]
                    && self.not_before_unix_ms >= g.not_before_unix_ms
                    && self.expires_at_unix_ms <= g.expires_at_unix_ms,
                "role exceeds original credential"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedObjectRoleV1 {
    pub role: ObjectRoleV1,
    pub signature: Vec<u8>,
}
fn bytes(body: &ObjectRoleV1) -> Result<Vec<u8>> {
    let mut out = b"mvm.mailbox.object-workload-role.v1\0".to_vec();
    out.extend(serde_jcs::to_vec(body)?);
    ensure!(
        out.len() <= 16 * 1024,
        "role exceeds public descriptor bound"
    );
    Ok(out)
}
impl SignedObjectRoleV1 {
    /// Local original authority attests both boots and the exact supplied grants.
    pub fn issue(role: ObjectRoleV1, key: &SigningKey, now: i64) -> Result<Self> {
        role.check(role.local(), now)?;
        ensure!(
            key.verifying_key().as_bytes() == &role.local().authority_key,
            "wrong role signer"
        );
        let signature = key.sign(&bytes(&role)?).to_bytes().to_vec();
        Ok(Self { role, signature })
    }
    pub fn verify(&self, local: &MailboxReaderBootBinding, now: i64) -> Result<&ObjectRoleV1> {
        let signature = Signature::from_slice(&self.signature)?;
        self.role.check(local, now)?;
        VerifyingKey::from_bytes(&local.authority_key)?.verify(&bytes(&self.role)?, &signature)?;
        Ok(&self.role)
    }
}
