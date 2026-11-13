//! Authenticated local inventory of a funded original audit file.
use super::{audit_signer::{AuditInventory, SignedAuditInventory}, signed_config};
use anyhow::{Result, ensure};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

const DOMAIN: &[u8] = b"mvm.audit.original-file.v1\0";

pub fn sign(value: &AuditInventory, signer: &SigningKey) -> Result<SignedAuditInventory> {
    let mut payload = DOMAIN.to_vec();
    payload.extend_from_slice(&serde_jcs::to_vec(value)?);
    let key = signer.verifying_key();
    Ok(SignedAuditInventory {
        key: key.to_bytes(),
        envelope: signed_config::wrap_payload(&payload,crate::security::SIG_ALG_ED25519,
            signed_config::key_id_for(&key), &signer.sign(&payload).to_bytes()),
    })
}

pub fn verify(signed: &SignedAuditInventory, enrolled: &[u8;32]) -> Result<AuditInventory> {
    ensure!(&signed.key == enrolled, "original audit signer changed");
    let key = VerifyingKey::from_bytes(enrolled)?;
    let payload = signed_config::verify_envelope(&signed.envelope, &key)?;
    let body = payload.strip_prefix(DOMAIN).ok_or_else(|| anyhow::anyhow!("wrong audit inventory domain"))?;
    Ok(serde_json::from_slice(body)?)
}
