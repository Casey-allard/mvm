//! Sender-local retry identities and the original guest's settlement statement.
//! Destination delivery still uses the canonical mailbox envelope and V2 receipt.
use super::{
    frame::Refusal, outbound::journal_direction_commitment, reader::MailboxReaderBootBinding,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{MessageId, SignedDestinationReceipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An ordinal is allocated in one originally admitted sender boot and direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderOrdinalV1 {
    pub direction: [u8; 32],
    pub ordinal: u64,
}

impl SenderOrdinalV1 {
    pub fn message_id(self) -> Result<MessageId, Refusal> {
        if self.ordinal == 0 || self.direction == [0; 32] {
            return Err(Refusal::Malformed);
        }
        let mut hash = Sha256::new();
        hash.update(b"mvm.mailbox.sender-ordinal.id.v1\0");
        hash.update(self.direction);
        hash.update(self.ordinal.to_be_bytes());
        Ok(MessageId::from_bytes(hash.finalize().into()))
    }
}

/// Check B's signed admission against the original sender generation and ordinal.
pub fn verify_sender_receipt(
    boot: &MailboxReaderBootBinding,
    handle: SenderOrdinalV1,
    receipt: &SignedDestinationReceipt,
) -> Result<(), Refusal> {
    let direction = boot
        .outbound_journal_v1
        .as_ref()
        .ok_or(Refusal::NotAuthorized)?;
    if direction.sender_settlement
        != Some(mvm_contract::protocol::mailbox::SenderSettlementProfile::OrdinalV1)
        || handle.direction
            != journal_direction_commitment(boot).map_err(|_| Refusal::NotAuthorized)?
        || receipt.receipt.message_id != handle.message_id()?
        || receipt.receipt.address != direction.address
        || receipt.receipt.execution_epoch != direction.execution_epoch
        || receipt.receipt.protocol_version != mvm_contract::protocol::mailbox::ProtocolVersion::V2
        || receipt.receipt.outcome
            != mvm_contract::protocol::mailbox::DeliveryOutcome::AcceptedLocalDurable
        || !(direction.not_before_unix_ms..direction.expires_at_unix_ms)
            .contains(&receipt.receipt.observed_at_unix_ms)
    {
        return Err(Refusal::NotAuthorized);
    }
    let peer =
        VerifyingKey::from_bytes(&direction.receipt_key).map_err(|_| Refusal::NotAuthorized)?;
    super::verify_receipt(receipt, &peer).map_err(|_| Refusal::NotAuthorized)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderSettlementV1 {
    pub handle: SenderOrdinalV1,
    pub receipt_digest: [u8; 32],
    pub signature: Vec<u8>,
}

impl SenderSettlementV1 {
    fn statement(handle: SenderOrdinalV1, receipt_digest: [u8; 32]) -> Vec<u8> {
        let mut bytes = b"mvm.mailbox.sender-ordinal.settlement.v1\0".to_vec();
        bytes.extend(handle.direction);
        bytes.extend(handle.ordinal.to_be_bytes());
        bytes.extend(receipt_digest);
        bytes
    }
    pub fn receipt_digest(receipt: &SignedDestinationReceipt) -> Result<[u8; 32], Refusal> {
        Ok(Sha256::digest(serde_jcs::to_vec(receipt).map_err(|_| Refusal::Malformed)?).into())
    }
    /// The agent calls this only after it has recorded the verified result under
    /// its original durable local settlement state. The key never leaves A.
    pub fn sign(
        boot: &MailboxReaderBootBinding,
        ordinal: u64,
        receipt: &SignedDestinationReceipt,
        key: &SigningKey,
    ) -> Result<Self, Refusal> {
        let handle = SenderOrdinalV1 {
            direction: journal_direction_commitment(boot).map_err(|_| Refusal::NotAuthorized)?,
            ordinal,
        };
        if key.verifying_key().to_bytes() != boot.ack_public_key {
            return Err(Refusal::NotAuthorized);
        }
        verify_sender_receipt(boot, handle, receipt)?;
        let receipt_digest = Self::receipt_digest(receipt)?;
        let signature = key
            .sign(&Self::statement(handle, receipt_digest))
            .to_bytes()
            .to_vec();
        Ok(Self {
            handle,
            receipt_digest,
            signature,
        })
    }
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), Refusal> {
        self.handle.message_id()?;
        let sig = Signature::from_slice(&self.signature).map_err(|_| Refusal::Malformed)?;
        key.verify_strict(&Self::statement(self.handle, self.receipt_digest), &sig)
            .map_err(|_| Refusal::NotAuthorized)
    }
}

/// Operations on the existing guest reader stream. Payload bytes use its
/// existing bounded representation; the signed plan supplies the destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum SenderRequestV1 {
    Submit {
        handle: SenderOrdinalV1,
        #[serde(with = "super::reader_wire::payload_base64")]
        payload: Vec<u8>,
    },
    Settle {
        statement: SenderSettlementV1,
    },
}
pub const MAX_ORDINAL_PAYLOAD: usize = 8192;

/// Requests on the workload's local reader socket. The agent alone holds the signing key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicationSenderRequestV1 {
    Stage {
        handle: SenderOrdinalV1,
        #[serde(with = "super::reader_wire::payload_base64")]
        payload: Vec<u8>,
    },
    Status {
        handle: SenderOrdinalV1,
    },
    Settle {
        handle: SenderOrdinalV1,
        receipt_digest: [u8; 32],
    },
}

impl std::fmt::Debug for ApplicationSenderRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stage { handle, payload } => f
                .debug_struct("Stage")
                .field("handle", handle)
                .field("payload_bytes", &payload.len())
                .finish(),
            Self::Status { handle } => f.debug_tuple("Status").field(handle).finish(),
            Self::Settle { handle, .. } => f.debug_tuple("Settle").field(handle).finish(),
        }
    }
}

#[cfg(all(test, unix))]
mod application_tests {
    use super::*;
    use crate::mailbox::reader_wire::{
        ApplicationReaderRequest, read_application_request, write_application_request,
    };
    use std::os::unix::net::UnixStream;

    #[test]
    fn application_sender_requests_roundtrip_and_cannot_supply_an_agent_statement() {
        let handle = SenderOrdinalV1 {
            direction: [5; 32],
            ordinal: 1,
        };
        for operation in [
            serde_json::json!({"operation":"stage", "handle":handle, "payload":"AAEA"}),
            serde_json::json!({"operation":"status", "handle":handle}),
            serde_json::json!({"operation":"settle", "handle":handle, "receipt_digest":vec![2;32]}),
        ] {
            let value = serde_json::json!({"operation":"sender_ordinal_v1", "request":operation});
            let request: ApplicationReaderRequest = serde_json::from_value(value.clone()).unwrap();
            let (mut client, mut agent) = UnixStream::pair().unwrap();
            write_application_request(&mut client, &request).unwrap();
            assert_eq!(
                serde_json::to_value(read_application_request(&mut agent).unwrap()).unwrap(),
                value
            );
        }
        let signed = serde_json::json!({"operation":"sender_ordinal_v1","request":{
            "operation":"settle","handle":handle,"receipt_digest":vec![2;32],"signature":vec![7;64]}});
        assert!(serde_json::from_value::<ApplicationReaderRequest>(signed).is_err());
    }
}
