use super::*;
use crate::mailbox::journal::*;
use crate::mailbox::reader::*;
use crate::mailbox::reader_wire::{ReaderResponse,read_response,write_response};

struct OriginalKey(HistoryKeyRef);
impl HistoryKeyCustody for OriginalKey {
    fn load_existing(&self, reference: &HistoryKeyRef) -> Result<Key,JournalError> {
        if reference != &self.0 {return Err(JournalError::HistoryKeyUnavailable);}
        Ok(Key::from_bytes([44;32]))
    }
}

#[test]
fn leased_call_survives_restart_with_exact_header_payload_and_original_signature() {
    let c=grant(false);let r=grant(true);
    let grants=ObjectPairGrants {call:&c,reply:&r};
    let selection=grants.commitment(&Nonce::from_bytes([1;16]), &Nonce::from_bytes([2;16])).unwrap();
    let (a,ab)=original(&r,Some(selection),1); let (b,bb)=original(&c,Some(selection),2);
    let ak=key(1).verifying_key();let bk=key(2).verifying_key();
    let ae=OriginalObjectEndpoint{plan:&a,boot:&ab,trusted_signers:&[("original",&ak)]};
    let be=OriginalObjectEndpoint{plan:&b,boot:&bb,trusted_signers:&[("original",&bk)]};
    let state=live(ab.boot,bb.boot);
    let pair=ObjectPairV1::check_originals(&ae,&be,grants,NOW,state).unwrap();
    let plan=verify_plan(&b,be.trusted_signers).unwrap().mailbox.unwrap();
    let address=c.grant.address;
    let auth=key(3);let sender_key=key(10).verifying_key();let data=Key::from_bytes([60;32]);
    let return_route=ReplyRoute{address:r.grant.address,capability_id:r.grant.capability_id};
    let envelope=sealed(&c,ab.boot,Some(return_route),NOW-10,71,70);
    let context=crate::mailbox::OpenContext{
        expected_tenant:address.tenant,expected_authorization_domain:address.authorization_domain,
        expected_mailbox:address.mailbox,expected_sender:c.grant.subject,
        expected_recipient:address.recipient,acting_principal:c.grant.subject,
        expected_capability_issuer:c.grant.issuer,current_execution_epoch:plan.epoch,
        current_policy_epoch:c.grant.policy_epoch,required_operation:MailboxOperation::Send,
        now_unix_ms:NOW,accepted_content_types:c.grant.content_types.clone(),revoked_capabilities:vec![],
    };
    let dir=tempfile::tempdir().unwrap();
    let history=OriginalKey(HistoryKeyRef::new(address,plan.epoch,[19;32],1).unwrap());
    let start=||{
        let anchor=FileJournalAnchor::open(&dir.path().join("anchor"),address,[29;32]).unwrap();
        let journal=MailboxJournal::open_local_with_custody(&dir.path().join("journal"),history.0.clone(),auth.verifying_key(),
            JournalLimits{max_records:8,max_bytes:128*1024},&history,&anchor,plan.retention.unwrap()).unwrap();
        (journal,anchor)
    };
    let (mut journal,anchor)=start();
    let receipt=journal.admit_local(JournalAdmission{envelope:&envelope,capability:&c,context:&context,
        encryption_key:&data,sender_key:&sender_key,signer:&auth},&anchor).unwrap();
    assert_eq!(receipt.receipt.message_id,MessageId::from_bytes([60;32]));
    let mut receive=c.grant.clone();
    receive.subject=address.recipient;receive.capability_id=CapabilityId::from_bytes([33;32]);
    receive.operations=CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    let cap=sign_capability(receive,&auth).unwrap();
    let mut read=context.clone();read.required_operation=MailboxOperation::Receive;read.acting_principal=address.recipient;
    let session=ConsumerSessionId::from_bytes([36;32]);let guest=key(42);
    let enrollment=sign_guest_reader_enrollment(MailboxGuestReaderEnrollment{
        protocol_version:ProtocolVersion::V1,signature_algorithm:SignatureAlgorithm::ED25519,
        plan_id:bb.plan_id.clone(),plan_nonce:bb.plan_nonce.clone(),address,
        consumer:address.recipient,consumer_boot:bb.boot,consumer_session:session,
        receive_capability_id:cap.grant.capability_id,ack_public_key:guest.verifying_key().to_bytes(),
        execution_epoch:plan.epoch,policy_epoch:cap.grant.policy_epoch,issued_at_unix_ms:NOW-1,expires_at_unix_ms:NOW+4500,
    },&auth).unwrap();
    let exercise=|journal:&mut MailboxJournal,anchor:&FileJournalAnchor,value:u8|{
        let challenge=[value;32];let proof=sign_reader_possession(&enrollment,&challenge,&guest).unwrap();
        let request=|| JournalGuestLease{receive:JournalReceive{capability:&cap,context:&read,encryption_key:&data,sender_key:&sender_key},
            plan:&plan,scope:MailboxGuestReaderScope{plan:&plan,plan_id:&bb.plan_id,plan_nonce:&bb.plan_nonce,
            receive:&cap.grant,current_boot:bb.boot,current_session:session,now_unix_ms:NOW},enrollment:&enrollment,
            challenge:&challenge,possession_signature:&proof,signer:&auth};
        let authority=|state|ObjectLeaseScope{pair:&pair,destination:&bb,state,original_call:None};
        let prior=journal.tip();
        assert!(journal.lease_next(request(),|_|panic!("cannot downgrade the selected reader")).is_err());
        let revoked=[c.grant.revocation_id];
        assert!(journal.lease_next_object(request(),authority(PairAuthorityState{at_callee:&revoked,..state}),
            |_|panic!("cannot expose after revocation")).is_err());
        assert_eq!(journal.tip(),prior);
        let record=journal.lease_next_object(request(),authority(state),|tip|anchor.advance(tip)).unwrap().unwrap();
        let wire=record.into_reader_response(Some(selection)).unwrap();
        let mut bytes=Vec::new();write_response(&mut bytes,&wire).unwrap();
        let decoded=read_response(&mut &bytes[..]).unwrap();
        let ReaderResponse::ObjectDeliveryV1{lease,header,payload}=&decoded else {panic!("wrong delivery")};
        verify_object_delivery_projection(&selection,header,payload,lease,&auth.verifying_key()).unwrap();
        assert_eq!(header.reply_to,Some(return_route)); assert_eq!(payload,b"obj\0");
        decoded
    };
    let first=exercise(&mut journal,&anchor,46);drop(journal);drop(anchor);
    let (mut journal,anchor)=start();
    assert_eq!(exercise(&mut journal,&anchor,47),first);
}
