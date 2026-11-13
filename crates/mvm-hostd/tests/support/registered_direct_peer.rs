use anyhow::{Result,ensure};
use ed25519_dalek::{SigningKey,pkcs8::EncodePrivateKey};
use mvm_core::net::session::{Session,read_sealed_frame,write_sealed_frame};
use mvm_contract::protocol::network_flow::Opcode;
use mvm_vmm::host::network_endpoint_spawn::AdmittedNetworkPlan;
use mvm_hostd::supervisor::flowmux::{PayloadResourceLimits,PayloadResourcePool,PreparedPayloadSession,accept_enrolled_payload};
use spiralcore_mvm_flowmux::{Role,scope::{PinnedScopePolicy,ScopeFacts},tls::{TlsCarrier,PinnedIdentity}};
use spiralcore_transfer::{resource_profile::ResourceProfile,v1::{Capabilities,ObjectEndpoint,ObjectMode,ObjectSender}};
use std::{net::{TcpStream,TcpListener,SocketAddr,Shutdown},io::{Read,Write},time::{Duration,Instant},os::unix::net::UnixStream};
pub const TARGET:&str="cooperator.mvm.peer";
pub fn fixture_identity(key:&SigningKey)->PinnedIdentity { PinnedIdentity::from_pkcs8(key.to_pkcs8_der().unwrap().as_bytes().to_vec()).unwrap() }
pub fn payload()->Vec<u8> { let mut bytes = b"{\"kind\":\"flowmux\",\"value\":1}\n".repeat(200); bytes.extend_from_slice(&[0,255,0,0]); bytes }
pub fn accept(listener:&TcpListener)->Result<TcpStream> {
    rustix::event::poll(&mut [rustix::event::PollFd::new(listener, rustix::event::PollFlags::IN)], Some(&rustix::event::Timespec{tv_sec:8,tv_nsec:0}))?;
    Ok(listener.accept()?.0)
}
pub fn serve_original(socket:TcpStream,address:SocketAddr,server_identity:PinnedIdentity,plan:AdmittedNetworkPlan,stream_id:u32)->Result<()> {
    let until=Instant::now()+Duration::from_secs(8);
    let initiator=fixture_identity(&SigningKey::from_bytes(&[9;32]));
    let tls=TlsCarrier::accept(socket, &server_identity,initiator.spki_sha256(),until)?;
    let facts = ScopeFacts {
        object_profile: 2,
        policy_sha256: hex::decode(&plan.policy_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
        plan_id: plan.plan_id.0,
        plan_version: plan.plan_version,
        plan_nonce: hex::decode(plan.plan_nonce.as_hex())
            .unwrap()
            .try_into()
            .unwrap(),
        bundle_sha256: hex::decode(&plan.bundle_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
        tenant: plan.tenant_id,
        instance: plan.instance_id,
        session: hex::encode([3;32]),
        guest_key: SigningKey::from_bytes(&[7;32]).verifying_key().to_bytes(),
        stream_id,
        requested_host: TARGET.into(),
        requested_port: 443,
        actual_peer: address,
        route: "peer".into(),
        initiator_spki: tls.peer_spki_sha256(),
        acceptor_spki: tls.local_spki_sha256(),
        tls_exporter: tls.exporter(),
    };
    let scopes = PinnedScopePolicy::new(1).unwrap();
    scopes
        .enroll(&facts, facts.initiator_spki, Role::Acceptor, until)
        .unwrap();
    let authority = scopes
        .authorize_scope(&facts, facts.initiator_spki, Role::Acceptor)
        .unwrap();
    let resources = ResourceProfile::SmallV1;
    // A separate cooperating endpoint in the test controller, explicitly not
    // another local child subdivision or a production host capacity grant.
    let pool = PayloadResourcePool::for_qualification(PayloadResourceLimits {
        max_active: 1,
        resident_bytes: 8 << 20,
        disk_bytes: 32 << 20,
    })
    .unwrap();
    let permit = pool.reserve_profile(resources).unwrap();
    let store = tempfile::tempdir().unwrap();
    let path = store.path().join("peer");
    let profile = Capabilities::small_v1()
        .negotiate(&Capabilities::small_v1())
        .unwrap();
    let sender = ObjectSender::new_with_resource_profile(
        ObjectMode::Whole,
        authority.context(),
        None,
        profile,
        resources,
    )
    .unwrap();
    let endpoint = ObjectEndpoint::open_with_resource_profile(
        &path,
        resources.receiver_limits(),
        authority.clone(),
        profile,
        resources,
    )
    .unwrap();
    let prepared = PreparedPayloadSession::new(
        authority,
        sender,
        endpoint,
        permit.with_owned_store(path.clone()).unwrap(),
    )
    .unwrap();
    let mut mapped = accept_enrolled_payload(tls, prepared, until).unwrap();
    let mut body = Vec::new();
    (&mut mapped).take((payload().len()+1) as u64).read_to_end(&mut body)?;
    ensure!(body == payload());
    mapped.write_all(&body)?; mapped.shutdown(Shutdown::Write)?;
    drop(mapped); pool.close_admission()?; ensure!(pool.drained()?); Ok(())
}
pub fn send(stream: &mut UnixStream, session: &mut Session, opcode: Opcode, id: u32, bytes: &[u8]) {
    let frame = mvm_contract::protocol::network_flow::encode(opcode, id, bytes).unwrap();
    write_sealed_frame(stream, &session.seal(&frame).unwrap()).unwrap();
}

pub fn receive(stream: &mut UnixStream, session: &mut Session) -> (Opcode, u32, Vec<u8>) {
    let sealed = read_sealed_frame(stream, 1 << 20).unwrap();
    let plain = session.open(&sealed).unwrap();
    let frame = mvm_contract::protocol::network_flow::decode(&plain).unwrap();
    (
        frame.header.opcode,
        frame.header.stream_id,
        frame.payload.to_vec(),
    )
}
