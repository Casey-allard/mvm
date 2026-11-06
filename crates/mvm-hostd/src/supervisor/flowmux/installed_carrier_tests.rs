use super::{OwnedTcpRelays, PayloadMappingConfig, SpiralCorePayloadFactory, payload_mapping::AdmittedTcpFacts};
use crate::installed_endpoint::InstalledEndpointResources;
use mvm_vmm::host::network_endpoint_spawn::InstalledEndpointChild;
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

mod resource_fixture {
    use crate as mvm_hostd;
    include!("../../../tests/common/installed_resource_fixture.rs");
}

const CHILD: &str = "supervisor::flowmux::installed_carrier_tests::carrier_fixture_child";

#[test]
fn carrier_fixture_child() {
    let Ok(mode) = std::env::var("MVM_INSTALLED_RESOURCES_FIXTURE") else {
        return;
    };
    // SAFETY: the fixture's pre_exec owns the protocol descriptor 199.
    assert!(unsafe { libc::dup2(199, 1) } >= 0);
    let mut child = InstalledEndpointChild::from_stdio().unwrap();
    let original = InstalledEndpointResources::from_child(&mut child).unwrap();
    let config = original.network_config().unwrap();
    let mapping = PayloadMappingConfig::new(
        config.network_policy.as_ref().unwrap(),
        config.admitted_network_plan.as_ref().unwrap().clone(),
    )
    .unwrap()
    .with_factory(Arc::new(
        SpiralCorePayloadFactory::from_installed_resources(&original)
            .unwrap()
            .unwrap(),
    ));
    let pool = original.payload_pool().unwrap();
    let empty = pool.snapshot().unwrap();
    let session_id = config.flowmux_identity.as_ref().unwrap().session_id.clone();
    let relays = OwnedTcpRelays::from_installed_resources(&original).unwrap();
    let try_tls = |stream_id| {
        let deadline = Instant::now() + Duration::from_secs(1);
        let reservation = relays.reserve_until(deadline).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (guest, _guest_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        reservation.bind_setup(&socket, Arc::new(guest)).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let reader = std::thread::spawn(move || peer.read(&mut [0; 1]));
        let result = mapping.map(
            socket,
            AdmittedTcpFacts {
                session_id: session_id.clone(),
                guest_key: [0; 32],
                stream_id,
                requested_host: "peer.example".into(),
                requested_port: 443,
                route: "direct",
                deadline,
                owned_relay: Some(reservation.witness().unwrap()),
            },
        );
        // An early refusal leaves the original wake clone in the reservation.
        // Release it before the peer checks for EOF.
        drop(reservation);
        (reader.join().unwrap().unwrap(), result.unwrap_err())
    };

    if mode == "carrier-unfunded" {
        // The fixture projects one carrier byte across two original slots.
        let (bytes, error) = try_tls(1);
        assert_eq!(bytes, 0, "unfunded connection sent TLS bytes: {error}");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "original payload carrier credit unavailable"
        );
    } else {
        assert_eq!(mode, "carrier-funded");
        let occupied = pool
            .reserve_profile(spiralcore_transfer::resource_profile::ResourceProfile::SmallV1)
            .unwrap();
        let charged = pool.snapshot().unwrap();
        let (bytes, error) = try_tls(1);
        assert_eq!(bytes, 0, "exhausted connection sent TLS bytes: {error}");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(error.to_string(), "aggregate payload pool full");
        assert_eq!(pool.snapshot().unwrap(), charged);
        drop(occupied);
        let (bytes, _) = try_tls(3);
        assert_eq!(bytes, 1, "funded connection never started TLS");
    }
    assert_eq!(pool.snapshot().unwrap(), empty);
    pool.close_admission().unwrap();
    assert!(pool.drained().unwrap());
    child
        .send_ready(Default::default(), Instant::now() + Duration::from_secs(2))
        .unwrap();
    let mut event = libc::pollfd {
        fd: child.control_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: bounded event wait on the original live control pipe.
    assert!(unsafe { libc::poll(&mut event, 1, 3000) } > 0);
    child
        .send_drained(Instant::now() + Duration::from_secs(2))
        .unwrap();
    std::process::exit(0);
}

#[tokio::test]
async fn insufficient_carrier_share_refuses_before_tls() {
    exercise("carrier-unfunded").await;
}

#[tokio::test]
async fn exhausted_pool_refuses_before_tls_and_tls_failure_refunds() {
    exercise("carrier-funded").await;
}

async fn exercise(mode: &str) {
    resource_fixture::resource_exchange(
        mode,
        &["--exact", CHILD, "--nocapture", "--test-threads=1"],
    )
    .await;
}
