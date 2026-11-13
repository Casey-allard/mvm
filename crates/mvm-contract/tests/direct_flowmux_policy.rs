use mvm_contract::policy::network_policy::NetworkPolicy;
use serde_json::json;

#[test]
fn a_required_direct_tcp_profile_survives_policy_projection() {
    let peer_key = [7u8; 32];
    let required = json!({
        "version": 1,
        "peers": [{
            "host": "peer.example",
            "port": 443,
            "server_name": "peer.example",
            "spki_sha256": peer_key,
            "profile": "spiral_core_object_stream_small_v1"
        }]
    });
    let mut input = serde_json::to_value(NetworkPolicy::deny_all()).unwrap();
    input["payload_mapping"] = required.clone();
    let projected: NetworkPolicy = serde_json::from_value(input).unwrap();
    assert!(!projected.admits_outbound());
    assert_eq!(
        serde_json::to_value(projected).unwrap()["payload_mapping"],
        required
    );
}
