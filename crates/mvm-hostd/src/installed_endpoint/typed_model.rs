//! Secondary layout drift checks for the source-audited bootstrap worksheet.
//! The field inventory, parser versions, vector growth and lifetimes form the
//! bound. sizeof assertions alone do not establish a requested-heap bound.

use anyhow::{Result, ensure};

pub(super) fn require_supported_model() -> Result<()> {
    ensure!(
        cfg!(target_pointer_width = "64"),
        "installed config model ABI unsupported"
    );
    Ok(())
}

const _: () = {
    // The source worksheet's fixed64KiB bookkeeping includes this flat
    // descriptor (currently1296B), in addition to paths and bounded peer
    // copies. Pointed-to config data remains in the separate node/byte terms.
    // Box allocation occurs only after from_child debits the real bootstrap.
    assert!(std::mem::size_of::<crate::supervisor::network_endpoint::EndpointConfig>() <= 2048);
    assert!(std::mem::size_of::<crate::telemetry_collector::TelemetryOnlyConfig>() <= 2048);
    use mvm_contract::{
        peer::PeerBinding,
        policy::{
            network_policy::{CooperatingTcpPeer, HostPort},
            redaction::RedactionProfile,
            reversible_replacement::ReversibleReplacementProfile,
            routes::{EgressRoute, EndpointRule},
        },
    };
    assert!(std::mem::size_of::<HostPort>() <= 256);
    assert!(std::mem::size_of::<PeerBinding>() <= 256);
    assert!(std::mem::size_of::<CooperatingTcpPeer>() <= 256);
    assert!(std::mem::size_of::<RedactionProfile>() <= 256);
    assert!(std::mem::size_of::<ReversibleReplacementProfile>() <= 256);
    assert!(std::mem::size_of::<EgressRoute>() <= 256);
    assert!(std::mem::size_of::<EndpointRule>() <= 256);
};
