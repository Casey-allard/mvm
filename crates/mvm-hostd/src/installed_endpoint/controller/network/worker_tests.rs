use super::*;
use mvm_core::host_lifetime::EndpointPartitionLimits;

fn limits(workers: u32, max_streams: u16) -> EndpointPartitionLimits {
    EndpointPartitionLimits {
        host_plaintext_bytes: 0,
        host_codec_bytes: 0,
        host_carrier_bytes: 0,
        host_metadata_bytes: 0,
        host_stack_bytes: 0,
        cache_disk_bytes: 0,
        staging_disk_bytes: 0,
        workers,
        max_streams,
    }
}

#[test]
fn serial_worker_quote_includes_all_selected_concurrent_owners() {
    let quote = owned_network_runtime_requirements().unwrap();
    assert_eq!(quote.controller.additional_threads, 0);
    assert_eq!(quote.additional_threads, 1);
    assert_eq!(quote.required_workers, 7);
    for workers in 0..quote.required_workers {
        assert!(quote.check_worker_limits(&limits(workers, 1)).is_err());
    }
    let funded = limits(quote.required_workers, 1);
    quote.check_worker_limits(&funded).unwrap();
    for max_streams in [0, 2, u16::MAX] {
        assert!(
            quote
                .check_worker_limits(&EndpointPartitionLimits {
                    max_streams,
                    ..funded
                })
                .is_err()
        );
    }
}
