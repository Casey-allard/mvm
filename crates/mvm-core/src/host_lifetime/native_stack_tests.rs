use super::calculate;

#[test]
fn known_stack_terms_include_the_rounded_signal_mapping_and_guard() {
    let terms = calculate(2 << 20, 4096, 8193, 16384).unwrap();
    assert_eq!(terms.rust_alt_mapping_bytes, 16384);
    assert_eq!(terms.rust_alt_guard_bytes, 4096);
    assert_eq!(terms.known_rust_bytes, (2 << 20) + 16384);
}

#[test]
fn unsupported_native_facts_do_not_produce_a_stack_charge() {
    assert!(calculate(1 << 20, 4096, 8192, 16384).is_err());
    assert!(calculate(2 << 20, 8192, 8192, 16384).is_err());
    assert!(calculate(2 << 20, 4096, 0, 16384).is_err());
    assert!(calculate(2 << 20, 4096, 8192, 3 << 20).is_err());
}
