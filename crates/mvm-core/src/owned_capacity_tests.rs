use super::*;

#[test]
fn owned_curated_controls_and_all_five_rules_preserve_canonical_redaction() {
    let policy = crate::policy::PiiPolicy {
        mode: Some("redact".into()),
        categories: Vec::new(),
    };
    let requirements = PiiRedactor::owned_pii_requirements(&policy).unwrap();
    assert_eq!(requirements.rule_count, 5);
    assert_eq!(requirements.regex_objects, 6);
    assert_eq!(requirements.nfa_size_limit_bytes, 512 * 1024);
    assert_eq!(requirements.rule_nfa_size_limit_bytes, 128 * 1024);
    assert_eq!(requirements.dfa_cache_limit_bytes, 256 * 1024);
    assert_eq!(requirements.nest_limit, 64);
    assert_eq!(requirements.max_concurrent_searches, 1);
    let owned = PiiRedactor::curated_owned(&policy).unwrap();
    let canonical = PiiRedactor::from_policy(&policy).unwrap().unwrap();
    let body = b"mail a@b.com ssn 123-45-6789 card 4111111111111111 phone +14155552671 iban GB82WEST12345698765432";
    assert_eq!(owned.redact(body), canonical.redact(body));
    assert_eq!(owned.scan(body), canonical.scan(body));
    assert_eq!(owned.match_spans(body), canonical.match_spans(body));
    for name in PII_CATEGORY_NAMES {
        assert!(
            owned.scan(body).contains(name),
            "missing canonical rule {name}"
        );
    }
}
