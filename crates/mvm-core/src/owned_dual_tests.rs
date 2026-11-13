use super::*;

#[test]
fn owned_subsets_modes_and_unicode_preserve_canonical_policy() {
    let body = "ssn 12٣-45-6789 mail a@b.com card 4111111111111111".as_bytes();
    for mode in [None, Some("detect"), Some("redact"), Some("refuse")] {
        let policy = crate::policy::PiiPolicy {
            mode: mode.map(str::to_owned),
            categories: vec!["credit_card".into(), "us_ssn".into(), "email".into()],
        };
        let owned = PiiRedactor::curated_owned(&policy).unwrap();
        let canonical = PiiRedactor::from_policy(&policy).unwrap().unwrap();
        assert_eq!(owned.mode(), canonical.mode());
        assert_eq!(owned.redact(body), canonical.redact(body));
        assert_eq!(owned.match_spans(body), canonical.match_spans(body));
        assert_eq!(owned.scan(body), ["credit_card", "us_ssn", "email"]);
        assert_eq!(
            PiiRedactor::owned_pii_requirements(&policy)
                .unwrap()
                .regex_objects,
            4
        );
    }
    let disabled = crate::policy::PiiPolicy {
        mode: Some("disabled".into()),
        categories: vec!["email".into()],
    };
    let full = PiiRedactor::curated_owned(&disabled).unwrap();
    assert_eq!(
        PiiRedactor::owned_pii_requirements(&disabled)
            .unwrap()
            .rule_count,
        5
    );
    assert_eq!(
        full.redact(body),
        PiiRedactor::with_default_rules().redact(body)
    );
}
