use super::*;
#[test]
fn split_scanner_actual_guard_rejects_each_unsupported_fact() {
    let policy = mvm_core::policy::RedactionPolicy::default();
    let facts = crate::stream::redact::StreamRedaction::owned_pii_requirements(&policy).unwrap();
    assert_eq!(checked_owned_scanner_facts(facts).unwrap(), 24_363_008);
    let changes: &[fn(&mut mvm_core::pii::OwnedPiiRequirements)] = &[
        |f| f.nfa_size_limit_bytes = 262_144,
        |f| f.nfa_size_limit_bytes = usize::MAX,
        |f| f.rule_nfa_size_limit_bytes = 524_288,
        |f| f.rule_nfa_size_limit_bytes = 65_536,
        |f| f.rule_nfa_size_limit_bytes = 0,
        |f| f.rule_nfa_size_limit_bytes = usize::MAX,
        |f| f.dfa_cache_limit_bytes = 131_072,
        |f| f.nest_limit = 65,
        |f| f.max_concurrent_searches = 2,
        |f| {
            f.rule_count = 6;
            f.regex_objects = 7;
        },
        |f| {
            f.rule_count = 0;
            f.regex_objects = 1;
        },
        |f| f.rule_count = usize::MAX,
        |f| f.regex_objects = usize::MAX,
    ];
    for change in changes {
        let mut unsupported = facts;
        change(&mut unsupported);
        assert!(checked_owned_scanner_facts(unsupported).is_err());
    }
}
#[test]
fn split_scanner_query_and_actual_model_count_one_set_and_each_rule() {
    for (count, expected) in
        (1..=5).zip([13_713_408, 16_375_808, 19_038_208, 21_700_608, 24_363_008])
    {
        let mut policy = mvm_core::policy::RedactionPolicy::default();
        policy.default.pii.categories = mvm_core::pii::DEFAULT_RULES[..count]
            .iter()
            .map(|r| r.name.to_owned())
            .collect();
        let facts =
            crate::stream::redact::StreamRedaction::owned_pii_requirements(&policy).unwrap();
        assert_eq!(facts.rule_count, count);
        assert_eq!(facts.regex_objects, count + 1);
        assert_eq!(checked_owned_scanner_facts(facts).unwrap(), expected);
        assert_eq!(owned_scanner_requested_bytes(&policy).unwrap(), expected);
    }
}
