//! Signed-plan retention controls; no guest or mailbox helper is started.
use super::*;

#[test]
fn ordinary_admission_persists_and_explicit_internal_admission_is_ephemeral() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let rootfs = home.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"retention fixture root").unwrap();
    for expected in [StreamRetention::Persist, StreamRetention::Ephemeral] {
        let ledger = InMemoryNonceLedger::new();
        let keys = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let mut params = admit_plan_tests::pinning_params(&rootfs, &ledger);
        params.backend_name = "libkrun";
        params.backend_kind = Some(mvm_core::vm_backend::BackendKind::Libkrun);
        params.restrict_agent_verbs = false;
        params.keys_dir = Some(keys.path());
        params.audit_dir = Some(audit.path());
        params.agent_verb_override = vec!["activate-environment".into(), "run-entrypoint".into()];
        let grant = mailbox_grant::resolve(Some(&"ab".repeat(32)), None, None)
            .unwrap()
            .unwrap();
        params.mailbox = Some(grant);
        let context = if expected == StreamRetention::Persist {
            admit_persistent_ingress(params, vec![], None)
        } else {
            admit_persistent_ingress_with_retention(
                params,
                vec![],
                None,
                StreamRetention::Ephemeral,
            )
        }
        .unwrap();
        let plan = context.admitted.plan();
        assert_eq!(plan.stream_retention, expected);
        assert_eq!(
            plan.mailbox,
            Some(mailbox_grant::at_workload_epoch(grant, "vm-pinned").unwrap())
        );
        assert_eq!(
            plan.agent_verbs
                .as_ref()
                .unwrap()
                .iter()
                .map(|verb| verb.as_str())
                .collect::<Vec<_>>(),
            ["activate-environment", "run-entrypoint"]
        );
    }
}
