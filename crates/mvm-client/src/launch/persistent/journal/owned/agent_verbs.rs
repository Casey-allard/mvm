//! Narrow the opt-in installed journal entrypoint before plan admission.
use anyhow::{Result, ensure};

const ACTIVATE: &str = "activate-environment";
const RUN: &str = "run-entrypoint";

pub(super) fn require_ephemeral(
    retention: mvm_core::plan::StreamRetention,
) -> Result<mvm_core::plan::StreamRetention> {
    ensure!(
        !retention.persists(),
        "installed journal workload streams must be ephemeral"
    );
    Ok(retention)
}

pub(super) fn select(requested: &[String]) -> Result<Vec<String>> {
    if requested.is_empty() {
        return Ok(vec![ACTIVATE.into(), RUN.into()]);
    }
    ensure!(
        requested.len() == 2
            && requested.iter().any(|verb| verb == ACTIVATE)
            && requested.iter().any(|verb| verb == RUN),
        "installed journal requires only activate-environment and run-entrypoint"
    );
    Ok(requested.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_entrypoint_refuses_persistent_workload_streams() {
        use mvm_core::plan::StreamRetention;
        assert_eq!(
            require_ephemeral(StreamRetention::Ephemeral).unwrap(),
            StreamRetention::Ephemeral
        );
        assert!(require_ephemeral(StreamRetention::Persist).is_err());
    }

    #[test]
    fn empty_request_selects_the_two_ephemeral_entrypoint_verbs() {
        assert_eq!(select(&[]).unwrap(), [ACTIVATE, RUN]);
    }

    #[test]
    fn exact_request_preserves_the_admitted_selection() {
        let requested = vec![ACTIVATE.into(), RUN.into()];
        assert_eq!(select(&requested).unwrap(), requested);
    }

    #[test]
    fn reversed_exact_request_is_valid_and_preserved() {
        let requested = vec![RUN.into(), ACTIVATE.into()];
        assert_eq!(select(&requested).unwrap(), requested);
    }

    #[test]
    fn broader_or_different_requests_refuse() {
        for requested in [
            vec![ACTIVATE.into(), RUN.into(), "exec".into()],
            vec![ACTIVATE.into(), "exec".into()],
            vec![RUN.into()],
        ] {
            assert!(select(&requested).is_err());
        }
    }

    #[test]
    fn duplicate_requests_refuse() {
        for verb in [ACTIVATE, RUN] {
            assert!(select(&[verb.into(), verb.into()]).is_err());
        }
    }
}
