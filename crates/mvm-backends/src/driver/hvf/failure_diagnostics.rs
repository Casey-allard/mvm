//! Payload-free projection of HVF startup failure observations.

pub(super) fn startup_failure_record(
    summary: mvm_vmm::host::hvf_supervisor::StartupSummary,
    status: Option<std::process::ExitStatus>,
) -> mvm_core::launch_trace::failure::Record {
    use mvm_core::launch_trace::failure::{Phase, Record, Stage};
    use mvm_vmm::host::hvf_supervisor::StartupStage as S;
    let mut record = Record::new(Phase::HvfReadiness);
    record.stage = match summary.stage {
        S::Unknown => Stage::Unknown,
        S::SignCheck => Stage::SignCheck,
        S::SigningLock => Stage::SigningLock,
        S::Signing => Stage::Signing,
        S::Reexec => Stage::Reexec,
        S::ConfigRead => Stage::ConfigRead,
        S::ConfigParse => Stage::ConfigParse,
        S::StatusPublish => Stage::StatusPublish,
        S::StartupInputs => Stage::StartupInputs,
        S::CapturePolicy => Stage::CapturePolicy,
        S::CaptureSetup => Stage::CaptureSetup,
        S::PidPublish => Stage::PidPublish,
        S::PidPublished => Stage::PidPublished,
    };
    record.exit_code = status.and_then(|status| status.code());
    record
}

pub(super) fn supervisor_unavailable_message(error: &anyhow::Error) -> String {
    format!(
        "HVF supervisor unavailable. Build it with `just payload::supervisors` \
         or install mvm with `mvmctl env bootstrap`, then retry.\n\nError: {error:#}"
    )
}

#[cfg(test)]
mod tests {
    use super::{startup_failure_record, supervisor_unavailable_message};

    #[test]
    fn supervisor_unavailable_message_names_the_remedies() {
        let err = anyhow::anyhow!("mvm-hvf-supervisor not found in PATH or aux dirs");
        let msg = supervisor_unavailable_message(&err);
        assert!(msg.contains("just payload::supervisors"), "{msg}");
        assert!(msg.contains("mvmctl env bootstrap"), "{msg}");
        assert!(msg.contains("mvm-hvf-supervisor not found"), "{msg}");
    }

    #[test]
    fn failure_record_keeps_the_stage_and_only_an_observed_exit() {
        use mvm_vmm::host::hvf_supervisor::{StartupStage, StartupSummary};
        use std::os::unix::process::ExitStatusExt;
        let summary = StartupSummary {
            stage: StartupStage::CaptureSetup,
        };
        let record =
            startup_failure_record(summary, Some(std::process::ExitStatus::from_raw(17 << 8)));
        assert_eq!(
            record.stage,
            mvm_core::launch_trace::failure::Stage::CaptureSetup
        );
        assert_eq!(record.exit_code, Some(17));
        assert_eq!(startup_failure_record(summary, None).exit_code, None);
    }
}
