//! Safe phase diagnostics without sharing or replacing original cleanup custody.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupStage {
    #[cfg(target_os = "linux")]
    RegisteredBootGrant,
    KernelObservation,
    GuestActivation,
}

impl std::fmt::Display for StartupStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            #[cfg(target_os = "linux")]
            Self::RegisteredBootGrant => "registered boot grant",
            Self::KernelObservation => "kernel observation",
            Self::GuestActivation => "guest activation",
        })
    }
}
impl std::error::Error for StartupStage {}

pub(super) fn retain_failure(
    retained: &mut Option<anyhow::Error>,
    error: anyhow::Error,
) -> anyhow::Error {
    let stage = error.downcast_ref::<StartupStage>().copied();
    *retained = Some(error);
    match stage {
        Some(stage) => anyhow::anyhow!(
            "installed native startup failed during {stage}; original error retained"
        ),
        None => anyhow::anyhow!("installed native startup failed; original error retained"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct CleanupOwner {
        value: u32,
        dropped: Arc<AtomicUsize>,
    }
    impl std::fmt::Display for CleanupOwner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("synthetic private backend input")
        }
    }
    impl std::error::Error for CleanupOwner {}
    impl Drop for CleanupOwner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn stage_projection_preserves_unique_mutable_cleanup_and_hides_backend_text() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let original = anyhow::Error::new(CleanupOwner {
            value: 7,
            dropped: dropped.clone(),
        })
        .context(super::StartupStage::GuestActivation);
        let mut retained = None;
        let reported = super::retain_failure(&mut retained, original);
        assert_eq!(
            reported.to_string(),
            "installed native startup failed during guest activation; original error retained"
        );
        assert!(!format!("{reported:#}").contains("private backend"));
        assert!(!format!("{reported:?}").contains("private backend"));
        let owner = retained
            .as_mut()
            .unwrap()
            .downcast_mut::<CleanupOwner>()
            .unwrap();
        owner.value += 1;
        assert_eq!(owner.value, 8);
        drop(reported);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(retained);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unknown_original_failure_keeps_the_existing_opaque_message() {
        let mut retained = None;
        let reported = super::retain_failure(
            &mut retained,
            anyhow::anyhow!("synthetic private backend input"),
        );
        assert_eq!(
            reported.to_string(),
            "installed native startup failed; original error retained"
        );
        assert_eq!(
            retained.unwrap().to_string(),
            "synthetic private backend input"
        );
    }

    #[test]
    fn each_typed_stage_uses_only_its_fixed_public_name() {
        for (stage, label) in [
            #[cfg(target_os = "linux")]
            (
                super::StartupStage::RegisteredBootGrant,
                "registered boot grant",
            ),
            (super::StartupStage::KernelObservation, "kernel observation"),
            (super::StartupStage::GuestActivation, "guest activation"),
        ] {
            let mut retained = None;
            let reported = super::retain_failure(
                &mut retained,
                anyhow::anyhow!("synthetic private backend input").context(stage),
            );
            assert!(reported.to_string().contains(label));
            assert_eq!(
                retained.unwrap().downcast_ref::<super::StartupStage>(),
                Some(&stage)
            );
        }
    }
}
