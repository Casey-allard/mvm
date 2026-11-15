//! Serialized calls under the original signed persistent journal admission.
use super::*;

fn journal_deadline(plan: &ExecutionPlan, until: Instant) -> Result<Instant> {
    let seconds = plan.resources.timeouts.exec_secs;
    deadline_with_cap(
        plan,
        until,
        (seconds != 0).then(|| Duration::from_secs(seconds.into())),
    )
}

impl InstalledSlot {
    pub(in crate::workload_runner::runner) fn journal_ready(&self, until: Instant) -> Result<()> {
        self.with_journal(until, |channel, _, until, _| channel.ready(until))
    }

    pub(in crate::workload_runner::runner) fn journal_entrypoint(
        &self,
        input: &[u8],
        until: Instant,
        event: &mut dyn FnMut(&EntrypointEvent),
    ) -> Result<EntrypointEvent> {
        self.with_journal(until, |channel, config, until, seconds| {
            anyhow::ensure!(
                input.len() <= 64 << 10,
                "original journal input exceeds bound"
            );
            let request = GuestRequest::RunEntrypoint {
                stdin: input.to_vec(),
                timeout_secs: seconds,
                env: vec![],
                stream_input: false,
            };
            observe_current(
                || {
                    self.owner
                        .check_parent_current(config, BackendKind::Firecracker)?;
                    anyhow::ensure!(Instant::now() < until, "original journal deadline expired");
                    Ok(())
                },
                |checked| channel.entrypoint(&request, until, checked),
                event,
            )
        })
    }

    fn with_journal<T>(
        &self,
        until: Instant,
        operation: impl FnOnce(
            &mut dyn mvm_vmm::driver::OriginalJournalControl,
            &mvm_core::vm_backend::VmStartConfig,
            Instant,
            u64,
        ) -> Result<T>,
    ) -> Result<T> {
        let (mut channel, config, until, seconds) = {
            let mut guarded = self.access()?;
            let state = guarded
                .as_mut()
                .context("original journal custody missing")?;
            anyhow::ensure!(
                !state.entrypoint_busy
                    && !state.journal_fenced
                    && !state.retired
                    && state.failure.is_none()
                    && state.vm.is_some(),
                "original journal unavailable or fenced"
            );
            state.journal_fenced = true;
            let config = state
                .launch
                .as_ref()
                .context("original launch missing")?
                .1
                .config()
                .clone();
            self.owner
                .check_parent_current(&config, BackendKind::Firecracker)?;
            let plan = mvm_core::plan::plan_from_admitted_json(
                config
                    .plan_json
                    .as_deref()
                    .context("signed journal plan missing")?,
            )?;
            anyhow::ensure!(
                selects_journal(&plan)
                    && has_verb(&plan, "activate-environment")
                    && has_verb(&plan, "run-entrypoint")
                    && plan
                        .agent_verbs
                        .as_ref()
                        .is_some_and(|verbs| verbs.len() == 2)
                    && plan.stream_edges.is_empty()
                    && !plan.stream_retention.persists(),
                "original journal admission differs"
            );
            let boot = state
                .journal_boot
                .as_ref()
                .context("original journal boot missing")?;
            boot.check_plan(&plan)?;
            anyhow::ensure!(
                &mvm_core::mailbox::reader::MailboxReaderBootBinding::load(&vm_state_dir(
                    &config.name
                ))? == boot,
                "original journal boot changed"
            );
            let until = journal_deadline(&plan, until)
                .context("original journal pre-operation admission deadline")?;
            let seconds = until.saturating_duration_since(Instant::now()).as_secs();
            anyhow::ensure!(seconds > 0, "original journal timeout below one second");
            let channel = state
                .journal
                .take()
                .context("original journal control missing")?;
            state.entrypoint_busy = true;
            (channel, config, until, seconds)
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let value = operation(&mut *channel, &config, until, seconds)?;
            self.owner
                .check_parent_current(&config, BackendKind::Firecracker)?;
            anyhow::ensure!(Instant::now() < until, "original journal deadline expired");
            Ok(value)
        }));
        let mut guarded = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("original journal custody poisoned"))?;
        let state = guarded
            .as_mut()
            .context("original journal custody absent after call")?;
        state.entrypoint_busy = false;
        state.journal = Some(channel);
        if matches!(&result, Ok(Ok(_))) {
            state.journal_fenced = false;
        }
        result.map_err(|_| anyhow::anyhow!("original journal callback unwound; control fenced"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(seconds: u32) -> ExecutionPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.valid_from = chrono::Utc::now() - chrono::Duration::seconds(1);
        plan.valid_until = chrono::Utc::now() + chrono::Duration::seconds(60);
        plan.resources.timeouts.exec_secs = seconds;
        plan
    }

    #[test]
    fn unbounded_journal_execution_still_obeys_the_callers_absolute_deadline() {
        let until = Instant::now() + Duration::from_secs(2);
        assert_eq!(journal_deadline(&plan(0), until).unwrap(), until);
    }

    #[test]
    fn unbounded_journal_execution_never_extends_signed_validity() {
        let mut plan = plan(0);
        plan.valid_until = chrono::Utc::now() + chrono::Duration::seconds(2);
        let before = Instant::now();
        let until = before + Duration::from_secs(10);
        let actual = journal_deadline(&plan, until).unwrap();
        assert!(actual < until);
        assert!(actual > before + Duration::from_secs(1));
        assert!(actual <= before + Duration::from_secs(2));
    }

    #[test]
    fn bounded_journal_execution_keeps_the_existing_cap() {
        let before = Instant::now();
        let actual = journal_deadline(&plan(1), before + Duration::from_secs(10)).unwrap();
        let after = Instant::now();
        assert!(actual >= before + Duration::from_secs(1));
        assert!(actual <= after + Duration::from_secs(1));
    }

    #[test]
    fn expired_journal_plan_or_caller_deadline_refuses() {
        let valid = plan(0);
        assert!(journal_deadline(&valid, Instant::now() - Duration::from_secs(1)).is_err());
        let mut expired = valid;
        expired.valid_until = chrono::Utc::now() - chrono::Duration::seconds(1);
        assert!(journal_deadline(&expired, Instant::now() + Duration::from_secs(2)).is_err());
    }

    #[test]
    fn one_shot_zero_cap_behavior_is_unchanged() {
        assert!(deadline(&plan(0), Instant::now() + Duration::from_secs(2), 0).is_err());
    }
}
