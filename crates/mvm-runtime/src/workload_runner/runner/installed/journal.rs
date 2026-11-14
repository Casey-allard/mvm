//! Serialized calls under the original signed persistent journal admission.
use super::*;

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
            let until = deadline(&plan, until, plan.resources.timeouts.exec_secs)?;
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
