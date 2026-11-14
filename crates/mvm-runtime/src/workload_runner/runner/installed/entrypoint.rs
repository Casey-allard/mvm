//! One entrypoint invocation over the session that activated this original guest.

use super::*;
use mvm_agentd::vsock::{EntrypointEvent, GuestRequest};
use mvm_core::plan::ExecutionPlan;

fn has_verb(plan: &ExecutionPlan, verb: &str) -> bool {
    plan.agent_verbs
        .as_ref()
        .is_some_and(|verbs| verbs.iter().any(|item| item.as_str() == verb))
}

fn selects_journal(plan: &ExecutionPlan) -> bool {
    plan.mailbox.is_some_and(|grant| {
        grant.retention.is_some()
            && grant.durable_object_pair_sha256_v1.is_none()
            && (grant.incoming_journal_policy_sha256_v1.is_some()
                ^ grant.outbound_journal_v1.is_some())
    })
}

fn deadline(plan: &ExecutionPlan, until: Instant, seconds: u32) -> Result<Instant> {
    deadline_with_cap(plan, until, Some(Duration::from_secs(seconds.into())))
}

fn deadline_with_cap(
    plan: &ExecutionPlan,
    until: Instant,
    cap: Option<Duration>,
) -> Result<Instant> {
    let start = Instant::now();
    let now = chrono::Utc::now();
    anyhow::ensure!(
        plan.valid_from <= now && now < plan.valid_until,
        "original entrypoint plan is outside its validity window"
    );
    let validity = (plan.valid_until - now).to_std()?;
    let budget = cap.map_or(validity, |cap| validity.min(cap));
    let end = until.min(
        start
            .checked_add(budget)
            .context("original entrypoint deadline overflow")?,
    );
    anyhow::ensure!(end > start, "original entrypoint deadline expired");
    Ok(end)
}

impl InstalledSlot {
    pub(in crate::workload_runner::runner) fn activate_entrypoint(
        &self,
        vm: &dyn RunningVm,
        config: &mvm_core::vm_backend::VmStartConfig,
        boot_cmdline: &str,
    ) -> Result<bool> {
        let plan = mvm_core::plan::plan_from_admitted_json(
            config
                .plan_json
                .as_deref()
                .context("original signed plan missing")?,
        )?;
        if !has_verb(&plan, "run-entrypoint") {
            return Ok(false);
        }
        anyhow::ensure!(
            has_verb(&plan, "activate-environment")
                && plan.stream_edges.is_empty()
                && !plan.stream_retention.persists()
                && cmdline::uses_installed_payload_anchor(config),
            "installed entrypoint requires original activation and registered direct endpoint"
        );
        // This is the exact in-memory VmmSpec passed to the original backend.
        // prepare_workload_boot refused an incoming signer token, then appended
        // only the checked registered signer's public key before boot.
        let host = mvm_agentd::vsock::verifying_key_from_hex(
            mvm_agentd::vsock::host_signer_pub_token(boot_cmdline)
                .context("original registered host key missing from boot spec")?,
        )?;
        let until = deadline(
            &plan,
            Instant::now() + crate::microvm::activation::ACTIVATION_READY_TIMEOUT,
            plan.resources.timeouts.boot_secs,
        )?;
        let channel = crate::microvm::activation::activate_installed_entrypoint(
            vm,
            config,
            &plan,
            &host,
            boot_cmdline,
            until,
        )?;
        let journal = if selects_journal(&plan) {
            anyhow::ensure!(
                plan.agent_verbs
                    .as_ref()
                    .is_some_and(|verbs| verbs.len() == 2),
                "original journal requires only activation and entrypoint verbs"
            );
            let boot = mvm_core::mailbox::reader::MailboxReaderBootBinding::load(&vm_state_dir(
                &config.name,
            ))?;
            boot.check_plan(&plan)?;
            let journal = channel.finish_journal_activation(until)?;
            self.owner
                .check_parent_current(config, BackendKind::Firecracker)?;
            Some((journal, boot))
        } else {
            let mut state = self.access()?;
            let custody = state
                .as_mut()
                .context("original entrypoint custody absent")?;
            anyhow::ensure!(
                custody.entrypoint.is_none() && custody.journal.is_none() && !custody.retired,
                "original activation already claimed"
            );
            custody.entrypoint = Some(channel);
            return Ok(true);
        };
        let mut state = self.access()?;
        let custody = state
            .as_mut()
            .context("original entrypoint custody absent")?;
        anyhow::ensure!(
            custody.entrypoint.is_none() && custody.journal.is_none() && !custody.retired,
            "original activation already claimed"
        );
        if let Some((journal, boot)) = journal {
            custody.journal = Some(journal);
            custody.journal_boot = Some(boot);
        }
        Ok(true)
    }

    pub(in crate::workload_runner::runner) fn run_entrypoint(
        &self,
        until: Instant,
        event: &mut dyn FnMut(&EntrypointEvent),
    ) -> Result<EntrypointEvent> {
        let (mut channel, config, until, seconds) = {
            let mut guarded = self.access()?;
            let state = guarded
                .as_mut()
                .context("original entrypoint slot missing")?;
            anyhow::ensure!(
                !state.retired
                    && state.failure.is_none()
                    && !state.entrypoint_busy
                    && state.vm.is_some(),
                "original entrypoint unavailable"
            );
            let config = state
                .launch
                .as_ref()
                .context("original launch missing")?
                .1
                .config();
            self.owner
                .check_parent_current(config, BackendKind::Firecracker)?;
            let plan = mvm_core::plan::plan_from_admitted_json(
                config
                    .plan_json
                    .as_deref()
                    .context("original signed plan missing")?,
            )?;
            anyhow::ensure!(
                has_verb(&plan, "run-entrypoint") && has_verb(&plan, "activate-environment"),
                "original plan does not authorize this entrypoint"
            );
            let until = deadline(&plan, until, plan.resources.timeouts.exec_secs)?;
            let seconds = until.saturating_duration_since(Instant::now()).as_secs();
            anyhow::ensure!(
                seconds > 0,
                "original deadline cannot fund a whole guest timeout second"
            );
            let config = config.clone();
            let channel = state
                .entrypoint
                .take()
                .context("original entrypoint unactivated or already spent")?;
            state.entrypoint_busy = true;
            (channel, config, until, seconds)
        };
        // One externally observable write spends this activated session even on
        // ambiguous loss or callback unwind. Never replace it with a new dial.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let request = GuestRequest::RunEntrypoint {
                stdin: Vec::new(),
                timeout_secs: seconds,
                env: mvm_core::guest_netd::proxy_env_vars(
                    mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN,
                ),
                stream_input: false,
            };
            observe_current(
                || {
                    self.owner
                        .check_parent_current(&config, BackendKind::Firecracker)?;
                    anyhow::ensure!(
                        Instant::now() < until,
                        "original entrypoint deadline expired"
                    );
                    Ok(())
                },
                |checked_event| channel.entrypoint(&request, until, checked_event),
                event,
            )
        }));
        drop(channel);
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("original entrypoint slot poisoned"))?
            .as_mut()
            .context("original entrypoint slot missing after dispatch")?
            .entrypoint_busy = false;
        result.map_err(|_| anyhow::anyhow!("original entrypoint dispatch unwound"))?
    }
}

#[path = "journal.rs"]
mod journal;

/// A rejected original event is never exposed to the capture sink or observer.
/// Latch the first refusal even if a later read would find current authority.
fn observe_current(
    mut check: impl FnMut() -> Result<()>,
    dispatch: impl FnOnce(&mut dyn FnMut(&EntrypointEvent)) -> Result<EntrypointEvent>,
    event: &mut dyn FnMut(&EntrypointEvent),
) -> Result<EntrypointEvent> {
    check()?;
    let mut refusal = None;
    let terminal = dispatch(&mut |frame| {
        if refusal.is_none() {
            match check() {
                Ok(()) => event(frame),
                Err(error) => refusal = Some(error),
            }
        }
    });
    if let Some(error) = refusal {
        return Err(error);
    }
    check()?;
    terminal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_control_selection_requires_retained_directed_mailbox_not_just_verbs() {
        use mvm_contract::protocol::mailbox::{
            ExecutionEpoch, MailboxGrant, MailboxId, MailboxRetentionPolicy,
        };
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        assert!(!selects_journal(&plan));
        let mut grant = MailboxGrant {
            durable_object_pair_sha256_v1: None,
            incoming_journal_policy_sha256_v1: None,
            outbound_journal_v1: None,
            mailbox: MailboxId::from_bytes([1; 32]),
            authority_key: [2; 32],
            epoch: ExecutionEpoch::new(1).unwrap(),
            report: None,
            retention: Some(MailboxRetentionPolicy::new(1000).unwrap()),
        };
        plan.mailbox = Some(grant);
        assert!(!selects_journal(&plan));
        grant.incoming_journal_policy_sha256_v1 = Some([3; 32]);
        plan.mailbox = Some(grant);
        assert!(selects_journal(&plan));
        grant.durable_object_pair_sha256_v1 = Some([4; 32]);
        plan.mailbox = Some(grant);
        assert!(!selects_journal(&plan));
        grant.durable_object_pair_sha256_v1 = None;
        grant.retention = None;
        plan.mailbox = Some(grant);
        assert!(!selects_journal(&plan));
    }

    #[test]
    fn lost_parent_authority_withholds_originating_event_and_terminal() {
        let mut observed = 0;
        let mut checks = 0;
        let result = observe_current(
            || {
                checks += 1;
                anyhow::ensure!(checks != 2, "original parent closed");
                Ok(())
            },
            |callback| {
                callback(&EntrypointEvent::Stdout { chunk: vec![1] });
                callback(&EntrypointEvent::Stderr { chunk: vec![2] });
                Ok(EntrypointEvent::Exit { code: 0 })
            },
            &mut |_| observed += 1,
        );
        assert_eq!(result.unwrap_err().to_string(), "original parent closed");
        assert_eq!(observed, 0);
        assert_eq!(checks, 2);
    }
}
