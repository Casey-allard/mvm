//! The installed manager keeps at most one fixed-size local acceptance. The
//! daemon can independently expire its terminal inventory. Losing either
//! remote acknowledgment never creates an acceptance here.
use super::*;

#[derive(Eq, PartialEq)]
struct Original {
    worker: MailboxWorkerOwner,
    nonce: [u8; 32],
}

#[derive(Default)]
pub(super) struct TerminalAcceptance(Mutex<Option<LocalCleanup>>);

struct LocalCleanup {
    original: Original,
    completed: bool,
}

impl TerminalAcceptance {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<LocalCleanup>>> {
        self.0
            .try_lock()
            .map_err(|_| anyhow::anyhow!("original mailbox cleanup pending or unavailable"))
    }

    pub(super) fn while_vacant<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let slot = self.lock()?;
        ensure!(
            slot.is_none(),
            "original mailbox cleanup not yet acknowledged"
        );
        operation()
    }

    /// All operations on this one-VM manager use a nonblocking lock. Competing
    /// callers retry instead of waiting for its service I/O or local cleanup.
    pub(super) fn finish(
        &self,
        worker: MailboxWorkerOwner,
        nonce: [u8; 32],
        retiring: bool,
        validate_original: impl FnOnce() -> Result<()>,
        confirm_services: impl FnOnce() -> Result<()>,
        cleanup_local: impl FnOnce() -> Result<()>,
        acknowledge: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let original = Original { worker, nonce };
        let mut slot = self.lock()?;
        if let Some(pending) = slot.as_ref() {
            ensure!(
                pending.original == original,
                "another original mailbox awaits cleanup acknowledgment"
            );
            ensure!(
                pending.completed,
                "original backend cleanup is unresolved; a name cannot authorize replay"
            );
        } else {
            ensure!(
                !retiring,
                "retirement marker has no original backend cleanup confirmation"
            );
        }
        validate_original()?;
        if slot.is_none() {
            confirm_services()?;
            *slot = Some(LocalCleanup {
                original,
                completed: false,
            });
            // A failure or panic can leave a partially stopped native backend.
            // Re-entry by VM name is forbidden. Only a successful original
            // callback permits retrying the non-destructive locator retirement.
            cleanup_local()?;
            slot.as_mut()
                .context("original local cleanup lost")?
                .completed = true;
        }
        acknowledge()?;
        *slot = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker() -> MailboxWorkerOwner {
        MailboxWorkerOwner {
            daemon_boot_nonce: [1; 32],
            generation: 1,
            lease: [2; 32],
            context_commitment: [3; 32],
        }
    }

    #[test]
    fn terminal_acceptance_requires_both_confirmations_and_exact_original_until_commit()
    -> Result<()> {
        let retained = TerminalAcceptance::default();
        let nonce = [4; 32];
        let forbidden = || -> Result<()> { panic!("unexpected action") };
        let yes = || Ok(());
        let checked = || {
            ensure!(
                retained.while_vacant(forbidden).is_err(),
                "native entry raced validation"
            );
            Ok(())
        };
        ensure!(
            retained
                .finish(
                    worker(),
                    nonce,
                    true,
                    forbidden,
                    forbidden,
                    forbidden,
                    forbidden
                )
                .is_err()
        );
        ensure!(
            retained
                .finish(
                    worker(),
                    nonce,
                    false,
                    checked,
                    || bail!("lost paired removal reply"),
                    forbidden,
                    forbidden
                )
                .is_err()
        );
        ensure!(
            retained
                .finish(worker(), nonce, false, checked, yes, yes, || bail!(
                    "durable retirement failed"
                ))
                .is_err()
        );
        let mut other = worker();
        other.generation = 2;
        ensure!(
            retained
                .finish(
                    other, nonce, true, forbidden, forbidden, forbidden, forbidden
                )
                .is_err()
        );
        ensure!(
            retained
                .finish(
                    worker(),
                    [5; 32],
                    true,
                    forbidden,
                    forbidden,
                    forbidden,
                    forbidden
                )
                .is_err()
        );
        ensure!(retained.while_vacant(forbidden).is_err());
        retained.finish(worker(), nonce, true, checked, forbidden, forbidden, yes)?;
        retained.while_vacant(yes)?;
        ensure!(
            retained
                .finish(
                    worker(),
                    nonce,
                    true,
                    forbidden,
                    forbidden,
                    forbidden,
                    forbidden
                )
                .is_err()
        );
        ensure!(
            retained
                .finish(
                    worker(),
                    nonce,
                    false,
                    checked,
                    yes,
                    || bail!("native stop uncertain"),
                    forbidden
                )
                .is_err()
        );
        ensure!(
            retained
                .finish(
                    worker(),
                    nonce,
                    false,
                    forbidden,
                    forbidden,
                    forbidden,
                    forbidden
                )
                .is_err()
        );
        Ok(())
    }
}
