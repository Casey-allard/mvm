//! Original failed backend start retained by the same installed provider that
//! issued the mailbox reservation. One active native start shares its one-VM
//! capacity. No process is recovered by resolving an arbitrary VM name.
use super::*;
use mvm_runtime::driver::hvf::ColdHvfBootFailure;

#[derive(Default)]
pub(super) struct NativeStartCustody {
    pending: Mutex<Option<Entered>>,
}
struct Entered {
    owner: MailboxWorkerOwner,
    // None while native code or original-owner recovery is running.
    failure: Option<anyhow::Error>,
}

impl NativeStartCustody {
    pub(super) fn run<T>(
        &self,
        owner: &MailboxWorkerOwner,
        start: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        {
            let mut slot = self.lock()?;
            ensure!(
                slot.is_none(),
                "installed backend start ownership is unresolved"
            );
            *slot = Some(Entered {
                owner: owner.clone(),
                failure: None,
            });
        }
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(start)).unwrap_or_else(|_| {
                Err(anyhow::anyhow!(
                    "installed backend start panicked after entry"
                ))
            });
        let mut slot = self.lock()?;
        match outcome {
            Ok(vm) => {
                *slot = None;
                Ok(vm)
            }
            Err(error) => {
                let message = format!("{error:#}");
                slot.as_mut()
                    .context("original entered start missing")?
                    .failure = Some(error);
                bail!(message)
            }
        }
    }

    pub(super) fn settle(&self, owner: &MailboxWorkerOwner) -> Result<()> {
        self.settle_with(owner, |error| {
            let failure = error.downcast::<ColdHvfBootFailure>()?;
            // The existing native owner knows whether its original child was
            // never launched, already collected, or still requires a live stop.
            if let Err(mut original) = failure.into_released_error() {
                if original.retry_stop().is_err() {
                    return Err(anyhow::Error::new(original));
                }
                drop(original.into_released_error().map_err(anyhow::Error::new)?);
            }
            Ok(())
        })
    }

    fn settle_with(
        &self,
        owner: &MailboxWorkerOwner,
        original_stop: impl FnOnce(anyhow::Error) -> Result<()>,
    ) -> Result<()> {
        let failure = {
            let mut slot = self.lock()?;
            let Some(entered) = slot.as_mut() else {
                return Ok(());
            };
            if &entered.owner != owner {
                // This different acquisition cannot touch the retained original.
                return Ok(());
            }
            entered
                .failure
                .take()
                .context("original backend start is in progress or uncertain")?
        };
        // Keep the slot reserved across potentially blocking native stop.
        let outcome = original_stop(failure);
        let mut slot = self.lock()?;
        match outcome {
            Ok(()) => {
                *slot = None;
                Ok(())
            }
            Err(original) => {
                let diagnostic = format!("{original:#}");
                slot.as_mut()
                    .context("original backend recovery missing")?
                    .failure = Some(original);
                bail!("original backend termination unconfirmed: {diagnostic}")
            }
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<Entered>>> {
        self.pending
            .lock()
            .map_err(|_| anyhow::anyhow!("original backend custody unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(n: u8) -> MailboxWorkerOwner {
        MailboxWorkerOwner {
            daemon_boot_nonce: [1; 32],
            generation: 1,
            lease: [n; 32],
            context_commitment: [3; 32],
        }
    }

    #[test]
    fn entered_backend_error_survives_retry_without_claiming_exit_or_releasing_another_owner() {
        let held = NativeStartCustody::default();
        let a = owner(2);
        let b = owner(4);
        assert!(
            held.run::<()>(&a, || anyhow::bail!("failure after backend entry"))
                .is_err()
        );
        for _ in 0..2 {
            assert!(held.settle(&a).is_err()); // untyped failure cannot prove native exit
        }
        held.settle(&b).unwrap();
        assert!(held.run::<()>(&b, || panic!("second start ran")).is_err());
        held.settle_with(&a, |original| {
            ensure!(original.to_string() == "failure after backend entry");
            Ok(())
        })
        .unwrap();
        held.run(&b, || Ok(())).unwrap();
        held.settle(&b).unwrap();
    }

    #[test]
    fn panicked_backend_keeps_original_slot_and_blocks_cleanup() {
        let held = NativeStartCustody::default();
        let original = owner(1);
        assert!(
            held.run::<()>(&original, || panic!("interrupted native start"))
                .is_err()
        );
        assert!(held.settle(&original).is_err());
        assert!(held.run::<()>(&original, || Ok(())).is_err());
    }
}
