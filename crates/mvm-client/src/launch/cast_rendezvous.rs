//! Bounded, one-shot meeting of the two real SDK launches. Each thread holds
//! its original VM name claim until its own boot files and its peer's are ready.
use anyhow::{Result, bail, ensure};
use mvm_core::vm_backend::VmStartConfig;
use mvm_hostd::{
    mailbox_launch::{
        cast_enrollment::PreparedOriginalCastBoot,
        cast_pair::{InstalledCastParticipant, development::PreparedRole},
    },
    mailbox_process::owned_client::InstalledMailboxClient,
    plan_admission::AdmittedPlan,
};
use std::{
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

/// Immutable borrows for a trusted pair preparer. The SDK regains the unique
/// original admission and VMM configuration before either VMM starts.
pub struct ReservedLaunch {
    pub(crate) plan: Arc<AdmittedPlan>,
    pub(crate) worker: Arc<InstalledMailboxClient>,
    pub(crate) config: Arc<VmStartConfig>,
}
impl ReservedLaunch {
    pub fn participant(&self) -> InstalledCastParticipant<'_> {
        InstalledCastParticipant {
            plan: &self.plan,
            worker: &self.worker,
        }
    }
    pub fn config(&self) -> &VmStartConfig {
        &self.config
    }
}

pub struct OriginalCastRole {
    pub boot: PreparedOriginalCastBoot,
    pub role: PreparedRole,
}

pub type PrepareBoth = dyn Fn(&ReservedLaunch, &ReservedLaunch, Instant) -> Result<[OriginalCastRole; 2]>
    + Send
    + Sync;

enum Phase<T, U> {
    Empty,
    Waiting(usize, T, Instant),
    Preparing,
    Ready([Option<U>; 2]),
    Failed,
}

struct Meeting<T, U, const PUBLICATION: bool = false> {
    phase: Mutex<Phase<T, U>>,
    changed: Condvar,
}
impl<T, U, const PUBLICATION: bool> Meeting<T, U, PUBLICATION> {
    fn new() -> Self {
        Self {
            phase: Mutex::new(Phase::Empty),
            changed: Condvar::new(),
        }
    }
    fn cancel(&self) {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Once both original boot files are staged and the shared deadline
        // checked, withdrawing a single side would make that decision asymmetric.
        if !(PUBLICATION && matches!(*phase, Phase::Ready(_))) {
            *phase = Phase::Failed;
            self.changed.notify_all();
        }
    }
    fn meet(
        &self,
        index: usize,
        input: T,
        deadline: Instant,
        prepare: impl FnOnce(&T, &T, Instant) -> Result<[U; 2]>,
    ) -> Result<U> {
        ensure!(index < 2, "invalid original Cast lane");
        let mut phase = self
            .phase
            .lock()
            .map_err(|_| anyhow::anyhow!("Cast pair state unavailable"))?;
        if PUBLICATION && matches!(*phase, Phase::Ready(_)) {
            bail!("original Cast publication already committed");
        }
        if Instant::now() >= deadline {
            *phase = Phase::Failed;
            self.changed.notify_all();
            bail!("Cast pair admission expired");
        }
        match &*phase {
            Phase::Empty => {
                *phase = Phase::Waiting(index, input, deadline);
            }
            Phase::Waiting(other, _, _) if *other != index => {
                let Phase::Waiting(_, peer, original_deadline) =
                    std::mem::replace(&mut *phase, Phase::Preparing)
                else {
                    unreachable!()
                };
                let limit = deadline.min(original_deadline);
                drop(phase);
                let mut guard = FailedPreparation {
                    meeting: self,
                    armed: true,
                };
                ensure!(
                    Instant::now() < limit,
                    "original Cast peer expired while preparing"
                );
                let result = if index == 1 {
                    prepare(&peer, &input, limit)
                } else {
                    prepare(&input, &peer, limit)
                };
                // Release both shared originals *before* waking an SDK that must
                // recover its unique plan, configuration and dispatch authority.
                drop(peer);
                drop(input);
                let result = result?;
                phase = self
                    .phase
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Cast pair state unavailable"))?;
                guard.armed = false;
                if !matches!(*phase, Phase::Preparing) || Instant::now() >= limit {
                    *phase = Phase::Failed;
                    self.changed.notify_all();
                    bail!("Cast pair expired or was cancelled");
                }
                *phase = Phase::Ready(result.map(Some));
                self.changed.notify_all();
            }
            _ => bail!("Cast pair lane is already occupied or retired"),
        }
        self.receive(phase, index, deadline)
    }
    fn receive<'a>(
        &'a self,
        mut phase: std::sync::MutexGuard<'a, Phase<T, U>>,
        index: usize,
        deadline: Instant,
    ) -> Result<U> {
        loop {
            if Instant::now() >= deadline && !(PUBLICATION && matches!(*phase, Phase::Ready(_))) {
                *phase = Phase::Failed;
                self.changed.notify_all();
                bail!("original Cast admission expired");
            }
            match &mut *phase {
                Phase::Ready(results) => {
                    return results[index]
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("original Cast role already consumed"));
                }
                Phase::Failed => bail!("original Cast peer cancelled or expired"),
                _ => {}
            }
            phase = self
                .changed
                .wait_timeout(phase, deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| anyhow::anyhow!("Cast pair state unavailable"))?
                .0;
        }
    }
}

struct FailedPreparation<'a, T, U, const PUBLICATION: bool> {
    meeting: &'a Meeting<T, U, PUBLICATION>,
    armed: bool,
}
impl<T, U, const PUBLICATION: bool> Drop for FailedPreparation<'_, T, U, PUBLICATION> {
    fn drop(&mut self) {
        if self.armed {
            self.meeting.cancel()
        }
    }
}

/// One installed pair, one direction, one pre-boot ceremony. Reuse needs a
/// new installation and fresh original issuer lanes. No polling or retries.
pub struct OriginalCastPair {
    names: [String; 2],
    wait: Duration,
    prepare: Arc<PrepareBoth>,
    admitted: Meeting<ReservedLaunch, OriginalCastRole>,
    published: Meeting<(), (), true>,
}
impl OriginalCastPair {
    pub(crate) fn new(
        names: [String; 2],
        wait: Duration,
        prepare: Arc<PrepareBoth>,
    ) -> Result<Self> {
        ensure!(
            names[0] != names[1] && wait > Duration::ZERO && wait <= Duration::from_secs(30),
            "invalid original Cast pair or wait"
        );
        Ok(Self {
            names,
            wait,
            prepare,
            admitted: Meeting::new(),
            published: Meeting::new(),
        })
    }
    pub(crate) fn index(&self, name: &str) -> Result<usize> {
        self.names
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| anyhow::anyhow!("VM outside original Cast pair"))
    }
    pub(crate) fn cancel_on_drop<'a>(&'a self, name: &'a str) -> PairLaunchCancellation<'a> {
        PairLaunchCancellation {
            pair: self,
            name,
            armed: true,
        }
    }
    pub(crate) fn cancel(&self, name: &str) {
        if self.names.iter().any(|n| n == name) {
            self.admitted.cancel();
            self.published.cancel();
        }
    }
    pub(crate) fn admit(&self, launch: ReservedLaunch) -> Result<(OriginalCastRole, Instant)> {
        let index = self.index(&launch.config.name)?;
        let expiry = launch
            .plan
            .plan()
            .valid_until
            .signed_duration_since(chrono::Utc::now())
            .to_std()
            .unwrap_or_default();
        let deadline = Instant::now() + expiry.min(self.wait);
        let role = self.admitted.meet(index, launch, deadline, |a, b, limit| {
            use mvm_hostd::mailbox_launch::cast_pair::development::EndpointRole;
            let roles = (self.prepare)(a, b, limit)?;
            let source = roles[0]
                .boot
                .role_commitment(&roles[0].role, EndpointRole::Source)?;
            let destination = roles[1]
                .boot
                .role_commitment(&roles[1].role, EndpointRole::Destination)?;
            ensure!(
                source == destination,
                "original SDK launches have different Cast directions"
            );
            Ok(roles)
        })?;
        Ok((role, deadline))
    }
    pub(crate) fn published(&self, name: &str, deadline: Instant) -> Result<()> {
        self.published
            .meet(self.index(name)?, (), deadline, |_, _, _| Ok([(), ()]))
    }
}

pub(crate) struct PairLaunchCancellation<'a> {
    pair: &'a OriginalCastPair,
    name: &'a str,
    armed: bool,
}
impl PairLaunchCancellation<'_> {
    pub(crate) fn disarm(&mut self) {
        self.armed = false
    }
}
impl Drop for PairLaunchCancellation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.pair.cancel(self.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_arrivals_order_once_and_retire_without_replacement() {
        let pair = Meeting::<i32, i32>::new();
        std::thread::scope(|s| {
            let a = s.spawn(|| {
                pair.meet(0, 11, Instant::now() + Duration::from_secs(2), |a, b, _| {
                    Ok([a + b, b - a])
                })
            });
            let b = pair
                .meet(1, 32, Instant::now() + Duration::from_secs(2), |a, b, _| {
                    Ok([a + b, b - a])
                })
                .unwrap();
            assert_eq!(a.join().unwrap().unwrap(), 43);
            assert_eq!(b, 21);
        });
        assert!(
            pair.meet(0, 5, Instant::now() + Duration::from_secs(1), |_, _, _| Ok(
                [0, 0]
            ))
            .is_err()
        );
    }
    // Park the first SDK immediately after lodging its original input. The
    // second SDK drives the real commit; the first reads it after its deadline.
    #[test]
    fn committed_publication_survives_delayed_original_and_late_cancellation() {
        let pair = Meeting::<(), u8, true>::new();
        let deadline = Instant::now() + Duration::from_millis(40);
        *pair.phase.lock().unwrap() = Phase::Waiting(0, (), deadline);
        assert_eq!(
            pair.meet(1, (), deadline, |_, _, _| Ok([11, 22])).unwrap(),
            22
        );
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        pair.cancel();
        assert!(
            pair.meet(1, (), deadline, |_, _, _| unreachable!())
                .is_err()
        );
        assert_eq!(
            pair.receive(pair.phase.lock().unwrap(), 0, deadline)
                .unwrap(),
            11
        );
        assert!(
            pair.receive(pair.phase.lock().unwrap(), 0, deadline)
                .is_err()
        );
    }
    #[test]
    fn missing_expired_or_cancelled_original_wakes_peer() {
        let missing = Meeting::<u8, u8>::new();
        assert!(
            missing
                .meet(
                    0,
                    1,
                    Instant::now() + Duration::from_millis(8),
                    |_, _, _| Ok([0, 0])
                )
                .is_err()
        );
        let failed = Meeting::<u8, u8>::new();
        std::thread::scope(|s| {
            let a = s.spawn(|| {
                failed.meet(0, 1, Instant::now() + Duration::from_secs(3), |_, _, _| {
                    Ok([0, 0])
                })
            });
            failed.cancel();
            assert!(a.join().unwrap().is_err());
        });
        let refused = Meeting::<u8, u8>::new();
        std::thread::scope(|s| {
            let a = s.spawn(|| {
                refused.meet(0, 1, Instant::now() + Duration::from_secs(3), |_, _, _| {
                    bail!("original withdrawn")
                })
            });
            assert!(
                refused
                    .meet(
                        1,
                        2,
                        Instant::now() + Duration::from_secs(3),
                        |_, _, _| bail!("original withdrawn")
                    )
                    .is_err()
            );
            assert!(a.join().unwrap().is_err());
        });
    }
    #[test]
    fn abort_while_both_originals_are_in_preparation_wakes_waiting_launch() {
        let pair = Meeting::<usize, usize>::new();
        let (began, entered) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let (woke, waiting) = std::sync::mpsc::sync_channel(1);
        let until = Instant::now() + Duration::from_secs(4);
        std::thread::scope(|s| {
            s.spawn(|| {
                let verdict = pair.meet(0, 11, until, |_, _, _| unreachable!());
                woke.send(verdict.is_err()).unwrap();
            });
            // Observe Waiting(index=0) before spawning the preparer. This is
            // a deterministic fixture condition, independent of task order.
            while !matches!(*pair.phase.lock().unwrap(), Phase::Waiting(0, _, _)) {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            let p = &pair;
            s.spawn(move || {
                assert!(
                    p.meet(1, 32, until, |_, _, _| {
                        began.send(()).unwrap();
                        resume.recv_timeout(Duration::from_secs(2)).unwrap();
                        Ok([11, 32])
                    })
                    .is_err()
                )
            });
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            pair.cancel();
            // The waiting SDK must be free to clean up before the trusted
            // preparer returns or releases its borrow of the old slot.
            assert!(waiting.recv_timeout(Duration::from_secs(1)).unwrap());
            release.send(()).unwrap();
        });
    }

    #[test]
    fn both_admissions_release_original_arcs_before_dispatch_returns() {
        let pair = Meeting::<Arc<u8>, usize>::new();
        let left = Arc::new(41);
        let right = Arc::new(43);
        let until = Instant::now() + Duration::from_secs(2);
        std::thread::scope(|s| {
            let a = s.spawn(|| {
                assert_eq!(
                    pair.meet(0, left.clone(), until, |a, b, _| Ok([
                        **a as usize,
                        **b as usize
                    ]))
                    .unwrap(),
                    41
                );
                assert_eq!(Arc::strong_count(&left), 1);
            });
            assert_eq!(
                pair.meet(1, right.clone(), until, |a, b, _| Ok([
                    **a as usize,
                    **b as usize
                ]))
                .unwrap(),
                43
            );
            assert_eq!(Arc::strong_count(&right), 1);
            a.join().unwrap();
        });
    }
}
