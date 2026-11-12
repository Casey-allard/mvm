//! One SDK rendezvous for two independently admitted, already booted originals.
use super::*;
use crate::mailbox_launch::object_pair::{
    InstalledParticipant, OriginalObjectPlan, PreparedObjectPair,
};
use crate::plan_admission::AdmittedPlan;
use std::sync::{Condvar, Mutex};

struct PairGate {
    state: Mutex<PairState>,
    changed: Condvar,
    until: Instant,
}
#[derive(Default)]
struct PairState {
    originals: [Option<AdmittedPlan>; 2],
    owners: OriginalObjectWorkers,
    outcome: Option<Result<(), String>>,
}
impl PairGate {
    fn cancel(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.outcome.is_none() {
            s.outcome = Some(Err("original object pair launch cancelled".into()));
        }
        self.changed.notify_all();
    }
}
/// Held by the normal SDK entry until both launches have passed the bilateral
/// barrier. Failure or unwind before joining wakes the other original.
pub struct OriginalLaunchGuard(Arc<PairGate>);
impl Drop for OriginalLaunchGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub struct OriginalObjectLaunch<'a> {
    plan: OriginalObjectPlan<'a>,
    pair: &'a PreparedObjectPair,
    idx: usize,
    #[cfg(target_os = "macos")]
    hvf: crate::plan_admission::object_hvf::OriginalHvf,
    gate: Arc<PairGate>,
}

impl PreparedObjectPair {
    pub fn reserve_original_workers<'a>(
        &'a self,
        caller: &'a str,
        a: [u8; 32],
        callee: &'a str,
        b: [u8; 32],
        until: Instant,
    ) -> Result<(OriginalObjectLaunch<'a>, OriginalObjectLaunch<'a>)> {
        let now = Instant::now();
        ensure!(
            until > now && until.duration_since(now) <= std::time::Duration::from_secs(180),
            "original pair launch requires a finite live deadline up to 180 seconds"
        );
        let (a, b) = self.select_original_plans(caller, a, callee, b)?;
        let gate = Arc::new(PairGate {
            state: Mutex::new(PairState::default()),
            changed: Condvar::new(),
            until,
        });
        let lane = |plan, idx| OriginalObjectLaunch {
            plan,
            pair: self,
            idx,
            #[cfg(target_os = "macos")]
            hvf: Default::default(),
            gate: Arc::clone(&gate),
        };
        Ok((lane(a, 0), lane(b, 1)))
    }
}
impl OriginalObjectLaunch<'_> {
    #[cfg(target_os = "macos")]
    pub(crate) fn hvf_original(&self) -> &crate::plan_admission::object_hvf::OriginalHvf {
        &self.hvf
    }
    /// Retry only an unconfirmed pre-worker rollback of this reservation.
    #[cfg(target_os = "macos")]
    pub fn retry_unserved_hvf_rollback(&self) -> Result<()> {
        self.hvf.retry_unserved()
    }
    pub fn plan(&self) -> &OriginalObjectPlan<'_> {
        &self.plan
    }
    pub fn guard(&self) -> OriginalLaunchGuard {
        OriginalLaunchGuard(Arc::clone(&self.gate))
    }
    pub(crate) fn require_open(&self) -> Result<()> {
        let s = self
            .gate
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("original pair launch state poisoned"))?;
        ensure!(
            Instant::now() < self.gate.until
                && s.outcome.is_none()
                && s.originals[self.idx].is_none(),
            "original pair launch is occupied or retired"
        );
        Ok(())
    }
    fn start(&self, s: &mut PairState) -> Result<()> {
        let a = s.originals[0].as_ref().unwrap();
        let b = s.originals[1].as_ref().unwrap();
        // Backend selection supplies the guest mux address only. The VMM
        // identity and authority always come from each original config session.
        let backend_a = AnyBackend::for_started_vm(&a.plan().image.name)
            .ok_or_else(|| anyhow::anyhow!("original A backend unavailable"))?;
        let backend_b = AnyBackend::for_started_vm(&b.plan().image.name)
            .ok_or_else(|| anyhow::anyhow!("original B backend unavailable"))?;
        #[cfg(target_os = "linux")]
        {
            let pair = self.pair.bind_originals(
                InstalledParticipant::from_original_firecracker(a)?,
                InstalledParticipant::from_original_firecracker(b)?,
            )?;
            pair.start_original_workers(&backend_a, &backend_b, &mut s.owners, self.gate.until)
        }
        #[cfg(target_os = "macos")]
        a.object_hvf()?.with_live(|ra| {
            b.object_hvf()?.with_live(|rb| {
                let pair = self.pair.bind_originals(
                    InstalledParticipant::from_original_hvf(a, ra)?,
                    InstalledParticipant::from_original_hvf(b, rb)?,
                )?;
                let result = pair.start_original_workers(
                    &backend_a,
                    &backend_b,
                    &mut s.owners,
                    self.gate.until,
                );
                // A helper may exist even if its peer failed before READY.
                if let Some(worker) = s.owners.caller.as_mut() {
                    worker.stop.hvf = Some(a.object_hvf()?.clone());
                }
                if let Some(worker) = s.owners.callee.as_mut() {
                    worker.stop.hvf = Some(b.object_hvf()?.clone());
                }
                result
            })
        })
    }

    /// Return the same admission even on a failed join. An exec'd helper
    /// stays in its original caller's slot through the resulting SDK rollback.
    pub fn join(
        &self,
        admitted: AdmittedPlan,
        owner: &mut Option<OriginalObjectWorker>,
    ) -> (AdmittedPlan, Result<()>) {
        #[cfg(target_os = "macos")]
        if admitted
            .object_hvf()
            .is_ok_and(|held| !held.same_reservation(&self.hvf))
        {
            return (
                admitted,
                Err(anyhow::anyhow!(
                    "original HVF belongs to a different SDK reservation"
                )),
            );
        }
        let mut s = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        if owner.is_some() || s.originals[self.idx].is_some() || s.outcome.is_some() {
            return (
                admitted,
                Err(anyhow::anyhow!("object pair lane occupied or retired")),
            );
        }
        s.originals[self.idx] = Some(admitted);
        while s.outcome.is_none() {
            if Instant::now() >= self.gate.until {
                s.outcome = Some(Err("original object pair rendezvous expired".into()));
            } else if s.originals.iter().all(Option::is_some) {
                let result = self.start(&mut s).and_then(|()| {
                    ensure!(
                        Instant::now() < self.gate.until,
                        "bilateral service readiness expired"
                    );
                    Ok(())
                });
                s.outcome = Some(result.map_err(|e| format!("{e:#}")));
            } else {
                let remaining = self.gate.until.saturating_duration_since(Instant::now());
                let (state, _) = self
                    .gate
                    .changed
                    .wait_timeout(s, remaining)
                    .unwrap_or_else(|e| e.into_inner());
                s = state;
                continue;
            }
            self.gate.changed.notify_all();
        }
        *owner = if self.idx == 0 {
            s.owners.caller.take()
        } else {
            s.owners.callee.take()
        };
        let result = s
            .outcome
            .as_ref()
            .unwrap()
            .clone()
            .map_err(anyhow::Error::msg);
        (
            s.originals[self.idx]
                .take()
                .expect("owned original registration"),
            result,
        )
    }
}

impl std::fmt::Debug for OriginalObjectLaunch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginalObjectLaunch")
            .field("role", &self.plan)
            .finish_non_exhaustive()
    }
}
