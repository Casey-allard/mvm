//! A single charged addressed-Cast turn for this installed coordinator. Credits
//! are part of the existing host/tenant ledger and leave control headroom.
use super::*;

pub(crate) const CAST_BODY_LIMIT: usize = 4096;
pub(crate) const CAST_WORK_BYTES: usize = 8 * CAST_BODY_LIMIT;

#[derive(Default)]
pub(super) struct CastLane {
    active: bool,
    last_admission: Option<Instant>,
}

pub(crate) struct CastCredit<'a> {
    workers: &'a MailboxWorkers,
    source: (&'a str, &'a MailboxWorkerOwner),
    destination: (&'a str, &'a MailboxWorkerOwner),
}

impl MailboxWorkers {
    fn check_cast_participants(
        &self,
        source: (&str, &MailboxWorkerOwner),
        destination: (&str, &MailboxWorkerOwner),
    ) -> io::Result<()> {
        if source.0 == destination.0 || source.1 == destination.1 {
            return Err(refused("Cast requires two original workers"));
        }
        let current = self.now_unix_ms()?;
        let slots = lock(&self.slots)?;
        // The registry mutex serializes pair lock order. Both originals remain
        // locked in this bounded observation; no socket I/O occurs here.
        let mut a = lock(
            slots
                .get(source.0)
                .ok_or_else(|| refused("missing original sender"))?,
        )?;
        let mut b = lock(
            slots
                .get(destination.0)
                .ok_or_else(|| refused("missing original receiver"))?,
        )?;
        for (slot, original) in [(&mut *a, source.1), (&mut *b, destination.1)] {
            if original.daemon_boot_nonce != self.boot
                || &slot.owner != original
                || slot.request.tenant != self.tenant
                || slot.request.mailbox_grant.local_service.is_none()
                || !slot.delegated
                || slot.busy
                || slot.stop_requested
                || slot.reservation_released
                || slot.state != MailboxWorkerState::Serving
                || current >= slot.request.admission_expires_at_unix_ms
            {
                return Err(refused("Cast worker no longer admitted and Serving"));
            }
            let child = slot
                .worker
                .as_mut()
                .ok_or_else(|| refused("original Cast worker not held"))?;
            if collect_child(child)?.is_some() {
                return Err(refused("original Cast worker has exited"));
            }
        }
        Ok(())
    }

    /// Bind original slots directly in the coordinator that owns them. The
    /// release source's signed context commitment includes the VM, backend,
    /// grant, tenant, workload and the exact admitted plan digest.
    pub(crate) fn original_cast_pair(
        &self,
        source: (&str, &MailboxWorkerOwner),
        destination: (&str, &MailboxWorkerOwner),
    ) -> io::Result<[MailboxWorkerRequest; 2]> {
        self.check_cast_participants(source, destination)?;
        let slots = lock(&self.slots)?;
        let original = |(name, owner): (&str, &MailboxWorkerOwner)| {
            let slot = lock(
                slots
                    .get(name)
                    .ok_or_else(|| refused("original Cast slot absent"))?,
            )?;
            if &slot.owner != owner
                || slot.stop_requested
                || slot.state != MailboxWorkerState::Serving
            {
                return Err(refused("original Cast slot changed"));
            }
            Ok(slot.request.clone())
        };
        Ok([original(source)?, original(destination)?])
    }
    pub(crate) fn reserve_cast<'a>(
        &'a self,
        source: (&'a str, &'a MailboxWorkerOwner),
        destination: (&'a str, &'a MailboxWorkerOwner),
    ) -> io::Result<CastCredit<'a>> {
        let _activation = self.try_activation()?;
        self.check_cast_participants(source, destination)?;
        let mut lane = lock(&self.cast_lane)?;
        if lane.active
            || lane
                .last_admission
                .is_some_and(|last| last.elapsed() < std::time::Duration::from_secs(60))
        {
            return Err(refused("addressed Cast lane busy or rate limited"));
        }
        self.budget.charge_cast_space(&self.tenant)?;
        lane.active = true;
        Ok(CastCredit {
            workers: self,
            source,
            destination,
        })
    }
}

impl MailboxWorkerBudget {
    fn charge_cast_space(&self, tenant_name: &str) -> io::Result<()> {
        let mut ledger = lock(&self.ledger)?;
        let host_headroom = CONTROL_WORKSPACE_BYTES.saturating_sub(ledger.host_controls);
        let tenant_headroom = CONTROL_WORKSPACE_BYTES.saturating_sub(
            ledger
                .tenant_controls
                .get(tenant_name)
                .copied()
                .unwrap_or_default(),
        );
        let account = ledger
            .tenants
            .get(tenant_name)
            .ok_or_else(|| refused("missing original tenant budget"))?;
        let host = ledger
            .host
            .bytes
            .checked_add(CAST_WORK_BYTES)
            .ok_or_else(|| refused("Cast budget overflow"))?;
        let tenant = account
            .bytes
            .checked_add(CAST_WORK_BYTES)
            .ok_or_else(|| refused("Cast budget overflow"))?;
        if host
            .checked_add(host_headroom)
            .is_none_or(|n| n > self.limits.host_bytes)
            || tenant
                .checked_add(tenant_headroom)
                .is_none_or(|n| n > self.limits.tenant_bytes)
        {
            return Err(refused("insufficient shared addressed Cast budget"));
        }
        ledger
            .tenants
            .get_mut(tenant_name)
            .expect("checked under ledger lock")
            .bytes = tenant;
        ledger.host.bytes = host;
        Ok(())
    }
}

impl CastCredit<'_> {
    pub(crate) fn workers(&self) -> &MailboxWorkers {
        self.workers
    }

    pub(crate) fn live(&self) -> io::Result<()> {
        let _activation = self.workers.try_activation()?;
        self.workers
            .check_cast_participants(self.source, self.destination)
    }
    pub(crate) fn admitted(&self) -> io::Result<()> {
        self.live()?;
        lock(&self.workers.cast_lane)?.last_admission = Some(Instant::now());
        Ok(())
    }
}
impl Drop for CastCredit<'_> {
    fn drop(&mut self) {
        // Keep the lane closed on accounting failure; do not mint replacement credit.
        let result = lock(&self.workers.cast_lane).and_then(|mut lane| {
            let mut ledger = lock(&self.workers.budget.ledger)?;
            refund_bytes(&mut ledger, &self.workers.tenant, CAST_WORK_BYTES)?;
            lane.active = false;
            Ok(())
        });
        if result.is_err() {
            self.workers
                .budget
                .cleanup
                .failed
                .store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_process::installed_profile::{InstalledMailboxProfile, MailboxPair};

    #[test]
    fn addressed_cast_shares_the_two_workers_and_preserves_control_headroom() {
        let limits =
            InstalledMailboxProfile::Pair(MailboxPair::new(["a", "b"]).unwrap()).worker_limits();
        let budget = MailboxWorkerBudget::new(limits).unwrap();
        let a = budget.charge("local", Some("a")).unwrap();
        let b = budget.charge("local", Some("b")).unwrap();
        let base = budget.usage().unwrap();
        assert!(budget.charge_cast_space("another-tenant").is_err());
        budget.charge_cast_space("local").unwrap();
        assert_eq!(budget.usage().unwrap().bytes, base.bytes + CAST_WORK_BYTES);
        // Both original workers and the unused control reservation still fit;
        // a second data allocation cannot consume that headroom.
        assert!(budget.charge_cast_space("local").is_err());
        budget.charge("local", None).unwrap();
        budget.release_control("local");
        refund_bytes(&mut budget.ledger.lock().unwrap(), "local", CAST_WORK_BYTES).unwrap();
        assert_eq!(budget.usage().unwrap(), base);
        for (name, cell) in [("a", a), ("b", b)] {
            budget.collected("local").unwrap();
            budget.retire("local", name).unwrap();
            budget.return_cell(cell.unwrap());
        }
    }
}
