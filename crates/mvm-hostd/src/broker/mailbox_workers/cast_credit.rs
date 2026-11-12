//! A single charged addressed-Cast turn for this installed coordinator. Credits
//! are part of the existing host/tenant ledger and leave control headroom.
use super::*;

pub(crate) const CAST_BODY_LIMIT: usize = 4096;
pub(crate) const CAST_WORK_BYTES: usize = 8 * CAST_BODY_LIMIT;

#[derive(Default)]
pub(super) struct CastLane {
    active: std::sync::Weak<HandoffWorkspace>,
    source_active: bool,
    original_source: std::sync::Weak<HandoffWorkspace>,
    last_admission: Option<Instant>,
}

pub(crate) struct CastCredit<'a> {
    workers: &'a MailboxWorkers,
    charge: Arc<HandoffWorkspace>,
    source: (&'a str, &'a MailboxWorkerOwner),
    destination: (&'a str, &'a MailboxWorkerOwner),
}

impl MailboxWorkers {
    fn check_cast_participants(
        &self,
        source: (&str, &MailboxWorkerOwner),
        destination: (&str, &MailboxWorkerOwner),
    ) -> io::Result<()> {
        self.with_cast_participants(source, destination, |_, _| Ok(()))
    }

    fn with_cast_participants<T>(
        &self,
        source: (&str, &MailboxWorkerOwner),
        destination: (&str, &MailboxWorkerOwner),
        operation: impl FnOnce(&mut Worker, &mut Worker) -> io::Result<T>,
    ) -> io::Result<T> {
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
        operation(
            a.worker
                .as_mut()
                .ok_or_else(|| refused("source child absent"))?,
            b.worker
                .as_mut()
                .ok_or_else(|| refused("destination child absent"))?,
        )
    }

    /// Bind original slots directly in the coordinator that owns them. The
    /// release source's signed context commitment includes the VM, backend,
    /// grant, tenant, workload and the exact admitted plan digest.
    pub(crate) fn claim_original_cast_turn(
        &self,
        source: (&str, &MailboxWorkerOwner),
        destination: (&str, &MailboxWorkerOwner),
        direction: [u8; 32],
        nonce: [u8; 32],
    ) -> io::Result<()> {
        use crate::mailbox_process::owned_wire::ReadyIngress;
        self.with_cast_participants(source, destination, |a, b| {
            if nonce == [0; 32]
                || direction == [0; 32]
                || a.ingress != ReadyIngress::CastSource(direction)
                || b.ingress != ReadyIngress::CastDestination(direction)
                || a.cast_control_nonce.is_some()
            {
                return Err(refused(
                    "original Cast control refused or already attempted",
                ));
            }
            a.cast_control_nonce = Some(nonce);
            Ok(())
        })
    }
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
        if lane.active.upgrade().is_some()
            || lane
                .last_admission
                .is_some_and(|last| last.elapsed() < std::time::Duration::from_secs(60))
        {
            return Err(refused("addressed Cast lane busy or rate limited"));
        }
        if self.budget.cleanup.failed.load(Ordering::Acquire) {
            return Err(refused("original Cast accounting unavailable"));
        }
        self.budget.charge_cast_space(&self.tenant)?;
        let charge = Arc::new(HandoffWorkspace {
            ledger: self.budget.ledger.clone(),
            failed: self.budget.cleanup.failed.clone(),
            tenant: self.tenant.clone(),
        });
        lane.active = Arc::downgrade(&charge);
        Ok(CastCredit {
            charge,
            workers: self,
            source,
            destination,
        })
    }
}

impl MailboxWorkers {
    /// Reserve the source generation before its first pull. A reconnect to
    /// the same authenticated original reuses its reservation. The process
    /// can still retain a sealed request after all its sockets are gone.
    pub(crate) fn retain_original_source(
        &self,
        source: (&str, &MailboxWorkerOwner),
        destination: (&str, &MailboxWorkerOwner),
        peer: &UnixStream,
        direction: [u8; 32],
    ) -> io::Result<()> {
        use crate::mailbox_process::owned_wire::ReadyIngress;
        let _activation = self.try_activation()?;
        let pid = mvm_vmm::host::uds_peer::connected_peer_pid(peer)?;
        self.with_cast_participants(source, destination, |a, b| {
            if u32::try_from(pid).ok() != Some(a.child.id())
                || direction == [0; 32]
                || a.ingress != ReadyIngress::CastSource(direction)
                || b.ingress != ReadyIngress::CastDestination(direction)
            {
                return Err(refused("source socket or original role mismatch"));
            }
            if self.budget.cleanup.failed.load(Ordering::Acquire) {
                return Err(refused("source accounting unavailable"));
            }
            let mut lane = lock(&self.cast_lane)?;
            if let Some(held) = lane.original_source.upgrade() {
                return if a
                    .source_workspace
                    .as_ref()
                    .is_some_and(|w| Arc::ptr_eq(&held, w))
                {
                    Ok(())
                } else {
                    Err(refused("another original owns the source workspace"))
                };
            }
            if lane.source_active || a.source_workspace.is_some() {
                return Err(refused("source workspace already owned"));
            }
            self.budget.charge_cast_space(&self.tenant)?;
            let allocation = Arc::new(HandoffWorkspace {
                ledger: self.budget.ledger.clone(),
                failed: self.budget.cleanup.failed.clone(),
                tenant: self.tenant.clone(),
            });
            lane.original_source = Arc::downgrade(&allocation);
            a.source_workspace = Some(allocation);
            Ok(())
        })
    }
}

/// Distinct from the short forwarding credit: the original A helper must
/// retain its exact sealed request across reconnects without blocking the
/// A→B forwarding lane. Both draw from the same real tenant/host ledger.
pub(crate) struct SourceCredit<'a>(&'a MailboxWorkers);
impl MailboxWorkers {
    pub(crate) fn reserve_cast_source<'a>(
        &'a self,
        source: (&str, &MailboxWorkerOwner),
        destination: (&str, &MailboxWorkerOwner),
    ) -> io::Result<SourceCredit<'a>> {
        let _activation = self.try_activation()?;
        self.check_cast_participants(source, destination)?;
        let mut lane = lock(&self.cast_lane)?;
        if lane.source_active || lane.original_source.upgrade().is_some() {
            return Err(refused("original source slot is already retained"));
        }
        self.budget.charge_cast_space(&self.tenant)?;
        lane.source_active = true;
        Ok(SourceCredit(self))
    }
}
impl Drop for SourceCredit<'_> {
    fn drop(&mut self) {
        let result = lock(&self.0.cast_lane).and_then(|mut lane| {
            let mut ledger = lock(&self.0.budget.ledger)?;
            refund_bytes(&mut ledger, &self.0.tenant, CAST_WORK_BYTES)?;
            lane.source_active = false;
            Ok(())
        });
        if result.is_err() {
            self.0.budget.cleanup.failed.store(true, Ordering::Release);
        }
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
/// The routing call and the original receiving process can hold the same
/// allocation. A dropped caller or a lost reply does not close the process.
pub(super) struct HandoffWorkspace {
    ledger: Arc<Mutex<Ledger>>,
    failed: Arc<AtomicBool>,
    tenant: String,
}
impl Drop for HandoffWorkspace {
    fn drop(&mut self) {
        if lock(&self.ledger)
            .and_then(|mut ledger| refund_bytes(&mut ledger, &self.tenant, CAST_WORK_BYTES))
            .is_err()
        {
            self.failed.store(true, Ordering::Release);
        }
    }
}

impl CastCredit<'_> {
    /// Link the real connected peer to its still-held original Child before
    /// writing any bytes. An incomplete exchange retains the allocation
    /// until that Child is collected. No PID reopen or filesystem receipt.
    fn receiving_worker<T>(
        &self,
        pid: i32,
        visit: impl FnOnce(&mut Worker) -> io::Result<T>,
    ) -> io::Result<T> {
        let slots = lock(&self.workers.slots)?;
        let mut slot = lock(
            slots
                .get(self.destination.0)
                .ok_or_else(|| refused("destination slot absent"))?,
        )?;
        if &slot.owner != self.destination.1 || slot.busy {
            return Err(refused("destination worker changed or busy"));
        }
        let worker = slot
            .worker
            .as_mut()
            .ok_or_else(|| refused("destination worker absent"))?;
        if u32::try_from(pid).ok() != Some(worker.child.id()) || collect_child(worker)?.is_some() {
            return Err(refused(
                "socket peer differs from the live original mailbox helper",
            ));
        }
        visit(worker)
    }
    fn hold_for_peer(&self, peer: &UnixStream, direction: [u8; 32]) -> io::Result<i32> {
        let _admission = self.workers.try_activation()?;
        let peer_pid = mvm_vmm::host::uds_peer::connected_peer_pid(peer)?;
        self.workers
            .with_cast_participants(self.source, self.destination, |_, worker| {
                if u32::try_from(peer_pid).ok() != Some(worker.child.id()) {
                    return Err(refused("data socket is not held by original destination"));
                }
                if direction == [0; 32]
                    || worker.ingress
                        != crate::mailbox_process::owned_wire::ReadyIngress::CastDestination(
                            direction,
                        )
                {
                    return Err(refused(
                        "original helper did not select this addressed ingress",
                    ));
                }
                if worker.cast_workspace.is_some() {
                    return Err(refused("original helper still owns an unresolved Cast"));
                }
                worker.cast_workspace = Some(self.charge.clone());
                Ok(peer_pid)
            })
    }
    fn finish_peer_turn(&self, authenticated_pid: i32) -> io::Result<()> {
        self.receiving_worker(authenticated_pid, |worker| {
            if !worker
                .cast_workspace
                .as_ref()
                .is_some_and(|hold| Arc::ptr_eq(hold, &self.charge))
            {
                return Err(refused("no matching original Cast charge"));
            }
            worker.cast_workspace = None;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_process::installed_profile::{InstalledMailboxProfile, MailboxPair};

    #[test]
    fn development_source_and_routed_turn_share_the_unchanged_host_budget() {
        let p = crate::mailbox_process::installed_profile::development_cast_capacity(
            &MailboxPair::new(["a", "b"]).unwrap(),
        );
        assert_eq!(p.queue.max_frame_bytes, 8192);
        assert_eq!(p.queue.max_depth, 2);
        assert_eq!(p.worker.host_bytes, 1024 * 1024);
        assert_eq!(p.worker.tenant_bytes, 1024 * 1024);
        let budget = MailboxWorkerBudget::new(p.worker).unwrap();
        let a = budget.charge("local", Some("a")).unwrap();
        let b = budget.charge("local", Some("b")).unwrap();
        let base = budget.usage().unwrap();
        budget.charge_cast_space("local").unwrap();
        budget.charge_cast_space("local").unwrap();
        assert_eq!(
            budget.usage().unwrap().bytes,
            base.bytes + 2 * CAST_WORK_BYTES
        );
        assert!(budget.charge_cast_space("local").is_err());
        budget.charge("local", None).unwrap();
        budget.release_control("local");
        for _ in 0..2 {
            refund_bytes(&mut budget.ledger.lock().unwrap(), "local", CAST_WORK_BYTES).unwrap();
        }
        assert_eq!(budget.usage().unwrap(), base);
        for (name, cell) in [("a", a), ("b", b)] {
            budget.collected("local").unwrap();
            budget.retire("local", name).unwrap();
            budget.return_cell(cell.unwrap());
        }
    }
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

impl CastCredit<'_> {
    /// One canonical peer frame on a fresh, kernel-identified connection.
    /// Only a complete peer response closes this transfer's temporary
    /// workspace. Errors leave the coordinator's charge on its original
    /// receiving Child through collection, including after this call drops.
    pub(crate) fn exchange_with_original(
        &self,
        stream: &mut UnixStream,
        encoded: &[u8],
        direction: [u8; 32],
        deadline: Instant,
    ) -> anyhow::Result<Result<(), mvm_core::mailbox::frame::Refusal>> {
        let limit = crate::mailbox_process::installed_profile::pair_queue_limits().max_frame_bytes;
        anyhow::ensure!(
            !encoded.is_empty() && encoded.len() <= limit,
            "invalid private peer frame size"
        );
        anyhow::ensure!(Instant::now() < deadline, "expired private handoff");
        // macOS no longer exposes LOCAL_PEERPID after the peer closes.
        // Keep the identity checked before writing on this same connection.
        let authenticated_pid = self.hold_for_peer(stream, direction)?;
        let mut io = crate::mailbox_process::owned_wire::DeadlineStream::new(stream, deadline);
        let verdict = mvm_core::mailbox::frame::strict_peer_verdict(&mut io, encoded)?;
        self.finish_peer_turn(authenticated_pid)?;
        Ok(verdict)
    }
}
