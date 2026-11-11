//! Bounded local coordination for a tenant's daemon and admitted VM launches.
//!
//! These records coordinate original owners. They neither grant permission nor
//! establish process identity or collection. A lost reservation remains visible.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::atomic_io::{FileLock, NewFile, write_private, write_private_new};

const MAX_RECORD_BYTES: usize = 65_536;
const MAX_PENDING: usize = 256;
const MAX_ID_BYTES: usize = 512;

/// A local generation marker, never a capability or an owner receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleGeneration {
    boot: [u8; 32],
    sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecyclePhase {
    Preparing,
    Active,
    Draining,
    Drained,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingLaunch {
    id: String,
    vm: String,
    plan_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    tenant: String,
    generation: LifecycleGeneration,
    revision: u64,
    lock_identity: LockIdentity,
    phase: LifecyclePhase,
    unresolved: bool,
    max_pending: u16,
    #[serde(deserialize_with = "deserialize_pending")]
    pending: Vec<PendingLaunch>,
}

/// Paths selected by an original caller's admitted tenant, not by session JSON.
#[derive(Clone)]
pub struct TenantLifecycleGate {
    home: PathBuf,
    tenant: String,
    directory: PathBuf,
    original_lock: Arc<File>,
}

/// One original launch's pending row. Dropping this never erases uncertainty.
pub struct LaunchReservation {
    gate: TenantLifecycleGate,
    generation: LifecycleGeneration,
    id: String,
    vm: String,
    plan_id: String,
}

/// A bounded observation of coordination state, never an admission receipt.
pub struct LifecycleSnapshot {
    record: Record,
}

/// Sole phase-writing role retained by the original daemon coordinator.
///
/// Core stores coordination facts only. The host must hold its original resource
/// exclusion and stage actual readiness, reconciliation and collection results
/// before using this role. Metadata cannot substitute for any of those results.
pub struct LifecycleCoordinator {
    gate: TenantLifecycleGate,
}

impl LifecycleGeneration {
    /// Bind the original daemon's boot nonce and checked resource epoch.
    pub fn new(boot: [u8; 32], sequence: u64) -> Result<Self> {
        ensure!(
            boot != [0; 32] && sequence > 0,
            "invalid lifecycle generation"
        );
        Ok(Self { boot, sequence })
    }

    /// Recorded local resource epoch only, not a canonical mailbox execution
    /// epoch, permission or validation receipt.
    pub fn resource_epoch(&self) -> u64 {
        self.sequence
    }
}

impl PendingLaunch {
    /// Original row identifier; possession grants no cleanup authority.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// VM identity copied from the original admitted plan.
    pub fn vm(&self) -> &str {
        &self.vm
    }
    /// Original canonical plan identifier.
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
}

impl LifecycleSnapshot {
    /// Original generation retained in this observation.
    pub fn generation(&self) -> &LifecycleGeneration {
        &self.record.generation
    }
    /// Checked mutation counter used to validate an external inventory scan.
    pub fn revision(&self) -> u64 {
        self.record.revision
    }
    /// Current coordination phase.
    pub fn phase(&self) -> LifecyclePhase {
        self.record.phase
    }
    /// Whether unresolved original work remains fenced.
    pub fn unresolved(&self) -> bool {
        self.record.unresolved
    }
    /// Bounded pending launches which require original-owner reconciliation.
    pub fn pending(&self) -> &[PendingLaunch] {
        &self.record.pending
    }
}

impl LifecycleCoordinator {
    /// Open original coordination state without creating, fencing or changing
    /// any record. Startup callers retain actual resource exclusion separately
    /// and must explicitly drain/reconcile this original generation before
    /// beginning a replacement epoch. This observation supplies no authority.
    pub fn open_existing(home: impl AsRef<Path>, tenant: &str, deadline: Instant) -> Result<Self> {
        let gate = TenantLifecycleGate::new(home, tenant)?;
        let lock = gate.lock(deadline)?;
        gate.read_record()?;
        drop(lock);
        Ok(Self { gate })
    }

    /// Fence startup after acquiring original resource exclusion and performing
    /// canonical legacy reconciliation, before spawning any child. Fresh state
    /// is Preparing. Existing generation, limits and rows
    /// survive; an existing lock with missing metadata is never initialized.
    pub fn prepare_after_exclusion(
        home: impl AsRef<Path>,
        tenant: &str,
        generation: LifecycleGeneration,
        max_pending: u16,
        deadline: Instant,
    ) -> Result<Self> {
        ensure!(valid_component(tenant), "invalid lifecycle tenant");
        ensure!(
            max_pending > 0 && usize::from(max_pending) <= MAX_PENDING,
            "invalid pending launch bound"
        );
        LifecycleGeneration::new(generation.boot, generation.sequence)?;
        let home = home.as_ref();
        require_private_directory(home)?;
        for path in [
            crate::config::host_agent_root_at(home),
            crate::config::host_agent_dir_at(home, tenant),
        ] {
            match fs::symlink_metadata(&path) {
                Ok(_) => require_private_directory(&path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    crate::private_fs::create_owned_private_dir(&path)?
                }
                Err(error) => return Err(error.into()),
            }
        }
        ensure!(
            Instant::now() < deadline,
            "lifecycle preparation deadline expired"
        );
        let directory = crate::config::host_agent_dir_at(home, tenant);
        require_no_intent(&directory)?;
        let created =
            write_private_new(&directory.join("lifecycle.lock"), b"")? == NewFile::Created;
        let gate = TenantLifecycleGate::new(home, tenant)?;
        let _lock = gate.lock(deadline)?;
        let (mut record, fresh) = match fs::symlink_metadata(directory.join("lifecycle.json")) {
            Ok(_) => (gate.read_record()?, false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && created => (
                Record {
                    version: 1,
                    tenant: tenant.to_owned(),
                    generation,
                    revision: 0,
                    lock_identity: lock_identity(&gate.original_lock.metadata()?)?,
                    phase: LifecyclePhase::Preparing,
                    unresolved: false,
                    max_pending,
                    pending: Vec::new(),
                },
                true,
            ),
            Err(error) => {
                return Err(error).context("missing or inaccessible initialized lifecycle state");
            }
        };
        if !fresh {
            record.unresolved |= record.phase != LifecyclePhase::Drained;
            record.phase = LifecyclePhase::Draining;
        }
        gate.write_record(&record)?;
        drop(_lock);
        Ok(Self { gate })
    }

    /// Read bounded original state while retaining this coordinator's lock identity.
    pub fn snapshot(&self, deadline: Instant) -> Result<LifecycleSnapshot> {
        let _lock = self.gate.lock(deadline)?;
        Ok(LifecycleSnapshot {
            record: self.gate.read_record()?,
        })
    }

    /// Recheck an external scan with a short read-only local-owner callback,
    /// releasing its nonblocking daemon guard before returning. The same file
    /// turn then persists Draining. Only success permits the caller to install
    /// its local fence and begin cleanup. Error retains the original service
    /// and coordinator; it is not a completed drain or permission to exit.
    pub fn begin_drain<T>(
        &self,
        expected: &LifecycleGeneration,
        expected_revision: u64,
        deadline: Instant,
        action: impl FnOnce(&LifecycleSnapshot) -> Result<T>,
    ) -> Result<T> {
        let _lock = self.gate.lock(deadline)?;
        let mut record = self.gate.read_record()?;
        ensure!(
            &record.generation == expected
                && record.revision == expected_revision
                && record.phase != LifecyclePhase::Drained,
            "lifecycle generation is no longer drainable"
        );
        let result = action(&LifecycleSnapshot {
            record: record.clone(),
        })?;
        record.phase = LifecyclePhase::Draining;
        self.gate.write_record(&record)?;
        Ok(result)
    }

    /// Settle one exact original row after the caller staged successful original
    /// cleanup. This callback checks retained results; it must not perform I/O,
    /// wait for a child, block on a mutex or await while the gate is held.
    pub fn settle_after_original_cleanup(
        &self,
        expected: &LifecycleGeneration,
        row_id: &str,
        deadline: Instant,
        check_original_cleanup: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.gate
            .settle_pending(expected, row_id, None, deadline, check_original_cleanup)
    }

    /// Persist Drained only after staged original collection checks succeed.
    /// These storage facts are not proof that any process was collected.
    pub fn finish_drain_after_collection(
        &self,
        expected: &LifecycleGeneration,
        deadline: Instant,
        check_original_owners: impl FnOnce(&LifecycleSnapshot) -> Result<()>,
    ) -> Result<()> {
        self.persist_drained(expected, None, deadline, check_original_owners)
    }

    /// Record retirement after the caller retained actual resource exclusion
    /// and reconciled a bounded inventory at this exact revision. This is not
    /// original-child collection and must not be logged as such.
    pub fn retire_after_resource_reconciliation(
        &self,
        expected: &LifecycleGeneration,
        expected_revision: u64,
        deadline: Instant,
        check_original_resources: impl FnOnce(&LifecycleSnapshot) -> Result<()>,
    ) -> Result<()> {
        self.persist_drained(
            expected,
            Some(expected_revision),
            deadline,
            check_original_resources,
        )
    }

    fn persist_drained(
        &self,
        expected: &LifecycleGeneration,
        expected_revision: Option<u64>,
        deadline: Instant,
        check_original_owners: impl FnOnce(&LifecycleSnapshot) -> Result<()>,
    ) -> Result<()> {
        let _lock = self.gate.lock(deadline)?;
        let mut record = self.gate.read_record()?;
        ensure!(
            &record.generation == expected && record.phase == LifecyclePhase::Draining,
            "original draining generation changed"
        );
        ensure!(
            expected_revision.is_none_or(|revision| record.revision == revision),
            "resource reconciliation inventory revision changed"
        );
        ensure!(
            record.pending.is_empty(),
            "original launch rows remain unresolved"
        );
        check_original_owners(&LifecycleSnapshot {
            record: record.clone(),
        })?;
        record.phase = LifecyclePhase::Drained;
        record.unresolved = false;
        self.gate.write_record(&record)
    }

    /// Persist uncertainty for an already draining original generation. The
    /// caller uses a separately bounded metadata I/O deadline, not a renewed
    /// cleanup grace. This transition cannot clear rows or loosen the phase.
    pub fn mark_unresolved(&self, expected: &LifecycleGeneration, deadline: Instant) -> Result<()> {
        let _lock = self.gate.lock(deadline)?;
        let mut record = self.gate.read_record()?;
        ensure!(
            &record.generation == expected && record.phase == LifecyclePhase::Draining,
            "only the original draining generation may become unresolved"
        );
        record.unresolved = true;
        self.gate.write_record(&record)
    }

    /// Stage a strictly newer resource epoch before any new child is spawned.
    /// Resource reconciliation must already have retired the prior generation.
    pub fn prepare_generation_after_reconciliation(
        &self,
        generation: &LifecycleGeneration,
        deadline: Instant,
    ) -> Result<()> {
        LifecycleGeneration::new(generation.boot, generation.sequence)?;
        let _lock = self.gate.lock(deadline)?;
        let mut record = self.gate.read_record()?;
        ensure!(
            record.phase == LifecyclePhase::Drained
                && !record.unresolved
                && record.pending.is_empty(),
            "prior generation remains unresolved"
        );
        ensure!(
            generation.sequence > record.generation.sequence,
            "retired resource epoch cannot be prepared again"
        );
        record.generation = generation.clone();
        record.phase = LifecyclePhase::Preparing;
        self.gate.write_record(&record)
    }

    /// Activate only the same Preparing generation, after actual signer and
    /// listener readiness and reconciliation were checked by the host.
    pub fn activate_after_reconciliation(
        &self,
        generation: &LifecycleGeneration,
        deadline: Instant,
    ) -> Result<()> {
        self.activate_after_reconciliation_with(generation, deadline, |_| Ok(()), |_| Ok(()))
    }

    /// Coordinate a host's staged readiness checks and local publication under
    /// one original file turn. Callbacks return no guards and must perform only
    /// short nonblocking memory checks/publication, without I/O or waiting.
    /// They must not own original service/resource custody. The host retains
    /// those owners and its closed external admission fence until success.
    ///
    /// Publication is not atomic: error or panic may follow a partial release.
    /// After an attempted Active write, failure attempts same-generation
    /// Draining/unresolved persistence; a failure of that fence remains explicit.
    /// This storage operation supplies no service/Child readiness receipt.
    pub fn activate_after_reconciliation_with(
        &self,
        generation: &LifecycleGeneration,
        deadline: Instant,
        precheck: impl FnOnce(&LifecycleSnapshot) -> Result<()>,
        publish: impl FnOnce(&LifecycleSnapshot) -> Result<()>,
    ) -> Result<()> {
        self.activate_with_writer(generation, deadline, precheck, publish, |gate, record| {
            gate.write_record(record)
        })
    }

    fn activate_with_writer(
        &self,
        generation: &LifecycleGeneration,
        deadline: Instant,
        precheck: impl FnOnce(&LifecycleSnapshot) -> Result<()>,
        publish: impl FnOnce(&LifecycleSnapshot) -> Result<()>,
        mut write: impl FnMut(&TenantLifecycleGate, &Record) -> Result<()>,
    ) -> Result<()> {
        LifecycleGeneration::new(generation.boot, generation.sequence)?;
        let _lock = self.gate.lock(deadline)?;
        let mut record = self.gate.read_record()?;
        ensure!(
            record.phase == LifecyclePhase::Preparing
                && !record.unresolved
                && record.pending.is_empty()
                && &record.generation == generation,
            "lifecycle reconciliation is incomplete"
        );
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            precheck(&LifecycleSnapshot {
                record: record.clone(),
            })
        }))
        .map_err(|_| anyhow::anyhow!("lifecycle activation precheck panicked"))??;
        ensure!(
            Instant::now() < deadline,
            "lifecycle activation deadline expired"
        );
        record.phase = LifecyclePhase::Active;
        let mut expected = record.clone();
        expected.revision = expected
            .revision
            .checked_add(1)
            .context("lifecycle mutation counter exhausted")?;
        let activated = (|| -> Result<()> {
            write(&self.gate, &record)?;
            ensure!(
                Instant::now() < deadline,
                "lifecycle activation deadline expired"
            );
            self.gate.validate_directory()?;
            let confirmed = self.gate.read_record()?;
            ensure!(
                serde_json::to_vec(&confirmed)? == serde_json::to_vec(&expected)?,
                "original Active lifecycle record changed before publication"
            );
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                publish(&LifecycleSnapshot { record: confirmed })
            }))
            .map_err(|_| anyhow::anyhow!("lifecycle activation publication panicked"))??;
            ensure!(
                Instant::now() < deadline,
                "lifecycle activation deadline expired"
            );
            Ok(())
        })();
        if let Err(original) = activated {
            // This is conservative failure fencing under the SAME retained
            // file turn, not a renewed activation or cleanup-grace grant. Even
            // if the original deadline expired, attempt to close durable Active.
            let fenced = (|| -> Result<()> {
                self.gate.validate_directory()?;
                let mut current = self.gate.read_record()?;
                ensure!(
                    &current.generation == generation,
                    "original activation generation changed during failure fencing"
                );
                current.phase = LifecyclePhase::Draining;
                current.unresolved = true;
                write(&self.gate, &current)
            })();
            return match fenced {
                Ok(()) => Err(original),
                Err(fence) => {
                    Err(original.context(format!("lifecycle failure fence unresolved: {fence:#}")))
                }
            };
        }
        Ok(())
    }
}

impl TenantLifecycleGate {
    fn settle_pending(
        &self,
        expected: &LifecycleGeneration,
        row_id: &str,
        original_identity: Option<(&str, &str)>,
        deadline: Instant,
        check_original_cleanup: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let _lock = self.lock(deadline)?;
        let mut record = self.read_record()?;
        ensure!(
            &record.generation == expected,
            "original cleanup generation changed"
        );
        let index = record.pending.iter().position(|row| row.id == row_id);
        match (index, original_identity) {
            (Some(index), Some((vm, plan_id))) => ensure!(
                record.pending[index].vm == vm && record.pending[index].plan_id == plan_id,
                "original cleanup row identity changed"
            ),
            (None, None) => anyhow::bail!("original launch row is absent"),
            _ => {}
        }
        check_original_cleanup()?;
        if let Some(index) = index {
            record.pending.remove(index);
            self.write_record(&record)?;
        }
        Ok(())
    }
    /// Select an existing private tenant namespace without initializing state.
    pub fn new(home: impl AsRef<Path>, tenant: &str) -> Result<Self> {
        ensure!(valid_component(tenant), "invalid lifecycle tenant");
        let home = home.as_ref().to_path_buf();
        let directory = crate::config::host_agent_dir_at(&home, tenant);
        require_no_intent(&directory)?;
        let lock_path = directory.join("lifecycle.lock");
        let expected = private_file_metadata(&lock_path)?;
        ensure!(
            expected.len() == 0,
            "lifecycle lock has unexpected contents"
        );
        let original_lock = open_metadata(&lock_path)?;
        ensure!(
            same_file(&expected, &original_lock.metadata()?),
            "lifecycle lock identity changed while opening"
        );
        let gate = Self {
            home,
            tenant: tenant.to_owned(),
            directory,
            original_lock: Arc::new(original_lock),
        };
        gate.validate_directory()?;
        Ok(gate)
    }

    /// Reserve before backend activation using the original admitted plan.
    /// Missing or unresolved daemon state is an error, never implicit Active.
    pub fn reserve_launch(
        &self,
        vm: &str,
        plan_id: &str,
        deadline: Instant,
    ) -> Result<LaunchReservation> {
        ensure!(
            valid_component(vm) && valid_identity(plan_id),
            "invalid launch identity"
        );
        let _lock = self.lock(deadline)?;
        let mut record = self.read_record()?;
        ensure!(
            record.phase == LifecyclePhase::Active && !record.unresolved,
            "tenant lifecycle is not Active"
        );
        ensure!(
            record.pending.len() < usize::from(record.max_pending),
            "pending launch capacity exhausted"
        );
        ensure!(
            !record.pending.iter().any(|row| row.vm == vm),
            "VM launch is already pending"
        );
        let id = uuid::Uuid::new_v4().to_string();
        record.pending.push(PendingLaunch {
            id: id.clone(),
            vm: vm.to_owned(),
            plan_id: plan_id.to_owned(),
        });
        self.write_record(&record)?;
        Ok(LaunchReservation {
            gate: self.clone(),
            generation: record.generation,
            id,
            vm: vm.to_owned(),
            plan_id: plan_id.to_owned(),
        })
    }

    /// Coordinate short local preparation under the original Preparing epoch.
    /// This is not an activation or readiness grant. The callback must not
    /// wait, spawn, perform I/O, acquire a blocking mutex or own original
    /// service/resource custody. Its revision is durable before it runs, even
    /// when the memory action subsequently refuses.
    pub fn with_preparing<T>(
        &self,
        expected: &LifecycleGeneration,
        deadline: Instant,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _lock = self.lock(deadline)?;
        let record = self.read_record()?;
        ensure!(
            &record.generation == expected
                && record.phase == LifecyclePhase::Preparing
                && !record.unresolved
                && record.pending.is_empty(),
            "original lifecycle generation is not Preparing"
        );
        self.write_record(&record)?;
        ensure!(
            Instant::now() < deadline,
            "lifecycle preparation deadline expired"
        );
        action()
    }

    /// Coordinate short cleanup memory operations under the original Draining
    /// generation. Pending rows and unresolved state remain intact; this grants
    /// no activation, cleanup authority or original-child collection receipt.
    /// The callback must not wait, spawn, perform I/O, acquire a blocking mutex
    /// or own original service/resource custody. The checked mutation revision
    /// is durable before it runs, even when the callback subsequently refuses.
    pub fn with_draining<T>(
        &self,
        expected: &LifecycleGeneration,
        deadline: Instant,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _lock = self.lock(deadline)?;
        let record = self.read_record()?;
        ensure!(
            &record.generation == expected && record.phase == LifecyclePhase::Draining,
            "original lifecycle generation is not Draining"
        );
        self.write_record(&record)?;
        ensure!(
            Instant::now() < deadline,
            "lifecycle cleanup deadline expired"
        );
        action()
    }

    /// Commit a bounded in-memory admission under the original active generation.
    /// The mutation revision is durably advanced before the callback; a refused
    /// callback conservatively invalidates earlier inventory scans too.
    /// The callback must not wait, spawn, perform socket I/O or acquire a blocking
    /// mutex. On contention it returns an error so retry occurs outside the gate.
    pub fn with_active<T>(
        &self,
        expected: &LifecycleGeneration,
        deadline: Instant,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _lock = self.lock(deadline)?;
        let record = self.read_record()?;
        ensure!(
            &record.generation == expected
                && record.phase == LifecyclePhase::Active
                && !record.unresolved,
            "original lifecycle generation is not Active"
        );
        self.write_record(&record)?;
        ensure!(
            Instant::now() < deadline,
            "lifecycle admission deadline expired"
        );
        action()
    }

    fn validate_directory(&self) -> Result<()> {
        for path in [
            &self.home,
            &crate::config::host_agent_root_at(&self.home),
            &self.directory,
        ] {
            require_private_directory(path)?;
        }
        Ok(())
    }

    fn lock(&self, deadline: Instant) -> Result<FileLock> {
        self.lock_with(deadline, FileLock::try_acquire)
    }

    fn lock_with(
        &self,
        deadline: Instant,
        mut acquire: impl FnMut(&Path) -> Result<Option<FileLock>>,
    ) -> Result<FileLock> {
        let path = self.directory.join("lifecycle.json");
        let lock_path = path.with_extension("lock");
        loop {
            ensure!(Instant::now() < deadline, "lifecycle lock deadline expired");
            self.validate_directory()?;
            require_no_intent(&self.directory)?;
            let before = private_file_metadata(&lock_path)?;
            ensure!(before.len() == 0, "lifecycle lock has unexpected contents");
            let original = self.original_lock.metadata()?;
            ensure!(
                same_file(&original, &before),
                "original lifecycle lock inode was replaced"
            );
            if let Some(lock) = acquire(&path)? {
                let after = private_file_metadata(&lock_path)?;
                ensure!(
                    same_file(&original, &lock.metadata()?) && same_file(&original, &after),
                    "lifecycle lock identity changed"
                );
                self.validate_directory()?;
                ensure!(Instant::now() < deadline, "lifecycle lock deadline expired");
                return Ok(lock);
            }
            std::thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn read_record(&self) -> Result<Record> {
        require_no_intent(&self.directory)?;
        let path = self.directory.join("lifecycle.json");
        let before = private_file_metadata(&path)?;
        ensure!(
            before.len() <= MAX_RECORD_BYTES as u64,
            "lifecycle metadata exceeds limit"
        );
        let mut file = open_metadata(&path)?;
        ensure!(
            same_file(&before, &file.metadata()?),
            "lifecycle metadata identity changed"
        );
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "lifecycle metadata exceeds limit"
        );
        let record: Record = serde_json::from_slice(&bytes).context("decode lifecycle metadata")?;
        ensure!(
            record.version == 1 && record.tenant == self.tenant,
            "lifecycle version or tenant mismatch"
        );
        ensure!(
            record.generation.boot != [0; 32] && record.generation.sequence > 0,
            "invalid lifecycle generation"
        );
        ensure!(
            record.revision > 0
                && (record.phase == LifecyclePhase::Draining || !record.unresolved)
                && (matches!(
                    record.phase,
                    LifecyclePhase::Active | LifecyclePhase::Draining
                ) || record.pending.is_empty()),
            "invalid lifecycle mutation history"
        );
        ensure!(
            record.lock_identity == lock_identity(&self.original_lock.metadata()?)?,
            "lifecycle state belongs to a different lock inode"
        );
        ensure!(
            record.max_pending > 0
                && usize::from(record.max_pending) <= MAX_PENDING
                && record.pending.len() <= usize::from(record.max_pending),
            "invalid pending launch bound"
        );
        let mut ids = std::collections::HashSet::new();
        let mut vms = std::collections::HashSet::new();
        for row in &record.pending {
            ensure!(
                valid_identity(&row.id) && valid_component(&row.vm) && valid_identity(&row.plan_id),
                "invalid pending launch identity"
            );
            ensure!(
                ids.insert(&row.id) && vms.insert(&row.vm),
                "duplicate pending launch"
            );
        }
        Ok(record)
    }

    fn write_record(&self, record: &Record) -> Result<()> {
        self.write_record_with(record, write_private)
    }

    fn write_record_with(
        &self,
        record: &Record,
        publish: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    ) -> Result<()> {
        self.write_record_staged(record, publish, crate::util::atomic_io::sync_dir)
    }

    fn write_record_staged(
        &self,
        record: &Record,
        publish: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
        cleanup_sync: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<()> {
        require_no_intent(&self.directory)?;
        let mut candidate = record.clone();
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .context("lifecycle mutation counter exhausted")?;
        let bytes = serde_json::to_vec(&candidate)?;
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "lifecycle metadata exceeds limit"
        );
        let intent = self.directory.join(".lifecycle.intent");
        let intent_bytes = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "tenant": &record.tenant,
            "generation": &record.generation,
            "candidate_sha256": hex::encode(Sha256::digest(&bytes)),
        }))?;
        ensure!(
            write_private_new(&intent, &intent_bytes)? == NewFile::Created,
            "lifecycle publication intent is already unresolved"
        );
        publish(&self.directory.join("lifecycle.json"), &bytes)?;
        fs::remove_file(&intent)?;
        // State and its directory are already durable before intent cleanup.
        // A cleanup-sync failure is returned to the writer; a successor may
        // safely observe that durable next state if the marker is absent.
        cleanup_sync(&self.directory)?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn activation_deadline_expiring_after_active_commit_never_releases_publication() {
        let home = tempfile::tempdir().unwrap();
        crate::private_fs::create_owned_private_dir(home.path()).unwrap();
        let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
        let metadata_deadline = Instant::now() + Duration::from_secs(1);
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            home.path(),
            "tenant-a",
            generation.clone(),
            256,
            metadata_deadline,
        )
        .unwrap();
        let expires = Instant::now() + Duration::from_millis(50);
        let published = std::cell::Cell::new(false);
        let mut writes = 0;
        let outcome = coordinator.activate_with_writer(
            &generation,
            expires,
            |_| Ok(()),
            |_| {
                published.set(true);
                Ok(())
            },
            |gate, record| {
                writes += 1;
                gate.write_record(record)?;
                if writes == 1 {
                    // A controlled writer completion, not a renewed activation
                    // budget: force the exact postcommit deadline boundary.
                    while Instant::now() < expires {
                        std::thread::yield_now();
                    }
                }
                Ok(())
            },
        );
        assert!(outcome.is_err());
        assert!(!published.get());
        assert_eq!(writes, 2, "expiry after Active commit must attempt fencing");
        let state = coordinator.snapshot(metadata_deadline).unwrap();
        assert_eq!(state.generation(), &generation);
        assert_eq!(state.phase(), LifecyclePhase::Draining);
        assert!(state.unresolved());
    }

    #[test]
    fn activation_state_barrier_failures_never_publish_and_attempt_conservative_fencing() {
        for postcommit in [false, true] {
            let home = tempfile::tempdir().unwrap();
            crate::private_fs::create_owned_private_dir(home.path()).unwrap();
            let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
            let deadline = || Instant::now() + Duration::from_secs(1);
            let coordinator = LifecycleCoordinator::prepare_after_exclusion(
                home.path(),
                "tenant-a",
                generation.clone(),
                256,
                deadline(),
            )
            .unwrap();
            let published = std::cell::Cell::new(false);
            let mut writes = 0;
            let outcome = coordinator.activate_with_writer(
                &generation,
                deadline(),
                |_| Ok(()),
                |_| {
                    published.set(true);
                    Ok(())
                },
                |gate, record| {
                    writes += 1;
                    if writes == 1 {
                        if postcommit {
                            gate.write_record_staged(record, write_private, |_| {
                                anyhow::bail!("controlled postcommit cleanup sync failure")
                            })
                        } else {
                            gate.write_record_with(record, |_, _| {
                                Err(std::io::Error::other(
                                    "controlled Active state publication failure",
                                ))
                            })
                        }
                    } else {
                        gate.write_record(record)
                    }
                },
            );
            assert!(outcome.is_err());
            assert!(!published.get());
            if postcommit {
                let state = coordinator.snapshot(deadline()).unwrap();
                assert_eq!(state.generation(), &generation);
                assert_eq!(state.phase(), LifecyclePhase::Draining);
                assert!(state.unresolved());
                assert_eq!(writes, 2, "durable Active must be conservatively fenced");
            } else {
                assert!(
                    coordinator
                        .gate
                        .directory
                        .join(".lifecycle.intent")
                        .is_file()
                );
                assert!(TenantLifecycleGate::new(home.path(), "tenant-a").is_err());
            }
        }
    }

    #[test]
    fn failed_publication_and_failed_fencing_keep_original_error_and_durable_uncertainty() {
        let home = tempfile::tempdir().unwrap();
        crate::private_fs::create_owned_private_dir(home.path()).unwrap();
        let generation = LifecycleGeneration::new([7; 32], 1).unwrap();
        let deadline = || Instant::now() + Duration::from_secs(1);
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            home.path(),
            "tenant-a",
            generation.clone(),
            256,
            deadline(),
        )
        .unwrap();
        let mut writes = 0;
        let outcome = coordinator.activate_with_writer(
            &generation,
            deadline(),
            |_| Ok(()),
            |_| anyhow::bail!("original partial publication refusal"),
            |gate, record| {
                writes += 1;
                if writes == 1 {
                    gate.write_record(record)
                } else {
                    gate.write_record_with(record, |_, _| {
                        Err(std::io::Error::other("controlled failure-fence refusal"))
                    })
                }
            },
        );
        let error = format!("{:#}", outcome.unwrap_err());
        assert!(error.contains("original partial publication refusal"));
        assert!(error.contains("controlled failure-fence refusal"));
        assert_eq!(writes, 2);
        assert!(
            coordinator
                .gate
                .directory
                .join(".lifecycle.intent")
                .is_file()
        );
        assert!(TenantLifecycleGate::new(home.path(), "tenant-a").is_err());
    }

    #[test]
    fn an_aba_path_restore_cannot_hide_the_actual_opened_lock_inode() {
        let home = tempfile::tempdir().expect("home");
        crate::private_fs::create_owned_private_dir(home.path()).expect("private home");
        crate::private_fs::create_owned_private_dir(crate::config::host_agent_root_at(home.path()))
            .expect("private agent root");
        let directory = crate::config::host_agent_dir_at(home.path(), "tenant-a");
        crate::private_fs::create_owned_private_dir(&directory).expect("private tenant");
        let path = directory.join("lifecycle.lock");
        write_private(&path, b"").expect("original lock");
        let gate = TenantLifecycleGate::new(home.path(), "tenant-a").expect("original gate");
        let original = directory.join("original-inode");
        let replacement = directory.join("replacement-inode");
        let result = gate.lock_with(Instant::now() + Duration::from_secs(1), |state_path| {
            fs::rename(&path, &original)?;
            write_private(&path, b"")?;
            let acquired = FileLock::try_acquire(state_path)?;
            ensure!(acquired.is_some(), "fixture must acquire replacement inode");
            fs::rename(&path, &replacement)?;
            fs::rename(&original, &path)?;
            Ok(acquired)
        });
        assert!(
            result.is_err(),
            "path checks must not accept a lock opened on the temporary replacement inode"
        );
    }

    #[test]
    fn a_fresh_gate_rejects_old_active_metadata_after_lock_inode_replacement() {
        use std::os::unix::fs::MetadataExt as _;
        let home = tempfile::tempdir().expect("home");
        crate::private_fs::create_owned_private_dir(home.path()).expect("private home");
        let deadline = || Instant::now() + Duration::from_secs(1);
        let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            home.path(),
            "tenant-a",
            generation.clone(),
            256,
            deadline(),
        )
        .expect("coordinator");
        coordinator
            .activate_after_reconciliation(&generation, deadline())
            .expect("Active generation");
        let lock_path = coordinator.gate.directory.join("lifecycle.lock");
        let original = fs::metadata(&lock_path).expect("original inode");
        write_private(&lock_path, b"").expect("replace inode after Active publication");
        let replacement = fs::metadata(&lock_path).expect("replacement inode");
        assert_ne!(
            (original.dev(), original.ino()),
            (replacement.dev(), replacement.ino())
        );
        assert!(
            TenantLifecycleGate::new(home.path(), "tenant-a")
                .and_then(|gate| gate.reserve_launch("vm-under-wrong-lock", "plan-a", deadline()))
                .is_err(),
            "a fresh client must not join a replacement lock using old Active metadata"
        );
    }

    #[test]
    fn a_retired_generation_cannot_reactivate_without_a_new_resource_epoch() {
        let home = tempfile::tempdir().expect("home");
        crate::private_fs::create_owned_private_dir(home.path()).expect("private home");
        let deadline = || Instant::now() + Duration::from_secs(1);
        let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            home.path(),
            "tenant-a",
            generation.clone(),
            256,
            deadline(),
        )
        .expect("coordinator");
        coordinator
            .activate_after_reconciliation(&generation, deadline())
            .expect("first bootstrap activation");
        coordinator
            .begin_drain(
                &generation,
                coordinator
                    .snapshot(deadline())
                    .expect("current revision")
                    .revision(),
                deadline(),
                |_| Ok(()),
            )
            .expect("drain original epoch");
        coordinator
            .finish_drain_after_collection(&generation, deadline(), |_| Ok(()))
            .expect("original epoch collected");
        assert!(
            coordinator
                .activate_after_reconciliation(&generation, deadline())
                .is_err(),
            "a retired resource epoch must not become Active again"
        );
        let reused_epoch =
            LifecycleGeneration::new([8; 32], 1).expect("fresh boot with stale epoch");
        assert!(
            coordinator
                .prepare_generation_after_reconciliation(&reused_epoch, deadline())
                .is_err()
        );
        let next_epoch = LifecycleGeneration::new([8; 32], 2).expect("new resource epoch");
        coordinator
            .prepare_generation_after_reconciliation(&next_epoch, deadline())
            .expect("stage new epoch before children");
        coordinator
            .activate_after_reconciliation(&next_epoch, deadline())
            .expect("checked newer resource epoch");
    }

    #[test]
    fn an_intervening_launch_invalidates_an_empty_inventory_scan() {
        let home = tempfile::tempdir().expect("home");
        let mut environment = crate::util::test_env::TestEnv::new();
        environment.isolate_mvm_home(home.path());
        crate::private_fs::create_owned_private_dir(home.path()).expect("private home");
        let deadline = || Instant::now() + Duration::from_secs(1);
        let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            home.path(),
            "tenant-a",
            generation.clone(),
            256,
            deadline(),
        )
        .expect("coordinator");
        coordinator
            .activate_after_reconciliation(&generation, deadline())
            .expect("Active generation");
        let scanned = coordinator
            .snapshot(deadline())
            .expect("inventory scan generation");
        assert!(scanned.pending().is_empty());
        let gate = TenantLifecycleGate::new(home.path(), "tenant-a").expect("same gate");
        let mut reservation = gate
            .reserve_launch("vm-a", "plan-a", deadline())
            .expect("intervening launch");
        let record = crate::session::SessionRecord::new_running(
            "vm-a",
            "workload-a",
            crate::session::SessionMode::Prod,
        );
        reservation
            .publish_running(&record, deadline())
            .expect("actual Running publication");
        let after = coordinator
            .snapshot(deadline())
            .expect("post-publication state");
        assert_eq!(after.generation(), scanned.generation());
        assert!(after.revision() > scanned.revision());
        assert!(
            after.pending().is_empty(),
            "pending rows alone returned to their old value"
        );
        assert!(
            coordinator
                .begin_drain(
                    scanned.generation(),
                    scanned.revision(),
                    deadline(),
                    |_| Ok(())
                )
                .is_err(),
            "a completed launch must invalidate the earlier empty session inventory scan"
        );
    }

    #[test]
    fn failed_draining_publication_cannot_leave_another_gate_active() {
        let home = tempfile::tempdir().expect("home");
        crate::private_fs::create_owned_private_dir(home.path()).expect("private home");
        let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            home.path(),
            "tenant-a",
            generation.clone(),
            256,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("coordinator");
        coordinator
            .activate_after_reconciliation(&generation, Instant::now() + Duration::from_secs(1))
            .expect("active generation");
        {
            let _lock = coordinator
                .gate
                .lock(Instant::now() + Duration::from_secs(1))
                .expect("original gate turn");
            let mut record = coordinator
                .gate
                .read_record()
                .expect("original Active state");
            record.phase = LifecyclePhase::Draining;
            assert!(
                coordinator
                    .gate
                    .write_record_with(&record, |_, _| Err(std::io::Error::other(
                        "injected state publication failure"
                    )))
                    .is_err()
            );
        }
        let other = TenantLifecycleGate::new(home.path(), "tenant-a");
        assert!(
            other
                .and_then(|gate| gate.reserve_launch(
                    "vm-after-failed-drain",
                    "plan-a",
                    Instant::now() + Duration::from_secs(1)
                ))
                .is_err(),
            "another gate must refuse after the draining intent survived a failed state write"
        );
    }

    #[test]
    fn cleanup_sync_failure_reports_error_but_preserves_the_durable_draining_state() {
        let home = tempfile::tempdir().expect("home");
        crate::private_fs::create_owned_private_dir(home.path()).expect("private home");
        let deadline = || Instant::now() + Duration::from_secs(1);
        let generation = LifecycleGeneration::new([7; 32], 1).expect("generation");
        let coordinator = LifecycleCoordinator::prepare_after_exclusion(
            home.path(),
            "tenant-a",
            generation.clone(),
            256,
            deadline(),
        )
        .expect("coordinator");
        coordinator
            .activate_after_reconciliation(&generation, deadline())
            .expect("Active generation");
        {
            let _lock = coordinator
                .gate
                .lock(deadline())
                .expect("original gate turn");
            let mut record = coordinator.gate.read_record().expect("Active state");
            record.phase = LifecyclePhase::Draining;
            assert!(
                coordinator
                    .gate
                    .write_record_staged(&record, write_private, |_| anyhow::bail!(
                        "injected intent cleanup directory-sync failure"
                    ))
                    .is_err()
            );
        }
        assert!(
            !coordinator
                .gate
                .directory
                .join(".lifecycle.intent")
                .exists()
        );
        let other = TenantLifecycleGate::new(home.path(), "tenant-a")
            .expect("durable state remains readable");
        assert!(
            other
                .reserve_launch("vm-after-failed-cleanup", "plan-a", deadline())
                .is_err()
        );
        assert_eq!(
            coordinator
                .snapshot(deadline())
                .expect("durable phase")
                .phase(),
            LifecyclePhase::Draining
        );
    }
}

impl LaunchReservation {
    /// Identifier of this original pending row; never cleanup authority.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Generation captured before backend activation.
    pub fn generation(&self) -> &LifecycleGeneration {
        &self.generation
    }

    /// Canonical plan identity retained before activation.
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    /// Publish only within the same original generation, then settle its row.
    /// A failure after writing Running retains conservative pending state.
    #[cfg(unix)]
    pub fn publish_running(
        &mut self,
        session: &crate::session::SessionRecord,
        deadline: Instant,
    ) -> Result<()> {
        ensure!(
            session.vm_name == self.vm && session.state == crate::session::SessionState::Running,
            "session does not match original launch"
        );
        let _lock = self.gate.lock(deadline)?;
        let mut record = self.gate.read_record()?;
        ensure!(
            record.generation == self.generation
                && record.phase == LifecyclePhase::Active
                && !record.unresolved,
            "original launch generation is no longer Active"
        );
        let index = record
            .pending
            .iter()
            .position(|row| row.id == self.id && row.vm == self.vm && row.plan_id == self.plan_id)
            .context("original launch reservation is absent")?;
        crate::session::write_session(session)?;
        record.pending.remove(index);
        self.gate.write_record(&record)
    }

    /// Settle only this original row after the caller staged successful
    /// canonical backend cleanup. This is not a helper-collection receipt.
    /// Failed cleanup retains the row; absence is idempotent only after the
    /// original generation was checked under the same gate.
    pub fn settle_after_original_cleanup(
        &mut self,
        deadline: Instant,
        check_original_cleanup: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.gate.settle_pending(
            &self.generation,
            &self.id,
            Some((&self.vm, &self.plan_id)),
            deadline,
            check_original_cleanup,
        )
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ID_BYTES && !value.chars().any(char::is_control)
}

fn require_private_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_dir(),
        "lifecycle namespace is not a plain directory"
    );
    crate::private_fs::require_current_owner(&meta)?;
    ensure!(
        crate::private_fs::mode_bits(path, &meta)? == 0o700,
        "lifecycle directory is not private"
    );
    Ok(())
}

fn require_no_intent(directory: &Path) -> Result<()> {
    match fs::symlink_metadata(directory.join(".lifecycle.intent")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect lifecycle publication intent"),
        Ok(_) => anyhow::bail!("lifecycle publication intent remains unresolved"),
    }
}

fn valid_component(value: &str) -> bool {
    valid_identity(value) && value != "." && value != ".." && !value.contains(['/', '\\'])
}

fn private_file_metadata(path: &Path) -> Result<Metadata> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_file(),
        "lifecycle object is not a regular file"
    );
    crate::private_fs::require_current_owner(&meta)?;
    ensure!(
        crate::private_fs::mode_bits(path, &meta)? & 0o777 == 0o600,
        "lifecycle file is not private"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(meta.nlink() == 1, "lifecycle file has multiple links");
    }
    Ok(meta)
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn lock_identity(metadata: &Metadata) -> Result<LockIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(LockIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "tenant lifecycle lock identity requires a supported Unix host",
        )
        .into())
    }
}

fn open_metadata(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        let file = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(File::from(file))
    }
    #[cfg(not(unix))]
    {
        Err(crate::private_fs::unsupported_platform_error(path).into())
    }
}

fn deserialize_pending<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<PendingLaunch>, D::Error> {
    struct Rows;
    impl<'de> serde::de::Visitor<'de> for Rows {
        type Value = Vec<PendingLaunch>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most 256 pending launches")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut rows = Vec::new();
            while rows.len() < MAX_PENDING {
                let Some(row) = sequence.next_element()? else {
                    return Ok(rows);
                };
                rows.push(row);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("pending launch limit exceeded"));
            }
            Ok(rows)
        }
    }
    deserializer.deserialize_seq(Rows)
}
