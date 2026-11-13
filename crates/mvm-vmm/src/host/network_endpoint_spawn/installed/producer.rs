//! Pre-Child retained effects stay with one original preparation owner.
use super::*;
use crate::host::host_agent_spawn::PreparedEndpointAudit;
use anyhow::ensure;
use mvm_core::crypto::aead::Key;

#[derive(Default)]
pub(super) struct RetainedFiles {
    state: Option<File>,
    records: Option<File>,
    wrapped: Option<File>,
}
impl std::fmt::Debug for RetainedFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedFiles").finish_non_exhaustive()
    }
}

pub(super) struct Preparation {
    custody: Option<InstalledCustody>,
    invoked: bool,
}
impl Preparation {
    pub(super) fn new(handoff: PreparedEndpointHandoff, audit: PreparedEndpointAudit) -> Self {
        Self {
            custody: Some(InstalledCustody {
                handoff,
                audit: Some(audit),
                telemetry: None,
                input: None,
                output: None,
                nonce: [0; 32],
                drained: false,
            }),
            invoked: false,
        }
    }
    pub(super) fn custody(&self) -> &InstalledCustody {
        self.custody.as_ref().expect("original preparation custody")
    }
    pub(super) fn take(&mut self) -> InstalledCustody {
        self.custody.take().expect("one original preparation")
    }
    pub(super) fn check_current(
        &self,
        original: &InstalledHostServices<'_>,
        params: &SubstitutionSpawnParams<'_>,
        deadline: Instant,
    ) -> Result<()> {
        current(
            &self.custody().handoff,
            self.custody()
                .audit
                .as_ref()
                .context("original audit custody missing")?,
            original,
            params,
            deadline,
        )
    }
    pub(super) fn error(mut self, reason: anyhow::Error) -> anyhow::Error {
        if self.invoked && self.custody.is_some() {
            let custody = self.custody.take();
            PreparationFailure {
                _reason: reason,
                custody,
            }
            .into()
        } else {
            reason
        }
    }
    pub(super) fn prepare_retained(
        &mut self,
        params: &SubstitutionSpawnParams<'_>,
        original: &InstalledHostServices<'_>,
        keys_dir: &Path,
        deadline: Instant,
    ) -> Result<(Key, records::RecordsProjection)> {
        self.check_current(original, params, deadline)?;
        let custody = self.custody.as_mut().expect("original preparation custody");
        custody.telemetry = Some(RetainedFiles::default());
        // Capture each actual observation before any fallible post-open work.
        // This is not a pathname-to-authority constructor: the SAME original
        // parent guard validates and protects this directory before key effects.
        let (registered_state, _) = original.registration.original_directories(original.registrar, &original.params)?;
        let state = registered_state.try_clone()?;
        custody
            .telemetry
            .as_mut()
            .expect("retained observations")
            .state = Some(state);
        self.invoked = true; // Any callback error may already have durable intent.
        let handoff = &custody.handoff;
        let audit = custody
            .audit
            .as_ref()
            .context("original audit custody missing")?;
        let files = custody.telemetry.as_mut().expect("retained observations");
        let state = files.state.as_ref().expect("original state observation");
        handoff.prepare_retained_telemetry(params.state_dir, state)?;
        current(handoff, audit, original, params, deadline)?;
        let (key, wrapped) =
            crate::host::telemetry_provisioning::provision_records_key_owned_with_file(
                state, keys_dir,
            )?;
        files.wrapped = Some(wrapped);
        current(handoff, audit, original, params, deadline)?;
        let records = File::from(rustix::fs::openat(
            state,
            crate::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::APPEND
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::from_raw_mode(0o600),
        )?);
        files.records = Some(records);
        let records = files
            .records
            .as_ref()
            .expect("original records observation");
        let projection =
            records::RecordsProjection::from_original(params.state_dir, state, records)?;
        current(handoff, audit, original, params, deadline)?;
        handoff.bind_retained_telemetry_files(
            params.state_dir,
            state,
            records,
            files
                .wrapped
                .as_ref()
                .expect("original wrapped observation"),
        )?;
        current(handoff, audit, original, params, deadline)?;
        Ok((key, projection))
    }
}
fn current(
    handoff: &PreparedEndpointHandoff,
    audit: &PreparedEndpointAudit,
    original: &InstalledHostServices<'_>,
    params: &SubstitutionSpawnParams<'_>,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "installed endpoint original startup deadline"
    );
    handoff.check_current()?;
    audit.check_current()?;
    original.check_endpoint(params)?;
    ensure!(
        Instant::now() < deadline,
        "installed endpoint original startup deadline"
    );
    Ok(())
}
impl Drop for Preparation {
    fn drop(&mut self) {
        if self.invoked
            && let Some(custody) = self.custody.take()
        {
            // At most one issuance under the original parent partition. No
            // failed-start cleanup/refund is inferred from unwind or Drop.
            std::mem::forget(custody);
        }
    }
}

struct PreparationFailure {
    _reason: anyhow::Error,
    custody: Option<InstalledCustody>,
}
impl std::fmt::Debug for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparationFailure").finish_non_exhaustive()
    }
}
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("installed retained endpoint preparation failed")
    }
}
impl std::error::Error for PreparationFailure {}
impl Drop for PreparationFailure {
    fn drop(&mut self) {
        if let Some(custody) = self.custody.take() {
            std::mem::forget(custody);
        }
    }
}
