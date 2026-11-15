//! Binds an operator-selected executable to the same nonce used to commit
//! its original signed object direction. Neither the hash nor the mailbox
//! address is authority to access a guest or to open the mailbox service.
use super::{PreparedObjectPair, reader_revocations, revocations_path};
use anyhow::{Result, ensure};
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant};
use mvm_core::mailbox::object_pair::role::ObjectParticipantRole;
use mvm_core::plan::{ExecutionPlan, Nonce};

#[derive(Clone, Copy)]
pub struct OriginalObjectPlan<'a> {
    pair: &'a PreparedObjectPair,
    names: [&'a str; 2],
    image_sha256: [u8; 32],
    role: ObjectParticipantRole,
}

impl std::fmt::Debug for OriginalObjectPlan<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginalObjectPlan")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl PreparedObjectPair {
    /// The operator supplies both measured root filesystem identities before
    /// signing either original plan. Both role views borrow the same preparation.
    pub fn select_original_plans<'a>(
        &'a self,
        caller_name: &'a str,
        caller_image: [u8; 32],
        callee_name: &'a str,
        callee_image: [u8; 32],
    ) -> Result<(OriginalObjectPlan<'a>, OriginalObjectPlan<'a>)> {
        use ObjectParticipantRole::{Callee, Caller};
        mvm_core::naming::validate_vm_name(caller_name)?;
        mvm_core::naming::validate_vm_name(callee_name)?;
        ensure!(caller_name != callee_name, "original VM names must differ");
        let select = |role, image_sha256| OriginalObjectPlan {
            pair: self,
            names: [caller_name, callee_name],
            image_sha256,
            role,
        };
        Ok((select(Caller, caller_image), select(Callee, callee_image)))
    }
}

impl OriginalObjectPlan<'_> {
    fn original(&self) -> (&str, MailboxGrant, &Nonce) {
        match self.role {
            ObjectParticipantRole::Caller => {
                (self.names[0], self.pair.caller, &self.pair.caller_nonce)
            }
            ObjectParticipantRole::Callee => {
                (self.names[1], self.pair.callee, &self.pair.callee_nonce)
            }
        }
    }
    pub fn grant(&self) -> MailboxGrant {
        self.original().1
    }
    fn check_image(&self, plan: &ExecutionPlan) -> Result<()> {
        let (name, grant, _) = self.original();
        ensure!(
            plan.workload.0 == name
                && plan.image.name == name
                && plan.image.sha256 == hex::encode(self.image_sha256)
                && plan.mailbox == Some(grant),
            "object plan mismatches original role, image, or selected mailbox"
        );
        Ok(())
    }

    fn check_grants(&self, now: i64) -> Result<()> {
        let keys = mvm_core::config::mvm_keys_dir();
        let p = self.pair;
        for (name, grant, flow, recv) in [
            (
                self.names[0],
                p.caller,
                &p.credentials.reply,
                &p.credentials.receive_at_caller,
            ),
            (
                self.names[1],
                p.callee,
                &p.credentials.call,
                &p.credentials.receive_at_callee,
            ),
        ] {
            let epoch = ExecutionEpoch::new(mvm_core::plan::synthesis::current_local_epoch(name)?)?;
            let derived = super::super::derived_keys(&keys, &grant.mailbox, grant.epoch)?;
            let template = super::super::template_for(&keys, &derived, &grant, now)?;
            ensure!(
                grant.epoch == epoch
                    && grant.authority_key == derived.authority.verifying_key().to_bytes()
                    && template.header.policy_epoch == template.capability.policy_epoch,
                "original mailbox epoch, installation or policy changed"
            );
            let revoked =
                reader_revocations(&revocations_path(&mvm_core::config::vm_state_dir(name)))
                    .map_err(|_| {
                        anyhow::anyhow!("current original mailbox revocations unavailable")
                    })?;
            for cred in [flow, recv] {
                let g = &cred.grant;
                ensure!(
                    (g.not_before_unix_ms..g.expires_at_unix_ms).contains(&now)
                        && g.policy_epoch == template.header.policy_epoch
                        && !revoked.contains(&g.revocation_id),
                    "original object credential expired or revoked"
                );
            }
        }
        Ok(())
    }
    pub(crate) fn apply_unsigned(&self, plan: &mut ExecutionPlan, now: i64) -> Result<()> {
        self.check_image(plan)?;
        self.check_grants(now)?;
        plan.nonce = self.original().2.clone();
        plan.plan_id = mvm_core::plan::compute_plan_id(plan);
        Ok(())
    }
    pub fn verify_selected_plan(&self, plan: &ExecutionPlan, now: i64) -> Result<()> {
        self.check_image(plan)?;
        ensure!(
            &plan.nonce == self.original().2,
            "original object plan nonce differs"
        );
        mvm_core::plan::verify_plan_id(plan)?;
        self.check_grants(now)
    }
}
