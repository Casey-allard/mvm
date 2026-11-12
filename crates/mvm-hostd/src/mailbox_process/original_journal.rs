//! Custody of a live destination helper for an explicitly paired local journal.
//! Only the canonical production launch can give a caller this handle. It
//! retains the original Child until collection. A pidfile cannot recreate it.

use super::{MailboxLaunchPosture, MailboxProcessConfig, spawn_serving, spawn_with_original};
use anyhow::{Context, Result, ensure};
use mvm_agentd::vsock::connect_unix_before;
use mvm_contract::protocol::mailbox::{MailboxAddress, PrincipalId};
use mvm_core::mailbox::reader::MailboxReaderBootBinding;
use mvm_core::plan::{ExecutionPlan, Variant};
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::host::uds_peer::connected_peer_pid;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use std::time::Instant;

/// The program which starts B owns its real process. Borrowing the handle
/// cannot transfer the mailbox keys, change its recipient, or reopen a PID.
pub struct OriginalJournalDestination {
    child: Child,
    socket: PathBuf,
    boot: MailboxReaderBootBinding,
    address: MailboxAddress,
    policy_epoch: u64,
    issuer: PrincipalId,
}

impl OriginalJournalDestination {
    /// Select this launcher instead of the ordinary PID-only launcher when B
    /// is the destination of an installed pair. All canonical admission,
    /// retention and verified cold-boot checks still run.
    pub fn start(
        plan: &ExecutionPlan,
        backend: &AnyBackend,
        vm_name: &str,
        posture: &MailboxLaunchPosture,
    ) -> Result<Self> {
        ensure!(
            posture.variant() == Variant::Prod,
            "paired journal requires production admission"
        );
        spawn_with_original(plan, backend, vm_name, Some(posture), |config, plan| {
            Self::spawn(config, plan).map_err(std::io::Error::other)
        })?
        .context("destination VM has no admitted mailbox")
    }

    fn spawn(config: &MailboxProcessConfig, plan: &ExecutionPlan) -> Result<Self> {
        let boot = config
            .reader_boot
            .clone()
            .context("guest reader boot is absent")?;
        boot.check_plan(plan)?;
        ensure!(
            config.grant.retention.is_some(),
            "destination has no admitted retention"
        );
        let (policy, _) = config.keys.trust();
        let current = &policy.context;
        let address = MailboxAddress {
            tenant: current.expected_tenant,
            authorization_domain: current.expected_authorization_domain,
            mailbox: config.grant.mailbox,
            recipient: current.expected_recipient,
        };
        let child = spawn_serving(config, &config.vm_state_dir)?;
        Ok(Self {
            child,
            socket: config.socket.clone(),
            boot,
            address,
            policy_epoch: current.current_policy_epoch,
            issuer: current.expected_capability_issuer,
        })
    }

    /// Before sending any credential or ciphertext, authenticate the connected
    /// kernel peer against the exclusively owned, still-live original Child.
    pub fn connect(&mut self, deadline: Instant) -> Result<UnixStream> {
        authenticated_connect(&mut self.child, &self.socket, deadline)
    }

    /// Observe terminal status only by collecting the original Child.
    pub fn try_collect(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    pub fn binding(&self) -> &MailboxReaderBootBinding {
        &self.boot
    }
    pub fn address(&self) -> MailboxAddress {
        self.address
    }
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }
    pub fn issuer(&self) -> PrincipalId {
        self.issuer
    }
}

fn authenticated_connect(
    child: &mut Child,
    path: &std::path::Path,
    deadline: Instant,
) -> Result<UnixStream> {
    ensure!(
        child.try_wait()?.is_none(),
        "original journal helper exited"
    );
    let socket = connect_unix_before(path, deadline)?;
    let peer = u32::try_from(connected_peer_pid(&socket)?)?;
    ensure!(
        peer == child.id() && child.try_wait()?.is_none(),
        "connected journal endpoint does not belong to the original live helper"
    );
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn journal_peer_child() {
        let Some(path) = std::env::var_os("MVM_TEST_ORIGINAL_JOURNAL_SOCKET") else {
            return;
        };
        let _listener = UnixListener::bind(path).unwrap();
        println!("journal-child-listening");
        std::io::stdout().flush().unwrap();
        let mut done = String::new();
        std::io::stdin().lock().read_line(&mut done).unwrap();
    }

    fn listener(path: &Path) -> Child {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "mailbox_process::original_journal::tests::journal_peer_child",
                "--exact",
                "--nocapture",
            ])
            .env("MVM_TEST_ORIGINAL_JOURNAL_SOCKET", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = std::io::BufReader::new(child.stdout.take().unwrap());
        assert!(
            output
                .lines()
                .map_while(std::result::Result::ok)
                .any(|l| l.contains("journal-child-listening"))
        );
        child
    }

    #[test]
    fn only_original_kernel_peer_can_receive_the_direction() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let socket = dir.path().join("b.sock");
        let mut original = listener(&socket);
        let deadline = || Instant::now() + Duration::from_secs(2);
        assert!(authenticated_connect(&mut original, &socket, deadline()).is_ok());
        std::fs::remove_file(&socket).unwrap();
        let mut replacement = listener(&socket);
        assert!(authenticated_connect(&mut original, &socket, deadline()).is_err());
        drop(original.stdin.take());
        assert!(original.wait().unwrap().success());
        assert!(authenticated_connect(&mut original, &socket, deadline()).is_err());
        drop(replacement.stdin.take());
        assert!(replacement.wait().unwrap().success());
    }
}
