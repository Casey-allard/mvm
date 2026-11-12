//! Publication evidence for the original pair. Only the authentic prepared
//! role bytes can produce the two expected file commitments.
use super::*;
use crate::mailbox_launch::cast_pair::development::{EndpointRole, PreparedRole};
use crate::mailbox_process::owned_client::InstalledMailboxClient;
use rustix::fs::{Mode, OFlags, open, openat};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::PathBuf};

#[derive(Clone)]
struct Side {
    name: String,
    directory: PathBuf,
    owner: MailboxWorkerOwner,
    plan: [u8; 32],
    sha256: [u8; 32],
    size: usize,
}
impl Side {
    fn new(boot: &PreparedOriginalCastBoot, client: &InstalledMailboxClient) -> Result<Self> {
        let r = client.acquire_request();
        ensure!(
            client.owner() == Some(&boot.owner) && r.plan_commitment == boot.plan,
            "published grant requires the original prepared VM and plan"
        );
        let bytes = serde_json::to_vec(&boot.boot)?;
        ensure!(bytes.len() <= 16384, "oversize original grant");
        mvm_core::naming::validate_vm_name(&r.vm_id)?;
        Ok(Self {
            name: r.vm_id.clone(),
            directory: mvm_core::config::vm_state_dir(&r.vm_id),
            owner: boot.owner.clone(),
            plan: boot.plan,
            sha256: Sha256::digest(&bytes).into(),
            size: bytes.len(),
        })
    }
    fn confirm(&self) -> Result<()> {
        let d = File::from(open(
            &self.directory,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let dir = d.metadata()?;
        mvm_core::private_fs::require_current_owner(&dir)?;
        ensure!(
            dir.mode() & 0o022 == 0,
            "untrusted original sidecar directory"
        );
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let mut f = File::from(openat(&d, "verb-grant.json", flags, Mode::empty())?);
        let m = f.metadata()?;
        mvm_core::private_fs::require_current_owner(&m)?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o777 == 0o600
                && m.len() == self.size as u64,
            "original sidecar metadata changed"
        );
        let mut bytes = Vec::with_capacity(self.size);
        (&mut f)
            .take(self.size as u64 + 1)
            .read_to_end(&mut bytes)?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        ensure!(
            bytes.len() == self.size && actual == self.sha256,
            "original pair has not published these signed boot records"
        );
        f.sync_all()?;
        d.sync_all()?;
        let fd = File::from(openat(&d, "verb-grant.json", flags, Mode::empty())?);
        let final_m = fd.metadata()?;
        let final_d = std::fs::symlink_metadata(&self.directory)?;
        ensure!(
            (
                final_m.dev(),
                final_m.ino(),
                final_m.ctime(),
                final_m.ctime_nsec()
            ) == (m.dev(), m.ino(), m.ctime(), m.ctime_nsec())
                && (final_d.dev(), final_d.ino()) == (dir.dev(), dir.ino()),
            "published original path changed"
        );
        Ok(())
    }
}
#[derive(Clone)]
pub struct ExpectedCastPublication {
    sides: [Side; 2],
    direction: [u8; 32],
    validity: std::ops::Range<i64>,
}
impl ExpectedCastPublication {
    pub fn from_originals(
        a: (
            &PreparedOriginalCastBoot,
            &PreparedRole,
            &InstalledMailboxClient,
        ),
        b: (
            &PreparedOriginalCastBoot,
            &PreparedRole,
            &InstalledMailboxClient,
        ),
    ) -> Result<Self> {
        let direction = a.0.role_commitment(a.1, EndpointRole::Source)?;
        ensure!(
            direction == b.0.role_commitment(b.1, EndpointRole::Destination)?,
            "different original directions"
        );
        let sides = [Side::new(a.0, a.2)?, Side::new(b.0, b.2)?];
        ensure!(
            sides[0].name != sides[1].name
                && sides[0].owner != sides[1].owner
                && sides[0].owner.daemon_boot_nonce == sides[1].owner.daemon_boot_nonce,
            "different original pair required"
        );
        let validity =
            a.0.validity.start.max(b.0.validity.start)..a.0.validity.end.min(b.0.validity.end);
        ensure!(!validity.is_empty(), "empty original publication window");
        Ok(Self {
            sides,
            direction,
            validity,
        })
    }
    pub(crate) fn verify(
        self,
        client: &InstalledMailboxClient,
        role: &PreparedRole,
    ) -> Result<std::ops::Range<i64>> {
        let r = client.acquire_request();
        let i = self
            .sides
            .iter()
            .position(|s| {
                r.vm_id == s.name && r.plan_commitment == s.plan && client.owner() == Some(&s.owner)
            })
            .context("publication requires exact original participant")?;
        let endpoint = if i == 0 {
            EndpointRole::Source
        } else {
            EndpointRole::Destination
        };
        ensure!(
            role.binds_boot(self.direction, endpoint)
                && self
                    .validity
                    .contains(&crate::mailbox_launch::now_unix_ms()),
            "original boot, time, or direction changed"
        );
        for side in self.sides {
            side.confirm()?;
        }
        ensure!(
            self.validity
                .contains(&crate::mailbox_launch::now_unix_ms()),
            "original publication expired"
        );
        Ok(self.validity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn expected(dir: &std::path::Path, bytes: &[u8], number: u8) -> Side {
        Side {
            name: format!("fixture-{number}"),
            directory: dir.to_owned(),
            owner: MailboxWorkerOwner {
                daemon_boot_nonce: [1; 32],
                lease: [number; 32],
                generation: u64::from(number),
                context_commitment: [number; 32],
            },
            plan: [number; 32],
            sha256: Sha256::digest(bytes).into(),
            size: bytes.len(),
        }
    }

    #[test]
    fn pair_publication_rejects_missing_stale_and_replaced_original_sidecars() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let a_bytes = b"prepared original alpha";
        let b_bytes = b"prepared original bravo";
        let sides = [
            expected(a.path(), a_bytes, 1),
            expected(b.path(), b_bytes, 2),
        ];
        let verify = || sides.iter().try_for_each(Side::confirm);
        let pa = a.path().join("verb-grant.json");
        let pb = b.path().join("verb-grant.json");
        let write = mvm_core::atomic_io::write_private_ephemeral;
        assert!(verify().is_err());
        write(&pa, a_bytes).unwrap();
        assert!(verify().is_err(), "one original cannot enable the pair");
        write(&pb, a_bytes).unwrap();
        assert!(verify().is_err(), "equal-size substituted content");
        write(&pb, b_bytes).unwrap();
        verify().unwrap();
        let relocated = b.path().join("moved.json");
        std::fs::rename(&pb, &relocated).unwrap();
        symlink(&relocated, &pb).unwrap();
        assert!(verify().is_err(), "symbolic alias to exact bytes");
        std::fs::remove_file(&pb).unwrap();
        std::fs::hard_link(&relocated, &pb).unwrap();
        assert!(verify().is_err(), "linked replacement");
    }
}
