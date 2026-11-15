//! Declared rootfs source planning; no fallback registry interpretation.
use super::*;

/// The work a declared rootfs source implies. One variant per verification
/// path: a materialized blob is booted as-is, a tree is injected and
/// materialized, and a reference is fetched from a registry first.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RootfsPlan {
    /// An already-materialized `rootfs.ext4` — boot it directly.
    Materialized(PathBuf),
    /// An unpacked OCI rootfs directory — inject runtime + materialize.
    UnpackedDir(PathBuf),
    /// A registry reference — pull + unpack + inject + materialize.
    Pull(ImageReference),
}

/// Turn a caller-declared rootfs source into the work it implies.
///
/// The declaration arrives parsed, so a mistyped path stops here instead of
/// falling through to the registry arm: the arms differ in how the bytes they
/// produce are verified, and which one runs must not depend on the caller's
/// working directory.
pub(super) fn plan_rootfs_source(source: RootfsSource) -> Result<RootfsPlan> {
    match source {
        // The filesystem is consulted only to tell a blob from a tree, and
        // only once the caller has declared the source local.
        RootfsSource::LocalPath(path) if path.is_file() => Ok(RootfsPlan::Materialized(path)),
        RootfsSource::LocalPath(path) if path.is_dir() => Ok(RootfsPlan::UnpackedDir(path)),
        RootfsSource::LocalPath(path) => Err(MvmError::InvalidSpec {
            reason: format!(
                "declared local rootfs path does not exist: {} — no registry fetch was \
                 attempted; write `oci:<reference>` to boot a registry image instead",
                path.display()
            ),
        }),
        RootfsSource::Oci { image_ref } => image_ref
            .parse::<ImageReference>()
            .map(RootfsPlan::Pull)
            .map_err(|e| MvmError::InvalidSpec {
                reason: format!(
                    "not a usable OCI reference: {image_ref:?}: {e}{}",
                    path_collision_hint(&image_ref)
                ),
            }),
        RootfsSource::Flake { flake_ref, attr } => Err(MvmError::InvalidSpec {
            reason: format!(
                "a flake source is built, not booted: build {flake_ref}#{attr} first, then \
                 declare the resulting rootfs path"
            ),
        }),
    }
}

/// A bare name is a registry reference by declaration, so a same-named file in
/// the caller's working directory is not silently preferred — but it is almost
/// certainly what they meant, so say so once the reference has failed to parse.
fn path_collision_hint(image_ref: &str) -> String {
    if Path::new(image_ref).exists() {
        format!(
            " (a filesystem entry named {image_ref:?} exists — write `./{image_ref}` or `path:{image_ref}` to boot it)"
        )
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `std::env::set_current_dir` is process-wide; this Mutex stops
    /// `cargo test`'s thread pool from racing between two cwd-mutating tests.
    /// The lock is held for the lifetime of [`CwdGuard`].
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CwdGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: PathBuf,
    }

    impl CwdGuard {
        fn enter(dir: &Path) -> Self {
            let guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::current_dir().expect("cwd");
            std::env::set_current_dir(dir).expect("chdir");
            CwdGuard {
                _guard: guard,
                prev,
            }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    fn reference(s: &str) -> ImageReference {
        s.parse().expect("parses as an OCI reference")
    }

    /// Both steps a caller takes with a declaration string — parse it, then
    /// plan the work — so these tests keep exercising the grammar rather than
    /// hand-building the parsed value.
    fn plan_rootfs(image: &str) -> Result<RootfsPlan> {
        let source: RootfsSource = image.parse().map_err(|e| MvmError::InvalidSpec {
            reason: format!("{e}"),
        })?;
        plan_rootfs_source(source)
    }

    #[test]
    fn plan_rootfs_routes_file_dir_and_registry() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rootfs.ext4");
        std::fs::write(&file, b"x").unwrap();

        // An existing file → a materialized rootfs.
        assert_eq!(
            plan_rootfs(&file.to_string_lossy()).unwrap(),
            RootfsPlan::Materialized(file.clone())
        );
        // An existing directory → an unpacked tree.
        assert_eq!(
            plan_rootfs(&dir.path().to_string_lossy()).unwrap(),
            RootfsPlan::UnpackedDir(dir.path().to_path_buf())
        );
        // A reference → a pull (no network touched here).
        assert_eq!(
            plan_rootfs("docker.io/library/alpine:3.20").unwrap(),
            RootfsPlan::Pull(reference("docker.io/library/alpine:3.20"))
        );
    }

    #[test]
    fn a_mistyped_local_path_is_refused_and_never_planned_as_a_pull() {
        let dir = tempfile::tempdir().unwrap();
        // The user meant `rootfs.ext4`; nothing exists at what they typed.
        let typo = dir.path().join("rootfs.ext5");

        let planned = plan_rootfs(&typo.to_string_lossy());

        // `Pull` is the only variant that reaches a registry, so refusing to
        // produce one is what "no fetch was attempted" means here.
        assert!(
            !matches!(planned, Ok(RootfsPlan::Pull(_))),
            "a typo'd local path must not be planned as a registry pull: {planned:?}"
        );
        let err = planned.expect_err("an absent declared path is an error");
        assert!(
            matches!(err, MvmError::InvalidSpec { .. }),
            "expected a spec error naming the path, got {err:?}"
        );
        assert!(
            err.to_string().contains(&typo.display().to_string()),
            "the error must name the path the caller typed: {err}"
        );
    }

    #[tokio::test]
    async fn resolve_local_rootfs_refuses_a_mistyped_path_before_any_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let typo = dir.path().join("rootfs.ext5");

        let declared: RootfsSource = typo.to_string_lossy().parse().expect("a path parses");
        let err = crate::local::resolve_local_rootfs(&declared, "m")
            .await
            .expect_err("an absent declared path is an error");

        assert!(matches!(err, MvmError::InvalidSpec { .. }), "got {err:?}");
        assert!(err.to_string().contains(&typo.display().to_string()));
    }

    #[test]
    fn a_registry_reference_survives_a_colliding_working_directory_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("alpine:3.20"), b"decoy").unwrap();
        std::fs::create_dir(dir.path().join("busybox")).unwrap();
        let _cwd = CwdGuard::enter(dir.path());

        // Both names exist in the cwd; neither is a declared path, so both
        // stay references.
        assert_eq!(
            plan_rootfs("alpine:3.20").unwrap(),
            RootfsPlan::Pull(reference("alpine:3.20"))
        );
        assert_eq!(
            plan_rootfs("busybox").unwrap(),
            RootfsPlan::Pull(reference("busybox"))
        );
        // The explicitly-relative form is how the caller asks for the file.
        assert_eq!(
            plan_rootfs("./alpine:3.20").unwrap(),
            RootfsPlan::Materialized(PathBuf::from("./alpine:3.20"))
        );
    }

    #[test]
    fn an_unbootable_declaration_names_what_is_wrong() {
        let empty = plan_rootfs("").expect_err("empty is not a source");
        assert!(matches!(empty, MvmError::InvalidSpec { .. }), "{empty:?}");

        let flake = plan_rootfs_source(RootfsSource::Flake {
            flake_ref: "./nix".into(),
            attr: "rootfs".into(),
        })
        .expect_err("a flake is built, not booted");
        assert!(flake.to_string().contains("./nix#rootfs"), "{flake}");
    }
}
