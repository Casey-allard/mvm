//! Exercise original-store retirement in a separate kernel-confined process.

use super::*;
use std::{
    os::{fd::AsRawFd, unix::process::ExitStatusExt},
    path::{Path, PathBuf},
};

const CHILD: &str = "jailer::seccomp::owned_store_tests::filter_child";
const CASE: &str = "MVM_OWNED_STORE_FILTER_CASE";
const ROOT: &str = "MVM_OWNED_STORE_FILTER_ROOT";

#[test]
fn filter_child() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    disable_core_dump();

    let root = PathBuf::from(std::env::var_os(ROOT).expect("test-owned directory"));
    let store = root.join("store");
    let name = std::ffi::CString::new(store.as_os_str().as_encoded_bytes()).unwrap();
    let spec = ConfinementSpec::telemetry_collector(&root, None, PathBuf::new());
    if case == "legacy" {
        apply(&spec).unwrap();
    } else {
        apply_with_owned_store(&spec).unwrap();
    }

    if case == "cleanup" {
        std::fs::remove_dir_all(&store).unwrap();
        assert!(!store.exists());
    } else {
        let flags = match case.as_str() {
            "legacy" => libc::AT_REMOVEDIR as u64,
            "unknown" => libc::AT_SYMLINK_NOFOLLOW as u64,
            "upper" => (1 << 32) | libc::AT_REMOVEDIR as u64,
            _ => panic!("unknown filter case"),
        };
        // SAFETY: The test owns the empty directory and name. Use the native
        // syscall ABI so the upper-bit control reaches seccomp unchanged.
        unsafe { libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, name.as_ptr(), flags) };
    }
    std::process::exit(0);
}

fn disable_core_dump() {
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: Limit core dumps in this disposable child before a possible SIGSYS.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) }, 0);
}

// Run before libtest starts threads, as required by the actual Landlock installer.
#[ctor::ctor]
fn rename_child() {
    let Some(case) = std::env::var(CASE)
        .ok()
        .filter(|s| s.starts_with("rename-"))
    else {
        return;
    };
    disable_core_dump();
    let root = PathBuf::from(std::env::var_os(ROOT).expect("original rename fixture"));
    let state = std::fs::File::open(root.join("state")).unwrap();
    let store = std::fs::File::open(root.join("store")).unwrap();
    let outside = std::fs::File::open(root.join("outside")).unwrap();
    let spec = ConfinementSpec::telemetry_collector(&root.join("state"), None, PathBuf::new());
    let owned = matches!(
        case.as_str(),
        "rename-store" | "rename-cwd" | "rename-upper"
    );
    let records = case != "rename-base";
    if case == "rename-base" {
        crate::jailer::confine_self(&spec).unwrap();
    } else {
        crate::jailer::confine_self_with_owned_files(
            &spec,
            &state,
            owned.then_some(&store),
            Some(&state),
            records,
        )
        .unwrap();
    }
    let fd = |f: &std::fs::File| u64::from(u32::try_from(f.as_raw_fd()).unwrap());
    let rename = |from: u64, to: u64| {
        // SAFETY: Both filenames are fixed, valid NUL-terminated strings.
        // Pass full-width scalar arguments to exercise the native seccomp ABI.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat,
                from,
                c"stage".as_ptr(),
                to,
                c"published".as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    match case.as_str() {
        "rename-store" => {
            let lane = rustix::fs::openat(
                &store,
                "lane",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            rustix::fs::renameat(&lane, "stage", &lane, "published").unwrap();
            // Both FDs pass BPF's scalar check. Landlock must refuse moving an
            // admitted state file into this preopened, ungranted sibling.
            assert_eq!(
                rename(fd(&state), fd(&outside)).unwrap_err().raw_os_error(),
                Some(libc::EACCES)
            );
        }
        "rename-records" => rename(fd(&state), fd(&state)).unwrap(),
        "rename-records-source" => rename(fd(&outside), fd(&state)).unwrap(),
        "rename-records-dest" => rename(fd(&state), fd(&outside)).unwrap(),
        "rename-cwd" => rename(libc::AT_FDCWD as u64, fd(&state)).unwrap(),
        "rename-upper" => rename(fd(&state), (1 << 32) | fd(&state)).unwrap(),
        "rename-base" => rename(fd(&state), fd(&state)).unwrap(),
        _ => panic!("unknown rename case"),
    }
    std::process::exit(0);
}

#[test]
fn renameat_publication_requires_original_store_or_exact_state_descriptors() {
    for case in [
        "rename-store",
        "rename-records",
        "rename-records-source",
        "rename-records-dest",
        "rename-base",
        "rename-cwd",
        "rename-upper",
    ] {
        let root = tempfile::tempdir().unwrap();
        for dir in ["state", "outside"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
            std::fs::write(root.path().join(dir).join("stage"), dir.as_bytes()).unwrap();
        }
        let output = run(case, root.path());
        let stderr = String::from_utf8_lossy(&output.stderr);
        if matches!(case, "rename-store" | "rename-records") {
            assert!(output.status.success(), "{case}: {stderr}");
        } else {
            assert!(
                output.status.signal() == Some(libc::SIGSYS) || output.status.code() == Some(159),
                "{case}: {stderr}"
            );
            assert!(
                stderr.contains(&format!(
                    "seccomp refused x86_64 syscall {};",
                    libc::SYS_renameat
                )),
                "{case}: {stderr}"
            );
        }
        for (dir, bytes, published) in [
            ("store/lane", b"store".as_slice(), case == "rename-store"),
            ("state", b"state", case == "rename-records"),
            ("outside", b"outside", false),
        ] {
            let path = root.path().join(dir);
            let (present, absent) = if published {
                ("published", "stage")
            } else {
                ("stage", "published")
            };
            assert_eq!(
                std::fs::read(path.join(present)).unwrap(),
                bytes,
                "{case}: {dir}"
            );
            assert_eq!(
                std::fs::symlink_metadata(path.join(absent))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound,
                "{case}: {dir}"
            );
        }
    }
}

fn run(case: &str, root: &Path) -> std::process::Output {
    let store = root.join("store");
    std::fs::create_dir(&store).unwrap();
    if case == "cleanup" {
        std::fs::write(store.join("original"), b"owned").unwrap();
    } else if case.starts_with("rename-") {
        std::fs::create_dir(store.join("lane")).unwrap();
        std::fs::write(store.join("lane/stage"), b"store").unwrap();
    }
    mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--test-threads=1"])
        .env(CASE, case)
        .env(ROOT, root)
        .output()
        .unwrap()
}

#[test]
fn original_store_directory_cleanup_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let output = run("cleanup", root.path());
    assert!(
        output.status.success(),
        "owned store cleanup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.path().join("store").exists());
}

#[test]
fn unlinkat_flags_are_scoped_to_original_store() {
    for case in ["legacy", "unknown", "upper"] {
        let root = tempfile::tempdir().unwrap();
        let output = run(case, root.path());
        assert!(
            output.status.signal() == Some(libc::SIGSYS) || output.status.code() == Some(159),
            "{case} did not trap: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let refusal = format!("seccomp refused x86_64 syscall {};", libc::SYS_unlinkat);
        assert!(String::from_utf8_lossy(&output.stderr).contains(&refusal));
        assert!(root.path().join("store").is_dir());
    }
}
