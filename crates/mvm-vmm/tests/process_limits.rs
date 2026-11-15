//! Original child ceilings are kernel enforcement, not resource admission.

use mvm_vmm::host::process_limits::limit_original_address_space;
use std::process::Command;

#[test]
fn zero_ceiling_refuses_before_execution() {
    let mut command = Command::new("unused-unfunded-child");
    assert!(limit_original_address_space(&mut command, 0).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_refuses_a_funded_ceiling() {
    let mut command = Command::new("unused-unsupported-child");
    let error = limit_original_address_space(&mut command, 512 << 20).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::Unsupported
    );
}

#[cfg(target_os = "linux")]
#[test]
fn original_child_preserves_stricter_caps_without_changing_the_parent() {
    use rustix::process::{Resource, getrlimit};
    const PROBE: &str = "MVM_TEST_SHARED_ORIGINAL_CEILING";
    let before = getrlimit(Resource::As);
    if let Some(expected) = std::env::var_os(PROBE) {
        let expected: u64 = expected.to_str().unwrap().parse().unwrap();
        assert_eq!(before.current, Some(expected));
        assert_eq!(before.maximum, Some(expected));
        let length = usize::try_from(expected).unwrap().checked_add(1).unwrap();
        // SAFETY: a private anonymous inaccessible mapping requests no backing
        // memory. A failed result is never dereferenced; unexpected success is unmapped.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        let error = std::io::Error::last_os_error();
        if mapping != libc::MAP_FAILED {
            // SAFETY: only the complete mapping just returned above is released.
            unsafe { libc::munmap(mapping, length) };
            panic!("child mapped more than its entire original address-space ceiling");
        }
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        return;
    }
    for (first, second) in [
        (512_u64 << 20, 256_u64 << 20),
        (256_u64 << 20, 512_u64 << 20),
    ] {
        let expected = [Some(first), Some(second), before.current, before.maximum]
            .into_iter()
            .flatten()
            .min()
            .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "original_child_preserves_stricter_caps_without_changing_the_parent",
                "--test-threads=1",
            ])
            .env(PROBE, expected.to_string());
        limit_original_address_space(&mut command, first).unwrap();
        limit_original_address_space(&mut command, second).unwrap();
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        let after = getrlimit(Resource::As);
        assert_eq!(after.current, before.current);
        assert_eq!(after.maximum, before.maximum);
    }
}
