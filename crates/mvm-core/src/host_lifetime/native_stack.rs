//! Known Rust stack terms; native pthread/TLS/cache costs remain separate.

use anyhow::{Result, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeThreadStackTerms {
    pub requested_builder_bytes: u64,
    pub rounded_builder_bytes: u64,
    pub minimum_builder_bytes: u64,
    pub page_bytes: u64,
    /// Includes its protected guard page, already rounded to actual pages.
    pub rust_alt_mapping_bytes: u64,
    pub rust_alt_guard_bytes: u64,
    /// Excludes native pthread control/TLS/default guards and cached stacks.
    pub known_rust_bytes: u64,
}

/// Numeric inputs for the qualified Rust stack model, never a quota grant.
pub fn native_thread_stack_terms(requested_builder_bytes: u64) -> Result<NativeThreadStackTerms> {
    let facts = platform_facts()?;
    calculate(
        requested_builder_bytes,
        facts.page,
        facts.signal,
        facts.minimum,
    )
}

struct PlatformFacts {
    page: u64,
    signal: u64,
    minimum: u64,
}

fn calculate(builder: u64, page: u64, signal: u64, minimum: u64) -> Result<NativeThreadStackTerms> {
    ensure!(
        matches!(builder, 2_097_152 | 8_388_608),
        "unqualified Builder stack class"
    );
    ensure!(
        matches!(page, 4096 | 16384 | 65536),
        "unsupported native page size"
    );
    ensure!(
        signal > 0 && signal <= 1 << 20,
        "unqualified signal stack size"
    );
    ensure!(
        minimum > 0 && minimum <= builder,
        "native minimum would enlarge Builder stack"
    );
    let round = |bytes: u64| -> Result<u64> {
        Ok(bytes
            .checked_add(page - 1)
            .ok_or_else(|| anyhow::anyhow!("native stack round overflow"))?
            / page
            * page)
    };
    let rounded_builder_bytes = round(builder)?;
    let rust_alt_mapping_bytes = round(
        signal
            .checked_add(page)
            .ok_or_else(|| anyhow::anyhow!("signal mapping overflow"))?,
    )?;
    Ok(NativeThreadStackTerms {
        requested_builder_bytes: builder,
        rounded_builder_bytes,
        minimum_builder_bytes: minimum,
        page_bytes: page,
        rust_alt_mapping_bytes,
        rust_alt_guard_bytes: page,
        known_rust_bytes: rounded_builder_bytes
            .checked_add(rust_alt_mapping_bytes)
            .ok_or_else(|| anyhow::anyhow!("native stack sum overflow"))?,
    })
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))
))]
fn platform_facts() -> Result<PlatformFacts> {
    let page = u64::try_from(rustix::param::page_size())?;
    let signal = u64::try_from(libc::SIGSTKSZ)?;
    #[cfg(target_os = "macos")]
    {
        ensure!(
            matches!(page, 4096 | 16384) && signal == 131072,
            "unqualified Darwin stack facts"
        );
        Ok(PlatformFacts {
            page,
            signal,
            minimum: u64::try_from(libc::PTHREAD_STACK_MIN)?,
        })
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        ensure!(
            matches!(page, 4096 | 16384 | 65536),
            "unqualified GNU page size"
        );
        ensure!(
            signal > 0 && signal <= 65536,
            "unqualified GNU signal stack constant"
        );
        let minimum_signal = u64::try_from(rustix::param::linux_minsigstksz())?;
        ensure!(
            minimum_signal > 0 && minimum_signal <= 65536,
            "unqualified kernel signal minimum"
        );
        Ok(PlatformFacts {
            page,
            signal: signal.max(minimum_signal),
            minimum: gnu_minimum()?,
        })
    }
}

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))
)))]
fn platform_facts() -> Result<PlatformFacts> {
    anyhow::bail!("native Rust stack model unsupported on this platform")
}

#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
// Rust has no safe query for GNU's static-TLS stack minimum. This leaf uses
// the same checked symbol/attribute ABI as its thread builder, starts no
// thread and grants no quota. The unsafe exception is limited to this query.
#[allow(unsafe_code)]
fn gnu_minimum() -> Result<u64> {
    type GetMinimum = unsafe extern "C" fn(*const libc::pthread_attr_t) -> libc::size_t;
    // SAFETY: read-only lookup of the same optional GNU entry used by Rust.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__pthread_get_minstack".as_ptr()) };
    ensure!(!address.is_null(), "GNU stack minimum query unavailable");
    // SAFETY: this symbol's GNU ABI has the function signature above.
    let minimum: GetMinimum = unsafe { std::mem::transmute(address) };
    let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    // SAFETY: storage is valid for one native pthread attribute object.
    let initialized = unsafe { libc::pthread_attr_init(attributes.as_mut_ptr()) };
    ensure!(
        initialized == 0,
        "native thread attributes initialization refused"
    );
    // SAFETY: successful initialization established this attribute object.
    let mut attributes = unsafe { attributes.assume_init() };
    // SAFETY: initialized default attributes, matching Rust's minimum query.
    let bytes = unsafe { minimum(&attributes) };
    // SAFETY: the same initialized object is destroyed exactly once.
    let destroyed = unsafe { libc::pthread_attr_destroy(&mut attributes) };
    ensure!(
        destroyed == 0,
        "native thread attributes destruction refused"
    );
    Ok(u64::try_from(bytes)?)
}

#[cfg(test)]
#[path = "native_stack_tests.rs"]
mod tests;
