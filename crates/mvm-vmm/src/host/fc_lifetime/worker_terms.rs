//! Known native Rust stack terms for the single owned workload-exit worker.
use anyhow::Result;
use mvm_core::host_lifetime::{NativeThreadStackTerms, native_thread_stack_terms};

pub fn owned_exit_capture_stack_terms() -> Result<NativeThreadStackTerms> {
    native_thread_stack_terms(2 * 1024 * 1024)
}
