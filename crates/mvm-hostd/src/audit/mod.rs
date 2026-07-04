//! Host-side audit binding: the chain-signed `AuditEmitter`, the host signing
//! keypair, and plan persistence. Library API so both the CLI and fleet
//! consumers emit identical chain entries.

pub mod emitter;
pub mod host_keypair;
pub mod plan_persist;
