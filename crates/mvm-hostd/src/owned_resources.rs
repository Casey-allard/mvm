//! Bounded local subdivisions of an already held installed parent partition.
//!
//! This module grants no authority and is not a whole-process/RSS bound.

use std::fmt;
use std::sync::Arc;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const FRAME_BYTES: usize = 65536;
pub const WORKSPACE_BYTES: u64 = 8 * 1024 * 1024;
pub const SERVICE_WORKSPACES: usize = 2;
pub const SIGNER_WORKSPACES: usize = 2;
pub const CONTROL_WORKSPACES: usize = 1;
const NODES: usize = 1024;
const DEPTH: usize = 32;

/// Recheck the kernel limit on each original process before establishing readiness.
pub fn check_process_address_space(limit: Option<std::num::NonZeroU64>) -> anyhow::Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        let actual = rustix::process::getrlimit(rustix::process::Resource::As);
        anyhow::ensure!(
            actual
                .current
                .zip(actual.maximum)
                .is_some_and(|(soft, hard)| soft <= hard && hard <= limit.get()),
            "original process address space exceeds its reservation"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = limit;
        anyhow::bail!("original process address-space enforcement unavailable")
    }
}

#[derive(Clone)]
pub struct WorkspacePool(Arc<Semaphore>);
pub struct WorkspacePermit {
    _held: OwnedSemaphorePermit,
}
impl WorkspacePool {
    pub fn new(slots: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            usize::BITS == 64
                && std::mem::size_of::<serde_json::Value>() <= 32
                && std::mem::size_of::<serde_json::Map<String, serde_json::Value>>() <= 32
                && std::mem::size_of::<String>() <= 24,
            "unqualified owned JSON layout"
        );
        anyhow::ensure!((1..=2).contains(&slots), "owned workspace count");
        Ok(Self(Arc::new(Semaphore::new(slots))))
    }
    pub fn try_acquire(&self) -> anyhow::Result<WorkspacePermit> {
        Ok(WorkspacePermit {
            _held: self.0.clone().try_acquire_owned()?,
        })
    }
    pub async fn acquire(&self) -> anyhow::Result<WorkspacePermit> {
        Ok(WorkspacePermit {
            _held: self.0.clone().acquire_owned().await?,
        })
    }
}

pub(crate) fn task_size(future: &impl Sized) -> anyhow::Result<()> {
    anyhow::ensure!(
        std::mem::size_of_val(future) <= 16 * 1024,
        "owned task frame size"
    );
    Ok(())
}

#[derive(Default)]
struct Shape {
    nodes: usize,
    depth: usize,
    text: usize,
}
impl Shape {
    fn node<E: serde::de::Error>(&mut self) -> Result<(), E> {
        self.nodes += 1;
        if self.nodes > NODES {
            return Err(E::custom("owned JSON node limit"));
        }
        Ok(())
    }
    fn text<E: serde::de::Error>(&mut self, text: &str) -> Result<(), E> {
        self.node()?;
        self.text = self
            .text
            .checked_add(text.len())
            .ok_or_else(|| E::custom("owned JSON text overflow"))?;
        if self.text > FRAME_BYTES {
            return Err(E::custom("owned JSON text limit"));
        }
        Ok(())
    }
    fn enter<E: serde::de::Error>(&mut self) -> Result<(), E> {
        self.node()?;
        self.depth += 1;
        if self.depth > DEPTH {
            return Err(E::custom("owned JSON depth limit"));
        }
        Ok(())
    }
}
struct ShapeSeed<'a>(&'a mut Shape);
impl<'de> DeserializeSeed<'de> for ShapeSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ShapeSeed<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded owned JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        self.0.node()
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        self.0.node()
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        self.0.node()
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        self.0.node()
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.0.node()
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        self.0.text(value)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
        self.0.enter()?;
        while access.next_element_seed(ShapeSeed(self.0))?.is_some() {}
        self.0.depth -= 1;
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
        self.0.enter()?;
        while access.next_key_seed(ShapeSeed(self.0))?.is_some() {
            access.next_value_seed(ShapeSeed(self.0))?;
        }
        self.0.depth -= 1;
        Ok(())
    }
}

/// Check shape before constructing the canonical owned typed tree.
/// serde_json may use bounded scratch for escaped strings; it creates no Value
/// tree here. The raw body and all scratch remain within the held workspace.
pub fn validate_shape(bytes: &[u8]) -> Result<(), serde_json::Error> {
    if bytes.len() > FRAME_BYTES {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "owned JSON body limit",
        ));
    }
    let mut shape = Shape::default();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    ShapeSeed(&mut shape).deserialize(&mut deserializer)?;
    deserializer.end()
}

pub(crate) fn validate_value(value: &serde_json::Value) -> Result<(), serde_json::Error> {
    fn walk(value: &serde_json::Value, shape: &mut Shape) -> Result<(), serde_json::Error> {
        match value {
            serde_json::Value::Array(values) => {
                shape.enter()?;
                for value in values {
                    walk(value, shape)?;
                }
                shape.depth -= 1;
            }
            serde_json::Value::Object(values) => {
                shape.enter()?;
                for (key, value) in values {
                    shape.text(key)?;
                    walk(value, shape)?;
                }
                shape.depth -= 1;
            }
            serde_json::Value::String(text) => shape.text(text)?,
            _ => shape.node()?,
        }
        Ok(())
    }
    walk(value, &mut Shape::default())
}

pub(crate) fn encoded_len(
    value: &impl serde::Serialize,
    cap: usize,
) -> Result<usize, serde_json::Error> {
    struct Count {
        used: usize,
        cap: usize,
    }
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.cap.saturating_sub(self.used) {
                return Err(std::io::Error::other("owned encoded byte limit"));
            }
            self.used += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count { used: 0, cap };
    serde_json::to_writer(&mut count, value)?;
    Ok(count.used)
}

pub(crate) fn read_key(path: &std::path::Path) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    read_key_checked(path, |_| Ok(()))
}

pub(crate) fn read_signer_secret(
    path: &std::path::Path,
) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    read_key_checked(path, |metadata| {
        mvm_core::private_fs::require_current_owner(metadata)?;
        anyhow::ensure!(
            mvm_core::private_fs::mode_bits(path, metadata)?
                == crate::audit::host_keypair::SECRET_MODE,
            "registered host signer requires owner-only mode 0600"
        );
        Ok(())
    })
}

fn read_key_checked(
    path: &std::path::Path,
    check: impl FnOnce(&std::fs::Metadata) -> anyhow::Result<()>,
) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() == 32,
        "owned key size/type"
    );
    check(&metadata)?;
    let mut bytes = zeroize::Zeroizing::new([0; 32]);
    file.read_exact(bytes.as_mut())?;
    anyhow::ensure!(file.read(&mut [0; 1])? == 0, "owned key changed size");
    Ok(bytes)
}

#[cfg(test)]
#[path = "owned_resources/registered_tests.rs"]
mod registered_tests;

#[path = "owned_resources/registered.rs"]
pub mod registered;
