//! Source-qualified requested-allocation terms; never a parent credential.
//! The exact parser/type closure and field derivation are recorded in
//! SpiralCore's installed-endpoint-bootstrap contract. Thread/TLS/OS terms
//! remain separate. The original parent reservation must precede this query.

use super::CONFIG_LIMIT;
use anyhow::{Result, anyhow};
use mvm_core::bounded_owned_json::{JsonShapeLimits, inspect_shape};
use serde::{
    Deserialize, Deserializer,
    de::{IgnoredAny, MapAccess, Visitor},
};
use std::fmt;

/// Overlapping fixed control/header/raw/scratch/path storage before decoding.
/// This replaces neither actual reservation nor the separate typed node term.
pub(super) const INSTALLED_BOOTSTRAP_MIN_BYTES: u64 = 9 * CONFIG_LIMIT as u64;

const NODE_REQUEST_BYTES: u64 = 1024;

/// Compute the checked instance workspace before typed canonical config decode.
/// No quota, process, file, payload or admission authority is minted here.
pub(super) fn installed_endpoint_bootstrap_requirement(config: &str) -> Result<u64> {
    let shape = inspect_shape(
        config.as_bytes(),
        JsonShapeLimits {
            bytes: CONFIG_LIMIT,
            nodes: CONFIG_LIMIT,
            depth: 128,
            text: CONFIG_LIMIT,
        },
    )
    .map_err(|_| anyhow!("invalid installed endpoint configuration"))?;
    // Match the existing installed parent's unsupported-container boundary
    // BEFORE typed Vec/BTreeMap construction. Unknown fields were already
    // visited by the whole-body guard, and the canonical decoder remains next.
    let fields: ProfileContainers<'_> = serde_json::from_str(config)
        .map_err(|_| anyhow!("invalid installed endpoint configuration"))?;
    if let Some(raw) = fields.tools {
        serde_json::from_str::<EmptyTools>(raw.get())
            .map_err(|_| anyhow!("installed endpoint tools unsupported"))?;
    }
    for raw in [fields.secrets, fields.ingress].into_iter().flatten() {
        serde_json::from_str::<[IgnoredAny; 0]>(raw.get())
            .map_err(|_| anyhow!("installed endpoint container unsupported"))?;
    }
    requirement_for_nodes(shape.nodes)
}

fn requirement_for_nodes(nodes: usize) -> Result<u64> {
    u64::try_from(nodes)
        .ok()
        .and_then(|nodes| nodes.checked_mul(NODE_REQUEST_BYTES))
        .and_then(|nodes| nodes.checked_add(INSTALLED_BOOTSTRAP_MIN_BYTES))
        .ok_or_else(|| anyhow!("installed endpoint workspace overflow"))
}

#[derive(Deserialize)]
struct ProfileContainers<'a> {
    #[serde(borrow)]
    tools: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    secrets: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    ingress: Option<&'a serde_json::value::RawValue>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EmptyTools {
    #[serde(rename = "allow")]
    _allow: [IgnoredAny; 0],
    #[serde(rename = "ask")]
    _ask: [IgnoredAny; 0],
    #[serde(rename = "deny")]
    _deny: [IgnoredAny; 0],
    #[serde(rename = "detail")]
    _detail: EmptyObject,
}

#[derive(Default)]
struct EmptyObject;
impl<'de> Deserialize<'de> for EmptyObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Empty;
        impl<'de> Visitor<'de> for Empty {
            type Value = EmptyObject;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("empty installed object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("nonempty installed object"));
                }
                Ok(EmptyObject)
            }
        }
        deserializer.deserialize_map(Empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_node_arithmetic_never_wraps_into_a_small_reservation() {
        assert!(requirement_for_nodes(usize::MAX).is_err());
        assert_eq!(
            requirement_for_nodes(0).unwrap(),
            INSTALLED_BOOTSTRAP_MIN_BYTES
        );
    }
}
