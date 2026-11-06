//! Borrowed structural preparse. Limits describe shape, not memory or authority.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonShapeLimits {
    pub bytes: usize,
    pub nodes: usize,
    pub depth: usize,
    pub text: usize,
}

/// Checked input facts only. These counts confer no allocation or authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonShape {
    pub nodes: usize,
    pub text_bytes: usize,
}

struct Shape {
    limits: JsonShapeLimits,
    nodes: usize,
    depth: usize,
    text: usize,
}
impl Shape {
    fn node<E: serde::de::Error>(&mut self) -> Result<(), E> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| E::custom("owned JSON node overflow"))?;
        if self.nodes > self.limits.nodes {
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
        if self.text > self.limits.text {
            return Err(E::custom("owned JSON text limit"));
        }
        Ok(())
    }
    fn enter<E: serde::de::Error>(&mut self) -> Result<(), E> {
        self.node()?;
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| E::custom("owned JSON depth overflow"))?;
        if self.depth > self.limits.depth {
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
pub fn validate_shape(bytes: &[u8], limits: JsonShapeLimits) -> Result<(), serde_json::Error> {
    inspect_shape(bytes, limits).map(|_| ())
}

/// Inspect the same bounded borrowed walk, without constructing a Value tree.
pub fn inspect_shape(
    bytes: &[u8],
    limits: JsonShapeLimits,
) -> Result<JsonShape, serde_json::Error> {
    if bytes.len() > limits.bytes {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "owned JSON body limit",
        ));
    }
    let mut shape = Shape {
        limits,
        nodes: 0,
        depth: 0,
        text: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    ShapeSeed(&mut shape).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(JsonShape {
        nodes: shape.nodes,
        text_bytes: shape.text,
    })
}

pub fn validate_value(
    value: &serde_json::Value,
    limits: JsonShapeLimits,
) -> Result<(), serde_json::Error> {
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
    walk(
        value,
        &mut Shape {
            limits,
            nodes: 0,
            depth: 0,
            text: 0,
        },
    )
}
