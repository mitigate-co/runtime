//! Untrusted client JSON parsing: no ambiguous duplicate keys or source-bearing errors.
//!
//! The strict visitor is adapted from the reviewed customer-side prototype parser.
//! No Platform code, keys, data, or history is imported.

use serde::{
    Deserialize,
    de::{Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::fmt;

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded JSON")
            }
            fn visit_bool<E: Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_i64<E: Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_f64<E: Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|v| StrictValue(v.into()))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, StrictValue(value))) =
                    map.next_entry::<String, StrictValue>()?
                {
                    if values.insert(key, value).is_some() {
                        return Err(A::Error::custom("duplicate"));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value, ()> {
    let StrictValue(value) = serde_json::from_slice(bytes).map_err(|_| ())?;
    fn bounded(value: &Value, depth: usize, budget: &mut usize) -> Result<(), ()> {
        if depth > 32 || *budget == 0 {
            return Err(());
        }
        *budget -= 1;
        match value {
            Value::String(s) if s.len() > 65_536 => return Err(()),
            Value::Array(items) => {
                for item in items {
                    bounded(item, depth + 1, budget)?;
                }
            }
            Value::Object(items) => {
                for (key, item) in items {
                    if key.len() > 4096 {
                        return Err(());
                    }
                    bounded(item, depth + 1, budget)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    bounded(&value, 0, &mut 32_768)?;
    Ok(value)
}
