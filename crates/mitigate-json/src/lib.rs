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

/// Rejected JSON; contains no parser diagnostics or original content.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvalidJson;

/// Parse at most 1 MiB, rejecting duplicate keys and excessive complexity.
/// Returned values remain untrusted local content and must never be logged.
pub fn parse(bytes: &[u8]) -> Result<Value, InvalidJson> {
    if bytes.len() > 1_048_576 {
        return Err(InvalidJson);
    }
    let StrictValue(value) = serde_json::from_slice(bytes).map_err(|_| InvalidJson)?;
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
    bounded(&value, 0, &mut 32_768).map_err(|_| InvalidJson)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_nested_ambiguity_and_complexity_without_diagnostics() {
        assert!(parse(br#"{"a":[{"key":1,"key":2}]}"#).is_err());
        assert!(parse(&vec![b' '; 1_048_577]).is_err());
        assert!(parse(format!("{}0{}", "[".repeat(33), "]".repeat(33)).as_bytes()).is_err());
        assert!(parse(format!("[{}0]", "0,".repeat(32_768)).as_bytes()).is_err());
        assert!(parse(format!("\"{}\"", "a".repeat(65_537)).as_bytes()).is_err());
        assert_eq!(parse(br#"{"ok":[null,true,2,2.5]}"#).unwrap()["ok"][3], 2.5);
    }
}
