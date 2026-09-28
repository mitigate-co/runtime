use crate::Rejection;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

/// Enrollment-scoped opaque reference. Generate randomly, retain its local
/// mapping, and rotate mappings on reenrollment. Never encode/hash customer
/// content or copy local audit fingerprints into this field.
///
/// Shape validation cannot establish how another producer obtained its bits.
/// This is a correlation identifier, not authentication or anonymization.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct SyncRef(String);

impl SyncRef {
    /// Generate a 128-bit random reference without reading workload data.
    pub fn fresh() -> Result<Self, Rejection> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|_| Rejection::Randomness)?;
        let mut text = String::from("ref_");
        for byte in bytes {
            write!(text, "{byte:02x}").map_err(|_| Rejection::Randomness)?;
        }
        Ok(Self(text))
    }

    /// Explicitly borrow the opaque identifier for a customer-local mapping.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn valid(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("ref_")
        && value.as_bytes()[4..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

impl<'de> Deserialize<'de> for SyncRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if !valid(&value) {
            return Err(serde::de::Error::custom("invalid sync reference"));
        }
        Ok(Self(value))
    }
}
