//! Deterministic local fingerprints, not encryption, signatures or anonymization.
//!
//! No network or file I/O. Content-derived digests are not automatically eligible
//! for Platform telemetry; their privacy treatment is a separate trust boundary.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Versioned canonicalization/hash contract recorded in snapshots.
pub const PROFILE: &str = "mitigate-local-jcs-sha256-v1";

/// Domain separates otherwise identical data in different security concepts.
#[derive(Copy, Clone)]
pub enum Domain {
    /// Bounded, redacted discovery facts; not executable provenance.
    ConfigurationSummary,
    /// Server's declared name, not authenticated identity.
    ServerIdentity,
    /// Version/protocol/capability facts reported by the server.
    ServerFacts,
    /// Tool name scoped to declared server identity.
    ToolIdentity,
    /// Complete local input schema.
    InputSchema,
    /// Complete local output schema.
    OutputSchema,
    /// Whitespace-normalized local description, never policy authority.
    Description,
    /// Salted exact local launch facts; never a telemetry configuration summary.
    LaunchConfiguration,
}
impl Domain {
    fn label(self) -> &'static [u8] {
        match self {
            Self::ConfigurationSummary => b"configuration-summary",
            Self::ServerIdentity => b"server-identity",
            Self::ServerFacts => b"server-facts",
            Self::ToolIdentity => b"tool-identity",
            Self::InputSchema => b"input-schema",
            Self::OutputSchema => b"output-schema",
            Self::Description => b"description",
            Self::LaunchConfiguration => b"launch-configuration",
        }
    }
}

/// Lowercase SHA-256 hexadecimal digest. Deserialization rejects all other shapes.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Fingerprint(String);
impl Fingerprint {
    /// Borrow the validated lowercase hexadecimal reference explicitly.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(serde::de::Error::custom("invalid fingerprint"));
        }
        Ok(Self(value))
    }
}

/// Input cannot be fingerprinted under the bounded numeric/complexity profile.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvalidDefinition;

fn validate(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    bytes: &mut usize,
) -> Result<(), InvalidDefinition> {
    if depth > 32 || *nodes == 0 {
        return Err(InvalidDefinition);
    }
    *nodes -= 1;
    match value {
        Value::String(s) => {
            if s.len() > 65_536 {
                return Err(InvalidDefinition);
            }
            *bytes = bytes.checked_sub(s.len()).ok_or(InvalidDefinition)?;
        }
        Value::Array(items) => {
            for item in items {
                validate(item, depth + 1, nodes, bytes)?;
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                if key.len() > 4096 {
                    return Err(InvalidDefinition);
                }
                *bytes = bytes.checked_sub(key.len()).ok_or(InvalidDefinition)?;
                validate(item, depth + 1, nodes, bytes)?;
            }
        }
        Value::Number(number) => {
            // JCS uses IEEE-754 doubles. Refuse integers outside the exact safe
            // range rather than silently conflating distinct schema constraints.
            const SAFE: u64 = 9_007_199_254_740_991;
            if number.as_i64().is_some_and(|n| n.unsigned_abs() > SAFE)
                || number.as_u64().is_some_and(|n| n > SAFE)
                || number
                    .as_f64()
                    .is_some_and(|n| !n.is_finite() || (n.fract() == 0.0 && n.abs() > SAFE as f64))
            {
                return Err(InvalidDefinition);
            }
        }
        _ => (),
    }
    Ok(())
}

/// RFC 8785 encoding with explicit size/depth/numeric guards. Strings and array
/// order retain their meaning; no schema simplification or reference fetching.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, InvalidDefinition> {
    validate(value, 0, &mut 32_768, &mut 1_048_576)?;
    let bytes = serde_json_canonicalizer::to_vec(value).map_err(|_| InvalidDefinition)?;
    if bytes.len() > 1_048_576 {
        return Err(InvalidDefinition);
    }
    Ok(bytes)
}

/// Hash canonical JSON with a versioned prefix and a fixed domain discriminator.
pub fn fingerprint(domain: Domain, value: &Value) -> Result<Fingerprint, InvalidDefinition> {
    let mut digest = Sha256::new();
    digest.update(PROFILE.as_bytes());
    digest.update([0]);
    digest.update(domain.label());
    digest.update([0]);
    digest.update(canonicalize(value)?);
    Ok(Fingerprint(format!("{:x}", digest.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn equivalent_encodings_match_and_domains_stay_distinct() {
        let a: Value =
            serde_json::from_str(r#"{"b":1.0,"a":"\u0061","nested":{"z":-0.0,"a":true}}"#).unwrap();
        let b = json!({"nested":{"a":true,"z":0},"a":"a","b":1});
        assert_eq!(
            canonicalize(&a).unwrap(),
            br#"{"a":"a","b":1,"nested":{"a":true,"z":0}}"#
        );
        assert_eq!(
            fingerprint(Domain::InputSchema, &a).unwrap(),
            fingerprint(Domain::InputSchema, &b).unwrap()
        );
        assert_ne!(
            fingerprint(Domain::InputSchema, &a).unwrap(),
            fingerprint(Domain::OutputSchema, &a).unwrap()
        );
        assert_ne!(
            fingerprint(Domain::InputSchema, &json!([1, 2])).unwrap(),
            fingerprint(Domain::InputSchema, &json!([2, 1])).unwrap()
        );
    }
    #[test]
    fn utf16_order_and_unicode_content_are_not_conflated() {
        assert_eq!(
            canonicalize(&json!({"\u{e000}":1,"\u{1f600}":2})).unwrap(),
            "{\"😀\":2,\"\u{e000}\":1}".as_bytes()
        );
        assert_ne!(
            fingerprint(Domain::Description, &json!("é")).unwrap(),
            fingerprint(Domain::Description, &json!("e\u{301}")).unwrap()
        );
        for invalid in [
            json!(9_007_199_254_740_992u64),
            json!(-9_007_199_254_740_992i64),
            json!(1e30),
        ] {
            assert_eq!(canonicalize(&invalid), Err(InvalidDefinition));
        }
    }
    #[test]
    fn digest_encoding_is_closed_and_bounded() {
        for value in ["not-a-hash".to_owned(), "A".repeat(64), "f".repeat(65)] {
            assert!(serde_json::from_value::<Fingerprint>(json!(value)).is_err());
        }
        assert!(canonicalize(&json!("x".repeat(65_537))).is_err());
        assert!(serde_json::from_value::<Fingerprint>(json!("0".repeat(64))).is_ok());
    }
}
