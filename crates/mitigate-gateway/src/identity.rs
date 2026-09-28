//! Only explicitly supplied local profiles can declare caller references.
use crate::Error;
use serde::{Deserialize, Serialize};

/// Where a local caller mapping came from; never derived from MCP clientInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// No mapping was supplied by the Runtime operator.
    Unknown,
    /// Explicit local operator configuration, not cryptographic authentication.
    GatewayProfile,
}

/// Strength of attribution; a profile cannot assert an authenticated principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityConfidence {
    /// No attribution evidence.
    Unknown,
    /// Operator-declared mapping of this endpoint to opaque caller references.
    Declared,
}

/// Local policy context. These references are not automatically safe for sync.
/// No Debug implementation: even operator-supplied labels do not belong in logs.
#[derive(Clone, Serialize)]
pub struct CallerIdentity {
    client_ref: Option<String>,
    principal_ref: Option<String>,
    agent_ref: Option<String>,
    identity_source: IdentitySource,
    confidence: IdentityConfidence,
}
impl Default for CallerIdentity {
    fn default() -> Self {
        Self {
            client_ref: None,
            principal_ref: None,
            agent_ref: None,
            identity_source: IdentitySource::Unknown,
            confidence: IdentityConfidence::Unknown,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    client_ref: String,
    principal_ref: Option<String>,
    agent_ref: Option<String>,
}
impl CallerIdentity {
    /// Parse an explicitly selected profile, never an MCP message or ambient
    /// client config. Local file protection remains the operator's trust boundary.
    pub fn from_profile(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4096 {
            return Err(Error::Profile);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Profile)?;
        let profile: Profile = serde_json::from_value(value).map_err(|_| Error::Profile)?;
        if profile.schema_version != 1
            || std::iter::once(&profile.client_ref)
                .chain(profile.principal_ref.iter())
                .chain(profile.agent_ref.iter())
                .any(|s| {
                    s.is_empty()
                        || s.len() > 128
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                })
        {
            return Err(Error::Profile);
        }
        Ok(Self {
            client_ref: Some(profile.client_ref),
            principal_ref: profile.principal_ref,
            agent_ref: profile.agent_ref,
            identity_source: IdentitySource::GatewayProfile,
            confidence: IdentityConfidence::Declared,
        })
    }
    /// Explicit client reference, absent when unknown.
    pub fn client_ref(&self) -> Option<&str> {
        self.client_ref.as_deref()
    }
    /// Explicit principal reference, absent when unknown.
    pub fn principal_ref(&self) -> Option<&str> {
        self.principal_ref.as_deref()
    }
    /// Explicit agent reference, absent when unknown.
    pub fn agent_ref(&self) -> Option<&str> {
        self.agent_ref.as_deref()
    }
    /// Mapping provenance, separate from MCP implementation names.
    pub fn source(&self) -> IdentitySource {
        self.identity_source
    }
    /// Attribution strength, never promoted by client-supplied data.
    pub fn confidence(&self) -> IdentityConfidence {
        self.confidence
    }
}
