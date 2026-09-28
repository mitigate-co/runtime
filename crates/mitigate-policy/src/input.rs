use crate::Error;
use mitigate_fingerprint::Fingerprint;
use mitigate_mcp::classification::CapabilityClass;
use serde::{Deserialize, Serialize};

/// Grant resolution supplied by the trusted gateway, never by a tool caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// No matching authorization.
    None,
    /// A matching explicit denial; the gateway must enforce it independently.
    Denied,
    /// A matching explicit grant.
    Explicit,
}
/// Constrained output. `RequireApproval` is not permission to invoke a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Policy permits proceeding to the gateway's remaining checks.
    Allow,
    /// Refuse invocation.
    Deny,
    /// Require a separate, still-valid approval before invocation.
    RequireApproval,
}
impl Decision {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "require_approval" => Ok(Self::RequireApproval),
            _ => Err(Error::Evaluation),
        }
    }
}
/// Closed local metadata, not a telemetry event or proof of authentication.
/// Unknown attribution is explicitly null. Hashes are not anonymization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInput {
    /// Must be one.
    pub schema_version: u32,
    /// Explicit caller reference; null when unknown.
    pub client: Option<Fingerprint>,
    /// Explicit principal reference; null when unknown.
    pub principal: Option<Fingerprint>,
    /// Explicit agent reference; null when unknown.
    pub agent: Option<Fingerprint>,
    /// Reviewed server identity.
    pub server: Fingerprint,
    /// Tool identity in the current inventory.
    pub tool: Fingerprint,
    /// Current input schema identity.
    pub schema_fingerprint: Fingerprint,
    /// Unique inferred/admin-reviewed classes, bounded by the closed vocabulary.
    pub capabilities: Vec<CapabilityClass>,
    /// True when the observed tool definition differs from the approved one.
    pub schema_changed: bool,
    /// Prior grant resolution; policy cannot override an explicit denial.
    pub grant: GrantState,
    /// Caller-supplied connectivity status from the trusted local composition.
    pub offline: bool,
}
impl PolicyInput {
    /// Parse a bounded, duplicate-free JSON object and validate all fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4096 {
            return Err(Error::Input);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Input)?;
        // Serde treats absent Option fields as None; the wire contract requires
        // explicit unknowns so producers cannot accidentally omit attribution.
        let object = value.as_object().ok_or(Error::Input)?;
        if !["client", "principal", "agent"]
            .iter()
            .all(|k| object.contains_key(*k))
        {
            return Err(Error::Input);
        }
        let input: Self = serde_json::from_value(value).map_err(|_| Error::Input)?;
        input.validate()?;
        Ok(input)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.capabilities.len() > 11
            || self
                .capabilities
                .iter()
                .enumerate()
                .any(|(i, c)| self.capabilities[..i].contains(c))
        {
            return Err(Error::Input);
        }
        Ok(())
    }
}
