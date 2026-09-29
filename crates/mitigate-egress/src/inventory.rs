//! Closed version-two inventory candidate protocol. Checked parts can enter the
//! ordinary consent/journal/outbox boundary; producers and hosted receivers must
//! additionally compose complete snapshots, tenant isolation and retention.
//! A valid part alone never establishes a complete or current fleet inventory.
use crate::{MAX_EVENT_BYTES, Rejection, SyncRef, model::Capability};
use serde::{Deserialize, Serialize};

mod snapshot;
#[cfg(test)]
mod tests;
pub use snapshot::{AssemblyError, CheckedSnapshot};

/// The local MCP enumerator already bounds one observed inventory to 512 tools.
pub const MAX_TOOLS: u16 = 512;
/// Fixed part size keeps worst-case taxonomy facts inside the existing 4 KiB cap.
pub const TOOLS_PER_PART: usize = 4;
/// Fixed field paths exposed by the inspector, never input-provided names.
pub const EVENT_FIELDS: &[&str] = &[
    "schema_version",
    "event_type",
    "event_id",
    "occurred_at_ms",
    "runtime_ref",
    "facts.snapshot_ref",
    "facts.server_ref",
    "facts.tools_supported",
    "facts.tool_count",
    "facts.part_index",
    "facts.tools[].tool_ref",
    "facts.tools[].schema_ref",
    "facts.tools[].capabilities",
    "facts.tools[].risk_flags",
    "facts.tools[].classification_sources",
    "facts.tools[].confidence",
];

/// Closed source of a local classification; not remote authentication or consent.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationSource {
    /// Versioned local deterministic rules.
    Deterministic,
    /// An explicit local override bound to this definition.
    Admin,
}
/// Strength of classification evidence, never a safety score.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Insufficient evidence or name-only inference.
    Low,
    /// Local schema shape contributes evidence.
    Medium,
    /// Explicit local administrator declaration.
    High,
}
/// Closed review flags. No rule matches, labels or schema values leave Runtime.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    /// Potential data/resource destruction.
    Destructive,
    /// Potential credential access.
    CredentialAccess,
    /// Potential unconstrained execution.
    ArbitraryCodeExecution,
    /// Potential external communication.
    ExternalCommunication,
    /// Potential identity/permission administration.
    IdentityAdmin,
    /// Potential infrastructure changes.
    InfrastructureChange,
    /// Unknown operation requires review.
    UnknownHighImpact,
}
/// One observed tool's correlation and classification facts, never its definition.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    /// Random enrollment-scoped mapping for the local tool identity.
    pub tool_ref: SyncRef,
    /// Random mapping for the locally observed definition revision, not its hash.
    pub schema_ref: SyncRef,
    /// One to eleven distinct closed capability labels; hints, not permissions.
    pub capabilities: Vec<Capability>,
    /// Zero to seven distinct review flags, retaining conservative baseline flags.
    pub risk_flags: Vec<RiskFlag>,
    /// Deterministic, optionally augmented by an explicit administrator override.
    pub classification_sources: Vec<ClassificationSource>,
    /// Confidence of the classification, not of tool trustworthiness.
    pub confidence: Confidence,
}
/// A bounded part of one independently identified, complete local observation.
/// Receivers must assemble every part before presenting its inventory as complete.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    /// Fresh random identifier shared by all parts of this observation.
    pub snapshot_ref: SyncRef,
    /// Enrollment-scoped random mapping for the local server identity.
    pub server_ref: SyncRef,
    /// Whether this server advertised tools; false requires an empty observation.
    pub tools_supported: bool,
    /// Number of tools in the full observation, at most 512.
    pub tool_count: u16,
    /// Zero-based part index; required parts derive from tool_count and part size.
    pub part_index: u8,
    /// Exactly four tools except the last part, or an empty sole part for zero.
    pub tools: Vec<Tool>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventType {
    McpInventorySnapshot,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u8,
    event_type: EventType,
    event_id: SyncRef,
    occurred_at_ms: u64,
    runtime_ref: SyncRef,
    facts: Facts,
}
/// A validated canonical candidate part. No generic Debug/Serialize/Deserialize.
/// Conversion to CheckedEvent still requires consent and journaled queue admission
/// before signing; the candidate alone is never permission to transmit.
///
/// ```compile_fail
/// fn accidental_export(part: &mitigate_egress::inventory::CheckedPart) {
///     let _ = serde_json::to_vec(part);
/// }
/// ```
pub struct CheckedPart {
    envelope: Envelope,
    bytes: Vec<u8>,
}
impl CheckedPart {
    /// Validate untrusted bounded JSON, including every exact nested field and
    /// reference/enum shape. Rejected input and parser causes are never retained.
    /// No queue, network, credential, consent or local audit operation occurs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Rejection> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(Rejection::Size);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Rejection::Json)?;
        Self::from_value(value)
    }
    pub(crate) fn from_value(value: serde_json::Value) -> Result<Self, Rejection> {
        // This protocol has no free-form string fields. Its exact deserializer
        // rejects all unknown objects/keys, including prohibited content fields.
        let envelope = serde_json::from_value(value).map_err(|_| Rejection::Schema)?;
        Self::check(envelope)
    }
    /// Construct from trusted local facts after mapping local identities to
    /// independent random references. Generate a fresh event ID for each part;
    /// retries must retain the original checked bytes and snapshot identity.
    pub fn new(
        event_id: SyncRef,
        runtime_ref: SyncRef,
        occurred_at_ms: u64,
        facts: Facts,
    ) -> Result<Self, Rejection> {
        Self::check(Envelope {
            schema_version: 2,
            event_type: EventType::McpInventorySnapshot,
            event_id,
            occurred_at_ms,
            runtime_ref,
            facts,
        })
    }
    fn check(mut envelope: Envelope) -> Result<Self, Rejection> {
        if envelope.schema_version != 2 {
            return Err(Rejection::Schema);
        }
        if envelope.occurred_at_ms > 253_402_300_799_999 {
            return Err(Rejection::Bounds);
        }
        envelope.facts.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(&envelope).map_err(|_| Rejection::Schema)?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(Rejection::Size);
        }
        Ok(Self { envelope, bytes })
    }
    /// Explicit canonical candidate bytes. They are not permission to transmit.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The immutable checked part facts; callers cannot mutate canonical state.
    pub fn facts(&self) -> &Facts {
        &self.envelope.facts
    }
    /// Stable per-part event identity, independent of customer data.
    pub fn event_id(&self) -> &SyncRef {
        &self.envelope.event_id
    }
    /// Scope of the observation. Receivers also bind the authenticated enrollment.
    pub fn runtime_ref(&self) -> &SyncRef {
        &self.envelope.runtime_ref
    }
    /// Observation time, identical across every part. Not a retention clock.
    pub fn occurred_at_ms(&self) -> u64 {
        self.envelope.occurred_at_ms
    }
}

impl Facts {
    /// Exact number of required parts for a validated full observation, including
    /// a sole empty part when zero tools are observed. Validate before relying on it.
    pub fn part_count(&self) -> usize {
        usize::from(self.tool_count).div_ceil(TOOLS_PER_PART).max(1)
    }
    fn validate(&mut self) -> Result<(), Rejection> {
        if self.tool_count > MAX_TOOLS || self.tools.len() > TOOLS_PER_PART {
            return Err(Rejection::Bounds);
        }
        let index = usize::from(self.part_index);
        if index >= self.part_count() || (!self.tools_supported && self.tool_count != 0) {
            return Err(Rejection::Facts);
        }
        let expected = (usize::from(self.tool_count) - index * TOOLS_PER_PART).min(TOOLS_PER_PART);
        if self.tools.len() != expected {
            return Err(Rejection::Facts);
        }
        self.tools
            .sort_unstable_by(|a, b| a.tool_ref.cmp(&b.tool_ref));
        if self
            .tools
            .windows(2)
            .any(|p| p[0].tool_ref == p[1].tool_ref)
        {
            return Err(Rejection::Facts);
        }
        for tool in &mut self.tools {
            if tool.capabilities.is_empty()
                || tool.capabilities.len() > 11
                || tool.risk_flags.len() > 7
                || tool.classification_sources.is_empty()
                || tool.classification_sources.len() > 2
            {
                return Err(Rejection::Bounds);
            }
            unique(&mut tool.capabilities)?;
            unique(&mut tool.risk_flags)?;
            unique(&mut tool.classification_sources)?;
            if tool.classification_sources[0] != ClassificationSource::Deterministic
                || (tool
                    .classification_sources
                    .contains(&ClassificationSource::Admin)
                    != (tool.confidence == Confidence::High))
            {
                return Err(Rejection::Facts);
            }
        }
        Ok(())
    }
}
fn unique<T: Ord>(values: &mut [T]) -> Result<(), Rejection> {
    values.sort_unstable();
    if values.windows(2).any(|p| p[0] == p[1]) {
        Err(Rejection::Facts)
    } else {
        Ok(())
    }
}
