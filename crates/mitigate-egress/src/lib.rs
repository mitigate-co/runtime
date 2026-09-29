//! Closed candidate events for optional Zero-Content synchronization.
//!
//! Validation is not enrollment, delivery permission, signing or an egress audit.
//! Candidate validation performs no I/O. The optional customer-local outbox
//! persists only validated events and bounded diagnostics; it owns no network
//! transport and cannot forward local audit exports.
mod guard;
pub mod inventory;
mod model;
pub mod outbox;
mod reference;
pub mod references;
pub mod self_test;
#[cfg(test)]
mod tests;

pub use model::{Attribution, Capability, Decision, DecisionFacts, Outcome, Phase};
pub use reference::SyncRef;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum untrusted input and canonical event size.
pub const MAX_EVENT_BYTES: usize = 4096;
/// Fixed field paths exposed by the inspector, never input-provided names.
pub const EVENT_FIELDS: &[&str] = &[
    "schema_version",
    "event_type",
    "event_id",
    "occurred_at_ms",
    "runtime_ref",
    "facts.call_ref",
    "facts.client_ref",
    "facts.principal_ref",
    "facts.agent_ref",
    "facts.attribution",
    "facts.server_ref",
    "facts.tool_ref",
    "facts.schema_ref",
    "facts.capabilities",
    "facts.policy_ref",
    "facts.policy_version",
    "facts.approval_ref",
    "facts.phase",
    "facts.decision",
    "facts.outcome",
    "facts.duration_ms",
];

/// Safe rejection categories. No rejected value, parser error or backend text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    /// Candidate or canonical event exceeds the explicit byte limit.
    Size,
    /// Malformed/ambiguous/deep JSON.
    Json,
    /// Unsupported version/type, missing fields or unknown keys.
    Schema,
    /// A prohibited content-bearing field was present.
    ProhibitedField,
    /// A string does not belong to the closed vocabulary/reference shape.
    Content,
    /// Numeric or collection bounds violated.
    Bounds,
    /// Identity, lifecycle or optional facts are inconsistent.
    Facts,
    /// Secure reference generation is unavailable.
    Randomness,
}
impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Size => "sync event exceeds its size limit",
            Self::Json => "sync event requires bounded unambiguous JSON",
            Self::Schema => "sync event does not match a supported closed schema",
            Self::ProhibitedField => "sync event contains a prohibited field",
            Self::Content => "sync event contains an unsupported string",
            Self::Bounds => "sync event exceeds a field limit",
            Self::Facts => "sync event facts are inconsistent",
            Self::Randomness => "secure sync reference generation is unavailable",
        })
    }
}
impl std::error::Error for Rejection {}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventType {
    McpToolDecision,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u8,
    event_type: EventType,
    event_id: SyncRef,
    occurred_at_ms: u64,
    runtime_ref: SyncRef,
    facts: DecisionFacts,
}

/// Canonical validated event. Private fields and no Deserialize/Serialize/Debug
/// prevent accidental unvalidated construction or generic logging/export.
/// Queue admission must still record its egress decision and enforce consent.
///
/// ```compile_fail
/// fn accidental_export(event: &mitigate_egress::CheckedEvent) {
///     let _ = serde_json::to_vec(event);
/// }
/// ```
pub struct CheckedEvent {
    envelope: Envelope,
    bytes: Vec<u8>,
}
impl CheckedEvent {
    /// Validate a strict closed event from an untrusted byte slice. Unknown and
    /// duplicate fields, arbitrary text, unsupported versions and facts fail.
    /// This never logs, persists or sends input (including rejected input).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Rejection> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(Rejection::Size);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Rejection::Json)?;
        guard::inspect(&value)?;
        let envelope: Envelope = serde_json::from_value(value).map_err(|_| Rejection::Schema)?;
        Self::check(envelope)
    }

    /// Construct one event from trusted local facts and enrollment-scoped opaque
    /// mappings. Caller supplies a stable event ID for idempotent queue retries.
    /// Time is trusted UTC Unix milliseconds, never copied from MCP metadata.
    pub fn decision(
        event_id: SyncRef,
        runtime_ref: SyncRef,
        occurred_at_ms: u64,
        facts: DecisionFacts,
    ) -> Result<Self, Rejection> {
        Self::check(Envelope {
            schema_version: 1,
            event_type: EventType::McpToolDecision,
            event_id,
            occurred_at_ms,
            runtime_ref,
            facts,
        })
    }

    fn check(mut envelope: Envelope) -> Result<Self, Rejection> {
        if envelope.schema_version != 1 {
            return Err(Rejection::Schema);
        }
        // Last millisecond of UTC year 9999, within interoperable integer range.
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

    /// Stable identifier for idempotent delivery, generated independently of content.
    pub fn event_id(&self) -> &SyncRef {
        &self.envelope.event_id
    }
    /// Enrollment-scoped runtime reference for local queue partition checks.
    pub fn runtime_ref(&self) -> &SyncRef {
        &self.envelope.runtime_ref
    }
    /// Trusted event observation time. Queue retention must use its own clock.
    pub fn occurred_at_ms(&self) -> u64 {
        self.envelope.occurred_at_ms
    }
    /// Explicit canonical bytes. These still require consent, recorded egress
    /// acceptance and enrollment integrity before optional Platform delivery.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
