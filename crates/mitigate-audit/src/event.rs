use crate::{CallContext, Error};
use mitigate_fingerprint::Fingerprint;
use mitigate_gateway::CallerIdentity;
use mitigate_mcp::classification::CapabilityClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Source of caller references; nothing in MCP clientInfo establishes identity.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// No explicit local profile was supplied.
    Unknown,
    /// Local operator profile, not authenticated identity.
    DeclaredProfile,
}
/// Audited gateway operation, not the tool's user-controlled name.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Request for a server's tool definitions.
    Inventory,
    /// Request to invoke a tool.
    ToolCall,
}
/// Explicit decision; a recorded allowance does not itself authorize execution.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Inventory access with execution disabled.
    InventoryOnly,
    /// Evaluated policy/grants allowed the action.
    Allow,
    /// Allowed with mandatory audit; version-two call events only.
    AllowAndLog,
    /// The action was denied.
    Deny,
    /// Local quota denied admission; version-two call events only.
    RateLimit,
    /// Emergency/exact disable denied admission; version-two call events only.
    DisableTool,
    /// Human approval is required and not yet satisfied.
    RequireApproval,
    /// No completed decision, due to a local/upstream error.
    Error,
}
/// Closed result classification, never raw upstream error text.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultClass {
    /// Decision recorded before execution; outcome not yet known.
    Pending,
    /// Operation completed successfully.
    Success,
    /// Operation failed.
    Error,
    /// Operation was cancelled; side effects may be uncertain.
    Cancelled,
    /// Invocation did not occur.
    NotInvoked,
    /// Dispatch may have occurred but no trustworthy completion was observed.
    /// Version-two call events only; never imply that retrying is safe.
    Uncertain,
}

/// Closed local metadata. No strings that could hold raw arguments or results.
/// Reference digests are local correlation keys, not anonymization or provenance.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDetails {
    /// Closed request type.
    pub operation: Operation,
    /// Hash of the explicitly declared client reference, absent when unknown.
    pub client_ref: Option<Fingerprint>,
    /// Hash of the explicitly declared principal reference, absent when unknown.
    pub principal_ref: Option<Fingerprint>,
    /// Hash of the explicitly declared agent reference, absent when unknown.
    pub agent_ref: Option<Fingerprint>,
    /// Provenance of caller mapping, never promoted to authenticated.
    pub attribution: Attribution,
    /// Owner-resolved server reference (reviewed launch for governed calls).
    /// The audit store does not verify executable identity or authority.
    pub server_ref: Fingerprint,
    /// Observed tool reference, absent for inventory/unknown tools.
    pub tool_ref: Option<Fingerprint>,
    /// Current inferred/admin classes; empty if no tool was resolved.
    pub capability_classes: Vec<CapabilityClass>,
    /// Observed input schema fingerprint, absent if no tool was resolved.
    pub schema_fingerprint: Option<Fingerprint>,
    /// Evaluated policy reference, if policy evaluation occurred.
    pub policy_ref: Option<Fingerprint>,
    /// Policy version, paired with policy_ref.
    pub policy_version: Option<u64>,
    /// Actual gateway decision.
    pub decision: Decision,
    /// Approval reference, if an approval was involved.
    pub approval_ref: Option<Fingerprint>,
    /// Outcome class without source messages.
    pub result_class: ResultClass,
    /// Elapsed monotonic duration, capped at one day.
    pub duration_ms: u64,
    /// Optional reference to separately managed local evidence. No evidence body.
    pub evidence_ref: Option<Fingerprint>,
}
impl EventDetails {
    /// Start a content-free record using only explicit caller mapping. Additional
    /// decision fields must be supplied by the trusted gateway composition.
    pub fn new(caller: &CallerIdentity, server_ref: Fingerprint, operation: Operation) -> Self {
        Self {
            operation,
            client_ref: caller.client_ref().map(|v| reference(b"client", v)),
            principal_ref: caller.principal_ref().map(|v| reference(b"principal", v)),
            agent_ref: caller.agent_ref().map(|v| reference(b"agent", v)),
            attribution: if caller.client_ref().is_some() {
                Attribution::DeclaredProfile
            } else {
                Attribution::Unknown
            },
            server_ref,
            tool_ref: None,
            capability_classes: Vec::new(),
            schema_fingerprint: None,
            policy_ref: None,
            policy_version: None,
            decision: Decision::Error,
            approval_ref: None,
            result_class: ResultClass::NotInvoked,
            duration_ms: 0,
            evidence_ref: None,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.duration_ms > 86_400_000
            || self.capability_classes.len() > 11
            || self
                .capability_classes
                .iter()
                .enumerate()
                .any(|(i, c)| self.capability_classes[..i].contains(c))
            || self.policy_ref.is_some() != self.policy_version.is_some()
            || self
                .policy_version
                .is_some_and(|v| v > 9_007_199_254_740_991)
            || (self.attribution == Attribution::Unknown
                && (self.client_ref.is_some()
                    || self.principal_ref.is_some()
                    || self.agent_ref.is_some()))
            || (self.attribution == Attribution::DeclaredProfile && self.client_ref.is_none())
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
fn reference(domain: &[u8], value: &str) -> Fingerprint {
    let mut hash = Sha256::new();
    hash.update(b"mitigate-local-audit-reference-v1\0");
    hash.update(domain);
    hash.update([0]);
    hash.update(value.as_bytes());
    serde_json::from_value(serde_json::Value::String(format!("{:x}", hash.finalize())))
        .expect("SHA-256 produces a valid fingerprint")
}

/// Immutable event envelope generated by the audit store.
#[derive(Clone, Serialize)]
pub struct Event {
    /// Local event schema version (distinct from the database schema).
    pub schema_version: u32,
    /// Random 128-bit ID encoded as 32 lowercase hex characters.
    pub event_id: String,
    /// Wall-clock milliseconds since Unix epoch; retention uses a nondecreasing clock.
    pub time_ms: u64,
    /// Bounded, typed event detail.
    pub detail: EventDetails,
    /// Version-two invocation context. Omitted entirely for legacy events so
    /// their canonical serialization and original chain hashes stay unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<CallContext>,
}
impl Event {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.time_ms > 9_007_199_254_740_991
            || self.event_id.len() != 32
            || !self
                .event_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        self.detail.validate()?;
        match (self.schema_version, &self.call) {
            (1, None)
                if !matches!(
                    self.detail.decision,
                    Decision::AllowAndLog | Decision::RateLimit | Decision::DisableTool
                ) && self.detail.result_class != ResultClass::Uncertain =>
            {
                Ok(())
            }
            (2, Some(call)) => call.validate(&self.detail),
            _ => Err(Error::InvalidInput),
        }
    }
}

// Preserve field presence as well as value: version one must not acquire a
// `call: null` field, and version two requires a complete, non-null context.
#[derive(Default)]
enum CallField {
    #[default]
    Absent,
    Present(CallContext),
}
impl<'de> Deserialize<'de> for CallField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        CallContext::deserialize(deserializer).map(Self::Present)
    }
}
impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u32,
            event_id: String,
            time_ms: u64,
            detail: EventDetails,
            #[serde(default)]
            call: CallField,
        }
        let wire = Wire::deserialize(deserializer)?;
        let event = Event {
            schema_version: wire.schema_version,
            event_id: wire.event_id,
            time_ms: wire.time_ms,
            detail: wire.detail,
            call: match wire.call {
                CallField::Absent => None,
                CallField::Present(call) => Some(call),
            },
        };
        event
            .validate()
            .map_err(|_| serde::de::Error::custom("invalid audit event"))?;
        Ok(event)
    }
}
