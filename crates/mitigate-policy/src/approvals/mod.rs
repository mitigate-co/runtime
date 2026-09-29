//! Local, one-call approvals. Raw arguments/results are never stored here.
//! A consumed approval satisfies only the approval check for its exact binding.
mod storage;
#[cfg(test)]
mod tests;

use mitigate_fingerprint::Fingerprint;
use mitigate_mcp::classification::CapabilityClass;
use serde::{Deserialize, Serialize};
pub use storage::ApprovalStore;

const MAX_TIME: u64 = 9_007_199_254_740_991;
const MAX_TTL: u64 = 300_000;
const MAX_RECORD: usize = 4096;

/// Content-free approval failures. None permits execution or automatic retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Malformed or unsupported metadata, reference, duration or transition.
    Input,
    /// Unsafe, inaccessible or already existing local file.
    Path,
    /// A competing SQLite operation prevented acquiring or completing a lock.
    Busy,
    /// SQLite interrupted the operation, including an exhausted execution budget.
    Interrupted,
    /// Corrupt, full, incompatible or otherwise unavailable local storage.
    Storage,
    /// No matching request exists.
    Missing,
    /// The request has already left the state required by this operation.
    State,
    /// Clock precedes the last committed observation, or is out of range.
    Clock,
    /// Pending/recent records fill the bounded store.
    Capacity,
}
impl Error {
    /// Stable diagnostic identifier without metadata or backend errors.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input => "approval_input_invalid",
            Self::Path => "approval_path_unavailable",
            Self::Busy => "approval_store_busy",
            Self::Interrupted => "approval_store_interrupted",
            Self::Storage => "approval_store_unavailable",
            Self::Missing => "approval_missing",
            Self::State => "approval_state_conflict",
            Self::Clock => "approval_clock_invalid",
            Self::Capacity => "approval_capacity_reached",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Input => "Invalid approval metadata. Check the closed schema, reference and duration.",
            Self::Path => "Cannot use the approval file. Check its type, permissions and whether the destination already exists.",
            Self::Busy => "Approval storage is busy. Inspect the request after the competing local operation finishes; execution is not authorized.",
            Self::Interrupted => "Approval storage was interrupted. Inspect local resource availability and request state; execution is not authorized.",
            Self::Storage => "Approval storage failed closed. Check access, disk space and database integrity before retrying.",
            Self::Missing => "Approval request not found. List current requests and use the exact reference.",
            Self::State => "Approval state changed. Inspect the request; do not reuse a completed approval.",
            Self::Clock => "Approval clock check failed. Correct the system clock; execution is not authorized.",
            Self::Capacity => "Approval storage is full. Resolve pending requests or wait for terminal-record retention to expire.",
        })
    }
}
impl std::error::Error for Error {}

/// Facts for exactly one live invocation. Only trusted gateway composition may
/// supply these. Keep the corresponding arguments immutable in local memory.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// Currently one.
    pub schema_version: u32,
    /// Known operator-mapped client; never inferred from MCP clientInfo.
    pub client: Fingerprint,
    /// Explicit principal, or unknown.
    pub principal: Option<Fingerprint>,
    /// Explicit agent, or unknown.
    pub agent: Option<Fingerprint>,
    /// Fresh random gateway session reference; never restored across restart.
    pub session_ref: Fingerprint,
    /// Fresh random invocation reference; never reused for a second request.
    pub call_ref: Fingerprint,
    /// Reviewed launch/server identity, not just the server's declared name.
    pub server: Fingerprint,
    /// Resolved tool within the reviewed server.
    pub tool: Fingerprint,
    /// Current input schema.
    pub schema_fingerprint: Fingerprint,
    /// Complete reviewed tool definition, including any output schema.
    pub definition_fingerprint: Fingerprint,
    /// Current policy identity and exact signed-message digest.
    pub policy_ref: Fingerprint,
    /// Positive policy version.
    pub policy_version: u64,
    /// Exact active policy bundle hash; equal versions alone are insufficient.
    pub policy_bundle_hash: Fingerprint,
    /// Nonempty unique capability classes; sorted before binding comparison.
    pub capabilities: Vec<CapabilityClass>,
    /// Explicit operator-selected environment, unknown when null.
    pub environment: Option<String>,
}
impl Binding {
    /// Parse bounded local metadata. This is not authentication or authorization.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_RECORD {
            return Err(Error::Input);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Input)?;
        let object = value.as_object().ok_or(Error::Input)?;
        if !["principal", "agent", "environment"]
            .iter()
            .all(|k| object.contains_key(*k))
        {
            return Err(Error::Input);
        }
        let binding: Self = serde_json::from_value(value).map_err(|_| Error::Input)?;
        binding.normalized()
    }
    fn normalized(mut self) -> Result<Self, Error> {
        if self.schema_version != 1
            || self.policy_version == 0
            || self.policy_version > MAX_TIME
            || self.capabilities.is_empty()
            || self.capabilities.len() > 11
            || self.environment.as_ref().is_some_and(|e| {
                e.is_empty()
                    || e.len() > 64
                    || !e
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
        {
            return Err(Error::Input);
        }
        self.capabilities.sort();
        if self.capabilities.windows(2).any(|c| c[0] == c[1]) {
            return Err(Error::Input);
        }
        Ok(self)
    }
}

/// Stored state. Only `Approved` can be consumed, exactly once, before expiry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Awaiting a local operator decision.
    Requested,
    /// Decided positively but not dispatched/consumed yet.
    Approved,
    /// Local operator refused or revoked before consumption.
    Denied,
    /// The bounded validity window elapsed.
    Expired,
    /// Caller/session/context invalidated the request.
    Cancelled,
    /// Committed consumption; never retry even if dispatch outcome is uncertain.
    Consumed,
}
impl State {
    fn active(self) -> bool {
        matches!(self, Self::Requested | Self::Approved)
    }
}
/// Fixed cancellation cause, without caller-provided messages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cancellation {
    /// Caller withdrew the operation.
    CallerCancelled,
    /// Binding changed while waiting, including policy/schema changes.
    ContextChanged,
    /// Owning gateway session ended.
    SessionEnded,
}
/// Operator decision, independent of the mutable request state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    /// Approve exactly the recorded pending call.
    Approve,
    /// Deny or revoke a not-yet-consumed request.
    Deny,
}
/// Attribution is deliberately declared; file access does not authenticate a
/// supplied human name/reference. OS access control protects the local store.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSource {
    /// An explicit local operator reference, not directory authentication.
    DeclaredLocal,
}
/// Local decision record. No secret, comment or arbitrary metadata field.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalDecision {
    /// Explicit local operator reference.
    pub operator_ref: Fingerprint,
    /// Strength/source of that attribution.
    pub source: OperatorSource,
    /// Actual choice.
    pub choice: Choice,
    /// Trusted decision time.
    pub time_ms: u64,
}
/// Closed metadata record for local review. This is not a telemetry schema.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Currently one.
    pub schema_version: u32,
    /// Random opaque reference generated by the store.
    pub approval_ref: Fingerprint,
    /// Immutable request binding.
    pub binding: Binding,
    /// Current state.
    pub state: State,
    /// Creation time.
    pub created_at_ms: u64,
    /// Exclusive expiry time, at most five minutes after creation.
    pub expires_at_ms: u64,
    /// Latest state transition time.
    pub updated_at_ms: u64,
    /// At most two decisions: initial choice and optional pre-consumption denial.
    /// Revocation retains who originally approved as well as who denied.
    pub decisions: Vec<LocalDecision>,
    /// Fixed cancellation cause, present only for cancelled requests.
    pub cancellation: Option<Cancellation>,
}
impl Record {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.binding.clone().normalized()? != self.binding
            || self.expires_at_ms > MAX_TIME
            || self.updated_at_ms > MAX_TIME
            || !(100..=MAX_TTL).contains(
                &self
                    .expires_at_ms
                    .checked_sub(self.created_at_ms)
                    .ok_or(Error::Input)?,
            )
            || self.updated_at_ms < self.created_at_ms
            || self.decisions.len() > 2
            || self.cancellation.is_some() != (self.state == State::Cancelled)
        {
            return Err(Error::Input);
        }
        if self.decisions.iter().any(|decision| {
            decision.time_ms < self.created_at_ms
                || decision.time_ms >= self.expires_at_ms
                || decision.time_ms > self.updated_at_ms
        }) || (self.decisions.len() == 2
            && (self.decisions[0].choice != Choice::Approve
                || self.decisions[1].choice != Choice::Deny
                || self.decisions[0].time_ms > self.decisions[1].time_ms))
        {
            return Err(Error::Input);
        }
        let choice = self.decisions.last().map(|d| d.choice);
        let valid = match self.state {
            State::Requested => choice.is_none() && self.updated_at_ms == self.created_at_ms,
            State::Approved | State::Consumed => {
                choice == Some(Choice::Approve) && self.updated_at_ms < self.expires_at_ms
            }
            State::Denied => {
                choice == Some(Choice::Deny) && self.updated_at_ms < self.expires_at_ms
            }
            State::Expired => {
                self.updated_at_ms >= self.expires_at_ms && choice != Some(Choice::Deny)
            }
            State::Cancelled => choice != Some(Choice::Deny),
        };
        if valid { Ok(()) } else { Err(Error::Input) }
    }
}

/// Result of checking the exact pending call. An unavailable state never permits
/// dispatch. Storage errors return `Err`, never this enum's `Ready` variant.
pub enum Consumption {
    /// Still waiting for a local decision; caller must keep a bounded deadline.
    Pending,
    /// Request ended without a consumable approval.
    Unavailable(State),
    /// Consumption committed before this non-cloneable permit was returned.
    Ready(Permit),
}
/// One consumed approval. Deliberately no Clone, Deserialize or Serialize.
/// This satisfies only approval; the gateway must still enforce its other gates.
pub struct Permit {
    reference: Fingerprint,
    operator: Fingerprint,
}
impl Permit {
    /// Local audit correlation reference.
    pub fn reference(&self) -> &Fingerprint {
        &self.reference
    }
    /// Declared local operator who approved this invocation.
    pub fn operator(&self) -> &Fingerprint {
        &self.operator
    }
}
/// Fresh cryptographic random local reference for a session/invocation. No
/// payload hash is used, so approval records cannot reveal predictable arguments.
pub fn fresh_reference() -> Result<Fingerprint, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Storage)?;
    serde_json::from_value(serde_json::Value::String(crate::bundle::encode_hex(&bytes)))
        .map_err(|_| Error::Storage)
}
