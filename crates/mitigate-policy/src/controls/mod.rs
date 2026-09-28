//! Local emergency stops and persistent, deterministic admission quotas.
//! These controls can only restrict access; passing them is not authorization.
mod storage;
#[cfg(test)]
mod tests;

use mitigate_fingerprint::Fingerprint;
use serde::{Deserialize, Serialize};
pub use storage::ControlStore;

const MAX_TIME: u64 = 9_007_199_254_740_991;
const MAX_DISABLED: usize = 256;
const MAX_LIMITS: usize = 128;
const MAX_CHANGES: usize = 256;

/// Content-free failures. Storage/clock errors must deny admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input is ambiguous, unknown, malformed or out of bounds.
    Input,
    /// File is unavailable, unsafe or already exists on creation.
    Path,
    /// Storage is corrupt, busy, full or could not commit.
    Storage,
    /// Trusted time is invalid or older than the persisted high-water mark.
    Clock,
    /// The bounded control configuration cannot accept another entry.
    Capacity,
}
impl Error {
    /// Stable diagnostic code, independent of input values and backend errors.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input => "control_input_invalid",
            Self::Path => "control_path_unavailable",
            Self::Storage => "control_store_unavailable",
            Self::Clock => "control_clock_rejected",
            Self::Capacity => "control_capacity_reached",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Input => "Control input rejected. Check the documented fields, references and rate bounds.",
            Self::Path => "Cannot use the control file. Check its type, permissions and whether the destination already exists.",
            Self::Storage => "Controls unavailable. Check database integrity, access and disk space before allowing calls.",
            Self::Clock => "Control clock rejected. Restore trustworthy time; do not reset the database to bypass quotas.",
            Self::Capacity => "Control capacity reached. Review existing entries before adding another.",
        })
    }
}
impl std::error::Error for Error {}

/// Exact local target. A tool is scoped to its server; no names or glob patterns.
/// Unknown caller attribution does not match a known identity target.
// Empty struct variants are intentional: Serde's internally tagged unit
// variants can ignore extra fields even with deny_unknown_fields on the enum.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// Shared quota for all calls. Use Stop/Resume for the emergency switch.
    Global {},
    /// Explicitly mapped client reference.
    Client {
        /// Local reference, not a credential or authentication assertion.
        reference: Fingerprint,
    },
    /// Explicitly mapped principal reference.
    Principal {
        /// Local reference.
        reference: Fingerprint,
    },
    /// Explicitly mapped agent reference.
    Agent {
        /// Local reference.
        reference: Fingerprint,
    },
    /// Reviewed server identity, not its self-declared label.
    Server {
        /// Local reference.
        reference: Fingerprint,
    },
    /// One tool within one reviewed server.
    Tool {
        /// Reviewed server reference.
        server: Fingerprint,
        /// Tool reference.
        tool: Fingerprint,
    },
}
impl Target {
    fn matches(&self, context: &Context) -> bool {
        match self {
            Self::Global {} => true,
            Self::Client { reference } => context.client.as_ref() == Some(reference),
            Self::Principal { reference } => context.principal.as_ref() == Some(reference),
            Self::Agent { reference } => context.agent.as_ref() == Some(reference),
            Self::Server { reference } => &context.server == reference,
            Self::Tool { server, tool } => &context.server == server && &context.tool == tool,
        }
    }
}

/// Trusted gateway facts. Never populate identity from MCP clientInfo or args.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// Must be one.
    pub schema_version: u32,
    /// Unknown stays null; grants separately require a mapped client.
    pub client: Option<Fingerprint>,
    /// Unknown stays null.
    pub principal: Option<Fingerprint>,
    /// Unknown stays null.
    pub agent: Option<Fingerprint>,
    /// Reviewed server reference.
    pub server: Fingerprint,
    /// Resolved tool reference.
    pub tool: Fingerprint,
}
impl Context {
    /// Read a bounded local diagnostic fixture; never authenticate its claims.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let value = document(bytes)?;
        if !["client", "principal", "agent"]
            .iter()
            .all(|k| value.get(*k).is_some())
        {
            return Err(Error::Input);
        }
        let context: Self = serde_json::from_value(value).map_err(|_| Error::Input)?;
        context.validate()?;
        Ok(context)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 {
            return Err(Error::Input);
        }
        Ok(())
    }
}

/// One token is charged per admitted call. Refill is continuous and exact using
/// integer sub-token units; no floating-point rounding or timer is required.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    /// Maximum burst, 1–1,000,000 calls.
    pub capacity: u32,
    /// Tokens replenished per period, 1–1,000,000.
    pub refill_tokens: u32,
    /// Period, 1–86,400,000 milliseconds.
    pub period_ms: u32,
}
impl Rate {
    fn validate(&self) -> Result<(), Error> {
        if !(1..=1_000_000).contains(&self.capacity)
            || !(1..=1_000_000).contains(&self.refill_tokens)
            || !(1..=86_400_000).contains(&self.period_ms)
        {
            return Err(Error::Input);
        }
        Ok(())
    }
    fn maximum(&self) -> u64 {
        u64::from(self.capacity) * u64::from(self.period_ms)
    }
}

/// Administrator change. Local file ownership authorizes writes; operator_ref
/// records a declaration, not a claim that this library authenticated a person.
// Keep Stop/Resume as empty struct variants so unknown fields are rejected.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    /// Block every new admission until an explicit Resume.
    Stop {},
    /// Clear the emergency stop, preserving individual disables and quotas.
    Resume {},
    /// Disable one exact non-global target.
    Disable {
        /// Target to disable.
        target: Target,
    },
    /// Clear one exact non-global disable.
    Enable {
        /// Target to enable; other controls still apply.
        target: Target,
    },
    /// Create or replace one quota. Changing a quota never refills it to burst.
    SetLimit {
        /// All matching quotas must have a token before any are charged.
        target: Target,
        /// New validated rate.
        rate: Rate,
    },
    /// Explicitly remove a quota; this administrative action is recorded.
    RemoveLimit {
        /// Exact quota target to remove.
        target: Target,
    },
}
impl Change {
    /// Parse one closed, bounded administrator change document.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let change: Self = serde_json::from_value(document(bytes)?).map_err(|_| Error::Input)?;
        change.validate()?;
        Ok(change)
    }
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Disable {
                target: Target::Global {},
            }
            | Self::Enable {
                target: Target::Global {},
            } => Err(Error::Input),
            Self::SetLimit { rate, .. } => rate.validate(),
            _ => Ok(()),
        }
    }
}
fn document(bytes: &[u8]) -> Result<serde_json::Value, Error> {
    if bytes.len() > 4096 {
        return Err(Error::Input);
    }
    mitigate_json::parse(bytes).map_err(|_| Error::Input)
}

/// Current local configuration; no payloads, names, paths or secrets.
#[derive(Serialize)]
pub struct Snapshot {
    /// Version one.
    pub schema_version: u32,
    /// Monotonic revision of actual administrator changes.
    pub revision: u64,
    /// Deny all new admissions.
    pub emergency_stop: bool,
    /// Exact disabled targets in deterministic order.
    pub disabled: Vec<Target>,
    /// Exact configured quotas in deterministic order.
    pub limits: Vec<Limit>,
}
/// A configured quota, without exposing mutable bucket internals.
#[derive(Serialize)]
pub struct Limit {
    /// Shared target.
    pub target: Target,
    /// Refill and burst configuration.
    pub rate: Rate,
}
/// Closed local administrator history. Retains the most recent 256 changes.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    /// Version one.
    pub schema_version: u32,
    /// Committed configuration revision.
    pub revision: u64,
    /// Trusted Unix milliseconds.
    pub time_ms: u64,
    /// Declared operator reference. OS file permissions are the write boundary.
    pub operator_ref: Fingerprint,
    /// Attribution is explicit, never inferred.
    pub source: OperatorSource,
    /// Exact change, without arbitrary text.
    pub change: Change,
}
/// Attribution contract for local administrative changes.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSource {
    /// Supplied by the local operator, not independently authenticated.
    DeclaredLocal,
}
/// Closed admission result. Allowed satisfies controls only, never grants,
/// policy, schema checks, approval or audit. Do not serialize it as telemetry.
#[derive(Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Admission {
    /// All matching quotas charged atomically after checking disables.
    Allowed {
        /// Configuration revision used in this admission.
        revision: u64,
    },
    /// At least one disable or the emergency stop blocked admission.
    Disabled {
        /// Configuration revision.
        revision: u64,
        /// Global stop takes precedence over quotas.
        emergency_stop: bool,
        /// Matching exact disables.
        targets: Vec<Target>,
    },
    /// No quotas were charged. Callers must not automatically retry tools.
    RateLimited {
        /// Configuration revision.
        revision: u64,
        /// Earliest potential retry; competing calls/changes can extend it.
        retry_after_ms: u64,
        /// Currently depleted matching quotas.
        targets: Vec<Target>,
    },
}
