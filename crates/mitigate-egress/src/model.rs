//! Wire enums are separate from local authority types: changes to local reports
//! must never silently widen the Platform contract or its dependency boundary.
use crate::{Rejection, SyncRef};
use serde::{Deserialize, Serialize};

/// Closed capability labels. No matched property names or description evidence.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Reads data.
    ReadData,
    /// Writes data.
    WriteData,
    /// Deletes data.
    DeleteData,
    /// Executes code.
    ExecuteCode,
    /// Accesses credentials.
    CredentialAccess,
    /// Communicates externally.
    ExternalCommunication,
    /// Controls a browser.
    BrowserAction,
    /// Changes identities or access.
    IdentityAdmin,
    /// Performs a financial action.
    FinancialAction,
    /// Changes infrastructure.
    InfrastructureChange,
    /// Classification is unknown.
    Unknown,
}

/// Source of caller attribution, never inferred from clientInfo or a tool payload.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// No caller mapping exists.
    Unknown,
    /// Explicit local declaration; not authenticated enterprise identity.
    DeclaredProfile,
}

/// Which call boundary this metadata describes.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Refusal before invocation.
    Decision,
    /// Waiting for a one-call approval.
    ApprovalPending,
    /// Permission committed before sending the call; not proof of execution.
    Dispatch,
    /// Observed outcome after dispatch admission.
    Completion,
}

/// Structured final authority, not raw policy evaluation output.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Call admitted with required local audit.
    AllowAndLog,
    /// Permission denied.
    Deny,
    /// One-call approval required.
    RequireApproval,
    /// Quota prevents admission.
    RateLimit,
    /// Emergency or exact-target stop prevents admission.
    DisableTool,
    /// Authority unavailable or invalid request.
    Error,
}

/// Outcome class; never upstream output or an error message.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// No terminal outcome yet.
    Pending,
    /// Successful observed completion.
    Success,
    /// Observed failure.
    Error,
    /// Cancellation observed after admission; no rollback implied.
    Cancelled,
    /// No dispatch was attempted.
    NotInvoked,
    /// Effects may have occurred; never safe to replay automatically.
    Uncertain,
}

/// Typed candidate facts. Construction alone grants no egress permission.
/// No local labels, content digests, environment strings or arbitrary metadata.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionFacts {
    /// Correlates lifecycle records for one call using an opaque mapping.
    pub call_ref: SyncRef,
    /// Caller mapping, or explicit null when unknown.
    #[serde(deserialize_with = "Option::deserialize")]
    pub client_ref: Option<SyncRef>,
    /// Principal mapping, or explicit null when unknown.
    #[serde(deserialize_with = "Option::deserialize")]
    pub principal_ref: Option<SyncRef>,
    /// Agent mapping, or explicit null when unknown.
    #[serde(deserialize_with = "Option::deserialize")]
    pub agent_ref: Option<SyncRef>,
    /// Actual source of caller mapping.
    pub attribution: Attribution,
    /// Enrollment-scoped server mapping, never raw executable/configuration hash.
    pub server_ref: SyncRef,
    /// Tool mapping, null when an invalid request did not resolve a tool.
    #[serde(deserialize_with = "Option::deserialize")]
    pub tool_ref: Option<SyncRef>,
    /// Opaque mapping for the observed schema revision, not a content digest.
    #[serde(deserialize_with = "Option::deserialize")]
    pub schema_ref: Option<SyncRef>,
    /// At most eleven distinct closed capability labels.
    pub capabilities: Vec<Capability>,
    /// Mapped policy identity, paired with a known version.
    #[serde(deserialize_with = "Option::deserialize")]
    pub policy_ref: Option<SyncRef>,
    /// Positive safe integer; null when no policy evaluation was possible.
    #[serde(deserialize_with = "Option::deserialize")]
    pub policy_version: Option<u64>,
    /// Opaque approval mapping when one was requested.
    #[serde(deserialize_with = "Option::deserialize")]
    pub approval_ref: Option<SyncRef>,
    /// Call lifecycle phase.
    pub phase: Phase,
    /// Gateway decision at that phase.
    pub decision: Decision,
    /// Observed outcome at that phase.
    pub outcome: Outcome,
    /// Monotonic elapsed duration capped at one day.
    pub duration_ms: u32,
}

impl DecisionFacts {
    pub(crate) fn validate(&mut self) -> Result<(), Rejection> {
        if self.duration_ms > 86_400_000
            || self.capabilities.len() > 11
            || self
                .policy_version
                .is_some_and(|v| v == 0 || v > 9_007_199_254_740_991)
        {
            return Err(Rejection::Bounds);
        }
        self.capabilities.sort_unstable();
        if self.capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Rejection::Facts);
        }
        if self.policy_ref.is_some() != self.policy_version.is_some()
            || self.tool_ref.is_some() != self.schema_ref.is_some()
            || (self.tool_ref.is_none() && !self.capabilities.is_empty())
            || (self.attribution == Attribution::Unknown
                && (self.client_ref.is_some()
                    || self.principal_ref.is_some()
                    || self.agent_ref.is_some()))
            || (self.attribution == Attribution::DeclaredProfile && self.client_ref.is_none())
        {
            return Err(Rejection::Facts);
        }
        let resolved = self.client_ref.is_some()
            && self.tool_ref.is_some()
            && self.policy_ref.is_some()
            && !self.capabilities.is_empty();
        let valid_phase = match self.phase {
            Phase::Decision => {
                self.outcome == Outcome::NotInvoked
                    && matches!(
                        self.decision,
                        Decision::Deny
                            | Decision::RateLimit
                            | Decision::DisableTool
                            | Decision::Error
                    )
            }
            Phase::ApprovalPending => {
                resolved
                    && self.approval_ref.is_some()
                    && self.decision == Decision::RequireApproval
                    && self.outcome == Outcome::Pending
            }
            Phase::Dispatch => {
                resolved
                    && self.decision == Decision::AllowAndLog
                    && self.outcome == Outcome::Pending
            }
            Phase::Completion => {
                resolved
                    && self.decision == Decision::AllowAndLog
                    && matches!(
                        self.outcome,
                        Outcome::Success | Outcome::Error | Outcome::Cancelled | Outcome::Uncertain
                    )
            }
        };
        if !valid_phase || (self.approval_ref.is_some() && !resolved) {
            return Err(Rejection::Facts);
        }
        Ok(())
    }
}
