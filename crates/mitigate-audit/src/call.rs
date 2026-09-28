//! Version-two local call correlation. No raw values or argument hashes.
use crate::{Decision, Error, EventDetails, Operation, ResultClass};
use mitigate_fingerprint::Fingerprint;
use serde::{Deserialize, Serialize};

/// Position in a governed invocation, independent of wall-clock ordering.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallPhase {
    /// Terminal refusal before dispatch, including validation/storage failure.
    Decision,
    /// Waiting for a local human decision; no tool has been invoked.
    ApprovalPending,
    /// Authorization committed before dispatch; completion is not yet known.
    Dispatch,
    /// Outcome observed after dispatch was authorized; effects may be uncertain.
    Completion,
}

/// Local operator attribution; OS file access does not authenticate a label.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSource {
    /// Explicit local operator reference, not a directory-authenticated identity.
    DeclaredLocal,
}

/// Human choice, distinct from the gateway's final authorization decision.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalChoice {
    /// Approved the bound action, subject to all remaining gateway checks.
    Approve,
    /// Denied or revoked the bound action before dispatch.
    Deny,
}

/// Operator metadata copied from a verified local approval record.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalActor {
    /// Local operator's opaque reference; never a display name/email.
    pub operator_ref: Fingerprint,
    /// Declared attribution strength.
    pub source: OperatorSource,
    /// Latest relevant human decision.
    pub choice: ApprovalChoice,
}

/// Closed correlation facts for a version-two event. These are local audit
/// fields, not permission to forward content-derived references to Platform.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallContext {
    /// Fresh random gateway session, never restored across process restart.
    pub session_ref: Fingerprint,
    /// Fresh random invocation ID; shared only by phases of this invocation.
    pub call_ref: Fingerprint,
    /// Phase of this invocation.
    pub phase: CallPhase,
    /// Complete reviewed tool definition, absent when resolution failed.
    #[serde(deserialize_with = "Option::deserialize")]
    pub definition_fingerprint: Option<Fingerprint>,
    /// Exact verified signed policy bundle, absent before policy resolution.
    #[serde(deserialize_with = "Option::deserialize")]
    pub policy_bundle_hash: Option<Fingerprint>,
    /// Human decision attribution when present; unknown stays explicit null.
    #[serde(deserialize_with = "Option::deserialize")]
    pub approval_actor: Option<ApprovalActor>,
}

impl CallContext {
    pub(crate) fn validate(&self, detail: &EventDetails) -> Result<(), Error> {
        if detail.operation != Operation::ToolCall
            || self.policy_bundle_hash.is_some() != detail.policy_ref.is_some()
            || detail.policy_version == Some(0)
            || (self.approval_actor.is_some() && detail.approval_ref.is_none())
        {
            return Err(Error::InvalidInput);
        }
        let resolved = detail.client_ref.is_some()
            && detail.tool_ref.is_some()
            && detail.schema_fingerprint.is_some()
            && !detail.capability_classes.is_empty()
            && self.definition_fingerprint.is_some()
            && self.policy_bundle_hash.is_some();
        let allowed = matches!(detail.decision, Decision::Allow | Decision::AllowAndLog);
        let approved = detail.approval_ref.is_none()
            || self
                .approval_actor
                .as_ref()
                .is_some_and(|a| a.choice == ApprovalChoice::Approve);
        let valid = match self.phase {
            CallPhase::Decision => {
                detail.result_class == ResultClass::NotInvoked
                    && matches!(
                        detail.decision,
                        Decision::Deny
                            | Decision::RateLimit
                            | Decision::DisableTool
                            | Decision::Error
                    )
            }
            CallPhase::ApprovalPending => {
                resolved
                    && detail.decision == Decision::RequireApproval
                    && detail.result_class == ResultClass::Pending
                    && detail.approval_ref.is_some()
                    && self.approval_actor.is_none()
            }
            CallPhase::Dispatch => {
                resolved && allowed && approved && detail.result_class == ResultClass::Pending
            }
            CallPhase::Completion => {
                resolved
                    && allowed
                    && approved
                    && matches!(
                        detail.result_class,
                        ResultClass::Success
                            | ResultClass::Error
                            | ResultClass::Cancelled
                            | ResultClass::Uncertain
                    )
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
}
