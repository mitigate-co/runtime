//! Explicit local authorization rules. No network, payloads or inferred identity.
//! A grant permits proceeding to policy/approval checks; it never invokes a tool.

use crate::{Decision, GrantState};
use mitigate_fingerprint::Fingerprint;
use mitigate_mcp::classification::CapabilityClass;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum explicit local grant document size before parsing.
pub const MAX_DOCUMENT: usize = 32_768;
const MAX_GRANTS: usize = 64;
const MAX_TIME: u64 = 9_007_199_254_740_991;

/// Closed, content-free errors; invalid input never resolves to an allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid or ambiguous rules. Reject the whole document.
    Rules,
    /// Missing, unknown, duplicate or out-of-bounds context fields.
    Context,
}
impl Error {
    /// Stable error code without input values.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Rules => "grant_rules_invalid",
            Self::Context => "grant_context_invalid",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rules => "Grant rules rejected. Check the version, explicit scope fields, unique references and time windows.",
            Self::Context => "Grant context rejected. Use the documented metadata fields and explicit nulls for unknown identity.",
        })
    }
}
impl std::error::Error for Error {}

/// Trusted local action facts. The gateway, not the MCP caller, supplies these.
/// Fingerprints are local references, not proof of authentication/anonymization.
/// No Debug/Serialize: caller context must not accidentally become a log/event.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantContext {
    /// Must be one.
    pub schema_version: u32,
    /// Explicitly mapped client. An unknown client cannot receive an allowance.
    pub client: Option<Fingerprint>,
    /// Declared principal, or explicitly unknown.
    pub principal: Option<Fingerprint>,
    /// Declared agent, or explicitly unknown.
    pub agent: Option<Fingerprint>,
    /// Reviewed server reference; self-declared server names are insufficient.
    pub server: Fingerprint,
    /// Resolved tool reference within that server.
    pub tool: Fingerprint,
    /// Nonempty unique classes. Unclassified actions must include `unknown`.
    pub capabilities: Vec<CapabilityClass>,
    /// Operator-selected environment/profile, absent when unknown.
    pub environment: Option<String>,
    /// Trusted UTC Unix milliseconds. Re-evaluate immediately before execution.
    pub time_ms: u64,
}
impl GrantContext {
    /// Parse a local test fixture; this does not authenticate its supplied facts.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4096 {
            return Err(Error::Context);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Context)?;
        required(&value, &["client", "principal", "agent", "environment"])
            .map_err(|_| Error::Context)?;
        let result: Self = serde_json::from_value(value).map_err(|_| Error::Context)?;
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.time_ms > MAX_TIME
            || !valid_classes(&self.capabilities)
            || self
                .environment
                .as_ref()
                .is_some_and(|e| !valid_environment(e))
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Effect {
    Allow,
    Deny,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    client: Option<Fingerprint>,
    principal: Option<Fingerprint>,
    agent: Option<Fingerprint>,
    server: Option<Fingerprint>,
    tool: Option<Fingerprint>,
    capabilities: Option<Vec<CapabilityClass>>,
    environment: Option<String>,
    not_before_ms: Option<u64>,
    expires_at_ms: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    grant_ref: Fingerprint,
    effect: Effect,
    scope: Scope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    grants: Vec<Grant>,
}

/// Validated immutable rules, owned by the local administrator. No ambient files
/// or automatic refresh. Construct a complete replacement before swapping it.
pub struct GrantSet {
    grants: Vec<Grant>,
}
impl GrantSet {
    /// Parse bounded, duplicate-free JSON. Every nullable scope field must be
    /// present: omitting a constraint can never accidentally create a wildcard.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_DOCUMENT {
            return Err(Error::Rules);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Rules)?;
        let rules = value
            .get("grants")
            .and_then(Value::as_array)
            .ok_or(Error::Rules)?;
        if rules.len() > MAX_GRANTS {
            return Err(Error::Rules);
        }
        for rule in rules {
            required(
                rule.get("scope").ok_or(Error::Rules)?,
                &[
                    "client",
                    "principal",
                    "agent",
                    "server",
                    "tool",
                    "capabilities",
                    "environment",
                    "not_before_ms",
                    "expires_at_ms",
                ],
            )?;
        }
        let mut document: Document = serde_json::from_value(value).map_err(|_| Error::Rules)?;
        if document.schema_version != 1 {
            return Err(Error::Rules);
        }
        document
            .grants
            .sort_by(|a, b| a.grant_ref.cmp(&b.grant_ref));
        if document
            .grants
            .windows(2)
            .any(|g| g[0].grant_ref == g[1].grant_ref)
        {
            return Err(Error::Rules);
        }
        for grant in &document.grants {
            let scope = &grant.scope;
            if scope
                .capabilities
                .as_ref()
                .is_some_and(|c| !valid_classes(c))
                || scope
                    .environment
                    .as_ref()
                    .is_some_and(|e| !valid_environment(e))
                || scope.not_before_ms.is_some_and(|t| t > MAX_TIME)
                || scope.expires_at_ms.is_some_and(|t| t > MAX_TIME)
                || scope
                    .expires_at_ms
                    .is_some_and(|end| end <= scope.not_before_ms.unwrap_or(0))
            {
                return Err(Error::Rules);
            }
        }
        Ok(Self {
            grants: document.grants,
        })
    }
    /// Number of validated rules, without exposing their local scope facts.
    pub fn len(&self) -> usize {
        self.grants.len()
    }
    /// Empty sets are valid and grant nothing.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
    /// Denials precede allowances regardless of ordering/specificity. Denial
    /// classes intersect the action; one allowance must cover *all* classes.
    /// Unknown clients cannot receive an allowance, even from a wildcard rule.
    /// This result is a diagnostic, not a reusable authorization/approval token.
    pub fn evaluate(&self, context: &GrantContext) -> Result<GrantResolution, Error> {
        context.validate()?;
        for effect in [Effect::Deny, Effect::Allow] {
            if effect == Effect::Allow && context.client.is_none() {
                return Ok(GrantResolution::none(Reason::UnknownClient));
            }
            let matched_grants: Vec<_> = self
                .grants
                .iter()
                .filter(|g| g.effect == effect && matches_scope(&g.scope, context, effect))
                .map(|g| g.grant_ref.clone())
                .collect();
            if !matched_grants.is_empty() {
                let (state, reason) = match effect {
                    Effect::Allow => (GrantState::Explicit, Reason::ExplicitAllow),
                    Effect::Deny => (GrantState::Denied, Reason::ExplicitDeny),
                };
                return Ok(GrantResolution {
                    schema_version: 1,
                    state,
                    reason,
                    matched_grants,
                });
            }
        }
        Ok(GrantResolution::none(Reason::NoMatchingGrant))
    }
}

/// Fixed explanation of grant resolution. No free-form rule diagnostics.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// At least one matching denial took precedence.
    ExplicitDeny,
    /// At least one matching allowance covered the complete action.
    ExplicitAllow,
    /// No explicit client attribution was available.
    UnknownClient,
    /// No applicable rule authorized the action.
    NoMatchingGrant,
}
/// Local diagnostic only. Matching grant references are sorted lexicographically
/// so rule reordering does not change the result. Never serialize as telemetry.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GrantResolution {
    schema_version: u32,
    state: GrantState,
    reason: Reason,
    matched_grants: Vec<Fingerprint>,
}
impl GrantResolution {
    fn none(reason: Reason) -> Self {
        Self {
            schema_version: 1,
            state: GrantState::None,
            reason,
            matched_grants: Vec::new(),
        }
    }
    /// State for policy input; still not permission to execute.
    pub fn state(&self) -> GrantState {
        self.state
    }
    /// Explanation of the deterministic resolution.
    pub fn reason(&self) -> Reason {
        self.reason
    }
    /// Constrain a policy result from the *same* action. Policy cannot override
    /// an explicit denial or missing grant. Do not cache across calls/time changes.
    pub fn constrain(&self, policy: Decision) -> Decision {
        if self.state == GrantState::Explicit {
            policy
        } else {
            Decision::Deny
        }
    }
}
fn required(value: &Value, keys: &[&str]) -> Result<(), Error> {
    let object = value.as_object().ok_or(Error::Rules)?;
    if keys.iter().all(|key| object.contains_key(*key)) {
        Ok(())
    } else {
        Err(Error::Rules)
    }
}
fn valid_classes(classes: &[CapabilityClass]) -> bool {
    !classes.is_empty()
        && classes.len() <= 11
        && !classes
            .iter()
            .enumerate()
            .any(|(i, c)| classes[..i].contains(c))
}
fn valid_environment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn exact<T: PartialEq>(constraint: Option<&T>, observed: Option<&T>) -> bool {
    constraint.is_none() || constraint == observed
}
fn matches_scope(scope: &Scope, context: &GrantContext, effect: Effect) -> bool {
    exact(scope.client.as_ref(), context.client.as_ref())
        && exact(scope.principal.as_ref(), context.principal.as_ref())
        && exact(scope.agent.as_ref(), context.agent.as_ref())
        && exact(scope.server.as_ref(), Some(&context.server))
        && exact(scope.tool.as_ref(), Some(&context.tool))
        && exact(scope.environment.as_ref(), context.environment.as_ref())
        && scope
            .not_before_ms
            .is_none_or(|start| context.time_ms >= start)
        && scope.expires_at_ms.is_none_or(|end| context.time_ms < end)
        && scope
            .capabilities
            .as_ref()
            .is_none_or(|classes| match effect {
                Effect::Deny => context.capabilities.iter().any(|c| classes.contains(c)),
                Effect::Allow => context.capabilities.iter().all(|c| classes.contains(c)),
            })
}

#[cfg(test)]
#[path = "grants_tests.rs"]
mod tests;
