use crate::{Rejection, reference};
use serde_json::Value;

// There are no free-form text fields. Reject anything outside the exact wire
// vocabulary, rather than relying on a best-effort catalogue of secret patterns.
// Random references are the sole deliberate high-entropy exception, with fixed
// shape and a trusted producer contract; they cannot carry an arbitrary string.
pub(crate) fn inspect(value: &Value) -> Result<(), Rejection> {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                let normalized: String = key
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                if matches!(
                    normalized.as_str(),
                    "prompt"
                        | "prompts"
                        | "content"
                        | "arguments"
                        | "resultbody"
                        | "document"
                        | "documents"
                        | "sourcecode"
                        | "secret"
                        | "password"
                        | "token"
                        | "authorization"
                        | "headers"
                        | "environment"
                        | "metadata"
                ) {
                    return Err(Rejection::ProhibitedField);
                }
                if let Value::String(text) = value {
                    let allowed = match key.as_str() {
                        "event_id" | "runtime_ref" | "call_ref" | "client_ref"
                        | "principal_ref" | "agent_ref" | "server_ref" | "tool_ref"
                        | "schema_ref" | "policy_ref" | "approval_ref" => reference::valid(text),
                        "event_type" => text == "mcp_tool_decision",
                        "attribution" => matches!(text.as_str(), "unknown" | "declared_profile"),
                        "phase" => matches!(
                            text.as_str(),
                            "decision" | "approval_pending" | "dispatch" | "completion"
                        ),
                        "decision" => matches!(
                            text.as_str(),
                            "allow_and_log"
                                | "deny"
                                | "require_approval"
                                | "rate_limit"
                                | "disable_tool"
                                | "error"
                        ),
                        "outcome" => matches!(
                            text.as_str(),
                            "pending"
                                | "success"
                                | "error"
                                | "cancelled"
                                | "not_invoked"
                                | "uncertain"
                        ),
                        _ => return Err(Rejection::Schema),
                    };
                    if !allowed {
                        return Err(Rejection::Content);
                    }
                }
                // Capabilities are the only string array. Deserialize checks its
                // exact vocabulary; recursive objects still undergo key checks.
                inspect(value)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                inspect(item)?;
            }
        }
        _ => (),
    }
    Ok(())
}
