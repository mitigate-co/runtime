//! Local MCP content-plane listener, independent of upstream launch and policy.
//!
//! This library opens no socket, reads no ambient identity and emits no logs.
//! Its service boundary must apply authorization before executing a tool. Client
//! implementation names and raw payloads are never identity or telemetry facts.
mod framing;
mod identity;
mod listener;
mod progress;
mod protocol;

pub use identity::{CallerIdentity, IdentityConfidence, IdentitySource};
pub use listener::{ToolRequest, ToolService, serve};
pub use progress::ProgressSink;
use std::fmt;

/// Content-free session failures, safe to expose in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Profile is malformed, ambiguous, oversized or uses unsupported fields.
    Profile,
    /// Invalid JSON-RPC, lifecycle transition or reused request ID.
    Protocol,
    /// A frame, request count or connection byte budget was exceeded.
    Limit,
    /// Initialization, partial frame, request or output exceeded its deadline.
    Timeout,
    /// The local pipe failed or closed in the middle of a frame.
    Disconnected,
    /// Caller cancelled in-flight work; reconnect to start another session.
    Cancelled,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Profile => "Invalid gateway profile. Use the documented version, opaque references and field limits.",
            Self::Protocol => "Invalid MCP session. Check message format, initialization order and unique request IDs.",
            Self::Limit => "Gateway session limit reached. Review message sizes and reconnect before sending more requests.",
            Self::Timeout => "Gateway deadline exceeded. Check the client and upstream health before reconnecting.",
            Self::Disconnected => "Gateway pipe closed unexpectedly. Reconnect the local client.",
            Self::Cancelled => "Gateway request cancelled. Reconnect to start another session.",
        })
    }
}
impl std::error::Error for Error {}

/// Fixed JSON-RPC faults; raw upstream error bodies must not cross this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Local authority/approval/control state could not be verified.
    GovernanceUnavailable,
    /// A local emergency switch or exact target disable blocked admission.
    Stopped,
    /// A local quota refused admission; no automatic retry is authorized.
    RateLimited,
    /// Required local audit could not be committed; no permission to proceed.
    AuditUnavailable,
    /// Explicit inventory-only endpoint; invocation is intentionally unavailable.
    Disabled,
    /// Invalid method parameters.
    InvalidParams,
    /// Service authorization refused the action.
    Denied,
    /// Upstream was unavailable, crashed or rejected the request.
    Upstream,
    /// Upstream definitions changed and need review.
    Changed,
}
impl Fault {
    pub(crate) const fn parts(self) -> (i32, &'static str) {
        match self {
            Self::GovernanceUnavailable => (
                -32008,
                "Local governance unavailable; check policy, approvals and controls",
            ),
            Self::Stopped => (-32009, "Tool call disabled by local controls"),
            Self::RateLimited => (
                -32010,
                "Local rate limit reached; no invocation was authorized",
            ),
            Self::AuditUnavailable => (
                -32007,
                "Local audit unavailable; verify storage before retrying",
            ),
            Self::Disabled => (-32006, "Tool calls disabled in inventory-only mode"),
            Self::InvalidParams => (-32602, "Invalid method parameters"),
            Self::Denied => (-32001, "Tool call denied by local policy"),
            Self::Upstream => (-32003, "Upstream request failed; check local server health"),
            Self::Changed => (-32004, "Tool definitions changed; review before retrying"),
        }
    }
}
