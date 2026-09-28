//! Explicit, bounded MCP enumeration and upstream transport. Discovery never
//! invokes these APIs. Gateway owners must authorize calls before relaying them.
//!
//! Launching requires a caller-reviewed executable and configuration. Process
//! groups/jobs manage lifecycle; they do not sandbox the server's OS privileges.

pub mod classification;
mod launch;
mod model;
mod protocol;
pub mod schema;
mod snapshot;
mod stdio;
mod upstream;

pub use launch::LaunchConfig;
pub use launch::review::{LaunchReceipt, LaunchReview};
pub use model::{Inventory, InventoryReport, Tool, ToolSummary};
pub use snapshot::{ChangeKind, Snapshot, SnapshotDiff, ToolChange};
use std::fmt;
pub use stdio::{enumerate, enumerate_with_shutdown};
pub use upstream::{CallFailure, Progress, StdioServer};

/// Fixed operational errors; never carries upstream messages, arguments or paths.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// Unavailable, oversized or invalid launch configuration.
    Configuration,
    /// Program/cwd must resolve to an absolute regular executable/directory.
    Executable,
    /// Explicit environment reference is invalid, missing or too large.
    Environment,
    /// A referenced native credential could not be resolved; nothing is launched.
    Credential,
    /// The OS refused to create the process/job/pipes.
    Launch,
    /// A pipe closed or failed before a complete response arrived.
    Disconnected,
    /// Malformed/ambiguous JSON-RPC or invalid tool definition.
    Protocol,
    /// Response, count, pagination or complexity budget exceeded.
    Limit,
    /// Whole enumeration or upstream transaction deadline elapsed.
    Timeout,
    /// Caller requested shutdown; process cleanup still runs before returning.
    Cancelled,
    /// Server negotiated a version outside the supported matrix.
    Version,
    /// Upstream returned a JSON-RPC error; source text is discarded.
    Upstream,
    /// Tool list changed during enumeration; do not accept a mixed snapshot.
    Changed,
    /// Process lifecycle completion could not be confirmed.
    Cleanup,
    /// Definition cannot be represented by the fingerprint profile without loss.
    Fingerprint,
    /// Snapshot is unavailable, invalid, incompatible or already exists on write.
    Snapshot,
    /// Explicit classification overrides are invalid, stale or unmatched.
    Classification,
    /// Review document is invalid, unavailable or cannot be created safely.
    LaunchReview,
    /// Executable, artifact or exact launch facts differ from local review.
    LaunchChanged,
    /// Tool schema is invalid or outside the supported execution profile.
    Schema,
    /// Schema compilation/validation exceeded a resource or waiting limit.
    SchemaLimit,
    /// Local arguments or structured results do not satisfy the tool schema.
    SchemaMismatch,
}

impl Error {
    /// Stable machine-readable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Configuration => "mcp_configuration_invalid",
            Self::Executable => "mcp_executable_invalid",
            Self::Environment => "mcp_environment_unavailable",
            Self::Credential => "mcp_credential_unavailable",
            Self::Launch => "mcp_launch_failed",
            Self::Disconnected => "mcp_disconnected",
            Self::Protocol => "mcp_protocol_invalid",
            Self::Limit => "mcp_limit_exceeded",
            Self::Timeout => "mcp_timeout",
            Self::Cancelled => "mcp_cancelled",
            Self::Version => "mcp_version_unsupported",
            Self::Upstream => "mcp_upstream_error",
            Self::Changed => "mcp_inventory_changed",
            Self::Cleanup => "mcp_cleanup_failed",
            Self::Fingerprint => "mcp_fingerprint_invalid",
            Self::Snapshot => "mcp_snapshot_invalid",
            Self::Classification => "mcp_classification_invalid",
            Self::LaunchReview => "mcp_launch_review_invalid",
            Self::LaunchChanged => "mcp_launch_changed",
            Self::Schema => "mcp_schema_unsupported",
            Self::SchemaLimit => "mcp_schema_limit",
            Self::SchemaMismatch => "mcp_schema_mismatch",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "Review the launch configuration against the supported schema and limits.",
            Self::Executable => "Select an absolute trusted executable and working directory; Windows requires an .exe file.",
            Self::Environment => "Check the explicitly allowed environment references and their size limits.",
            Self::Credential => "A native credential is missing, locked, invalid or unavailable. Check the launch references and unlock the OS store before retrying.",
            Self::Launch => "The server could not start. Check executable permissions and process restrictions.",
            Self::Disconnected => "The server connection is closed, invalidated or failed before the request completed. Reconnect before retrying.",
            Self::Protocol => "The server returned invalid or ambiguous MCP data. Check its protocol compatibility.",
            Self::Limit => "The server exceeded a response or inventory limit. Review its configuration before retrying.",
            Self::Timeout => "The server did not complete the operation before the deadline. Check its health or adjust timeout_ms.",
            Self::Cancelled => "The operation was cancelled and the server was stopped.",
            Self::Version => "The server negotiated an unsupported MCP version. Check the compatibility reference.",
            Self::Upstream => "The server rejected an MCP request. Its error body was withheld to protect sensitive content.",
            Self::Changed => "The tool list changed during enumeration. Retry to obtain a consistent inventory.",
            Self::Cleanup => "Process cleanup could not be confirmed. Check the server process before retrying.",
            Self::Fingerprint => "A definition exceeds the fingerprint profile or contains an unsafe large numeric constraint. Review the fingerprint reference.",
            Self::Snapshot => "Use a valid compatible snapshot for reading or a new writable filename for saving; existing files are never overwritten.",
            Self::Classification => "Review the explicit classification file, its limits and fingerprints against a fresh snapshot; every override must match the current server and tool definition.",
            Self::LaunchReview => "Use a valid private launch review or a new writable path. Check explicit artifact paths and size limits.",
            Self::LaunchChanged => "The launch differs from its review. Inspect executable, artifacts, arguments and environment before creating a new review.",
            Self::Schema => "The tool schema is invalid or unsupported for execution. Review the schema-validation profile before retrying.",
            Self::SchemaLimit => "Tool schema validation exceeded a resource or wait limit. Reduce schema or value complexity before retrying.",
            Self::SchemaMismatch => "The tool arguments or structured result do not match the declared schema. Source values were withheld.",
        })
    }
}
impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;
