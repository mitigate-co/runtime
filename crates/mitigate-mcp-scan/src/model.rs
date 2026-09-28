//! Local inventory output, deliberately incapable of carrying credentials or argv.

use serde::Serialize;

/// Supported project configuration adapters. These do not search home directories.
#[derive(Debug, Copy, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Claude Code project `.mcp.json`.
    ClaudeProject,
    /// Cursor project `.cursor/mcp.json`.
    CursorProject,
}

impl SourceKind {
    /// Fixed relative path; never derived from untrusted configuration contents.
    pub const fn path(self) -> &'static str {
        match self {
            Self::ClaudeProject => ".mcp.json",
            Self::CursorProject => ".cursor/mcp.json",
        }
    }
}

/// Declared transport, not a claim that a reachable server was observed.
#[derive(Debug, Copy, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Command-based transport.
    Stdio,
    /// Declared HTTP/streamable HTTP.
    Http,
    /// Declared legacy SSE.
    Sse,
    /// Unspecified or unsupported transport; no inference of compatibility.
    Unknown,
}

/// Structured configuration warnings. None are authorization or proof of safety.
#[derive(Debug, Copy, Clone, Serialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ConfigRisk {
    /// Executable is looked up through a client-controlled search path.
    PathLookup,
    /// Configuration declares a shell/interpreter command wrapper.
    ShellWrapper,
    /// Batch script may implicitly involve a command shell on Windows.
    BatchScript,
    /// Unresolved client variable. Scanner never expands it.
    VariableExpansion,
    /// Potential credentials embedded in URL user info or query.
    UrlCredentials,
    /// Network transport lacks TLS outside loopback.
    InsecureRemote,
    /// Literal environment/header values require credential review.
    InlineValues,
    /// Environment file is referenced but never read by discovery.
    EnvironmentFile,
    /// Dynamic header command is configured but never invoked by discovery.
    HeaderHelper,
    /// Unknown extra fields may alter client behavior outside this adapter's scope.
    UnreviewedOptions,
    /// Transport is unspecified, unsupported, or inconsistent with the declaration.
    TransportUnresolved,
}

/// Credential mechanisms present, without names, references, or values.
#[derive(Debug, Copy, Clone, Serialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum CredentialReferenceType {
    /// Literal environment entries were found.
    InlineEnvironment,
    /// Client-interpolated environment reference was found.
    EnvironmentReference,
    /// External environment-file declaration was found; file was not opened.
    EnvironmentFile,
    /// Literal header entries were found.
    InlineHeader,
    /// Client-interpolated header reference was found.
    HeaderReference,
    /// OAuth configuration exists; its values are excluded.
    OAuth,
    /// Dynamic header helper exists; its command is excluded.
    HeaderHelper,
    /// URL contains user info or query, excluded from the endpoint origin.
    Url,
}

/// Normalized local declaration. This is not a Platform telemetry event.
///
/// Server names and endpoint origins remain customer-controlled local labels.
/// Never submit this structure directly to Platform; optional sync uses a separate
/// closed egress contract. Raw commands, argv, env, headers and URL paths are absent.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiscoveredServer {
    /// Configuration adapter that observed this declaration.
    pub source_kind: SourceKind,
    /// Known relative configuration file location.
    pub source_path: &'static str,
    /// Bounded local server label. Human rendering must escape terminal controls.
    pub server_name: String,
    /// Declared transport.
    pub transport: TransportKind,
    /// Executable basename or URL origin only; arguments and URL paths are excluded.
    pub command_or_url: Option<String>,
    /// Number of arguments, without their values.
    pub argument_count: usize,
    /// Package named in a recognized npx declaration; not installed provenance.
    pub package_name: Option<String>,
    /// Explicit numeric version from that declaration, never a resolved tag/range.
    pub package_version: Option<String>,
    /// Credential mechanism categories, not values or names.
    pub credential_reference_types: Vec<CredentialReferenceType>,
    /// Deterministic declaration warnings; tool capabilities require enumeration.
    pub risks: Vec<ConfigRisk>,
}

/// A complete read-only scan. An invalid present source fails the whole scan.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ScanReport {
    /// Stable local report contract version.
    pub schema_version: u32,
    /// Sources checked, including absent sources so scope remains explicit.
    pub sources: Vec<SourceObservation>,
    /// Declarations, ordered by source then server name. No programs were launched.
    pub servers: Vec<DiscoveredServer>,
}

/// Whether a known configuration file was present in the requested root.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SourceObservation {
    /// Adapter used for this file.
    pub source_kind: SourceKind,
    /// Known relative location.
    pub source_path: &'static str,
    /// True only after the entire present file was successfully parsed.
    pub present: bool,
}
