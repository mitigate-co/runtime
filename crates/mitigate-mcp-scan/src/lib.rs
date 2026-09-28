//! Read-only project discovery. No environment expansion, secret lookup, network,
//! recursive traversal, imported-script execution, or automatic MCP server launch.

mod model;
mod normalize;

use mitigate_config::ScanLimits;
pub use model::*;
use std::{
    fmt, fs,
    io::{self, Read},
    path::Path,
};

/// Safe error category, independent of parser/OS error text.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ScanErrorCode {
    /// Requested root is unavailable or not a directory.
    RootUnavailable,
    /// Unsupported resource limits supplied to the library.
    InvalidLimits,
    /// Present source cannot be read.
    SourceUnavailable,
    /// Source includes a symlink/reparse point or non-regular file.
    UnsafeSource,
    /// Present source exceeds the configured byte limit.
    SourceTooLarge,
    /// Invalid, ambiguous, too complex, or unsupported configuration shape.
    InvalidDocument,
    /// A malformed server declaration cannot be normalized safely.
    InvalidServer,
    /// Total declarations exceed the configured limit; no partial result returned.
    ServerLimit,
}

/// Fixed error fields; never retains raw configuration or sensitive OS diagnostics.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ScanError {
    /// Stable diagnostic class.
    pub code: ScanErrorCode,
    /// Known source adapter, when the failure belongs to one source.
    pub source: Option<SourceKind>,
}

impl ScanError {
    /// Stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self.code {
            ScanErrorCode::RootUnavailable => "scan_root_unavailable",
            ScanErrorCode::InvalidLimits => "scan_invalid_limits",
            ScanErrorCode::SourceUnavailable => "scan_source_unavailable",
            ScanErrorCode::UnsafeSource => "scan_unsafe_source",
            ScanErrorCode::SourceTooLarge => "scan_source_too_large",
            ScanErrorCode::InvalidDocument => "scan_invalid_document",
            ScanErrorCode::InvalidServer => "scan_invalid_server",
            ScanErrorCode::ServerLimit => "scan_server_limit",
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = self.source {
            write!(f, "{}: ", source.path())?;
        }
        f.write_str(match self.code {
            ScanErrorCode::RootUnavailable => "Cannot open the project directory. Check --root and its permissions.",
            ScanErrorCode::InvalidLimits => "Use the supported scan limits in the Runtime configuration reference.",
            ScanErrorCode::SourceUnavailable => "Cannot read this configuration. Check file permissions and retry.",
            ScanErrorCode::UnsafeSource => "Scan regular files inside the project; links and special files are refused.",
            ScanErrorCode::SourceTooLarge => "Configuration exceeds the scan byte limit. Review it or set a supported larger limit.",
            ScanErrorCode::InvalidDocument => "Use a JSON object containing mcpServers. Duplicate keys, excessive nesting and trailing content are rejected.",
            ScanErrorCode::InvalidServer => "A server declaration has invalid fields or incompatible command/URL settings. Check the adapter reference.",
            ScanErrorCode::ServerLimit => "Too many server declarations. Narrow the scan or set a supported larger server limit.",
        })
    }
}
impl std::error::Error for ScanError {}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Include junctions and other reparse points, not only symbolic links.
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn read_source(
    root: &Path,
    source: SourceKind,
    limit: usize,
) -> Result<Option<Vec<u8>>, ScanErrorCode> {
    let mut path = root.to_path_buf();
    for part in Path::new(source.path()) {
        path.push(part);
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ScanErrorCode::SourceUnavailable),
        };
        if is_link(&metadata) {
            return Err(ScanErrorCode::UnsafeSource);
        }
        if path != root.join(source.path()) && !metadata.is_dir() {
            return Err(ScanErrorCode::UnsafeSource);
        }
    }
    if !path
        .symlink_metadata()
        .map_err(|_| ScanErrorCode::SourceUnavailable)?
        .is_file()
    {
        return Err(ScanErrorCode::UnsafeSource);
    }
    let file = fs::File::open(path).map_err(|_| ScanErrorCode::SourceUnavailable)?;
    if !file
        .metadata()
        .map_err(|_| ScanErrorCode::SourceUnavailable)?
        .is_file()
    {
        return Err(ScanErrorCode::UnsafeSource);
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ScanErrorCode::SourceUnavailable)?;
    if bytes.len() > limit {
        return Err(ScanErrorCode::SourceTooLarge);
    }
    Ok(Some(bytes))
}

/// Inspect only the supported configuration paths below a caller-selected root.
///
/// Missing sources are normal. Any present malformed/oversized source aborts the
/// scan, so callers cannot mistake a truncated inventory for a complete one.
/// Paths found *inside* configuration are never followed. This is not a sandbox
/// against an attacker with the same OS identity racing filesystem changes.
pub fn scan_project(root: &Path, limits: &ScanLimits) -> Result<ScanReport, ScanError> {
    if !(1024..=1_048_576).contains(&limits.max_file_bytes)
        || !(1..=256).contains(&limits.max_servers)
    {
        return Err(ScanError {
            code: ScanErrorCode::InvalidLimits,
            source: None,
        });
    }
    let root = root.canonicalize().map_err(|_| ScanError {
        code: ScanErrorCode::RootUnavailable,
        source: None,
    })?;
    if !root.is_dir() {
        return Err(ScanError {
            code: ScanErrorCode::RootUnavailable,
            source: None,
        });
    }
    let mut report = ScanReport {
        schema_version: 2,
        sources: Vec::new(),
        servers: Vec::new(),
    };
    for source in [SourceKind::ClaudeProject, SourceKind::CursorProject] {
        let fail = |code| ScanError {
            code,
            source: Some(source),
        };
        let bytes = read_source(&root, source, limits.max_file_bytes).map_err(fail)?;
        report.sources.push(SourceObservation {
            source_kind: source,
            source_path: source.path(),
            present: bytes.is_some(),
        });
        if let Some(bytes) = bytes {
            let value =
                mitigate_json::parse(&bytes).map_err(|_| fail(ScanErrorCode::InvalidDocument))?;
            let servers = value
                .get("mcpServers")
                .and_then(|v| v.as_object())
                .ok_or_else(|| fail(ScanErrorCode::InvalidDocument))?;
            if report.servers.len() + servers.len() > limits.max_servers {
                return Err(fail(ScanErrorCode::ServerLimit));
            }
            let top_unknown = value.as_object().is_some_and(|fields| {
                fields
                    .keys()
                    .any(|key| key != "mcpServers" && key != "$schema")
            });
            for (name, declaration) in servers {
                let server = normalize::server(source, name, declaration, top_unknown)
                    .map_err(|_| fail(ScanErrorCode::InvalidServer))?;
                report.servers.push(server);
            }
        }
    }
    Ok(report)
}
