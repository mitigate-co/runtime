//! Versioned local configuration, independent of Platform and transport clients.
//!
//! Parsing returns fixed error categories, never Serde's content-bearing errors.
//! This schema contains no credentials, network destination or executable command.

use serde::{Deserialize, Serialize};
use std::{fmt, fs::File, io::Read, path::Path};

/// Maximum size of a Runtime configuration document, including whitespace.
pub const MAX_CONFIG_BYTES: usize = 65_536;
/// Configuration schema supported by this Runtime.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Non-secret configuration. Missing nested scan settings use conservative defaults.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Required; unsupported versions fail without attempting migration.
    pub schema_version: u32,
    /// Local discovery limits. These do not authorize executing discovered programs.
    #[serde(default)]
    pub scan: ScanLimits,
}

/// Bounds for local configuration discovery, before any network/process probe.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ScanLimits {
    /// Per client-configuration file byte limit (1 KiB through 1 MiB).
    pub max_file_bytes: usize,
    /// Maximum normalized server declarations per scan (1 through 256).
    pub max_servers: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 262_144,
            max_servers: 128,
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            scan: ScanLimits::default(),
        }
    }
}

/// Content-free errors safe for CLI output and operational logs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// File could not be opened or read.
    Unavailable,
    /// Symlink, directory, or other non-regular file.
    NotRegularFile,
    /// Document exceeds the hard parser limit.
    TooLarge,
    /// Invalid JSON, unknown or duplicate fields, or wrong field types.
    InvalidDocument,
    /// Recognizable document uses a schema this binary cannot interpret.
    UnsupportedVersion,
    /// Known limits are outside the supported range.
    InvalidLimits,
}

impl ConfigError {
    /// Stable machine-readable category; does not include paths or source text.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "config_unavailable",
            Self::NotRegularFile => "config_not_regular_file",
            Self::TooLarge => "config_too_large",
            Self::InvalidDocument => "config_invalid_document",
            Self::UnsupportedVersion => "config_unsupported_version",
            Self::InvalidLimits => "config_invalid_limits",
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Cannot read the configuration. Check the path and file permissions.",
            Self::NotRegularFile => "Choose a regular configuration file, not a link or directory.",
            Self::TooLarge => "Configuration exceeds 64 KiB. Remove unrelated data.",
            Self::InvalidDocument => "Invalid configuration. Use the documented JSON fields and types; duplicate fields are rejected.",
            Self::UnsupportedVersion => "Unsupported configuration version. Use schema_version 1 or upgrade Mitigate.",
            Self::InvalidLimits => "Scan limits are out of range. Use 1024–1048576 bytes and 1–256 servers.",
        })
    }
}

impl std::error::Error for ConfigError {}

impl RuntimeConfig {
    /// Parse bounded untrusted bytes without logging or echoing their contents.
    ///
    /// Direct typed deserialization rejects duplicate and unknown object fields.
    /// Serde's recursion limit remains enabled. No paths, environment variables,
    /// secret stores, network endpoints, or child processes are accessed.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| ConfigError::InvalidDocument)?;
        if config.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        if !(1024..=1_048_576).contains(&config.scan.max_file_bytes)
            || !(1..=256).contains(&config.scan.max_servers)
        {
            return Err(ConfigError::InvalidLimits);
        }
        Ok(config)
    }

    /// Read a local regular file, retaining at most one byte over the size limit.
    ///
    /// The final path component must not be a symlink. This is input validation,
    /// not protection against a same-user attacker replacing paths concurrently.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let metadata = path
            .symlink_metadata()
            .map_err(|_| ConfigError::Unavailable)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ConfigError::NotRegularFile);
        }
        let file = File::open(path).map_err(|_| ConfigError::Unavailable)?;
        if !file
            .metadata()
            .map_err(|_| ConfigError::Unavailable)?
            .is_file()
        {
            return Err(ConfigError::NotRegularFile);
        }
        let mut bytes = Vec::new();
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::Unavailable)?;
        Self::from_slice(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_version_and_safe_defaults() {
        assert_eq!(
            RuntimeConfig::from_slice(br#"{"schema_version":1}"#).unwrap(),
            RuntimeConfig::default()
        );
        let bytes = serde_json::to_vec(&RuntimeConfig::default()).unwrap();
        assert_eq!(
            RuntimeConfig::from_slice(&bytes).unwrap(),
            RuntimeConfig::default()
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_wrongly_typed_fields_without_echoing_values() {
        for input in [
            r#"{"schema_version":1,"secret":"private-fixture-value"}"#,
            r#"{"schema_version":1,"schema_version":1}"#,
            r#"{"schema_version":1,"scan":{"max_servers":1,"max_servers":2}}"#,
            r#"{"schema_version":1,"scan":{"command":"private-fixture-value"}}"#,
            r#"{"schema_version":"private-fixture-value"}"#,
            r#"{"schema_version":1,"scan":{"max_servers":-1}}"#,
            r#"{"schema_version":1,"scan":null}"#,
            r#"{}"#,
            r#"{"schema_version":1}{}"#,
        ] {
            let error = RuntimeConfig::from_slice(input.as_bytes()).unwrap_err();
            assert_eq!(error, ConfigError::InvalidDocument);
            assert!(!error.to_string().contains("private-fixture-value"));
            assert!(!format!("{error:?}").contains("private-fixture-value"));
        }
    }

    #[test]
    fn enforces_byte_version_and_scan_limits() {
        assert_eq!(
            RuntimeConfig::from_slice(&vec![b' '; MAX_CONFIG_BYTES + 1]),
            Err(ConfigError::TooLarge)
        );
        assert_eq!(
            RuntimeConfig::from_slice(br#"{"schema_version":2}"#),
            Err(ConfigError::UnsupportedVersion)
        );
        for scan in [
            r#"{"max_servers":0}"#,
            r#"{"max_servers":257}"#,
            r#"{"max_file_bytes":1023}"#,
            r#"{"max_file_bytes":1048577}"#,
        ] {
            let input = format!(r#"{{"schema_version":1,"scan":{scan}}}"#);
            assert_eq!(
                RuntimeConfig::from_slice(input.as_bytes()),
                Err(ConfigError::InvalidLimits)
            );
        }
        let nested = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        assert_eq!(
            RuntimeConfig::from_slice(nested.as_bytes()),
            Err(ConfigError::InvalidDocument)
        );
    }
}
