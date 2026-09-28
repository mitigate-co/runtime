//! Launch validation is independent of untrusted client discovery. Never serializes.

use crate::{Error, Result};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

/// A reviewed local process declaration. No inline credentials or shell strings.
///
/// Deserialization does not grant execution. Enumeration and managed connection
/// callers must obtain explicit intent. Debug/Serialize are intentionally absent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchConfig {
    schema_version: u32,
    pub(crate) executable_path: String,
    pub(crate) working_directory: String,
    #[serde(default)]
    pub(crate) argv: Vec<String>,
    #[serde(default)]
    allowed_environment_keys: Vec<String>,
    #[serde(default = "default_timeout")]
    pub(crate) timeout_ms: u64,
}
fn default_timeout() -> u64 {
    30_000
}

impl LaunchConfig {
    /// Parse bounded strict JSON without retaining source-bearing diagnostics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65_536 {
            return Err(Error::Configuration);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Configuration)?;
        let config: Self = serde_json::from_value(value).map_err(|_| Error::Configuration)?;
        config.validate()?;
        Ok(config)
    }
    /// Read an explicitly selected regular file; source contents never enter errors.
    pub fn from_file(path: &Path) -> Result<Self> {
        let metadata = path.symlink_metadata().map_err(|_| Error::Configuration)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Error::Configuration);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Error::Configuration);
            }
        }
        let file = fs::File::open(path).map_err(|_| Error::Configuration)?;
        if !file.metadata().map_err(|_| Error::Configuration)?.is_file() {
            return Err(Error::Configuration);
        }
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Configuration)?;
        Self::from_bytes(&bytes)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !(100..=120_000).contains(&self.timeout_ms)
            || self.argv.len() > 64
            || self.argv.iter().any(|a| a.len() > 4096 || a.contains('\0'))
            || self.argv.iter().map(String::len).sum::<usize>() > 32_768
            || self.allowed_environment_keys.len() > 32
        {
            return Err(Error::Configuration);
        }
        let mut names = std::collections::BTreeSet::new();
        for name in &self.allowed_environment_keys {
            if name.is_empty()
                || name.len() > 128
                || !name.bytes().enumerate().all(|(i, c)| {
                    c.is_ascii_alphabetic() || c == b'_' || (i > 0 && c.is_ascii_digit())
                })
                || !names.insert(name.to_ascii_uppercase())
            {
                return Err(Error::Environment);
            }
        }
        Ok(())
    }
    pub(crate) fn paths(&self) -> Result<(PathBuf, PathBuf)> {
        fn resolve(value: &str, directory: bool) -> Result<PathBuf> {
            if value.len() > 4096
                || value.chars().any(char::is_control)
                || !Path::new(value).is_absolute()
            {
                return Err(Error::Executable);
            }
            let path = fs::canonicalize(value).map_err(|_| Error::Executable)?;
            if (directory && !path.is_dir()) || (!directory && !path.is_file()) {
                return Err(Error::Executable);
            }
            #[cfg(windows)]
            if !directory
                && !path
                    .extension()
                    .is_some_and(|s| s.eq_ignore_ascii_case("exe"))
            {
                return Err(Error::Executable);
            }
            Ok(path)
        }
        Ok((
            resolve(&self.executable_path, false)?,
            resolve(&self.working_directory, true)?,
        ))
    }
    pub(crate) fn environment(&self) -> Result<BTreeMap<String, OsString>> {
        let mut result = BTreeMap::new();
        // Do not inherit PATH, HOME, loaders, proxies, API keys or telemetry.
        // Windows system location and temporary directories support ordinary OS use.
        for name in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                result.insert(name.to_owned(), value);
            }
        }
        for name in &self.allowed_environment_keys {
            let value = std::env::var_os(name).ok_or(Error::Environment)?;
            if value.len() > 8192 {
                return Err(Error::Environment);
            }
            result.insert(name.clone(), value);
        }
        if result.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > 65_536 {
            return Err(Error::Environment);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_ambiguous_secret_bearing_or_unbounded_launch_input() {
        for bytes in [
            br#"{"schema_version":1,"schema_version":1,"executable_path":"unused","working_directory":"unused"}"#.to_vec(),
            br#"{"schema_version":1,"executable_path":"unused","working_directory":"unused","env":{"TOKEN":"secret-canary"}}"#.to_vec(),
            vec![b' ';65_537],
        ] { assert_eq!(LaunchConfig::from_bytes(&bytes).err(),Some(Error::Configuration)); }
        for (field, value, expected) in [
            ("argv", json!(vec!["a"; 65]), Error::Configuration),
            ("argv", json!(["\u{0}"]), Error::Configuration),
            ("timeout_ms", json!(120_001), Error::Configuration),
            (
                "allowed_environment_keys",
                json!(["TOKEN", "token"]),
                Error::Environment,
            ),
            (
                "allowed_environment_keys",
                json!(["TOKEN=secret-canary"]),
                Error::Environment,
            ),
            (
                "allowed_environment_keys",
                json!(["1TOKEN"]),
                Error::Environment,
            ),
        ] {
            let mut value_config =
                json!({"schema_version":1,"executable_path":"unused","working_directory":"unused"});
            value_config[field] = value;
            assert_eq!(
                LaunchConfig::from_bytes(&serde_json::to_vec(&value_config).unwrap()).err(),
                Some(expected)
            );
        }
    }
}
