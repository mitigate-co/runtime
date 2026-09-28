//! Launch validation is independent of untrusted client discovery. Never serializes.
pub(crate) mod review;

use crate::{Error, Result};
use mitigate_secrets::{NativeStore, Secret, SecretRef, SecretStore};
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
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchConfig {
    schema_version: u32,
    pub(crate) executable_path: String,
    pub(crate) working_directory: String,
    #[serde(default)]
    pub(crate) argv: Vec<String>,
    #[serde(default)]
    allowed_environment_keys: Vec<String>,
    #[serde(default)]
    secret_references: Vec<SecretBinding>,
    #[serde(default)]
    artifact_paths: Vec<String>,
    #[serde(default = "default_timeout")]
    pub(crate) timeout_ms: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretBinding {
    environment_key: String,
    secret_ref: String,
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
            || self.allowed_environment_keys.len() + self.secret_references.len() > 32
            || self.artifact_paths.len() > 32
            || self.artifact_paths.iter().any(|p| {
                p.len() > 4096 || p.chars().any(char::is_control) || !Path::new(p).is_absolute()
            })
        {
            return Err(Error::Configuration);
        }
        let mut names = std::collections::BTreeSet::new();
        for name in self
            .allowed_environment_keys
            .iter()
            .chain(self.secret_references.iter().map(|s| &s.environment_key))
        {
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
        for binding in &self.secret_references {
            if ["SYSTEMROOT", "WINDIR", "TEMP", "TMP"]
                .contains(&binding.environment_key.to_ascii_uppercase().as_str())
                || SecretRef::parse(&binding.secret_ref).is_err()
            {
                return Err(Error::Credential);
            }
        }
        Ok(())
    }
    pub(crate) async fn secrets(&self) -> Result<Vec<(String, Secret)>> {
        self.secrets_from(&NativeStore).await
    }
    async fn secrets_from(&self, store: &impl SecretStore) -> Result<Vec<(String, Secret)>> {
        self.validate()?;
        let mut resolved = Vec::with_capacity(self.secret_references.len());
        for binding in &self.secret_references {
            let reference = SecretRef::parse(&binding.secret_ref).map_err(|_| Error::Credential)?;
            let secret = store
                .read(&reference)
                .await
                .map_err(|_| Error::Credential)?;
            resolved.push((binding.environment_key.clone(), secret));
        }
        Ok(resolved)
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

    fn with_bindings(bindings: serde_json::Value, allowed: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema_version":1,"executable_path":"unused","working_directory":"unused","secret_references":bindings,"allowed_environment_keys":allowed})).unwrap()
    }

    #[test]
    fn secret_bindings_reject_conflicts_inline_values_and_reserved_keys() {
        let reference = "sec_0123456789abcdef0123456789abcdef";
        for bindings in [
            json!([{"environment_key":"TOKEN","secret_ref":reference,"value":"secret-canary"}]),
            json!([{"environment_key":"TOKEN","secret_ref":"secret-canary"}]),
            json!([{"environment_key":"TEMP","secret_ref":reference}]),
            json!([{"environment_key":"systemroot","secret_ref":reference}]),
            json!([{"environment_key":"TOKEN=secret-canary","secret_ref":reference}]),
            json!([{"environment_key":"TOKEN","secret_ref":reference},{"environment_key":"token","secret_ref":reference}]),
            json!(vec![
                json!({"environment_key":"TOKEN","secret_ref":reference});
                33
            ]),
        ] {
            assert!(LaunchConfig::from_bytes(&with_bindings(bindings, json!([]))).is_err());
        }
        let binding = json!([{"environment_key":"TOKEN","secret_ref":reference}]);
        assert!(
            LaunchConfig::from_bytes(&with_bindings(binding.clone(), json!(["token"]))).is_err()
        );
        assert!(LaunchConfig::from_bytes(&with_bindings(binding, json!([]))).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_for_execution_only_uses_requested_refs_and_fails_closed() {
        use std::cell::RefCell;
        struct Store {
            reads: RefCell<Vec<String>>,
            fail: bool,
        }
        impl SecretStore for Store {
            async fn read(
                &self,
                reference: &SecretRef,
            ) -> std::result::Result<Secret, mitigate_secrets::Error> {
                self.reads.borrow_mut().push(reference.as_str().to_owned());
                if self.fail {
                    return Err(mitigate_secrets::Error::Missing);
                }
                Secret::from_bytes(b"secret-canary".to_vec())
            }
        }
        let store = Store {
            reads: RefCell::default(),
            fail: false,
        };
        let empty = LaunchConfig::from_bytes(&with_bindings(json!([]), json!([]))).unwrap();
        assert!(empty.secrets_from(&store).await.unwrap().is_empty());
        assert!(store.reads.borrow().is_empty());
        let reference = "sec_0123456789abcdef0123456789abcdef";
        let config = LaunchConfig::from_bytes(&with_bindings(
            json!([{"environment_key":"TOKEN","secret_ref":reference}]),
            json!([]),
        ))
        .unwrap();
        let values = config.secrets_from(&store).await.unwrap();
        assert_eq!(&*store.reads.borrow(), &[reference]);
        assert_eq!(values[0].0, "TOKEN");
        assert!(values[0].1.expose(|v| v == "secret-canary"));
        let failed = Store {
            reads: RefCell::default(),
            fail: true,
        };
        assert_eq!(
            config.secrets_from(&failed).await.err(),
            Some(Error::Credential)
        );
    }

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
