//! Explicit local enforcement inputs. No credentials or discovered configuration.
use mitigate_gateway::Fault;
use mitigate_mcp::{Snapshot, classification::ClassificationOverrides};
use mitigate_policy::{Authority, read_document};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnforcementConfig {
    pub schema_version: u32,
    pub policy_db: PathBuf,
    pub policy_authority: PathBuf,
    pub grants: PathBuf,
    pub approvals_db: PathBuf,
    pub controls_db: PathBuf,
    pub audit_db: PathBuf,
    pub tool_snapshot: PathBuf,
    #[serde(deserialize_with = "Option::deserialize")]
    pub classification_overrides: Option<PathBuf>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub environment: Option<String>,
    pub approval_timeout_ms: u64,
}
impl EnforcementConfig {
    pub fn from_file(path: &Path) -> Result<Self, Fault> {
        let bytes = read_document(path, 16_384).map_err(|_| Fault::GovernanceUnavailable)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Fault> {
        if bytes.len() > 16_384 {
            return Err(Fault::GovernanceUnavailable);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Fault::GovernanceUnavailable)?;
        let config: Self =
            serde_json::from_value(value).map_err(|_| Fault::GovernanceUnavailable)?;
        if config.schema_version != 1
            || !(100..=270_000).contains(&config.approval_timeout_ms)
            || config.environment.as_ref().is_some_and(|e| {
                e.is_empty()
                    || e.len() > 64
                    || !e
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
            || [
                &config.policy_db,
                &config.policy_authority,
                &config.grants,
                &config.approvals_db,
                &config.controls_db,
                &config.audit_db,
                &config.tool_snapshot,
            ]
            .into_iter()
            .chain(config.classification_overrides.iter())
            .any(|p| !p.is_absolute() || p.as_os_str().len() > 4096)
        {
            return Err(Fault::GovernanceUnavailable);
        }
        Ok(config)
    }
    pub fn authority(&self) -> Result<Authority, Fault> {
        Authority::from_bytes(
            &read_document(&self.policy_authority, 1024)
                .map_err(|_| Fault::GovernanceUnavailable)?,
        )
        .map_err(|_| Fault::GovernanceUnavailable)
    }
    pub fn definitions(&self) -> Result<(Snapshot, ClassificationOverrides), Fault> {
        let snapshot =
            Snapshot::from_file(&self.tool_snapshot).map_err(|_| Fault::GovernanceUnavailable)?;
        let overrides = self
            .classification_overrides
            .as_ref()
            .map(|p| ClassificationOverrides::from_file(p))
            .transpose()
            .map_err(|_| Fault::GovernanceUnavailable)?
            .unwrap_or_default();
        Ok((snapshot, overrides))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn configuration_is_closed_requires_explicit_unknowns_and_bounds_approval_waits() {
        let root = std::env::temp_dir();
        let good = json!({"schema_version":1,"policy_db":root.join("policy.sqlite"),
            "policy_authority":root.join("trust.json"),"grants":root.join("grants.json"),
            "approvals_db":root.join("approvals.sqlite"),"controls_db":root.join("controls.sqlite"),
            "audit_db":root.join("audit.sqlite"),"tool_snapshot":root.join("snapshot.json"),
            "classification_overrides":null,"environment":null,"approval_timeout_ms":120000});
        assert!(EnforcementConfig::from_bytes(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (field, value) in [
            ("policy_db", json!("relative.sqlite")),
            ("approval_timeout_ms", json!(99)),
            ("approval_timeout_ms", json!(270001)),
            ("environment", json!("private value")),
            ("schema_version", json!(2)),
            ("metadata", json!({"secret":"canary"})),
        ] {
            let mut invalid = good.clone();
            invalid[field] = value;
            assert!(EnforcementConfig::from_bytes(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        for field in [
            "environment",
            "classification_overrides",
            "audit_db",
            "policy_authority",
        ] {
            let mut invalid = good.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(EnforcementConfig::from_bytes(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
    }
}
