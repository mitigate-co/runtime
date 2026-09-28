//! Explicit local fingerprint snapshots. Never persist raw definitions or secrets.

use crate::{Error, Inventory, Result};
use mitigate_fingerprint::{Domain, Fingerprint, PROFILE, fingerprint};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolFingerprint {
    pub(crate) name: String,
    pub(crate) identity: Fingerprint,
    pub(crate) input_schema: Fingerprint,
    pub(crate) output_schema: Option<Fingerprint>,
    pub(crate) description: Option<Fingerprint>,
}

/// Closed local snapshot. Digests are change detectors, not anonymization or
/// proof of authenticity. Do not submit this document directly to Platform.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    schema_version: u32,
    fingerprint_profile: String,
    server_identity: Fingerprint,
    pub(crate) server_facts: Fingerprint,
    tools_supported: bool,
    pub(crate) tools: Vec<ToolFingerprint>,
}

impl Snapshot {
    /// Fingerprint observed definitions independently so a description edit is
    /// distinguishable from an input/output schema or server-version change.
    pub fn from_inventory(inventory: &Inventory) -> Result<Self> {
        fn hash(domain: Domain, value: &serde_json::Value) -> Result<Fingerprint> {
            fingerprint(domain, value).map_err(|_| Error::Fingerprint)
        }
        let server_identity = hash(Domain::ServerIdentity, &json!(inventory.server_name))?;
        let server_facts = hash(
            Domain::ServerFacts,
            &json!({"name":inventory.server_name,"version":inventory.server_version,"protocol":inventory.protocol_version,"tools_supported":inventory.tools_supported}),
        )?;
        if inventory.tools.len() > 512 {
            return Err(Error::Snapshot);
        }
        let mut tools = Vec::with_capacity(inventory.tools.len());
        for tool in &inventory.tools {
            if tool.name.len() > 128 || tool.description.as_ref().is_some_and(|s| s.len() > 16_384)
            {
                return Err(Error::Fingerprint);
            }
            tools.push(ToolFingerprint {
                name: tool.name.clone(),
                identity: hash(Domain::ToolIdentity, &json!([server_identity, tool.name]))?,
                input_schema: hash(Domain::InputSchema, &tool.input_schema)?,
                output_schema: tool
                    .output_schema
                    .as_ref()
                    .map(|s| hash(Domain::OutputSchema, s))
                    .transpose()?,
                description: tool
                    .description
                    .as_ref()
                    .map(|s| {
                        hash(
                            Domain::Description,
                            &json!(s.split_whitespace().collect::<Vec<_>>().join(" ")),
                        )
                    })
                    .transpose()?,
            });
        }
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        let snapshot = Self {
            schema_version: 1,
            fingerprint_profile: PROFILE.to_owned(),
            server_identity,
            server_facts,
            tools_supported: inventory.tools_supported,
            tools,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.fingerprint_profile != PROFILE
            || self.tools.len() > 512
            || (!self.tools_supported && !self.tools.is_empty())
        {
            return Err(Error::Snapshot);
        }
        let mut previous = None;
        for tool in &self.tools {
            if tool.name.is_empty()
                || tool.name.len() > 128
                || !tool
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                || previous.is_some_and(|p: &str| p >= tool.name.as_str())
            {
                return Err(Error::Snapshot);
            }
            previous = Some(tool.name.as_str());
            let expected = fingerprint(
                Domain::ToolIdentity,
                &json!([self.server_identity, tool.name]),
            )
            .map_err(|_| Error::Snapshot)?;
            if tool.identity != expected {
                return Err(Error::Snapshot);
            }
        }
        Ok(())
    }

    /// Parse a closed, bounded snapshot; duplicate and unknown fields fail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Snapshot)?;
        let snapshot: Self = serde_json::from_value(value).map_err(|_| Error::Snapshot)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Read an explicitly chosen regular snapshot (1 MiB maximum).
    pub fn from_file(path: &Path) -> Result<Self> {
        let metadata = path.symlink_metadata().map_err(|_| Error::Snapshot)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Error::Snapshot);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Error::Snapshot);
            }
        }
        let file = fs::File::open(path).map_err(|_| Error::Snapshot)?;
        if !file.metadata().map_err(|_| Error::Snapshot)?.is_file() {
            return Err(Error::Snapshot);
        }
        let mut bytes = Vec::new();
        file.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Snapshot)?;
        Self::from_bytes(&bytes)
    }

    /// Save only at explicit user request. Exclusive creation prevents clobbering
    /// existing files/links; Unix permissions are owner-only. A failed write may
    /// leave an incomplete new file, which the loader will reject.
    pub fn write_new(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|_| Error::Snapshot)?;
        bytes.push(b'\n');
        if bytes.len() > 1_048_576 {
            return Err(Error::Snapshot);
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|_| Error::Snapshot)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Snapshot)
    }

    /// Compare validated compatible snapshots by case-sensitive local tool name.
    /// A changed server identity remains explicit; no identity attribution inferred.
    pub fn diff(&self, after: &Self) -> Result<SnapshotDiff> {
        self.validate()?;
        after.validate()?;
        let before: BTreeMap<_, _> = self.tools.iter().map(|t| (t.name.as_str(), t)).collect();
        let current: BTreeMap<_, _> = after.tools.iter().map(|t| (t.name.as_str(), t)).collect();
        let mut changes = Vec::new();
        for (name, tool) in &before {
            match current.get(name) {
                None => changes.push(ToolChange::presence(name, ChangeKind::Removed)),
                Some(now) => {
                    let change = ToolChange {
                        name: (*name).to_owned(),
                        kind: ChangeKind::Changed,
                        identity_changed: tool.identity != now.identity,
                        input_schema_changed: tool.input_schema != now.input_schema,
                        output_schema_changed: tool.output_schema != now.output_schema,
                        description_changed: tool.description != now.description,
                    };
                    if change.identity_changed
                        || change.input_schema_changed
                        || change.output_schema_changed
                        || change.description_changed
                    {
                        changes.push(change);
                    }
                }
            }
        }
        for name in current.keys() {
            if !before.contains_key(name) {
                changes.push(ToolChange::presence(name, ChangeKind::Added));
            }
        }
        changes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(SnapshotDiff {
            schema_version: 1,
            server_identity_changed: self.server_identity != after.server_identity,
            server_facts_changed: self.server_facts != after.server_facts,
            tools_supported_changed: self.tools_supported != after.tools_supported,
            tools: changes,
        })
    }
}

/// Stable category of an observed tool change.
#[derive(Debug, Copy, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Present only in the later snapshot.
    Added,
    /// Present only in the earlier snapshot.
    Removed,
    /// Present in both with changed fingerprints.
    Changed,
}

/// Tool-level changes; omitted raw descriptions and schemas cannot leak here.
#[derive(Serialize)]
pub struct ToolChange {
    /// Local tool name, still untrusted customer-controlled text.
    pub name: String,
    /// Addition, removal or fingerprint difference.
    pub kind: ChangeKind,
    /// Identity differs on a tool present in both snapshots.
    pub identity_changed: bool,
    /// Input definition differs on a tool present in both snapshots.
    pub input_schema_changed: bool,
    /// Output definition differs on a tool present in both snapshots.
    pub output_schema_changed: bool,
    /// Normalized description differs on a tool present in both snapshots.
    pub description_changed: bool,
}
impl ToolChange {
    fn presence(name: &str, kind: ChangeKind) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            identity_changed: false,
            input_schema_changed: false,
            output_schema_changed: false,
            description_changed: false,
        }
    }
}

/// Versioned local difference report. No implicit approval or trust decision.
#[derive(Serialize)]
pub struct SnapshotDiff {
    /// Report contract version.
    pub schema_version: u32,
    /// Declared server name changed; no authenticated identity claim.
    pub server_identity_changed: bool,
    /// Server version/protocol/capability facts changed.
    pub server_facts_changed: bool,
    /// The tools capability appeared or disappeared.
    pub tools_supported_changed: bool,
    /// Sorted tool additions/removals/changes.
    pub tools: Vec<ToolChange>,
}
impl SnapshotDiff {
    /// Whether any recorded identity, fact or definition changed.
    pub fn is_empty(&self) -> bool {
        !self.server_identity_changed
            && !self.server_facts_changed
            && !self.tools_supported_changed
            && self.tools.is_empty()
    }
}
