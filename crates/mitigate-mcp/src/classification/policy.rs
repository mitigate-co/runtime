//! Overrides are explicit local declarations, never discovered in a repository.
//! Fingerprints detect stale declarations; they do not authenticate a server or
//! protect a policy file from another process running as the same local user.

use super::types::{CapabilityClass, Classification, ClassificationSource, Confidence, flags};
use crate::{Error, Result, snapshot::ToolFingerprint};
use mitigate_fingerprint::{Fingerprint, PROFILE};
use serde::Deserialize;
use std::{collections::BTreeSet, fs, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    fingerprint_profile: String,
    server_facts: Fingerprint,
    tools: Vec<Override>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Override {
    identity: Fingerprint,
    input_schema: Fingerprint,
    output_schema: Option<Fingerprint>,
    description: Option<Fingerprint>,
    classes: Vec<CapabilityClass>,
}

/// Explicit administrator classifications for one observed server snapshot.
/// Default means no overrides. Files must be supplied by the operator; there is
/// no project/home discovery, registry fetch, execution or authorization effect.
#[derive(Default)]
pub struct ClassificationOverrides {
    document: Option<Document>,
}

impl ClassificationOverrides {
    /// Parse a closed 256 KiB document, rejecting duplicates, unknown fields,
    /// unsupported profiles and ambiguous class sets. No source text is returned.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 262_144 {
            return Err(Error::Classification);
        }
        let value = mitigate_json::parse(bytes).map_err(|_| Error::Classification)?;
        let mut document: Document =
            serde_json::from_value(value).map_err(|_| Error::Classification)?;
        if document.schema_version != 1
            || document.fingerprint_profile != PROFILE
            || document.tools.len() > 512
        {
            return Err(Error::Classification);
        }
        for (index, item) in document.tools.iter().enumerate() {
            let unique: BTreeSet<_> = item.classes.iter().copied().collect();
            if item.classes.is_empty()
                || item.classes.len() > 11
                || unique.len() != item.classes.len()
                || (unique.contains(&CapabilityClass::Unknown) && unique.len() != 1)
                || document.tools[..index]
                    .iter()
                    .any(|previous| previous.identity == item.identity)
            {
                return Err(Error::Classification);
            }
        }
        for item in &mut document.tools {
            item.classes.sort();
        }
        Ok(Self {
            document: Some(document),
        })
    }

    /// Read a caller-selected regular file. Protect it with OS permissions; a
    /// same-user attacker able to replace policy files is outside this boundary.
    pub fn from_file(path: &Path) -> Result<Self> {
        let metadata = path.symlink_metadata().map_err(|_| Error::Classification)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Error::Classification);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Error::Classification);
            }
        }
        let file = fs::File::open(path).map_err(|_| Error::Classification)?;
        if !file
            .metadata()
            .map_err(|_| Error::Classification)?
            .is_file()
        {
            return Err(Error::Classification);
        }
        let mut bytes = Vec::new();
        file.take(262_145)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Classification)?;
        Self::from_bytes(&bytes)
    }

    pub(super) fn len(&self) -> usize {
        self.document.as_ref().map_or(0, |d| d.tools.len())
    }

    pub(super) fn check_server(&self, server_facts: &Fingerprint) -> Result<()> {
        if self
            .document
            .as_ref()
            .is_some_and(|d| &d.server_facts != server_facts)
        {
            return Err(Error::Classification);
        }
        Ok(())
    }

    pub(super) fn apply(
        &self,
        definition: &ToolFingerprint,
        mut baseline: Classification,
        matched: &mut BTreeSet<usize>,
    ) -> Result<Classification> {
        let Some(document) = &self.document else {
            return Ok(baseline);
        };
        let Some((index, item)) = document
            .tools
            .iter()
            .enumerate()
            .find(|(_, item)| item.identity == definition.identity)
        else {
            return Ok(baseline);
        };
        if item.input_schema != definition.input_schema
            || item.output_schema != definition.output_schema
            || item.description != definition.description
        {
            return Err(Error::Classification);
        }
        matched.insert(index);
        baseline.classes.clone_from(&item.classes);
        baseline.flags.extend(flags(&item.classes));
        baseline.flags.sort();
        baseline.flags.dedup();
        baseline.sources.push(ClassificationSource::Admin);
        baseline.confidence = Confidence::High;
        baseline.overridden = true;
        Ok(baseline)
    }
}
