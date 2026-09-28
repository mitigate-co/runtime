//! Optional source-attributed public registry facts. No network requests,
//! collector/curation implementation, local inventory export or authorization.
mod model;
#[cfg(test)]
mod tests;
mod validation;

pub use model::{
    Assertion, Capability, Confidence, Ecosystem, Fact, Source, SourceKind, Transport,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::Path,
};

/// Maximum bounded catalog bytes, before parsing.
pub const MAX_CATALOG_BYTES: usize = 1_048_576;

/// Fixed registry errors contain no source text, URL, path or parser diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Cannot read an explicitly selected regular bounded file.
    File,
    /// Malformed/ambiguous/unknown JSON schema.
    Schema,
    /// Byte, collection or timestamp limits exceeded.
    Bounds,
    /// Invalid identifiers, URLs or public assertion fields.
    Content,
    /// Duplicate identifiers, missing provenance or inconsistent timestamps.
    Provenance,
    /// Lookup requires a canonical public subject reference.
    Subject,
    /// Trusted observation clock is unavailable or out of range.
    Clock,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::File => "registry catalog unavailable; select a readable regular file",
            Self::Schema => {
                "registry catalog schema rejected; obtain a supported unambiguous catalog"
            }
            Self::Bounds => "registry catalog exceeds supported limits; obtain a bounded catalog",
            Self::Content => "registry catalog contains invalid public facts; review its source",
            Self::Provenance => "registry provenance is inconsistent; obtain a corrected catalog",
            Self::Subject => "invalid public subject; use a canonical namespace/server reference",
            Self::Clock => "registry clock unavailable; correct the local OS clock",
        })
    }
}
impl std::error::Error for Error {}

/// Validated public evidence. Private storage prevents construction around checks.
/// Validation does not authenticate a publisher or establish any tool's safety.
pub struct Catalog {
    generated_at_ms: u64,
    expires_at_ms: u64,
    sources: BTreeMap<String, Source>,
    facts: Vec<Fact>,
}
/// Freshness at a trusted local observation time. Stale/future claims remain explicit.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Document is within its declared validity interval.
    Current,
    /// Document expiry was reached.
    Expired,
    /// Document claims to have been generated after the observation clock.
    Future,
}
/// Local lookup result; not a telemetry contract, a grant or installation command.
#[derive(Serialize)]
pub struct Lookup<'a> {
    /// Result format version.
    pub schema_version: u8,
    /// Exact canonical public subject requested.
    pub subject: String,
    /// Whether the supplied catalog has any facts for this subject.
    pub found: bool,
    /// Declared catalog generation time.
    pub generated_at_ms: u64,
    /// Declared catalog expiry time.
    pub expires_at_ms: u64,
    /// Trusted local lookup observation.
    pub checked_at_ms: u64,
    /// Time assessment, without discarding or silently refreshing evidence.
    pub freshness: Freshness,
    /// Always false for an explicitly selected unsigned catalog.
    pub publisher_authenticated: bool,
    /// Always false: these facts never replace local policy or review.
    pub grants_access: bool,
    /// Every matching fact, preserving source disagreement and uncertainty.
    pub facts: Vec<&'a Fact>,
    /// All and only sources referenced by the returned facts.
    pub sources: Vec<&'a Source>,
}
impl Catalog {
    /// Parse a closed public catalog. No fetch, code execution or policy mutation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(Error::Bounds);
        }
        let doc: model::Document =
            serde_json::from_value(mitigate_json::parse(bytes).map_err(|_| Error::Schema)?)
                .map_err(|_| Error::Schema)?;
        if doc.schema_version != 1 {
            return Err(Error::Schema);
        }
        if doc.sources.len() > 64
            || doc.facts.len() > 1024
            || doc.generated_at_ms > validation::MAX_TIME
            || doc.expires_at_ms > validation::MAX_TIME
            || doc.expires_at_ms <= doc.generated_at_ms
            || doc.expires_at_ms - doc.generated_at_ms > 30 * 86_400_000
        {
            return Err(Error::Bounds);
        }
        let mut sources = BTreeMap::new();
        for source in doc.sources {
            if !validation::slug(&source.source_ref, 64) || !validation::public_url(&source.url) {
                return Err(Error::Content);
            }
            if source.retrieved_at_ms > doc.generated_at_ms
                || sources.insert(source.source_ref.clone(), source).is_some()
            {
                return Err(Error::Provenance);
            }
        }
        let mut facts = doc.facts;
        let mut ids = BTreeSet::new();
        for fact in &facts {
            if !validation::slug(&fact.fact_ref, 64) || !validation::subject(&fact.subject) {
                return Err(Error::Content);
            }
            if !ids.insert(&fact.fact_ref)
                || sources
                    .get(&fact.source_ref)
                    .is_none_or(|s| fact.observed_at_ms > s.retrieved_at_ms)
            {
                return Err(Error::Provenance);
            }
            validation::assertion(&fact.assertion, fact.observed_at_ms)?;
        }
        facts.sort_by(|a, b| {
            (&a.subject, &a.source_ref, a.observed_at_ms, &a.fact_ref).cmp(&(
                &b.subject,
                &b.source_ref,
                b.observed_at_ms,
                &b.fact_ref,
            ))
        });
        Ok(Self {
            generated_at_ms: doc.generated_at_ms,
            expires_at_ms: doc.expires_at_ms,
            sources,
            facts,
        })
    }
    /// Read one explicit bounded regular file, rejecting a final symlink or
    /// Windows reparse point observed before opening. The caller must select a
    /// trusted parent; this is not protection against concurrent same-user
    /// replacement. Never search home directories, repair or download data.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::File)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_CATALOG_BYTES as u64
        {
            return Err(Error::File);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Error::File);
            }
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|_| Error::File)?
            .take(MAX_CATALOG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::File)?;
        Self::from_bytes(&bytes)
    }
    /// Return all source-attributed claims, including disagreements, with explicit
    /// catalog freshness. Absence is unknown, never a positive safety conclusion.
    pub fn lookup(&self, subject: &str, now_ms: u64) -> Result<Lookup<'_>, Error> {
        if !validation::subject(subject) {
            return Err(Error::Subject);
        }
        if now_ms > validation::MAX_TIME {
            return Err(Error::Clock);
        }
        let facts: Vec<_> = self.facts.iter().filter(|f| f.subject == subject).collect();
        let sources = self
            .sources
            .values()
            .filter(|s| facts.iter().any(|f| f.source_ref == s.source_ref))
            .collect();
        Ok(Lookup {
            schema_version: 1,
            subject: subject.to_owned(),
            found: !facts.is_empty(),
            generated_at_ms: self.generated_at_ms,
            expires_at_ms: self.expires_at_ms,
            checked_at_ms: now_ms,
            freshness: if now_ms < self.generated_at_ms {
                Freshness::Future
            } else if now_ms >= self.expires_at_ms {
                Freshness::Expired
            } else {
                Freshness::Current
            },
            publisher_authenticated: false,
            grants_access: false,
            facts,
            sources,
        })
    }
}
