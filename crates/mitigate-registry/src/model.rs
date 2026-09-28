use serde::{Deserialize, Serialize};

/// Declared public evidence source type, not authenticated publisher identity.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Publisher-maintained documentation or manifest.
    Publisher,
    /// A package registry's public record.
    PackageRegistry,
    /// A named public advisory database.
    AdvisoryDatabase,
    /// A separately attributed public review.
    IndependentReview,
}
/// Public source provenance. URLs are display references, never fetched by parsing.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Unique bounded catalog-local identifier.
    pub source_ref: String,
    /// Canonical credential/query/fragment-free public HTTPS reference.
    pub url: String,
    /// Declared evidence category.
    pub kind: SourceKind,
    /// UTC retrieval time recorded by the publisher of the catalog.
    pub retrieved_at_ms: u64,
}
/// Publisher-declared confidence, not a Runtime verification result or risk score.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Limited or indirect support.
    Low,
    /// Corroborated but incomplete support.
    Medium,
    /// Strong source support as judged by the catalog publisher.
    High,
}
/// Supported public package namespaces.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    /// npm, including scoped packages.
    Npm,
    /// Python package index, canonical normalized names.
    Pypi,
    /// Rust package registry.
    CratesIo,
}
/// Publicly reported MCP transport. This does not imply Runtime adapter support.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Standard input/output transport.
    Stdio,
    /// Streamable HTTP transport.
    StreamableHttp,
    /// Legacy server-sent events transport.
    Sse,
}
/// Public capability claim, deliberately separate from local authorization types.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read customer data.
    ReadData,
    /// Modify customer data.
    WriteData,
    /// Delete customer data.
    DeleteData,
    /// Execute code.
    ExecuteCode,
    /// Access credentials.
    CredentialAccess,
    /// Communicate with external destinations.
    ExternalCommunication,
    /// Browser actions.
    BrowserAction,
    /// Identity administration.
    IdentityAdmin,
    /// Financial actions.
    FinancialAction,
    /// Infrastructure changes.
    InfrastructureChange,
    /// Unclassified capability; never inferred safe.
    Unknown,
}
/// Closed public assertions. No free-form descriptions, instructions, scores or
/// generic metadata. A fact is attributed evidence, not permission to run code.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Assertion {
    /// A public repository reference reported by this source.
    Repository {
        /// Canonical public HTTPS location.
        url: String,
    },
    /// A particular public package and release version.
    Package {
        /// Package namespace.
        ecosystem: Ecosystem,
        /// Canonical bounded package identifier.
        name: String,
        /// Exact reported release, not a range or install command.
        version: String,
    },
    /// Reported supported transport.
    Transport {
        /// MCP transport category.
        transport: Transport,
    },
    /// A reported capability; never a grant or authoritative local classification.
    Capability {
        /// Fixed capability label.
        capability: Capability,
    },
    /// Public release date according to the named source.
    Release {
        /// Exact bounded release label.
        version: String,
        /// UTC publication time.
        published_at_ms: u64,
    },
    /// An advisory reference, not a finding that a deployment is vulnerable.
    Advisory {
        /// Canonical CVE or GHSA identifier.
        advisory_id: String,
        /// Public source supporting this reference.
        url: String,
    },
}
/// One independently attributed claim. Conflicting sources are kept separately.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    /// Unique bounded catalog-local identity.
    pub fact_ref: String,
    /// Canonical public MCP subject, e.g. `io.example/synthetic-server`.
    pub subject: String,
    /// Existing source identifier from the same document.
    pub source_ref: String,
    /// UTC observation time, no later than source retrieval.
    pub observed_at_ms: u64,
    /// Confidence attributed to the document publisher, never invented locally.
    pub confidence: Confidence,
    /// Closed assertion value.
    pub assertion: Assertion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Document {
    pub schema_version: u8,
    pub generated_at_ms: u64,
    pub expires_at_ms: u64,
    pub sources: Vec<Source>,
    pub facts: Vec<Fact>,
}
