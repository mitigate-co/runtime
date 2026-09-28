//! Local deterministic capability hints and explicitly supplied bound overrides.
//! A classification is never an authorization decision or proof of server behavior.

mod policy;
mod rules;
mod types;

use crate::{Error, Inventory, Result, Snapshot};
pub use policy::ClassificationOverrides;
use serde::Serialize;
pub use types::{CapabilityClass, Classification, ClassificationSource, Confidence, RiskFlag};

/// Inspection report with explicit capability/risk evidence, without raw definitions.
#[derive(Serialize)]
pub struct ClassifiedInventory<'a> {
    /// Version 2 adds per-tool classifications to inspection output.
    pub schema_version: u32,
    /// Negotiated protocol version.
    pub protocol_version: &'a str,
    /// Server-declared name; not authenticated identity.
    pub server_name: &'a str,
    /// Server-declared version; not installed provenance.
    pub server_version: &'a str,
    /// Advertised tools capability.
    pub tools_supported: bool,
    /// Name-sorted classified tools.
    pub tools: Vec<ClassifiedTool<'a>>,
}

/// Local tool report. No schema/description/argument values are serialized.
#[derive(Serialize)]
pub struct ClassifiedTool<'a> {
    /// Validated local tool label.
    pub name: &'a str,
    /// Whether the server supplied a description; its text is excluded.
    pub description_present: bool,
    /// Number of top-level input properties; their names/values are excluded.
    pub input_property_count: usize,
    /// Whether an output schema was supplied.
    pub output_schema_present: bool,
    /// Capability hints and source-attributed review information.
    pub classification: Classification,
}

impl Inventory {
    /// Classify observed names/schema shape. Overrides are bound to the exact
    /// fingerprint profile, declared identity and input/output/description hashes.
    /// A stale or unmatched supplied override is an error, never silently ignored.
    pub fn classify(&self, overrides: &ClassificationOverrides) -> Result<ClassifiedInventory<'_>> {
        let snapshot = Snapshot::from_inventory(self)?;
        overrides.check_server(&snapshot.server_facts)?;
        let mut matched = std::collections::BTreeSet::new();
        let mut tools = Vec::with_capacity(self.tools.len());
        for tool in &self.tools {
            let baseline = rules::classify(tool)?;
            let definition = snapshot
                .tools
                .iter()
                .find(|t| t.name == tool.name)
                .ok_or(Error::Classification)?;
            let classification = overrides.apply(definition, baseline, &mut matched)?;
            tools.push(ClassifiedTool {
                name: &tool.name,
                description_present: tool.description.is_some(),
                input_property_count: tool
                    .input_schema
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .map_or(0, |p| p.len()),
                output_schema_present: tool.output_schema.is_some(),
                classification,
            });
        }
        if matched.len() != overrides.len() {
            return Err(Error::Classification);
        }
        tools.sort_by(|a, b| a.name.cmp(b.name));
        Ok(ClassifiedInventory {
            schema_version: 2,
            protocol_version: &self.protocol_version,
            server_name: &self.server_name,
            server_version: &self.server_version,
            tools_supported: self.tools_supported,
            tools,
        })
    }
}
