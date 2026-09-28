//! Local definitions and a deliberately narrower CLI report.

use serde::Serialize;
use serde_json::Value;

/// Observed local tool definition. Description/schema are hostile content.
/// No Debug/Serialize: diagnostics and default reports must not echo them.
pub struct Tool {
    /// Case-sensitive server-declared identity, not registry provenance.
    pub name: String,
    /// Untrusted description for local normalization/classification only.
    pub description: Option<String>,
    /// Bounded schema; external references are never fetched.
    pub input_schema: Value,
    /// Optional bounded output schema.
    pub output_schema: Option<Value>,
}

/// A complete point-in-time local enumeration, never a Platform event.
pub struct Inventory {
    /// Negotiated supported protocol version.
    pub protocol_version: String,
    /// Server-declared name, not an authenticated identity.
    pub server_name: String,
    /// Server-declared version, not verified package provenance.
    pub server_version: String,
    /// Whether the server advertised the tools capability.
    pub tools_supported: bool,
    /// Tools ordered by exact name, with no duplicate identities.
    pub tools: Vec<Tool>,
}

/// Local CLI report with raw descriptions, schemas and upstream messages excluded.
/// Names are still untrusted local labels; this is not a cloud egress contract.
#[derive(Serialize)]
pub struct InventoryReport<'a> {
    /// Local report schema version.
    pub schema_version: u32,
    /// Negotiated protocol version.
    pub protocol_version: &'a str,
    /// Unverified server name.
    pub server_name: &'a str,
    /// Unverified server version.
    pub server_version: &'a str,
    /// Advertised capability; false distinguishes unsupported from zero tools.
    pub tools_supported: bool,
    /// Narrow descriptions of observed tools.
    pub tools: Vec<ToolSummary<'a>>,
}

/// Counts and local identity only; no original schema/description content.
#[derive(Serialize)]
pub struct ToolSummary<'a> {
    /// Case-sensitive local identity.
    pub name: &'a str,
    /// Whether a description was provided.
    pub description_present: bool,
    /// Number of top-level input properties, not their names or values.
    pub input_property_count: usize,
    /// Whether an output schema was provided.
    pub output_schema_present: bool,
}
impl Inventory {
    /// Build the default narrow report; never includes raw definition content.
    pub fn report(&self) -> InventoryReport<'_> {
        InventoryReport {
            schema_version: 1,
            protocol_version: &self.protocol_version,
            server_name: &self.server_name,
            server_version: &self.server_version,
            tools_supported: self.tools_supported,
            tools: self
                .tools
                .iter()
                .map(|t| ToolSummary {
                    name: &t.name,
                    description_present: t.description.is_some(),
                    input_property_count: t
                        .input_schema
                        .get("properties")
                        .and_then(Value::as_object)
                        .map_or(0, |p| p.len()),
                    output_schema_present: t.output_schema.is_some(),
                })
                .collect(),
        }
    }
}
