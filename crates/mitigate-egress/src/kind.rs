use crate::{EVENT_FIELDS, inventory};
use serde::Serialize;

/// Reviewed event contracts admitted by the local egress boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Version-one governed tool-call decision/lifecycle metadata.
    McpToolDecision,
    /// Version-two part of an observed inventory, not a complete snapshot itself.
    McpInventorySnapshot,
}
impl EventKind {
    /// Exact supported set, in stable diagnostic order.
    pub const ALL: [Self; 2] = [Self::McpToolDecision, Self::McpInventorySnapshot];
    /// Fixed wire type name, never caller-provided text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::McpToolDecision => "mcp_tool_decision",
            Self::McpInventorySnapshot => "mcp_inventory_snapshot",
        }
    }
    /// Exact event schema version associated with this type.
    pub fn schema_version(self) -> u8 {
        match self {
            Self::McpToolDecision => 1,
            Self::McpInventorySnapshot => 2,
        }
    }
    /// Reviewed field paths for local inspectors, not event data.
    pub fn fields(self) -> &'static [&'static str] {
        match self {
            Self::McpToolDecision => EVENT_FIELDS,
            Self::McpInventorySnapshot => inventory::EVENT_FIELDS,
        }
    }
}
