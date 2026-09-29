//! Pure completeness checks over already validated parts from one enrollment.
//! Hosted storage must authenticate, isolate and deduplicate before this step.
use super::{CheckedPart, MAX_TOOLS, TOOLS_PER_PART, Tool};
use crate::SyncRef;
use std::{collections::BTreeSet, fmt};

/// Fixed assembly failures without any supplied identifier or source value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyError {
    /// At least one required part is missing. Never interpret absence as deletion.
    Incomplete,
    /// Parts disagree, repeat a part/event/tool or violate global reference order.
    Conflict,
    /// Too many parts were supplied; do not allocate an unbounded observation.
    Bounds,
}
impl fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "inventory observation is incomplete",
            Self::Conflict => "inventory observation contains conflicting parts",
            Self::Bounds => "inventory observation exceeds its part limit",
        })
    }
}
impl std::error::Error for AssemblyError {}

/// Complete validated observation of one server at one instant. Completeness is
/// not authentication, recency, current installation, health or granted access.
/// No generic serialization: callers deliberately project the facts they need.
pub struct CheckedSnapshot {
    runtime_ref: SyncRef,
    snapshot_ref: SyncRef,
    server_ref: SyncRef,
    occurred_at_ms: u64,
    tools_supported: bool,
    tools: Vec<Tool>,
}
impl CheckedSnapshot {
    /// Assemble exactly one part per index after authenticated enrollment-scoped
    /// storage has deduplicated retries. Parts may arrive out of order. Nothing is
    /// persisted, and incomplete or conflicting input never releases a snapshot.
    ///
    /// The caller must bind every part to the same authenticated enrollment and
    /// enforce retention/arrival limits. Opaque references are not that authority.
    pub fn from_parts(parts: &[CheckedPart]) -> Result<Self, AssemblyError> {
        if parts.len() > usize::from(MAX_TOOLS).div_ceil(TOOLS_PER_PART) {
            return Err(AssemblyError::Bounds);
        }
        let Some(first) = parts.first() else {
            return Err(AssemblyError::Incomplete);
        };
        let facts = first.facts();
        let mut ordered: Vec<_> = parts.iter().collect();
        ordered.sort_unstable_by_key(|part| part.facts().part_index);
        let mut indices = BTreeSet::new();
        let mut events = BTreeSet::new();
        let mut previous = None;
        for part in &ordered {
            let next = part.facts();
            if part.runtime_ref() != first.runtime_ref()
                || part.occurred_at_ms() != first.occurred_at_ms()
                || next.snapshot_ref != facts.snapshot_ref
                || next.server_ref != facts.server_ref
                || next.tools_supported != facts.tools_supported
                || next.tool_count != facts.tool_count
                || !indices.insert(next.part_index)
                || !events.insert(part.event_id())
            {
                return Err(AssemblyError::Conflict);
            }
            for tool in &next.tools {
                // Global opaque-reference order is fixed by the producer before
                // chunking. This also rejects repeats across separate parts.
                if previous.is_some_and(|prior| prior >= &tool.tool_ref) {
                    return Err(AssemblyError::Conflict);
                }
                previous = Some(&tool.tool_ref);
            }
        }
        if parts.len() != facts.part_count() {
            return Err(AssemblyError::Incomplete);
        }
        // Each part already has a valid index and its exact required length.
        // Distinct indices covering this count imply every required part exists.
        Ok(Self {
            runtime_ref: first.runtime_ref().clone(),
            snapshot_ref: facts.snapshot_ref.clone(),
            server_ref: facts.server_ref.clone(),
            occurred_at_ms: first.occurred_at_ms(),
            tools_supported: facts.tools_supported,
            tools: ordered
                .iter()
                .flat_map(|part| part.facts().tools.iter().cloned())
                .collect(),
        })
    }
    /// Observed runtime mapping, bound separately to authenticated enrollment.
    pub fn runtime_ref(&self) -> &SyncRef {
        &self.runtime_ref
    }
    /// Independent random identity of this complete observation.
    pub fn snapshot_ref(&self) -> &SyncRef {
        &self.snapshot_ref
    }
    /// Opaque enrollment-scoped mapping for the observed server.
    pub fn server_ref(&self) -> &SyncRef {
        &self.server_ref
    }
    /// Local observation time; receivers separately enforce arrival and retention.
    pub fn occurred_at_ms(&self) -> u64 {
        self.occurred_at_ms
    }
    /// Advertised capability; false and true with no tools are distinct facts.
    pub fn tools_supported(&self) -> bool {
        self.tools_supported
    }
    /// Complete reference-sorted observed tools. Absence describes this snapshot,
    /// not proof that the tool was uninstalled or never exists elsewhere.
    pub fn tools(&self) -> &[Tool] {
        &self.tools
    }
}
