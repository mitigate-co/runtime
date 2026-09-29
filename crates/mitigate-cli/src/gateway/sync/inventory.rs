//! One bounded observation, projected only after fresh listing and durable audit.
//! The worker maps local digests in small batches and never holds an owner across
//! channel waits. Partial admission stays partial; failures never renew consent.
use super::{
    InventoryPermit, Status,
    capture::{capability, local_key},
};
use crate::gateway::facts::ToolFacts;
use mitigate_egress::{
    Capability, CheckedEvent, SyncRef,
    inventory::{
        CheckedPart, ClassificationSource, Confidence, Facts, MAX_TOOLS, RiskFlag, TOOLS_PER_PART,
        Tool,
    },
    outbox::Admission,
    references::{Kind, LocalKey},
};
use mitigate_enrollment::storage::sync::CaptureSession;
use mitigate_fingerprint::Fingerprint;
use mitigate_mcp::classification as local;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
mod tests;

// Neither local keys nor this projection have Debug/Serialize/Deserialize. No
// tool name, definition, rule match or arbitrary string can enter the channel.
struct Classification {
    capabilities: Vec<Capability>,
    risk_flags: Vec<RiskFlag>,
    sources: Vec<ClassificationSource>,
    confidence: Confidence,
}
impl Classification {
    fn from_tool(tool: &ToolFacts) -> Option<Self> {
        if tool.capabilities.is_empty()
            || tool.capabilities.len() > 11
            || tool.risk_flags.len() > 7
            || tool.classification_sources.len() > 2
        {
            return None;
        }
        Some(Self {
            capabilities: tool.capabilities.iter().map(capability).collect(),
            risk_flags: tool
                .risk_flags
                .iter()
                .map(|value| match value {
                    local::RiskFlag::Destructive => RiskFlag::Destructive,
                    local::RiskFlag::CredentialAccess => RiskFlag::CredentialAccess,
                    local::RiskFlag::ArbitraryCodeExecution => RiskFlag::ArbitraryCodeExecution,
                    local::RiskFlag::ExternalCommunication => RiskFlag::ExternalCommunication,
                    local::RiskFlag::IdentityAdmin => RiskFlag::IdentityAdmin,
                    local::RiskFlag::InfrastructureChange => RiskFlag::InfrastructureChange,
                    local::RiskFlag::UnknownHighImpact => RiskFlag::UnknownHighImpact,
                })
                .collect(),
            sources: tool
                .classification_sources
                .iter()
                .map(|value| match value {
                    local::ClassificationSource::Deterministic => {
                        ClassificationSource::Deterministic
                    }
                    local::ClassificationSource::Admin => ClassificationSource::Admin,
                })
                .collect(),
            confidence: match tool.confidence {
                local::Confidence::Low => Confidence::Low,
                local::Confidence::Medium => Confidence::Medium,
                local::Confidence::High => Confidence::High,
            },
        })
    }
}

pub(in crate::gateway) struct InventoryCapture {
    ticket: InventoryPermit,
    keys: Vec<LocalKey>,
    mapped: Vec<SyncRef>,
    classifications: Vec<Classification>,
    tools: Option<Vec<Tool>>,
    snapshot: SyncRef,
    time_ms: u64,
    supported: bool,
    part: usize,
}
impl InventoryCapture {
    pub(super) fn new<'a>(
        ticket: InventoryPermit,
        server: &Fingerprint,
        tools: impl ExactSizeIterator<Item = &'a ToolFacts>,
        supported: bool,
        time_ms: u64,
    ) -> Option<Self> {
        let count = tools.len();
        if count > usize::from(MAX_TOOLS) || (!supported && count != 0) {
            return None;
        }
        let mut keys = Vec::with_capacity(1 + count * 2);
        keys.push(local_key(Kind::Server, server)?);
        let mut classifications = Vec::with_capacity(count);
        for tool in tools {
            keys.push(local_key(Kind::Tool, &tool.tool)?);
            // Inventory revisions cover input/output/description plus identity.
            // Decision v1 schema_ref remains the input-schema mapping unchanged.
            keys.push(local_key(Kind::Schema, &tool.definition)?);
            classifications.push(Classification::from_tool(tool)?);
        }
        Some(Self {
            ticket,
            keys,
            classifications,
            mapped: Vec::with_capacity(1 + count * 2),
            tools: None,
            snapshot: SyncRef::fresh().ok()?,
            time_ms,
            supported,
            part: 0,
        })
    }

    fn bind(&mut self) -> Option<()> {
        if self.mapped.len() != self.keys.len() {
            return None;
        }
        let mut tools = Vec::with_capacity(self.classifications.len());
        for (index, facts) in self.classifications.drain(..).enumerate() {
            tools.push(Tool {
                tool_ref: self.mapped[1 + index * 2].clone(),
                schema_ref: self.mapped[2 + index * 2].clone(),
                capabilities: facts.capabilities,
                risk_flags: facts.risk_flags,
                classification_sources: facts.sources,
                confidence: facts.confidence,
            });
        }
        tools.sort_unstable_by(|a, b| a.tool_ref.cmp(&b.tool_ref));
        if tools
            .windows(2)
            .any(|pair| pair[0].tool_ref == pair[1].tool_ref)
        {
            return None;
        }
        self.tools = Some(tools);
        Some(())
    }

    fn event(&self, runtime: SyncRef) -> Option<CheckedEvent> {
        let tools = self.tools.as_ref()?;
        let start = self.part * TOOLS_PER_PART;
        let end = (start + TOOLS_PER_PART).min(tools.len());
        let part = CheckedPart::new(
            SyncRef::fresh().ok()?,
            runtime,
            self.time_ms,
            Facts {
                snapshot_ref: self.snapshot.clone(),
                server_ref: self.mapped.first()?.clone(),
                tools_supported: self.supported,
                tool_count: tools.len().try_into().ok()?,
                part_index: self.part.try_into().ok()?,
                tools: tools.get(start..end)?.to_vec(),
            },
        )
        .ok()?;
        Some(CheckedEvent::inventory(part))
    }

    /// At most 16 mapped keys OR one admitted part per ownership interval.
    /// Return ownership only when safe to continue under the original permit.
    pub(super) fn advance(
        mut self,
        session: &mut CaptureSession,
        stopped: &AtomicBool,
    ) -> (Status, Option<Self>) {
        if stopped.load(Ordering::Acquire) {
            return (Status::Dropped, None);
        }
        if self.mapped.len() < self.keys.len() {
            let start = self.mapped.len();
            let end = (start + 16).min(self.keys.len());
            match session.resolve(&self.ticket.permit, &self.keys[start..end]) {
                Ok(Some(mapped)) if mapped.len() == end - start => self.mapped.extend(mapped),
                Ok(None) => return (Status::Paused, None),
                _ => return (Status::Dropped, None),
            }
            if self.mapped.len() == self.keys.len() && self.bind().is_none() {
                return (Status::Dropped, None);
            }
            return (Status::Ready, Some(self));
        }
        let Some(event) = self.event(session.runtime_ref().clone()) else {
            return (Status::Dropped, None);
        };
        match session.admit(&self.ticket.permit, &event) {
            Ok(Admission::Queued | Admission::Duplicate) => {
                self.part += 1;
                let count = self
                    .tools
                    .as_ref()
                    .map_or(0, Vec::len)
                    .div_ceil(TOOLS_PER_PART)
                    .max(1);
                (Status::Ready, (self.part < count).then_some(self))
            }
            Ok(Admission::Paused | Admission::ConsentChanged) => (Status::Paused, None),
            _ => (Status::Dropped, None),
        }
    }
}
