//! Definition facts owned by the gateway. Raw schemas remain in the transport.
use mitigate_fingerprint::{Domain, Fingerprint, fingerprint};
use mitigate_gateway::Fault;
use mitigate_mcp::{
    Snapshot, StdioServer,
    classification::{
        CapabilityClass, ClassificationOverrides, ClassificationSource, Confidence, RiskFlag,
    },
};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct ToolFacts {
    pub tool: Fingerprint,
    pub schema: Fingerprint,
    pub definition: Fingerprint,
    pub capabilities: Vec<CapabilityClass>,
    pub risk_flags: Vec<RiskFlag>,
    pub classification_sources: Vec<ClassificationSource>,
    pub confidence: Confidence,
}

pub(super) fn bind(
    server: &StdioServer,
    snapshot: &Snapshot,
    overrides: &ClassificationOverrides,
) -> Result<(Fingerprint, BTreeMap<String, ToolFacts>), Fault> {
    let receipt = server
        .launch_receipt()
        .ok_or(Fault::GovernanceUnavailable)?;
    let inventory = server.inventory();
    let current = Snapshot::from_inventory(inventory).map_err(|_| Fault::Changed)?;
    if !snapshot
        .diff(&current)
        .map_err(|_| Fault::Changed)?
        .is_empty()
    {
        return Err(Fault::Changed);
    }
    let report = inventory.classify(overrides).map_err(|_| Fault::Changed)?;
    let mut facts = BTreeMap::new();
    for tool in &inventory.tools {
        let hash =
            |domain, value| fingerprint(domain, &value).map_err(|_| Fault::GovernanceUnavailable);
        let identity = hash(Domain::ToolIdentity, json!([receipt.launch_ref, tool.name]))?;
        let schema = hash(Domain::InputSchema, tool.input_schema.clone())?;
        let output = tool
            .output_schema
            .as_ref()
            .map(|s| hash(Domain::OutputSchema, s.clone()))
            .transpose()?;
        let description = tool
            .description
            .as_ref()
            .map(|s| {
                hash(
                    Domain::Description,
                    json!(s.split_whitespace().collect::<Vec<_>>().join(" ")),
                )
            })
            .transpose()?;
        let definition = hash(
            Domain::GovernedToolDefinition,
            json!({"tool":identity,"input_schema":schema,"output_schema":output,"description":description}),
        )?;
        let classification = &report
            .tools
            .iter()
            .find(|item| item.name == tool.name)
            .ok_or(Fault::GovernanceUnavailable)?
            .classification;
        facts.insert(
            tool.name.clone(),
            ToolFacts {
                tool: identity,
                schema,
                definition,
                capabilities: classification.classes.clone(),
                risk_flags: classification.flags.clone(),
                classification_sources: classification.sources.clone(),
                confidence: classification.confidence,
            },
        );
    }
    Ok((receipt.launch_ref.clone(), facts))
}
