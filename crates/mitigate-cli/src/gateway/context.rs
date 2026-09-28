//! Inspect exactly the local facts used by enforcement, without needing grants
//! to exist yet. No authority mutation, tool call or sensitive definition export.
use super::{facts, profile};
use crate::output;
use mitigate_audit::{Attribution, EventDetails, Operation};
use mitigate_fingerprint::Fingerprint;
use mitigate_gateway::CallerIdentity;
use mitigate_mcp::{
    Error, LaunchConfig, LaunchReview, Snapshot, StdioServer,
    classification::{CapabilityClass, ClassificationOverrides},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
    time::Duration,
};

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    client_ref: Option<Fingerprint>,
    principal_ref: Option<Fingerprint>,
    agent_ref: Option<Fingerprint>,
    attribution: Attribution,
    server_ref: Fingerprint,
    tools: Vec<Tool>,
}
#[derive(Serialize)]
struct Tool {
    name: String,
    tool_ref: Fingerprint,
    schema_fingerprint: Fingerprint,
    definition_fingerprint: Fingerprint,
    capability_classes: Vec<CapabilityClass>,
}
impl Report {
    fn from_server(
        server: &StdioServer,
        snapshot: &Snapshot,
        overrides: &ClassificationOverrides,
        caller: &CallerIdentity,
    ) -> Result<Self, Error> {
        let (server_ref, tools) =
            facts::bind(server, snapshot, overrides).map_err(|_| Error::Changed)?;
        let identity = EventDetails::new(caller, server_ref.clone(), Operation::Inventory);
        Ok(Self {
            schema_version: 1,
            client_ref: identity.client_ref,
            principal_ref: identity.principal_ref,
            agent_ref: identity.agent_ref,
            attribution: identity.attribution,
            server_ref,
            tools: tools
                .into_iter()
                .map(|(name, facts)| Tool {
                    name,
                    tool_ref: facts.tool,
                    schema_fingerprint: facts.schema,
                    definition_fingerprint: facts.definition,
                    capability_classes: facts.capabilities,
                })
                .collect(),
        })
    }
    fn human(&self, mut out: impl Write) -> io::Result<()> {
        writeln!(out, "Local governance references")?;
        writeln!(
            out,
            "Attribution: {}",
            match self.attribution {
                Attribution::Unknown => "unknown",
                Attribution::DeclaredProfile => "declared profile",
            }
        )?;
        for (label, reference) in [
            ("Client", &self.client_ref),
            ("Principal", &self.principal_ref),
            ("Agent", &self.agent_ref),
        ] {
            writeln!(
                out,
                "{label}: {}",
                reference.as_ref().map_or("unknown", Fingerprint::as_str)
            )?;
        }
        writeln!(out, "Server: {}", self.server_ref.as_str())?;
        writeln!(out, "Tools: {}", self.tools.len())?;
        for tool in &self.tools {
            writeln!(out, "\n{}", tool.name)?;
            writeln!(out, "  Tool: {}", tool.tool_ref.as_str())?;
            writeln!(out, "  Input schema: {}", tool.schema_fingerprint.as_str())?;
            writeln!(
                out,
                "  Definition: {}",
                tool.definition_fingerprint.as_str()
            )?;
            write!(out, "  Capabilities: ")?;
            output::json(&tool.capability_classes, &mut out)?;
        }
        writeln!(out, "\nNo grants changed. No tools called.")
    }
}

pub(crate) fn run(
    launch: &Path,
    review: &Path,
    snapshot: &Path,
    profile_path: Option<&Path>,
    overrides_path: Option<&Path>,
    machine: bool,
) -> io::Result<ExitCode> {
    let caller = match profile(profile_path) {
        Ok(caller) => caller,
        Err(error) => {
            output::error("gateway_profile_invalid", &error.to_string(), machine)?;
            return Ok(ExitCode::from(2));
        }
    };
    let inspect = || -> Result<Report, Error> {
        let config = LaunchConfig::from_file(launch)?;
        let review = LaunchReview::from_file(review)?;
        let snapshot = Snapshot::from_file(snapshot)?;
        let overrides = overrides_path
            .map(ClassificationOverrides::from_file)
            .transpose()?
            .unwrap_or_default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Launch)?;
        let result = runtime.block_on(async {
            let mut server = StdioServer::connect_reviewed_with_shutdown(&config, &review, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
            let report = Report::from_server(&server, &snapshot, &overrides, &caller);
            // Even stale definitions require confirmed cleanup before any output.
            server.close().await?;
            report
        });
        runtime.shutdown_timeout(Duration::from_millis(50));
        result
    };
    let report = match inspect() {
        Ok(report) => report,
        Err(error) => return crate::mcp_error(error, machine),
    };
    if machine {
        output::json(&report, io::stdout().lock())?;
    } else {
        report.human(io::stdout().lock())?;
    }
    Ok(ExitCode::SUCCESS)
}
