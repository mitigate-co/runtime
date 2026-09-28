//! Presentation never prints raw upstream descriptions, schemas or error bodies.
use mitigate_mcp::{
    ChangeKind, SnapshotDiff,
    classification::{
        CapabilityClass, ClassificationSource, ClassifiedInventory, Confidence, RiskFlag,
    },
};
use mitigate_mcp_scan::{ConfigRisk, ScanReport, TransportKind};
use serde::Serialize;
use std::io::{self, Write};

pub(crate) fn json(value: &impl Serialize, mut output: impl Write) -> io::Result<()> {
    serde_json::to_writer(&mut output, value).map_err(io::Error::other)?;
    writeln!(output)
}

pub(crate) fn error(code: &'static str, message: &str, machine: bool) -> io::Result<()> {
    #[derive(Serialize)]
    struct Report<'a> {
        schema_version: u32,
        error: &'static str,
        message: &'a str,
    }
    if machine {
        json(
            &Report {
                schema_version: 1,
                error: code,
                message,
            },
            io::stderr().lock(),
        )
    } else {
        writeln!(io::stderr().lock(), "{code}: {message}")
    }
}

// ASCII escaping prevents control sequences, bidirectional text and invisible
// Unicode from disguising local labels in a terminal. JSON retains exact labels.
fn safe(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
fn cell(value: &str, width: usize) -> String {
    let value = safe(value);
    if value.len() > width {
        format!("{}...", &value[..width - 3])
    } else {
        value
    }
}
fn joined<T>(values: &[T], label: impl Fn(&T) -> &'static str) -> String {
    values.iter().map(label).collect::<Vec<_>>().join(", ")
}

fn capability(class: &CapabilityClass) -> &'static str {
    match class {
        CapabilityClass::ReadData => "Read data",
        CapabilityClass::WriteData => "Write data",
        CapabilityClass::DeleteData => "Delete data",
        CapabilityClass::ExecuteCode => "Execute code",
        CapabilityClass::CredentialAccess => "Access credentials",
        CapabilityClass::ExternalCommunication => "External communication",
        CapabilityClass::BrowserAction => "Browser actions",
        CapabilityClass::IdentityAdmin => "Manage identities",
        CapabilityClass::FinancialAction => "Financial actions",
        CapabilityClass::InfrastructureChange => "Change infrastructure",
        CapabilityClass::Unknown => "Unknown",
    }
}
fn flag(flag: &RiskFlag) -> &'static str {
    match flag {
        RiskFlag::Destructive => "Destructive",
        RiskFlag::CredentialAccess => "Credential access",
        RiskFlag::ArbitraryCodeExecution => "Code execution",
        RiskFlag::ExternalCommunication => "External communication",
        RiskFlag::IdentityAdmin => "Identity administration",
        RiskFlag::InfrastructureChange => "Infrastructure change",
        RiskFlag::UnknownHighImpact => "Unknown impact",
    }
}
fn source(source: &ClassificationSource) -> &'static str {
    match source {
        ClassificationSource::Deterministic => "Deterministic rules",
        ClassificationSource::Admin => "Administrator",
    }
}
fn confidence(value: Confidence) -> &'static str {
    match value {
        Confidence::Low => "Low",
        Confidence::Medium => "Medium",
        Confidence::High => "High (administrator declaration)",
    }
}
fn transport(value: TransportKind) -> &'static str {
    match value {
        TransportKind::Stdio => "stdio",
        TransportKind::Http => "HTTP",
        TransportKind::Sse => "SSE",
        TransportKind::Unknown => "Unresolved",
    }
}
fn config_risk(risk: &ConfigRisk) -> &'static str {
    match risk {
        ConfigRisk::PathLookup => {
            "Review executable resolution; use a trusted absolute path for inspection."
        }
        ConfigRisk::ShellWrapper => "Review the shell wrapper before execution.",
        ConfigRisk::BatchScript => {
            "Review the batch script; inspection requires a Windows executable."
        }
        ConfigRisk::VariableExpansion => {
            "Resolve client variables before creating a launch configuration."
        }
        ConfigRisk::UrlCredentials => "Move embedded URL credentials to a secure reference.",
        ConfigRisk::InsecureRemote => "Use HTTPS for remote servers.",
        ConfigRisk::InlineValues => "Review inline environment/header values for credentials.",
        ConfigRisk::EnvironmentFile => {
            "Review the referenced environment file; discovery did not open it."
        }
        ConfigRisk::HeaderHelper => "Review the header helper; discovery did not execute it.",
        ConfigRisk::UnreviewedOptions => {
            "Review additional client options outside this adapter's scope."
        }
        ConfigRisk::TransportUnresolved => {
            "Confirm the transport supported by this client and server."
        }
    }
}

pub(crate) fn scan(report: &ScanReport, details: bool, mut output: impl Write) -> io::Result<()> {
    let flagged = report
        .servers
        .iter()
        .filter(|s| !s.risks.is_empty())
        .count();
    writeln!(
        output,
        "{} server declaration(s); {flagged} need review. No servers started or contacted.",
        report.servers.len()
    )?;
    if report.servers.is_empty() {
        return writeln!(
            output,
            "Checked .mcp.json and .cursor/mcp.json. Use --root to choose another project."
        );
    }
    if !details {
        writeln!(
            output,
            "\n{:<24}  {:<18}  {:<10}  REVIEW",
            "SERVER", "SOURCE", "TRANSPORT"
        )?;
    }
    for server in &report.servers {
        if details {
            writeln!(output, "\n{}", safe(&server.server_name))?;
            writeln!(output, "  Source: {}", server.source_path)?;
            writeln!(output, "  Transport: {}", transport(server.transport))?;
            writeln!(
                output,
                "  Target: {}",
                safe(server.command_or_url.as_deref().unwrap_or("Unresolved"))
            )?;
            writeln!(
                output,
                "  Arguments: {} (values excluded)",
                server.argument_count
            )?;
            if let Some(package) = &server.package_name {
                writeln!(
                    output,
                    "  Declared package: {} ({})",
                    safe(package),
                    safe(
                        server
                            .package_version
                            .as_deref()
                            .unwrap_or("version unresolved")
                    )
                )?;
            }
            if server.risks.is_empty() {
                writeln!(
                    output,
                    "  No configuration flags. Server behavior has not been inspected."
                )?;
            }
            for risk in &server.risks {
                writeln!(output, "  - {}", config_risk(risk))?;
            }
        } else {
            writeln!(
                output,
                "{:<24}  {:<18}  {:<10}  {}",
                cell(&server.server_name, 24),
                server.source_path,
                transport(server.transport),
                server.risks.len()
            )?;
        }
    }
    if !details {
        writeln!(output, "\nUse --details for full labels and review steps.")?;
    }
    Ok(())
}

pub(crate) fn inspect(
    report: &ClassifiedInventory<'_>,
    details: bool,
    mut output: impl Write,
) -> io::Result<()> {
    let flagged = report
        .tools
        .iter()
        .filter(|t| !t.classification.flags.is_empty())
        .count();
    writeln!(
        output,
        "{} tool(s); {flagged} need review. MCP {}. No tools called.",
        report.tools.len(),
        safe(report.protocol_version)
    )?;
    if !report.tools_supported {
        return writeln!(output, "Server does not advertise tools.");
    }
    if report.tools.is_empty() {
        return writeln!(output, "The server returned an empty tool list.");
    }
    writeln!(
        output,
        "Capability hints require review; they do not grant access."
    )?;
    if details {
        writeln!(
            output,
            "Server: {} ({})",
            safe(report.server_name),
            safe(report.server_version)
        )?;
    } else {
        writeln!(output, "\n{:<24}  {:<26}  REVIEW", "TOOL", "CAPABILITIES")?;
    }
    for tool in &report.tools {
        let c = &tool.classification;
        let classes = joined(&c.classes, capability);
        let flags = if c.flags.is_empty() {
            "No flags".to_owned()
        } else {
            joined(&c.flags, flag)
        };
        if details {
            writeln!(output, "\n{}", safe(tool.name))?;
            writeln!(output, "  Capabilities: {classes}")?;
            writeln!(output, "  Review: {flags}")?;
            writeln!(
                output,
                "  Source: {}; confidence: {}",
                joined(&c.sources, source),
                confidence(c.confidence)
            )?;
            writeln!(output, "  Rules: {}", c.rules.join(", "))?;
            if c.overridden {
                writeln!(
                    output,
                    "  Original inference: {}",
                    joined(&c.inferred_classes, capability)
                )?;
            }
            writeln!(
                output,
                "  Input properties: {}; output schema: {}",
                tool.input_property_count,
                if tool.output_schema_present {
                    "present"
                } else {
                    "absent"
                }
            )?;
        } else {
            writeln!(
                output,
                "{:<24}  {:<26}  {}",
                cell(tool.name, 24),
                cell(&classes, 26),
                cell(&flags, 32)
            )?;
        }
    }
    if !details {
        writeln!(
            output,
            "\nUse --details for full labels, evidence and review flags."
        )?;
    }
    Ok(())
}

pub(crate) fn diff(report: &SnapshotDiff, mut output: impl Write) -> io::Result<()> {
    if report.is_empty() {
        return writeln!(output, "No changes.");
    }
    if report.server_identity_changed {
        writeln!(output, "Server identity changed.")?;
    }
    if report.server_facts_changed {
        writeln!(output, "Server facts changed.")?;
    }
    if report.tools_supported_changed {
        writeln!(output, "Tools capability changed.")?;
    }
    for tool in &report.tools {
        let fields = [
            (tool.identity_changed, "identity"),
            (tool.input_schema_changed, "input schema"),
            (tool.output_schema_changed, "output schema"),
            (tool.description_changed, "description"),
        ]
        .into_iter()
        .filter_map(|(changed, label)| changed.then_some(label))
        .collect::<Vec<_>>()
        .join(", ");
        let change = match tool.kind {
            ChangeKind::Added => "Added",
            ChangeKind::Removed => "Removed",
            ChangeKind::Changed => "Changed",
        };
        if fields.is_empty() {
            writeln!(output, "{change} {}", safe(&tool.name))?;
        } else {
            writeln!(output, "{change} {} ({fields})", safe(&tool.name))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mitigate_mcp::{Inventory, Tool, classification::ClassificationOverrides};
    use serde_json::json;
    #[test]
    fn terminal_cells_escape_control_bidi_unicode_and_bound_width() {
        let dangerous = "\u{1b}[31mhidden\n\u{202e}x\u{200b}long";
        let full = safe(dangerous);
        assert!(full.is_ascii());
        assert!(!full.contains('\n'));
        assert!(!full.contains('\u{1b}'));
        assert!(full.contains("\\u{202e}"));
        assert_eq!(cell(dangerous, 24).len(), 24);
        assert!(cell(dangerous, 24).ends_with("..."));
    }

    #[test]
    fn inspection_detail_is_readable_and_never_includes_definition_content() {
        let inventory = Inventory {
            protocol_version: "2025-11-25".into(),
            server_name: "fixture".into(),
            server_version: "1.0.0".into(),
            tools_supported: true,
            tools: vec![Tool {
                name: "delete_records".into(),
                description: Some("description-canary".into()),
                input_schema: json!({"type":"object","properties":{"secret-canary":{"type":"string","default":"value-canary"}},"additionalProperties":false}),
                output_schema: None,
            }],
        };
        let report = inventory
            .classify(&ClassificationOverrides::default())
            .unwrap();
        let mut rendered = Vec::new();
        inspect(&report, true, &mut rendered).unwrap();
        let text = String::from_utf8(rendered).unwrap();
        assert!(text.contains("Delete data"));
        assert!(text.contains("Destructive"));
        assert!(text.contains("Deterministic rules; confidence: Medium"));
        assert!(!text.contains("canary"));
        let mut encoded = Vec::new();
        super::json(&report, &mut encoded).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(
            value["tools"][0]["classification"]["sources"],
            json!(["deterministic"])
        );
        assert!(!String::from_utf8(encoded).unwrap().contains("canary"));
    }
}
