//! Explicit public-catalog lookup, separate from local authority and telemetry.
use crate::{args::RegistryCommand, output};
use mitigate_registry::{Catalog, Error, Freshness, Lookup};
use std::{
    io::{self, Write},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn run(command: RegistryCommand, machine: bool) -> io::Result<ExitCode> {
    let RegistryCommand::Lookup { catalog, subject } = command;
    let result = (|| -> Result<_, Error> {
        let catalog = Catalog::from_file(&catalog)?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Clock)?
                .as_millis(),
        )
        .map_err(|_| Error::Clock)?;
        // Finish validation before emitting anything. JSON escaping also keeps
        // user-selected public URL paths inert in terminals and machine output.
        let report = catalog.lookup(&subject, now)?;
        let mut bytes = Vec::new();
        if machine {
            output::json(&report, &mut bytes).map_err(|_| Error::Schema)?;
        } else {
            render(&report, &mut bytes).map_err(|_| Error::Schema)?;
        }
        Ok(bytes)
    })();
    match result {
        Ok(bytes) => {
            io::stdout().lock().write_all(&bytes)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            output::error("registry_lookup_failed", &error.to_string(), machine)?;
            Ok(ExitCode::from(2))
        }
    }
}

fn render(report: &Lookup<'_>, mut out: impl Write) -> io::Result<()> {
    let freshness = match report.freshness {
        Freshness::Current => "current",
        Freshness::Expired => "expired; obtain a current catalog",
        Freshness::Future => "future-dated; check the source and local clock",
    };
    writeln!(out, "Subject: {}\nCatalog: {freshness}", report.subject)?;
    writeln!(out, "Unsigned source claims. No access granted.")?;
    if !report.found {
        return writeln!(out, "No facts found. Safety is unknown.");
    }
    writeln!(
        out,
        "{} facts from {} sources:",
        report.facts.len(),
        report.sources.len()
    )?;
    for fact in &report.facts {
        let confidence = serde_json::to_string(&fact.confidence).map_err(io::Error::other)?;
        let assertion = serde_json::to_string(&fact.assertion).map_err(io::Error::other)?;
        writeln!(
            out,
            "{} | {} | confidence={} | observed_ms={}\n  {assertion}",
            fact.fact_ref, fact.source_ref, confidence, fact.observed_at_ms
        )?;
    }
    writeln!(out, "Sources:")?;
    for source in &report.sources {
        let url = serde_json::to_string(&source.url).map_err(io::Error::other)?;
        let kind = serde_json::to_string(&source.kind).map_err(io::Error::other)?;
        writeln!(
            out,
            "{} | {kind} | retrieved_ms={} | {url}",
            source.source_ref, source.retrieved_at_ms
        )?;
    }
    Ok(())
}
