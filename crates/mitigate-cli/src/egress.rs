//! Local privacy/operator reports. No sender, input payload import or store mutation.
use crate::{
    args::{EgressCommand, PrivacyCommand},
    output,
};
use mitigate_egress::{
    EVENT_FIELDS, MAX_EVENT_BYTES, SyncRef,
    outbox::{Action, Error, Outbox, Partition, Report as QueueReport},
    self_test,
};
use serde::Serialize;
use std::{
    io::{self, Write},
    process::ExitCode,
};

#[derive(Serialize)]
struct EventContract {
    event_type: &'static str,
    schema_version: u8,
    fields: &'static [&'static str],
    max_event_bytes: usize,
}
#[derive(Serialize)]
struct Inspection {
    schema_version: u8,
    delivery_status: &'static str,
    destination: Option<&'static str>,
    supported_events: Vec<EventContract>,
    observed_event_types: Vec<&'static str>,
    observed_schema_versions: Vec<u8>,
    queue: Option<QueueReport>,
}
fn reference(text: Option<String>) -> Result<SyncRef, Error> {
    serde_json::from_value(serde_json::Value::String(text.ok_or(Error::Input)?))
        .map_err(|_| Error::Input)
}
pub(crate) fn inspect(command: EgressCommand, machine: bool) -> io::Result<ExitCode> {
    let EgressCommand::Inspect {
        db,
        runtime_ref,
        enrollment_ref,
    } = command;
    let result = (|| -> Result<Inspection, Error> {
        let queue = match db {
            Some(path) => Some(Outbox::inspect_file(
                &path,
                Partition {
                    runtime_ref: reference(runtime_ref)?,
                    enrollment_ref: reference(enrollment_ref)?,
                },
            )?),
            None if runtime_ref.is_none() && enrollment_ref.is_none() => None,
            None => return Err(Error::Input),
        };
        let observed = queue.as_ref().is_some_and(|q| {
            q.pending > 0
                || q.counters
                    .iter()
                    .any(|c| c.action == Action::Queued && c.totals.events > 0)
        });
        Ok(Inspection {
            schema_version: 1,
            delivery_status: "not_configured",
            destination: None,
            supported_events: vec![EventContract {
                event_type: "mcp_tool_decision",
                schema_version: 1,
                fields: EVENT_FIELDS,
                max_event_bytes: MAX_EVENT_BYTES,
            }],
            observed_event_types: if observed {
                vec!["mcp_tool_decision"]
            } else {
                Vec::new()
            },
            observed_schema_versions: if observed { vec![1] } else { Vec::new() },
            queue,
        })
    })();
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            output::error("egress_inspection_failed", &error.to_string(), machine)?;
            return Ok(ExitCode::from(2));
        }
    };
    if machine {
        output::json(&report, io::stdout().lock())?;
    } else {
        render(&report, io::stdout().lock())?;
    }
    Ok(ExitCode::SUCCESS)
}
fn render(report: &Inspection, mut out: impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Destination: not configured. This build has no Platform sender."
    )?;
    writeln!(
        out,
        "Supported event: mcp_tool_decision v1 (maximum {MAX_EVENT_BYTES} bytes)."
    )?;
    writeln!(out, "Fields: {}", EVENT_FIELDS.join(", "))?;
    let Some(queue) = &report.queue else {
        return writeln!(
            out,
            "No queue selected. Use --db, --runtime-ref and --enrollment-ref to inspect retained counts."
        );
    };
    writeln!(
        out,
        "Runtime: {}\nEnrollment: {}",
        queue.partition.runtime_ref.as_str(),
        queue.partition.enrollment_ref.as_str()
    )?;
    writeln!(
        out,
        "Queue: {}. Retained: {} events, {} bytes, {} leases, {} receipts.",
        if queue.paused { "paused" } else { "accepting" },
        queue.pending,
        queue.payload_bytes,
        queue.leased,
        queue.receipts
    )?;
    writeln!(
        out,
        "Limits: {} events, {} ms. Expiry is applied by the worker, not this read-only report.",
        queue.limits.max_events, queue.limits.max_age_ms
    )?;
    writeln!(
        out,
        "Observed schema versions: {}.",
        if report.observed_schema_versions.is_empty() {
            "none"
        } else {
            "1"
        }
    )?;
    writeln!(out, "ACTION  EVENTS  BYTES")?;
    // These are closed enums/numbers from verified state, never event strings.
    let value = serde_json::to_value(&queue.counters).map_err(io::Error::other)?;
    for counter in value
        .as_array()
        .ok_or_else(|| io::Error::other("invalid report"))?
    {
        writeln!(
            out,
            "{}  {}  {}",
            counter["action"].as_str().unwrap_or(""),
            counter["totals"]["events"],
            counter["totals"]["bytes"]
        )?;
    }
    writeln!(
        out,
        "Recent decisions: {}. Use --json for the bounded journal.",
        queue.recent.len()
    )
}

pub(crate) fn privacy(command: PrivacyCommand, machine: bool) -> io::Result<ExitCode> {
    let PrivacyCommand::SelfTest { work_dir } = command;
    let parent = work_dir.unwrap_or_else(std::env::temp_dir);
    let report = match self_test::run(&parent) {
        Ok(report) => report,
        Err(error) => {
            output::error("privacy_test_unavailable", &error.to_string(), machine)?;
            return Ok(ExitCode::from(2));
        }
    };
    if machine {
        output::json(&report, io::stdout().lock())?;
    } else {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "Privacy self-test: {}. No network requests.",
            if report.passed { "passed" } else { "FAILED" }
        )?;
        for check in &report.checks {
            writeln!(
                out,
                "{}: {}/{} rejected",
                check.category, check.rejected, check.attempted
            )?;
        }
        if !report.passed {
            writeln!(
                out,
                "Keep optional synchronization disabled; inspect the failed checks."
            )?;
        }
    }
    Ok(if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}
