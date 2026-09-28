//! Explicit, content-free local control administration and read-only diagnosis.
use crate::{
    args::{ControlAdmin, ControlsCommand},
    output,
};
use mitigate_fingerprint::Fingerprint;
use mitigate_policy::{
    SystemClock,
    controls::{Admission, Change, Context, ControlStore, Error, HistoryEntry, Snapshot, Target},
    read_document,
};
use serde::Serialize;
use std::{
    io::{self, Write},
    process::ExitCode,
};

#[derive(Serialize)]
#[serde(untagged)]
enum Report {
    Snapshot(Snapshot),
    History {
        schema_version: u32,
        changes: Vec<HistoryEntry>,
    },
    Preview {
        schema_version: u32,
        mode: &'static str,
        result: Admission,
    },
}
fn apply(admin: ControlAdmin, change: Change) -> Result<Report, Error> {
    let operator: Fingerprint =
        serde_json::from_value(serde_json::Value::String(admin.operator_ref))
            .map_err(|_| Error::Input)?;
    let mut store = ControlStore::open(&admin.db)?;
    Ok(Report::Snapshot(store.apply(
        change,
        operator,
        SystemClock,
    )?))
}
fn execute(command: ControlsCommand) -> Result<Report, Error> {
    match command {
        ControlsCommand::Init { db } => Ok(Report::Snapshot(ControlStore::create(&db)?.status()?)),
        ControlsCommand::Status { db } => Ok(Report::Snapshot(ControlStore::open(&db)?.status()?)),
        ControlsCommand::History { db } => Ok(Report::History {
            schema_version: 1,
            changes: ControlStore::open(&db)?.history()?,
        }),
        ControlsCommand::Stop(admin) => apply(admin, Change::Stop {}),
        ControlsCommand::Resume(admin) => apply(admin, Change::Resume {}),
        ControlsCommand::Apply { admin, change } => apply(
            admin,
            Change::from_bytes(&read_document(&change, 4096).map_err(|_| Error::Path)?)?,
        ),
        ControlsCommand::Test { db, context } => {
            let context =
                Context::from_bytes(&read_document(&context, 4096).map_err(|_| Error::Path)?)?;
            let mut store = ControlStore::open(&db)?;
            Ok(Report::Preview {
                schema_version: 1,
                mode: "preview",
                result: store.preview(&context, SystemClock)?,
            })
        }
    }
}
fn target(target: &Target) -> String {
    match target {
        Target::Global {} => "all calls".into(),
        Target::Client { reference } => format!("client {}", reference.as_str()),
        Target::Principal { reference } => format!("principal {}", reference.as_str()),
        Target::Agent { reference } => format!("agent {}", reference.as_str()),
        Target::Server { reference } => format!("server {}", reference.as_str()),
        Target::Tool { server, tool } => {
            format!("tool {} / server {}", tool.as_str(), server.as_str())
        }
    }
}
fn change(change: &Change) -> String {
    match change {
        Change::Stop {} => "Emergency stop enabled".into(),
        Change::Resume {} => "Emergency stop cleared".into(),
        Change::Disable { target: t } => format!("Disabled {}", target(t)),
        Change::Enable { target: t } => format!("Enabled {}", target(t)),
        Change::SetLimit { target: t, rate } => format!(
            "Limit {}: burst {}, refill {} per {} ms",
            target(t),
            rate.capacity,
            rate.refill_tokens,
            rate.period_ms
        ),
        Change::RemoveLimit { target: t } => format!("Removed limit for {}", target(t)),
    }
}
fn human(report: Report, out: &mut impl Write) -> io::Result<()> {
    match report {
        Report::Snapshot(s) => {
            writeln!(
                out,
                "Controls revision {}. Emergency stop: {}.",
                s.revision,
                if s.emergency_stop { "enabled" } else { "off" }
            )?;
            writeln!(
                out,
                "{} disabled targets. {} rate limits.",
                s.disabled.len(),
                s.limits.len()
            )?;
            for t in s.disabled {
                writeln!(out, "Disabled {}", target(&t))?;
            }
            for l in s.limits {
                writeln!(
                    out,
                    "{}: burst {}, refill {} per {} ms",
                    target(&l.target),
                    l.rate.capacity,
                    l.rate.refill_tokens,
                    l.rate.period_ms
                )?;
            }
        }
        Report::History { changes, .. } => {
            if changes.is_empty() {
                writeln!(out, "No control changes.")?;
            }
            for h in changes {
                writeln!(
                    out,
                    "Revision {} at {} Unix ms: {}. Declared local operator {}",
                    h.revision,
                    h.time_ms,
                    change(&h.change),
                    h.operator_ref.as_str()
                )?;
            }
        }
        Report::Preview { result, .. } => {
            match result {
                Admission::Allowed { revision } => writeln!(
                    out,
                    "Controls pass at revision {revision}. Other governance checks still apply."
                )?,
                Admission::Disabled {
                    emergency_stop,
                    targets,
                    revision,
                } => {
                    writeln!(
                        out,
                        "Disabled at revision {revision}. Emergency stop: {emergency_stop}."
                    )?;
                    for t in targets {
                        writeln!(out, "Disabled {}", target(&t))?;
                    }
                }
                Admission::RateLimited {
                    revision,
                    retry_after_ms,
                    targets,
                } => {
                    writeln!(
                        out,
                        "Rate limited at revision {revision}. Retry may be possible in {retry_after_ms} ms."
                    )?;
                    for t in targets {
                        writeln!(out, "Depleted {}", target(&t))?;
                    }
                }
            }
            writeln!(out, "Preview only. No quota consumed or tool invoked.")?;
        }
    }
    Ok(())
}
pub(crate) fn run(command: ControlsCommand, machine: bool) -> io::Result<ExitCode> {
    match execute(command) {
        Ok(report) => {
            if machine {
                output::json(&report, io::stdout().lock())?;
            } else {
                human(report, &mut io::stdout().lock())?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            output::error(error.code(), &error.to_string(), machine)?;
            Ok(ExitCode::from(2))
        }
    }
}
