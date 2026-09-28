//! Explicit local audit management. No arbitrary SQL or event import command.
use crate::{args::AuditCommand, output};
use mitigate_audit::{AuditStore, Error, Retention};
use serde::Serialize;
use std::{
    io::{self, Write},
    process::ExitCode,
};

pub(crate) fn run(command: AuditCommand, machine: bool) -> io::Result<ExitCode> {
    // Construct the complete verified response before touching stdout.
    let result = (|| -> Result<serde_json::Value, Error> {
        match command {
            AuditCommand::Init {
                db,
                max_records,
                max_age_days,
                max_payload_bytes,
            } => {
                let mut store = AuditStore::create(
                    &db,
                    Retention {
                        max_records,
                        max_age_seconds: u64::from(max_age_days) * 86_400,
                        max_payload_bytes,
                    },
                )?;
                encode(&store.verify()?)
            }
            AuditCommand::Verify { db } => encode(&AuditStore::open(&db)?.verify()?),
            AuditCommand::List { db, after, limit } => {
                encode(&AuditStore::open(&db)?.page(after, limit)?)
            }
            AuditCommand::Prune { db, confirm: _ } => {
                let mut store = AuditStore::open(&db)?;
                let removed = store.prune()?;
                let verified = store.verify()?;
                Ok(
                    serde_json::json!({"schema_version":1,"removed_records":removed,"verification":verified}),
                )
            }
        }
    })();
    match result {
        Ok(value) => {
            if machine {
                output::json(&value, io::stdout().lock())?;
            } else {
                let mut out = io::stdout().lock();
                if let Some(rows) = value["records"].as_array() {
                    writeln!(out, "SEQUENCE  TIME (UNIX MS)  OPERATION  DECISION  RESULT")?;
                    for row in rows {
                        let event = &row["event"];
                        let detail = &event["detail"];
                        writeln!(
                            out,
                            "{}  {}  {}  {}  {}",
                            row["sequence"],
                            event["time_ms"],
                            detail["operation"].as_str().unwrap_or(""),
                            detail["decision"].as_str().unwrap_or(""),
                            detail["result_class"].as_str().unwrap_or("")
                        )?;
                    }
                    if rows.is_empty() {
                        writeln!(out, "No retained events.")?;
                    }
                    writeln!(
                        out,
                        "Retention checkpoint: {}. Tail: {}.",
                        value["anchor_sequence"], value["head_sequence"]
                    )?;
                    if let Some(after) = value["next_after"].as_u64() {
                        writeln!(out, "Next page: repeat with --after {after}.")?;
                    }
                } else {
                    let report = if value.get("verification").is_some() {
                        &value["verification"]
                    } else {
                        &value
                    };
                    if let Some(removed) = value["removed_records"].as_u64() {
                        writeln!(out, "Removed {removed} expired records.")?;
                    }
                    writeln!(
                        out,
                        "Audit verified: {} records, {} event bytes. Retention checkpoint: {}. Tail: {}.",
                        report["records"],
                        report["payload_bytes"],
                        report["anchor_sequence"],
                        report["head_sequence"]
                    )?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            output::error(error.code(), &error.to_string(), machine)?;
            Ok(ExitCode::from(2))
        }
    }
}
fn encode(value: &impl Serialize) -> Result<serde_json::Value, Error> {
    serde_json::to_value(value).map_err(|_| Error::Unavailable)
}
