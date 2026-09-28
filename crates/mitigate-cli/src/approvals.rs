//! Local metadata review. No argument/result values enter the approval store.
use crate::{args::ApprovalsCommand, output};
use mitigate_fingerprint::Fingerprint;
use mitigate_policy::{
    SystemClock,
    approvals::{ApprovalStore, Binding, Choice, Error, Record, State},
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
    Created {
        schema_version: u32,
        action: &'static str,
    },
    Record(Box<Record>),
    List {
        schema_version: u32,
        records: Vec<Record>,
    },
}
fn reference(value: &str) -> Result<Fingerprint, Error> {
    serde_json::from_value(serde_json::Value::String(value.into())).map_err(|_| Error::Input)
}
fn execute(command: ApprovalsCommand) -> Result<Report, Error> {
    match command {
        ApprovalsCommand::Init { db } => {
            ApprovalStore::create(&db)?;
            Ok(Report::Created {
                schema_version: 1,
                action: "approval_store_created",
            })
        }
        ApprovalsCommand::Request {
            db,
            context,
            expires_in_seconds,
        } => {
            let binding =
                Binding::from_bytes(&read_document(&context, 4096).map_err(|_| Error::Path)?)?;
            let mut store = ApprovalStore::open(&db)?;
            Ok(Report::Record(Box::new(store.request(
                binding,
                SystemClock,
                u64::from(expires_in_seconds) * 1000,
            )?)))
        }
        ApprovalsCommand::List { db } => {
            let mut store = ApprovalStore::open(&db)?;
            Ok(Report::List {
                schema_version: 1,
                records: store.list(SystemClock)?,
            })
        }
        ApprovalsCommand::Show { db, reference: id } => {
            let id = reference(&id)?;
            let mut store = ApprovalStore::open(&db)?;
            Ok(Report::Record(Box::new(store.get(&id, SystemClock)?)))
        }
        ApprovalsCommand::Approve {
            db,
            reference: id,
            operator_ref,
            confirm: _,
        } => {
            let (id, operator) = (reference(&id)?, reference(&operator_ref)?);
            let mut store = ApprovalStore::open(&db)?;
            Ok(Report::Record(Box::new(store.decide(
                &id,
                Choice::Approve,
                operator,
                SystemClock,
            )?)))
        }
        ApprovalsCommand::Deny {
            db,
            reference: id,
            operator_ref,
            confirm: _,
        } => {
            let (id, operator) = (reference(&id)?, reference(&operator_ref)?);
            let mut store = ApprovalStore::open(&db)?;
            Ok(Report::Record(Box::new(store.decide(
                &id,
                Choice::Deny,
                operator,
                SystemClock,
            )?)))
        }
    }
}
fn state(state: State) -> &'static str {
    match state {
        State::Requested => "requested",
        State::Approved => "approved",
        State::Denied => "denied",
        State::Expired => "expired",
        State::Cancelled => "cancelled",
        State::Consumed => "consumed",
    }
}
fn display(record: &Record, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "{}  {}",
        record.approval_ref.as_str(),
        state(record.state)
    )?;
    writeln!(out, "  Client: {}", record.binding.client.as_str())?;
    writeln!(
        out,
        "  Principal: {}",
        record
            .binding
            .principal
            .as_ref()
            .map_or("unknown", Fingerprint::as_str)
    )?;
    writeln!(
        out,
        "  Agent: {}",
        record
            .binding
            .agent
            .as_ref()
            .map_or("unknown", Fingerprint::as_str)
    )?;
    writeln!(out, "  Server: {}", record.binding.server.as_str())?;
    writeln!(out, "  Tool: {}", record.binding.tool.as_str())?;
    writeln!(out, "  Session: {}", record.binding.session_ref.as_str())?;
    writeln!(out, "  Call: {}", record.binding.call_ref.as_str())?;
    writeln!(
        out,
        "  Schema: {}",
        record.binding.schema_fingerprint.as_str()
    )?;
    writeln!(
        out,
        "  Definition: {}",
        record.binding.definition_fingerprint.as_str()
    )?;
    writeln!(out, "  Policy: {}", record.binding.policy_ref.as_str())?;
    writeln!(
        out,
        "  Policy bundle: {}",
        record.binding.policy_bundle_hash.as_str()
    )?;
    writeln!(
        out,
        "  Environment: {}",
        record.binding.environment.as_deref().unwrap_or("unknown")
    )?;
    writeln!(
        out,
        "  Policy version: {}  Expires at (Unix ms): {}",
        record.binding.policy_version, record.expires_at_ms
    )?;
    // Only the closed taxonomy is formatted; no free-form tool labels/descriptions.
    writeln!(
        out,
        "  Capabilities: {}",
        serde_json::to_string(&record.binding.capabilities).map_err(io::Error::other)?
    )?;
    for decision in &record.decisions {
        writeln!(
            out,
            "  {} by declared local operator: {}",
            match decision.choice {
                Choice::Approve => "Approved",
                Choice::Deny => "Denied",
            },
            decision.operator_ref.as_str()
        )?;
    }
    Ok(())
}
pub(crate) fn run(command: ApprovalsCommand, machine: bool) -> io::Result<ExitCode> {
    match execute(command) {
        Ok(report) => {
            if machine {
                output::json(&report, io::stdout().lock())?;
            } else {
                let mut out = io::stdout().lock();
                match report {
                    Report::Created { .. } => writeln!(out, "Approval store created.")?,
                    Report::Record(record) => display(&record, &mut out)?,
                    Report::List { records, .. } => {
                        if records.is_empty() {
                            writeln!(out, "No approval requests.")?;
                        }
                        for record in &records {
                            writeln!(
                                out,
                                "{}  {}",
                                record.approval_ref.as_str(),
                                state(record.state)
                            )?;
                        }
                    }
                }
                writeln!(out, "No tool invoked.")?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            output::error(error.code(), &error.to_string(), machine)?;
            Ok(ExitCode::from(2))
        }
    }
}
