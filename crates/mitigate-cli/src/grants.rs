//! Explicit local grant diagnostics. No caller facts or scope values are printed.
use crate::{args::GrantsCommand, output};
use mitigate_policy::grants::{self, GrantContext, GrantResolution, GrantSet, Reason};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

#[derive(Serialize)]
#[serde(untagged)]
enum Report {
    Valid {
        schema_version: u32,
        valid: bool,
        rules: usize,
    },
    Resolution(GrantResolution),
}
enum Failure {
    File,
    Grant(grants::Error),
}
impl From<grants::Error> for Failure {
    fn from(error: grants::Error) -> Self {
        Self::Grant(error)
    }
}
fn read(path: &Path, max: usize) -> Result<Vec<u8>, Failure> {
    mitigate_policy::read_document(path, max).map_err(|_| Failure::File)
}
fn execute(command: GrantsCommand) -> Result<Report, Failure> {
    let (path, input) = match command {
        GrantsCommand::Check { rules } => (rules, None),
        GrantsCommand::Test { rules, input } => (rules, Some(input)),
    };
    let rules = GrantSet::from_bytes(&read(&path, grants::MAX_DOCUMENT)?)?;
    match input {
        None => Ok(Report::Valid {
            schema_version: 1,
            valid: true,
            rules: rules.len(),
        }),
        Some(path) => {
            let input = GrantContext::from_bytes(&read(&path, 4096)?)?;
            Ok(Report::Resolution(rules.evaluate(&input)?))
        }
    }
}
pub(crate) fn run(command: GrantsCommand, machine: bool) -> io::Result<ExitCode> {
    match execute(command) {
        Ok(report) => {
            if machine {
                output::json(&report, io::stdout().lock())?;
            } else {
                let mut out = io::stdout().lock();
                match report {
                    Report::Valid { rules, .. } => {
                        writeln!(out, "Grants valid: {rules} rules. No servers started.")?
                    }
                    Report::Resolution(resolution) => writeln!(
                        out,
                        "{}. No tool invoked.",
                        match resolution.reason() {
                            Reason::ExplicitAllow =>
                                "Grant matched; policy and approval checks still apply",
                            Reason::ExplicitDeny => "Denied by an explicit grant rule",
                            Reason::UnknownClient => "No grant: client identity is unknown",
                            Reason::NoMatchingGrant => "No matching grant",
                        }
                    )?,
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            match error {
                Failure::File => output::error(
                    "grant_file_unavailable",
                    "Cannot read the grant file. Check its type, size and permissions.",
                    machine,
                )?,
                Failure::Grant(error) => output::error(error.code(), &error.to_string(), machine)?,
            }
            Ok(ExitCode::from(2))
        }
    }
}
