//! Explicit enrollment orchestration; secrets use a bounded pipe or hidden prompt.
use crate::{args::EnrollmentCommand, hidden_input, output};
use mitigate_enrollment::{
    EnrollmentCode, PlatformOrigin, https,
    storage::{self, EnrollmentStore, Status},
};
use mitigate_secrets::Secret;
use serde::Serialize;
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::ExitCode,
};
use zeroize::Zeroizing;

#[derive(Serialize)]
struct Report {
    schema_version: u8,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrolled_at_ms: Option<u64>,
    sync_status: &'static str,
}
struct Failure {
    code: &'static str,
    message: String,
}
impl From<storage::Error> for Failure {
    fn from(error: storage::Error) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}
impl From<https::Error> for Failure {
    fn from(error: https::Error) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}
fn input_error() -> Failure {
    Failure {
        code: "enrollment_code",
        message: "Paste one complete enrollment code from your organization's Runtimes page."
            .to_owned(),
    }
}
impl From<hidden_input::Error> for Failure {
    fn from(error: hidden_input::Error) -> Self {
        let (code, message) = match error {
            hidden_input::Error::Cancelled => (
                "enrollment_cancelled",
                "Enrollment cancelled. No local enrollment was created.",
            ),
            hidden_input::Error::Unavailable => (
                "enrollment_terminal",
                "Hidden input is unavailable. Use a normal terminal or --stdin with a secure pipe.",
            ),
            hidden_input::Error::Restore => (
                "enrollment_terminal",
                "Terminal input could not be restored. Close this terminal and retry. No enrollment was created.",
            ),
            hidden_input::Error::Invalid => return input_error(),
        };
        Self {
            code,
            message: message.to_owned(),
        }
    }
}
fn origin(value: &str) -> Result<PlatformOrigin, Failure> {
    PlatformOrigin::parse(value).map_err(|_| Failure {
        code: "enrollment_origin",
        message: "Use the organization's canonical HTTPS Platform address, without a path or trailing slash.".to_owned(),
    })
}
fn read_code(reader: impl Read) -> Result<EnrollmentCode, Failure> {
    // 85 exact bytes plus an optional LF/CRLF and one overflow-detection byte.
    // Input and rejected bytes are zeroized; never trim general whitespace.
    let mut bytes = Zeroizing::new(Vec::with_capacity(88));
    reader
        .take(88)
        .read_to_end(&mut bytes)
        .map_err(|_| input_error())?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let secret = Secret::from_bytes(std::mem::take(&mut *bytes)).map_err(|_| input_error())?;
    EnrollmentCode::from_secret(secret).map_err(|_| input_error())
}
fn new_state(path: &Path) -> Result<(), Failure> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(storage::Error::Exists.into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(storage::Error::Path.into()),
    }
}
fn report(store: &EnrollmentStore) -> Report {
    let (status, enrolled_at_ms) = match store.status() {
        Status::Pending => ("pending", None),
        Status::Confirmed { enrolled_at_ms } => ("confirmed", Some(enrolled_at_ms)),
    };
    Report {
        schema_version: 2,
        status,
        runtime_ref: Some(store.identity().runtime_ref().as_str().to_owned()),
        enrollment_ref: Some(store.identity().enrollment_ref().as_str().to_owned()),
        enrolled_at_ms,
        sync_status: "not_checked",
    }
}
fn submit(store: EnrollmentStore) -> Result<Report, Failure> {
    // Keep the exclusive owner alive through the entire blocking exchange and
    // durable confirmation. Any error leaves recoverable state, never a new key.
    let claim = store.claim()?;
    let receipt = https::submit(&claim)?;
    drop(claim);
    let confirmed = store.confirm(receipt.as_bytes())?;
    Ok(report(&confirmed))
}
fn execute(command: EnrollmentCommand, machine: bool) -> Result<Report, Failure> {
    match command {
        EnrollmentCommand::Start {
            platform,
            state,
            stdin,
        } => {
            let origin = origin(&platform)?;
            new_state(&state)?;
            let code = if stdin {
                if io::stdin().is_terminal() {
                    return Err(input_error());
                }
                read_code(io::stdin().lock())?
            } else {
                if machine {
                    return Err(Failure {
                        code: "enrollment_code",
                        message: "Use --stdin with --json to read the code from a secure pipe."
                            .to_owned(),
                    });
                }
                EnrollmentCode::from_secret(hidden_input::enrollment_code()?)
                    .map_err(|_| input_error())?
            };
            submit(EnrollmentStore::create(&state, origin, code)?)
        }
        EnrollmentCommand::Retry { platform, state } => {
            let store = EnrollmentStore::open(&state, &origin(&platform)?)?;
            // Retrying a successfully persisted receipt is local and idempotent;
            // it never re-sends a used bootstrap code or asserts current access.
            if matches!(store.status(), Status::Confirmed { .. }) {
                Ok(report(&store))
            } else {
                submit(store)
            }
        }
        EnrollmentCommand::Status { platform, state } => {
            Ok(report(&EnrollmentStore::open(&state, &origin(&platform)?)?))
        }
        EnrollmentCommand::Forget {
            platform,
            state,
            confirm: _,
        } => {
            EnrollmentStore::forget(&state, &origin(&platform)?)?;
            Ok(Report {
                schema_version: 2,
                status: "forgotten",
                runtime_ref: None,
                enrollment_ref: None,
                enrolled_at_ms: None,
                sync_status: "not_checked",
            })
        }
    }
}
pub(crate) fn run(command: EnrollmentCommand, machine: bool) -> io::Result<ExitCode> {
    match execute(command, machine) {
        Ok(report) => {
            if machine {
                output::json(&report, io::stdout().lock())?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "{}",
                    match report.status {
                        "confirmed" =>
                            "Enrollment confirmed locally. Use sync status to check optional delivery.",
                        "pending" =>
                            "Enrollment pending. Run enroll retry with the same Platform and state file.",
                        _ =>
                            "Local enrollment credential deleted. Revoke the Runtime in your organization's Runtimes page. The state file is retained.",
                    }
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            output::error(error.code, &error.message, machine)?;
            Ok(ExitCode::from(2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pipe_input_accepts_only_one_bounded_code_without_echoing_bad_input() {
        let valid = format!(
            "mcp1:00000000-0000-4000-8000-000000000001:{}",
            "A".repeat(43)
        );
        for suffix in ["", "\n", "\r\n"] {
            assert!(read_code(format!("{valid}{suffix}").as_bytes()).is_ok());
        }
        for invalid in [
            format!(" {valid}"),
            format!("{valid} "),
            format!("{valid}\n\n"),
            format!("{valid}\r"),
            "secret-canary".repeat(1000),
        ] {
            let error = read_code(invalid.as_bytes()).err().unwrap();
            assert_eq!(error.code, "enrollment_code");
            assert!(!error.message.contains("canary"));
        }
        let mut input = io::Cursor::new(vec![b'A'; 10000]);
        assert!(read_code(&mut input).is_err());
        assert_eq!(input.position(), 88);
    }
}
