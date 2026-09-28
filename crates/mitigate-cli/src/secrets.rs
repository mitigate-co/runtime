//! Explicit local management. Values never appear in argv, output or diagnostics.
use crate::{args::SecretsCommand, output};
use mitigate_secrets::{Error, NativeStore, Secret, SecretRef, SecretStore};
use serde::Serialize;
use std::{
    io::{self, IsTerminal, Write},
    process::ExitCode,
    time::Duration,
};

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    action: &'static str,
    secret_ref: String,
}
enum Operation {
    Import(Secret),
    Replace(Secret),
    Check,
    Delete,
}
fn read_input() -> Result<Secret, Error> {
    if io::stdin().is_terminal() {
        return Err(Error::InvalidValue);
    }
    Secret::from_reader(io::stdin().lock())
}
pub(crate) fn run(command: SecretsCommand, machine: bool) -> io::Result<ExitCode> {
    // Input validation and pipe reading precede any store mutation.
    let prepared = match command {
        SecretsCommand::Import { stdin: _ } => {
            SecretRef::generate().and_then(|r| Ok((r, Operation::Import(read_input()?))))
        }
        SecretsCommand::Replace {
            reference,
            stdin: _,
        } => SecretRef::parse(&reference).and_then(|r| Ok((r, Operation::Replace(read_input()?)))),
        SecretsCommand::Check { reference } => {
            SecretRef::parse(&reference).map(|r| (r, Operation::Check))
        }
        SecretsCommand::Delete {
            reference,
            confirm: _,
        } => SecretRef::parse(&reference).map(|r| (r, Operation::Delete)),
    };
    let result = prepared.and_then(|(reference, operation)| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .map_err(|_| Error::Unavailable)?;
        let result = runtime.block_on(async {
            let action = match operation {
                Operation::Import(value) => {
                    // Refuse the astronomically unlikely reference collision.
                    match NativeStore.read(&reference).await {
                        Err(Error::Missing) => (),
                        _ => return Err(Error::Unavailable),
                    }
                    NativeStore.put(&reference, value).await?;
                    "imported"
                }
                Operation::Replace(value) => {
                    drop(NativeStore.read(&reference).await?);
                    NativeStore.put(&reference, value).await?;
                    "replaced"
                }
                Operation::Check => {
                    drop(NativeStore.read(&reference).await?);
                    "available"
                }
                Operation::Delete => {
                    NativeStore.delete(&reference).await?;
                    "deleted"
                }
            };
            Ok(Report {
                schema_version: 1,
                action,
                secret_ref: reference.as_str().to_owned(),
            })
        });
        runtime.shutdown_timeout(Duration::from_millis(50));
        result
    });
    match result {
        Ok(report) => {
            if machine {
                output::json(&report, io::stdout().lock())?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "Credential {}. Reference: {}",
                    report.action,
                    report.secret_ref
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            output::error(error.code(), &error.to_string(), machine)?;
            Ok(ExitCode::from(2))
        }
    }
}
