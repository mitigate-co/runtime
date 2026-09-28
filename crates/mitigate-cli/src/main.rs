//! CLI composition: explicit local actions with content-free operational errors.
mod args;
mod gateway;
mod output;

use args::{Cli, Command, ConfigCommand, McpCommand};
use clap::{Parser, error::ErrorKind};
use mitigate_config::{CONFIG_SCHEMA_VERSION, RuntimeConfig};
use mitigate_mcp::{Snapshot, classification::ClassificationOverrides};
use serde::Serialize;
use std::{
    io::{self, Write},
    process::ExitCode,
};

#[derive(Serialize)]
struct VersionReport {
    schema_version: u32,
    product: &'static str,
    version: &'static str,
    config_schema_version: u32,
}
#[derive(Serialize)]
struct ConfigReport {
    schema_version: u32,
    valid: bool,
    config: RuntimeConfig,
}

fn mcp_error(error: mitigate_mcp::Error, machine: bool) -> io::Result<ExitCode> {
    output::error(error.code(), &error.to_string(), machine)?;
    Ok(ExitCode::from(2))
}
fn findings_exit(found: bool, fail: bool) -> ExitCode {
    if found && fail {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}

fn execute(cli: Cli) -> io::Result<ExitCode> {
    match cli.command {
        Command::Mcp {
            command:
                McpCommand::Serve {
                    launch_config,
                    allow_exec: _,
                    inventory_only: _,
                    profile,
                },
        } => {
            return gateway::run(&launch_config, profile.as_deref());
        }
        Command::Mcp {
            command:
                McpCommand::Diff {
                    before,
                    after,
                    fail_on_change,
                },
        } => {
            let diff = match Snapshot::from_file(&before)
                .and_then(|before| before.diff(&Snapshot::from_file(&after)?))
            {
                Ok(diff) => diff,
                Err(error) => return mcp_error(error, cli.json),
            };
            if cli.json {
                output::json(&diff, io::stdout().lock())?;
            } else {
                output::diff(&diff, io::stdout().lock())?;
            }
            return Ok(findings_exit(!diff.is_empty(), fail_on_change));
        }
        Command::Mcp {
            command:
                McpCommand::Inspect {
                    launch_config,
                    allow_exec: _,
                    snapshot,
                    classification_overrides,
                    details,
                    fail_on_risk,
                },
        } => {
            let overrides = match classification_overrides {
                Some(path) => match ClassificationOverrides::from_file(&path) {
                    Ok(overrides) => overrides,
                    Err(error) => return mcp_error(error, cli.json),
                },
                None => ClassificationOverrides::default(),
            };
            let result = mitigate_mcp::LaunchConfig::from_file(&launch_config).and_then(|config| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| mitigate_mcp::Error::Launch)?;
                runtime.block_on(mitigate_mcp::enumerate_with_shutdown(&config, async {
                    let _ = tokio::signal::ctrl_c().await;
                }))
            });
            let inventory = match result {
                Ok(inventory) => inventory,
                Err(error) => return mcp_error(error, cli.json),
            };
            let report = match inventory.classify(&overrides) {
                Ok(report) => report,
                Err(error) => return mcp_error(error, cli.json),
            };
            if let Some(path) = snapshot
                && let Err(error) =
                    Snapshot::from_inventory(&inventory).and_then(|s| s.write_new(&path))
            {
                return mcp_error(error, cli.json);
            }
            if cli.json {
                output::json(&report, io::stdout().lock())?;
            } else {
                output::inspect(&report, details, io::stdout().lock())?;
            }
            return Ok(findings_exit(
                report
                    .tools
                    .iter()
                    .any(|t| !t.classification.flags.is_empty()),
                fail_on_risk,
            ));
        }
        Command::Mcp {
            command:
                McpCommand::Scan {
                    root,
                    runtime_config,
                    details,
                    fail_on_risk,
                },
        } => {
            let config = match runtime_config {
                None => RuntimeConfig::default(),
                Some(path) => match RuntimeConfig::from_file(&path) {
                    Ok(config) => config,
                    Err(error) => {
                        output::error(error.code(), &error.to_string(), cli.json)?;
                        return Ok(ExitCode::from(2));
                    }
                },
            };
            let report = match mitigate_mcp_scan::scan_project(&root, &config.scan) {
                Ok(report) => report,
                Err(error) => {
                    output::error(error.code(), &error.to_string(), cli.json)?;
                    return Ok(ExitCode::from(2));
                }
            };
            if cli.json {
                output::json(&report, io::stdout().lock())?;
            } else {
                output::scan(&report, details, io::stdout().lock())?;
            }
            return Ok(findings_exit(
                report.servers.iter().any(|s| !s.risks.is_empty()),
                fail_on_risk,
            ));
        }
        Command::Version => {
            let report = VersionReport {
                schema_version: 1,
                product: "Mitigate Runtime",
                version: env!("CARGO_PKG_VERSION"),
                config_schema_version: CONFIG_SCHEMA_VERSION,
            };
            if cli.json {
                output::json(&report, io::stdout().lock())?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "Mitigate Runtime {} (configuration v{})",
                    report.version,
                    report.config_schema_version
                )?;
            }
        }
        Command::Config {
            command: ConfigCommand::Check { config },
        } => {
            let config = match RuntimeConfig::from_file(&config) {
                Ok(config) => config,
                Err(error) => {
                    output::error(error.code(), &error.to_string(), cli.json)?;
                    return Ok(ExitCode::from(2));
                }
            };
            if cli.json {
                output::json(
                    &ConfigReport {
                        schema_version: 1,
                        valid: true,
                        config,
                    },
                    io::stdout().lock(),
                )?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "Configuration valid (schema v{}). No servers started.",
                    config.schema_version
                )?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn parse_error(error: clap::Error, machine: bool) -> io::Result<ExitCode> {
    // Clap's detailed errors echo user-supplied values. Keep those out of logs,
    // including malformed options that accidentally contain credentials.
    let message = match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            error.print()?;
            return Ok(ExitCode::SUCCESS);
        }
        ErrorKind::MissingRequiredArgument => {
            "Missing required options. Inspection/serve require --launch-config and --allow-exec; serve also requires --inventory-only. Run the command with --help."
        }
        ErrorKind::ArgumentConflict => {
            "Conflicting options. Use --details for human output or --json for reports; serve uses MCP on stdout and cannot use --json. Check the command's --help."
        }
        ErrorKind::InvalidSubcommand => "Unknown command. Run mitigate --help to list commands.",
        _ => {
            "Invalid command arguments. Run the command with --help to check available options and required values."
        }
    };
    output::error("cli_invalid_arguments", message, machine)?;
    Ok(ExitCode::from(2))
}

fn finish(result: io::Result<ExitCode>, machine: bool) -> ExitCode {
    match result {
        Ok(code) => code,
        // A downstream consumer closing its pipe is normal CLI behavior.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(_) => {
            let _ = output::error(
                "output_unavailable",
                "Cannot write output. Check the destination and retry.",
                machine,
            );
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    // Examine only the global switch; never format or log argument values.
    let machine = arguments
        .iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .any(|a| a == "--json");
    let result = match Cli::try_parse_from(arguments) {
        Ok(cli) => execute(cli),
        Err(error) => parse_error(error, machine),
    };
    finish(result, machine)
}
