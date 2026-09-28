//! CLI composition: content-free operational errors and explicit local actions.

use clap::{Parser, Subcommand};
use mitigate_config::{CONFIG_SCHEMA_VERSION, ConfigError, RuntimeConfig};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "mitigate",
    version,
    about = "Local-first MCP security for Mitigate"
)]
struct Cli {
    /// Emit the versioned JSON contract instead of human output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the installed Runtime version and configuration schema.
    Version,
    /// Validate local Runtime configuration without starting servers.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Discover MCP declarations without running servers or connecting to them.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Read Claude Code and Cursor project configurations locally.
    Scan {
        /// Project directory; only documented configuration paths are inspected.
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Optional Runtime configuration for scanner resource limits.
        #[arg(long)]
        runtime_config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Check a regular JSON file. No credentials, network or server execution.
    Check {
        /// Local Runtime JSON configuration file.
        #[arg(long)]
        config: PathBuf,
    },
}

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

#[derive(Serialize)]
struct ErrorReport {
    schema_version: u32,
    error: &'static str,
    message: String,
}

fn write_json(value: &impl Serialize, output: impl Write) -> io::Result<()> {
    let mut output = output;
    serde_json::to_writer(&mut output, value).map_err(io::Error::other)?;
    writeln!(output)
}

fn config_error(error: ConfigError, json: bool) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    if json {
        write_json(
            &ErrorReport {
                schema_version: 1,
                error: error.code(),
                message: error.to_string(),
            },
            stderr,
        )
    } else {
        writeln!(stderr, "{}: {error}", error.code())
    }
}

fn execute(cli: Cli) -> io::Result<ExitCode> {
    match cli.command {
        Command::Mcp {
            command:
                McpCommand::Scan {
                    root,
                    runtime_config,
                },
        } => {
            let config = match runtime_config {
                None => RuntimeConfig::default(),
                Some(path) => match RuntimeConfig::from_file(&path) {
                    Ok(config) => config,
                    Err(error) => {
                        config_error(error, cli.json)?;
                        return Ok(ExitCode::from(2));
                    }
                },
            };
            let report = match mitigate_mcp_scan::scan_project(&root, &config.scan) {
                Ok(report) => report,
                Err(error) => {
                    if cli.json {
                        write_json(
                            &ErrorReport {
                                schema_version: 1,
                                error: error.code(),
                                message: error.to_string(),
                            },
                            io::stderr().lock(),
                        )?;
                    } else {
                        writeln!(io::stderr().lock(), "{}: {error}", error.code())?;
                    }
                    return Ok(ExitCode::from(2));
                }
            };
            if cli.json {
                write_json(&report, io::stdout().lock())?;
            } else {
                let mut output = io::stdout().lock();
                writeln!(
                    output,
                    "{} MCP server declaration(s). No servers started or contacted.",
                    report.servers.len()
                )?;
                for server in &report.servers {
                    let name: String = server
                        .server_name
                        .chars()
                        .flat_map(char::escape_default)
                        .collect();
                    let destination: String = server
                        .command_or_url
                        .as_deref()
                        .unwrap_or("unresolved")
                        .chars()
                        .flat_map(char::escape_default)
                        .collect();
                    writeln!(
                        output,
                        "{}  {name}  {:?}  {destination}",
                        server.source_path, server.transport
                    )?;
                    if !server.risks.is_empty() {
                        writeln!(output, "  Review: {:?}", server.risks)?;
                    }
                }
                if report.servers.is_empty() {
                    writeln!(
                        output,
                        "Checked .mcp.json and .cursor/mcp.json. Use --root to choose another project."
                    )?;
                }
            }
        }
        Command::Version => {
            let report = VersionReport {
                schema_version: 1,
                product: "Mitigate Runtime",
                version: env!("CARGO_PKG_VERSION"),
                config_schema_version: CONFIG_SCHEMA_VERSION,
            };
            if cli.json {
                write_json(&report, io::stdout().lock())?;
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
                    config_error(error, cli.json)?;
                    return Ok(ExitCode::from(2));
                }
            };
            if cli.json {
                write_json(
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

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(code) => code,
        // A downstream consumer closing its pipe is normal CLI behavior.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(
                io::stderr(),
                "output_unavailable: Cannot write output. Check the destination and retry."
            );
            ExitCode::from(1)
        }
    }
}
