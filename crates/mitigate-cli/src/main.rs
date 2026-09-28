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
    /// Discover servers, inspect trusted tools and compare local snapshots.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Compare two local fingerprint snapshots without starting a server.
    Diff {
        /// Earlier snapshot.
        #[arg(long)]
        before: PathBuf,
        /// Later snapshot.
        #[arg(long)]
        after: PathBuf,
    },
    /// Start an explicitly trusted local server and enumerate tools without calls.
    Inspect {
        /// Reviewed Runtime launch configuration, separate from discovery files.
        #[arg(long)]
        launch_config: PathBuf,
        /// Required: this executes the configured program with your OS privileges.
        #[arg(long, required = true)]
        allow_exec: bool,
        /// Save fingerprints to a new local file; never overwrites an existing file.
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
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

fn mcp_error(error: mitigate_mcp::Error, json: bool) -> io::Result<ExitCode> {
    if json {
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
    Ok(ExitCode::from(2))
}

fn execute(cli: Cli) -> io::Result<ExitCode> {
    match cli.command {
        Command::Mcp {
            command: McpCommand::Diff { before, after },
        } => {
            let result = mitigate_mcp::Snapshot::from_file(&before)
                .and_then(|before| before.diff(&mitigate_mcp::Snapshot::from_file(&after)?));
            match result {
                Err(error) => return mcp_error(error, cli.json),
                Ok(diff) if cli.json => write_json(&diff, io::stdout().lock())?,
                Ok(diff) => {
                    let mut output = io::stdout().lock();
                    if diff.is_empty() {
                        writeln!(output, "No changes.")?;
                    }
                    if diff.server_identity_changed {
                        writeln!(output, "Server identity changed.")?;
                    }
                    if diff.server_facts_changed {
                        writeln!(output, "Server facts changed.")?;
                    }
                    if diff.tools_supported_changed {
                        writeln!(output, "Tools capability changed.")?;
                    }
                    for tool in diff.tools {
                        let fields = [
                            (tool.identity_changed, "identity"),
                            (tool.input_schema_changed, "input schema"),
                            (tool.output_schema_changed, "output schema"),
                            (tool.description_changed, "description"),
                        ]
                        .into_iter()
                        .filter_map(|(changed, name)| changed.then_some(name))
                        .collect::<Vec<_>>()
                        .join(", ");
                        if fields.is_empty() {
                            writeln!(output, "{:?} {}", tool.kind, tool.name)?;
                        } else {
                            writeln!(output, "{:?} {} ({fields})", tool.kind, tool.name)?;
                        }
                    }
                }
            }
        }
        Command::Mcp {
            command:
                McpCommand::Inspect {
                    launch_config,
                    allow_exec: _,
                    snapshot,
                },
        } => {
            let result = mitigate_mcp::LaunchConfig::from_file(&launch_config)
                .and_then(|config| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| mitigate_mcp::Error::Launch)?;
                    runtime.block_on(mitigate_mcp::enumerate_with_shutdown(&config, async {
                        let _ = tokio::signal::ctrl_c().await;
                    }))
                })
                .and_then(|inventory| {
                    if let Some(path) = snapshot {
                        mitigate_mcp::Snapshot::from_inventory(&inventory)?.write_new(&path)?;
                    }
                    Ok(inventory)
                });
            match result {
                Ok(inventory) => {
                    if cli.json {
                        write_json(&inventory.report(), io::stdout().lock())?;
                    } else {
                        let mut output = io::stdout().lock();
                        writeln!(
                            output,
                            "{} tool(s). MCP {}. No tools called.",
                            inventory.tools.len(),
                            inventory.protocol_version
                        )?;
                        if !inventory.tools_supported {
                            writeln!(output, "Server does not advertise tools.")?;
                        }
                        for tool in &inventory.tools {
                            writeln!(output, "{}", tool.name)?;
                        }
                    }
                }
                Err(error) => return mcp_error(error, cli.json),
            }
        }
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
