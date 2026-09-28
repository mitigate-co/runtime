//! Commands expose read-only discovery separately from intentional execution.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "mitigate",
    version,
    about = "Local-first MCP security for Mitigate"
)]
pub(crate) struct Cli {
    /// Emit the versioned JSON contract instead of human output.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Store local credentials without putting their values in configuration.
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },
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
pub(crate) enum SecretsCommand {
    /// Import a credential from a pipe into the native OS store; return its reference.
    Import {
        /// Required: read the credential from non-terminal stdin, never an argument.
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Replace one existing reference's value using non-terminal stdin.
    Replace {
        /// Opaque reference from a previous import.
        #[arg(long)]
        reference: String,
        /// Required: read the replacement value from a pipe.
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Check that one credential can be read; never reveal its value.
    Check {
        #[arg(long)]
        reference: String,
    },
    /// Delete one local credential. Existing upstream processes must be restarted.
    Delete {
        #[arg(long)]
        reference: String,
        /// Required: confirm deletion of this one local reference.
        #[arg(long, required = true)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum McpCommand {
    /// Serve a reviewed server's inventory over stdio; tool calls stay disabled.
    Serve {
        /// Reviewed local process launch configuration.
        #[arg(long)]
        launch_config: PathBuf,
        /// Required: execute the configured server with your OS privileges.
        #[arg(long, required = true)]
        allow_exec: bool,
        /// Required until policy/grants are configured: deny every tool call.
        #[arg(long, required = true, conflicts_with = "json")]
        inventory_only: bool,
        /// Explicit local caller mapping; omitted attribution remains unknown.
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// Compare local snapshots without starting a server.
    Diff {
        /// Earlier snapshot.
        #[arg(long)]
        before: PathBuf,
        /// Later snapshot.
        #[arg(long)]
        after: PathBuf,
        /// Return exit code 3 when any fingerprint changed.
        #[arg(long)]
        fail_on_change: bool,
    },
    /// Execute a trusted local server and enumerate/classify tools without calls.
    Inspect {
        /// Reviewed Runtime launch configuration, separate from discovery files.
        #[arg(long)]
        launch_config: PathBuf,
        /// Required: execute the configured program with your OS privileges.
        #[arg(long, required = true)]
        allow_exec: bool,
        /// Save fingerprints to a new file; never overwrite an existing file.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        /// Explicit local admin classifications bound to current fingerprints.
        #[arg(long)]
        classification_overrides: Option<PathBuf>,
        /// Show full labels, evidence and review flags in human output.
        #[arg(long, conflicts_with = "json")]
        details: bool,
        /// Return exit code 3 when at least one review flag is present.
        #[arg(long)]
        fail_on_risk: bool,
    },
    /// Read Claude Code and Cursor project configurations locally.
    Scan {
        /// Project directory; only documented configuration paths are inspected.
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Optional Runtime configuration for scanner resource limits.
        #[arg(long)]
        runtime_config: Option<PathBuf>,
        /// Show full declarations and actionable review guidance.
        #[arg(long, conflicts_with = "json")]
        details: bool,
        /// Return exit code 3 when at least one configuration risk is present.
        #[arg(long)]
        fail_on_risk: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommand {
    /// Check a regular JSON file. No credentials, network or server execution.
    Check {
        /// Local Runtime JSON configuration file.
        #[arg(long)]
        config: PathBuf,
    },
}
