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
    /// Validate, sign, activate and test local MCP policies.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Create, verify, read or prune a local metadata audit database.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
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
        /// Existing audit database initialized with `mcp audit init`.
        #[arg(long)]
        audit_db: Option<PathBuf>,
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
pub(crate) enum PolicyCommand {
    /// Check source against the restricted Mitigate Rego Profile.
    Check {
        #[arg(long)]
        source: PathBuf,
    },
    /// Test local source and metadata only; never authorize or invoke a tool.
    Test {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Generate a native-store signing key and a new public trust document.
    Keygen {
        #[arg(long)]
        trust_out: PathBuf,
    },
    /// Sign reviewed source with a native credential reference; write a new bundle.
    Sign {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        key_ref: String,
        #[arg(long)]
        version: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Create a new empty policy store bound to an independent trust document.
    Init {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
    /// Verify and atomically activate a newer signed bundle.
    Activate {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Reverify and report the active local policy without printing source.
    Status {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
    /// Evaluate the stored verified policy on a local metadata fixture.
    Evaluate {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuditCommand {
    /// Create a new private audit file; never overwrite an existing path.
    Init {
        #[arg(long)]
        db: PathBuf,
        /// Retain at most this many records (1–100,000).
        #[arg(long, default_value_t = 10_000)]
        max_records: u32,
        /// Retain records for this many days (1–365).
        #[arg(long, default_value_t = 30)]
        max_age_days: u32,
        /// Maximum retained event bytes (4 KiB–64 MiB).
        #[arg(long, default_value_t = 16_777_216)]
        max_payload_bytes: u64,
    },
    /// Verify the complete retained hash chain and report retention checkpoints.
    Verify {
        #[arg(long)]
        db: PathBuf,
    },
    /// Verify and read a bounded page of local audit metadata.
    List {
        #[arg(long)]
        db: PathBuf,
        /// Sequence after which to read; retention gaps appear in the checkpoint.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Number of records to show (1–250).
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Permanently remove records outside the stored retention limits.
    Prune {
        #[arg(long)]
        db: PathBuf,
        /// Required explicit intent to delete expired records.
        #[arg(long, required = true)]
        confirm: bool,
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
