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
    /// Enable, inspect, pause or explicitly send optional content-free events.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Connect this Runtime to an organization without enabling telemetry.
    Enroll {
        #[command(subcommand)]
        command: EnrollmentCommand,
    },
    /// Look up attributed public facts; never install servers or change grants.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Test the local privacy boundary using synthetic data; never send telemetry.
    Privacy {
        #[command(subcommand)]
        command: PrivacyCommand,
    },
    /// Inspect supported egress fields and optional retained queue diagnostics.
    Egress {
        #[command(subcommand)]
        command: EgressCommand,
    },
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
pub(crate) enum SyncCommand {
    /// Consent to optional event sync; create local state without starting a sender.
    Enable {
        /// New private sync profile. Other sync commands need only this path.
        #[arg(long)]
        profile: PathBuf,
        /// Existing confirmed enrollment file.
        #[arg(long)]
        enrollment: PathBuf,
        /// Original canonical HTTPS Platform origin.
        #[arg(long)]
        platform: String,
        /// New private queue file; never overwrites an existing database.
        #[arg(long)]
        outbox: PathBuf,
    },
    /// Inspect local consent and safe queue counts; no network or credential access.
    Status {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Pause new events and wait for active delivery to finish; retain queued events.
    Pause {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Resume consent after checking the original native enrollment; does not send.
    Resume {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Pause, wait for delivery to finish and delete retained local queue payloads.
    Purge {
        #[arg(long)]
        profile: PathBuf,
        /// Confirm local deletion. Previously hosted records are not removed.
        #[arg(long, required = true)]
        confirm: bool,
    },
    /// Deliver at most one queued event over verified HTTPS; never resumes consent.
    Send {
        #[arg(long)]
        profile: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum EnrollmentCommand {
    /// Save a new native identity, then send its one-use enrollment proof over HTTPS.
    Start {
        /// Canonical HTTPS Platform origin, without a path or trailing slash.
        #[arg(long)]
        platform: String,
        /// New enrollment file in an existing private local directory.
        #[arg(long)]
        state: PathBuf,
        /// Read a secure pipe instead of prompting; required with --json. Never put the code in an argument or environment variable.
        #[arg(long)]
        stdin: bool,
    },
    /// Recover a pending request using its original code and identity.
    Retry {
        /// Original canonical HTTPS Platform origin.
        #[arg(long)]
        platform: String,
        /// Existing enrollment file.
        #[arg(long)]
        state: PathBuf,
    },
    /// Inspect the local enrollment receipt without contacting Platform.
    Status {
        /// Original canonical HTTPS Platform origin.
        #[arg(long)]
        platform: String,
        /// Existing enrollment file.
        #[arg(long)]
        state: PathBuf,
    },
    /// Delete this native enrollment credential; does not revoke Platform access.
    Forget {
        /// Original canonical HTTPS Platform origin.
        #[arg(long)]
        platform: String,
        /// Existing enrollment file, retained to prevent concurrent reuse.
        #[arg(long)]
        state: PathBuf,
        /// Confirm deletion of the local key and pending code/receipt.
        #[arg(long, required = true)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PrivacyCommand {
    /// Inject synthetic secrets/content into a temporary queue and verify rejection.
    SelfTest {
        /// Existing writable parent for private temporary fixtures; defaults to OS temp.
        #[arg(long)]
        work_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum EgressCommand {
    /// Show exact fields and safe counts; never dump bodies, mutate stores or send.
    Inspect {
        /// Existing optional queue; omit all three scope options to inspect this build's schema.
        #[arg(long, requires_all = ["runtime_ref", "enrollment_ref"])]
        db: Option<PathBuf>,
        /// Independently configured opaque runtime reference; not a local audit fingerprint.
        #[arg(long, requires_all = ["db", "enrollment_ref"])]
        runtime_ref: Option<String>,
        /// Independently configured opaque enrollment reference; not an authentication secret.
        #[arg(long, requires_all = ["db", "runtime_ref"])]
        enrollment_ref: Option<String>,
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
    /// Show verified local references for exact grants and control targets; never call tools.
    Context {
        /// Explicit process configuration, separate from discovery files.
        #[arg(long)]
        launch_config: PathBuf,
        /// Existing exact executable/artifact/configuration review.
        #[arg(long)]
        launch_review: PathBuf,
        /// Existing reviewed tool fingerprint snapshot.
        #[arg(long)]
        tool_snapshot: PathBuf,
        /// Required: execute the selected server with your OS privileges.
        #[arg(long, required = true)]
        allow_exec: bool,
        /// Explicit local caller mapping; omitted attribution remains unknown.
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Reviewed classifications bound to these definitions.
        #[arg(long)]
        classification_overrides: Option<PathBuf>,
    },
    /// Manage local emergency stops, disabled targets and rate limits.
    Controls {
        #[command(subcommand)]
        command: ControlsCommand,
    },
    /// Review and verify exact local launch facts without executing a server.
    Launch {
        #[command(subcommand)]
        command: LaunchCommand,
    },
    /// Review and decide bounded local approval requests.
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// Validate local grant rules or test them against action metadata.
    Grants {
        #[command(subcommand)]
        command: GrantsCommand,
    },
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
    /// Serve inventory or explicitly governed tool calls over local stdio.
    Serve {
        /// Reviewed local process launch configuration.
        #[arg(long)]
        launch_config: PathBuf,
        /// Required: execute the configured server with your OS privileges.
        #[arg(long, required = true)]
        allow_exec: bool,
        /// Deny every tool call; mutually exclusive with enforcement.
        #[arg(long, required_unless_present = "enforce", conflicts_with_all = ["json", "enforce"])]
        inventory_only: bool,
        /// Explicit local governance configuration for approved tool execution.
        #[arg(long, requires = "launch_review", conflicts_with_all = ["json", "audit_db"])]
        enforce: Option<PathBuf>,
        /// Capture safe metadata into an existing consented sync queue.
        #[arg(long, requires = "enforce")]
        sync_profile: Option<PathBuf>,
        /// Explicit local caller mapping; omitted attribution remains unknown.
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Existing audit database initialized with `mcp audit init`.
        #[arg(long)]
        audit_db: Option<PathBuf>,
        /// Require exact executable/artifact/configuration review before launch.
        #[arg(long)]
        launch_review: Option<PathBuf>,
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
pub(crate) enum RegistryCommand {
    /// Read all matching claims from an explicit local public catalog; no network.
    Lookup {
        /// Explicit public catalog JSON; no automatic downloads or home-directory search.
        #[arg(long)]
        catalog: PathBuf,
        /// Canonical public namespace/server reference, not a local inventory ID.
        #[arg(long)]
        subject: String,
    },
}

#[derive(clap::Args)]
pub(crate) struct ControlAdmin {
    /// Existing local control database.
    #[arg(long)]
    pub db: PathBuf,
    /// Declared operator reference: 64 lowercase hexadecimal characters.
    #[arg(long)]
    pub operator_ref: String,
    /// Required explicit intent to change local enforcement configuration.
    #[arg(long, required = true)]
    pub confirm: bool,
}

#[derive(Subcommand)]
pub(crate) enum ControlsCommand {
    /// Create a new private local control store; no tool calls are enabled.
    Init {
        #[arg(long)]
        db: PathBuf,
    },
    /// Show current emergency, disable and rate-limit configuration.
    Status {
        #[arg(long)]
        db: PathBuf,
    },
    /// Show the last 256 configuration changes and declared operators.
    History {
        #[arg(long)]
        db: PathBuf,
    },
    /// Block every new admission. Already-dispatched effects cannot be undone.
    Stop(ControlAdmin),
    /// Clear emergency stop; individual disables and quotas remain in effect.
    Resume(ControlAdmin),
    /// Apply one reviewed JSON change: disable, enable, set_limit or remove_limit.
    Apply {
        #[command(flatten)]
        admin: ControlAdmin,
        #[arg(long)]
        change: PathBuf,
    },
    /// Preview action metadata without consuming quota or invoking a tool.
    Test {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        context: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum LaunchCommand {
    /// Fingerprint selected code and launch facts; write a new private review.
    Review {
        #[arg(long)]
        launch_config: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify current launch facts against an existing private review.
    Check {
        #[arg(long)]
        launch_config: PathBuf,
        #[arg(long)]
        review: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ApprovalsCommand {
    /// Create a new private local approval store.
    Init {
        #[arg(long)]
        db: PathBuf,
    },
    /// Create a metadata-only request for local testing; no tool is invoked.
    Request {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        context: PathBuf,
        /// Validity window, 1–300 seconds; approvals are always for one call.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u32).range(1..=300))]
        expires_in_seconds: u32,
    },
    /// List bounded local approval metadata, applying expiry and retention.
    List {
        #[arg(long)]
        db: PathBuf,
    },
    /// Show one request and its immutable scope before deciding.
    Show {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        reference: String,
    },
    /// Approve one still-pending request; all gateway checks still apply.
    Approve {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        reference: String,
        /// Declared local operator reference; not an authentication credential.
        #[arg(long)]
        operator_ref: String,
        /// Required explicit decision for this exact request.
        #[arg(long, required = true)]
        confirm: bool,
    },
    /// Deny a pending request or revoke approval before consumption.
    Deny {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        reference: String,
        #[arg(long)]
        operator_ref: String,
        #[arg(long, required = true)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum GrantsCommand {
    /// Validate explicit grant scopes without starting a server.
    Check {
        #[arg(long)]
        rules: PathBuf,
    },
    /// Resolve a local action fixture; never authorize or invoke a tool.
    Test {
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        input: PathBuf,
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
