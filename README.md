# Mitigate Runtime

Tool calls through the library validate arguments and structured results using
the [bounded local JSON Schema profile](docs/SCHEMA_VALIDATION.md). The CLI offers
explicit inventory-only and [governed-call modes](docs/ENFORCEMENT.md).

The Apache-2.0 customer-side MCP scanner and gateway for Mitigate. Local operation must work without a Platform account. Credentials and tool payloads stay on the customer side.

Development has started. No release binaries or production-ready gateway are published yet. The executable work packages and acceptance gates are in [the MCP specification](docs/modules/mcp/LOW_LEVEL.md). See [implementation status](docs/IMPLEMENTATION.md) for verified scope.

## Run from source

Install Rust through rustup and a native C build toolchain (Visual Studio C++ build
tools on Windows, Xcode command-line tools on macOS, or a C compiler on Linux).
Windows also needs the matching MSVC Spectre-mitigated x64/x86 libraries, required
by Regorus. The repository pins its Rust toolchain and lockfile; SQLite is bundled
from source.

```sh
cargo run --locked -- version
cargo run --locked -- config check --config examples/runtime.json --json
cargo run --locked -- mcp scan --root examples/scanner-project
cargo run --locked -- mcp scan --root examples/scanner-project --json
```

These commands work without an account, credentials, or a network connection once build dependencies are available. The scanner reads two documented project configuration locations without launching or contacting servers. Replace the fixture root with your project directory to inspect its declarations. [Scanner scope and output](docs/SCANNER.md) explains what is checked and excluded; [configuration v1](docs/CONFIGURATION.md) documents resource limits.

To enumerate a trusted server, use the separate [explicit launch workflow](docs/ENUMERATION.md). The synthetic demonstration runs locally:

```sh
cargo run --locked -p mitigate-mcp-fixture -- launch-config > target/fixture-launch.json
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec --json
```

`inspect` starts the selected program with your OS privileges. It never calls tools. Its [capability report](docs/CLASSIFICATION.md) shows evidence and review flags; explicit local overrides remain bound to current tool definitions. Use the inventory-only gateway to list tools, or explicitly configure governed calls with reviewed local authority.

Use [native credentials](docs/SECRETS.md) when a reviewed server requires a key.
`mitigate secrets import --stdin` reads a pipe into your OS store and returns an
opaque launch reference. Values never belong in command arguments or launch files.
Check, rotate and delete credentials locally without a Platform account.

[Launch review](docs/LAUNCH_REVIEW.md) binds a selected executable, code artifacts
and exact launch configuration to a private local reference. `mcp launch review`
and `check` do not execute code. `--launch-review FILE` checks the binding before
launch and invalidates the connection on code drift. It is required for governed calls.

Use [local audit](docs/AUDIT.md) to record inventory requests and denied calls:
initialize a private database with `mitigate mcp audit init --db FILE`, then add
`--audit-db FILE` to serve. Verify, page through, or prune its bounded metadata
history locally. No arguments, results or credentials are audit fields.

Use [local policies](docs/POLICY.md) to validate and test the restricted Rego
profile, generate native-store signing keys, and activate verified bundles.
Policy evaluation works offline; governed calls also require explicit grants and
the approval, control, launch-review and audit checks.

Use [local grants](docs/GRANTS.md) to validate exact scopes and test whether an
action has an explicit allowance or denial. These local diagnostics invoke no tools.
Use [mcp context](docs/GOVERNANCE_CONTEXT.md) to obtain the reviewed references
for those scopes without calculating hashes or starting a governed call first.

[Local approvals](docs/APPROVALS.md) support metadata review, bounded one-call
decisions and revocation before consumption. Approval does not invoke a tool or
bypass grants/policy; the governed gateway consumes it at final admission.

[Local controls](docs/CONTROLS.md) provide emergency stops, exact target disables
and persistent admission quotas. Configure and review them using `mcp controls`;
its diagnostic preview neither charges quota nor invokes tools.

```sh
cargo run --locked -- mcp grants check --rules examples/grants/read-development.json
cargo run --locked -- mcp grants test --rules examples/grants/read-development.json --input examples/grants/read-context.json --json
```

```sh
cargo run --locked -- mcp policy test --source examples/policies/read-and-review.rego --input examples/policies/read-input.json --json
```

Add `--snapshot target/before.json` to save fingerprints to a new local file. After a later inspection saved to another file, compare them offline:

```sh
cargo run --locked -- mcp diff --before target/before.json --after target/after.json --json
```

See [fingerprints and snapshots](docs/FINGERPRINTS.md) for the complete tested example, privacy boundary and numeric compatibility limits.

Use `--details` for full human reports, or `--json` for the versioned machine contract. Add `--fail-on-risk` to scan/inspect or `--fail-on-change` to diff for opt-in exit 3 on findings. The [CLI reference](docs/CLI.md) includes exit codes, examples and recovery steps.

## Verify

Look up [source-attributed public registry facts](docs/REGISTRY.md) offline:

```sh
cargo run --locked -- mcp registry lookup --catalog examples/registry/catalog.json --subject io.example/synthetic-server --json
```

The supplied example is synthetic. Lookups preserve source disagreement and
show freshness; they do not install servers, authenticate publishers or grant access.

Run the [privacy self-test and egress inspector](docs/PRIVACY_COMMANDS.md) locally:

```sh
cargo run --locked -- privacy self-test --json
cargo run --locked -- egress inspect --json
```

The self-test uses an isolated synthetic queue and sends nothing. The inspector
shows exact supported fields and optional retained queue diagnostics. This build
has no Platform sender; accepted queue events do not imply cloud delivery.

The [gateway reference](docs/GATEWAY.md) documents `mcp serve --launch-config FILE --allow-exec --inventory-only`, its local protocol and explicit caller profiles. It lists real upstream definitions while disabling tool calls. Exercise the complete CLI with `cargo run --locked -p mitigate-mcp-fixture -- gateway-contract target/debug/mitigate` (append `.exe` on Windows after building both binaries). Full gateway enforcement remains in development.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
cargo deny check licenses bans sources
```

CI also runs the documented CLI commands on Windows, Linux and macOS and scans the complete Git history for secrets. `cargo-audit` and `cargo-deny` are development tools pinned in CI, not Runtime dependencies.

Read [AGENTS.md](AGENTS.md), [architecture](docs/ARCHITECTURE.md), [privacy](docs/PRIVACY_ARCHITECTURE.md), and [security reporting](SECURITY.md). Hosted services live separately in the private `mitigate-co/platform` repository.
