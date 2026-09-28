# Mitigate Runtime

The Apache-2.0 customer-side MCP scanner and gateway for Mitigate. Local operation must work without a Platform account. Credentials and tool payloads stay on the customer side.

Development has started. No release binaries or production-ready gateway are published yet. The executable work packages and acceptance gates are in [the MCP specification](docs/modules/mcp/LOW_LEVEL.md). See [implementation status](docs/IMPLEMENTATION.md) for verified scope.

## Run from source

Install Rust through rustup. The repository pins its toolchain and lockfile.

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

`inspect` starts the selected program with your OS privileges. It never calls tools. Its [capability report](docs/CLASSIFICATION.md) shows evidence and review flags; explicit local overrides remain bound to current tool definitions. The gateway and enforcement are not implemented yet.

Add `--snapshot target/before.json` to save fingerprints to a new local file. After a later inspection saved to another file, compare them offline:

```sh
cargo run --locked -- mcp diff --before target/before.json --after target/after.json --json
```

See [fingerprints and snapshots](docs/FINGERPRINTS.md) for the complete tested example, privacy boundary and numeric compatibility limits.

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
cargo deny check licenses bans sources
```

CI also runs the documented CLI commands on Windows, Linux and macOS and scans the complete Git history for secrets. `cargo-audit` and `cargo-deny` are development tools pinned in CI, not Runtime dependencies.

Read [AGENTS.md](AGENTS.md), [architecture](docs/ARCHITECTURE.md), [privacy](docs/PRIVACY_ARCHITECTURE.md), and [security reporting](SECURITY.md). Hosted services live separately in the private `mitigate-co/platform` repository.
