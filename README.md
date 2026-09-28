# Mitigate Runtime

The Apache-2.0 customer-side MCP scanner and gateway for Mitigate. Local operation must work without a Platform account. Credentials and tool payloads stay on the customer side.

Development has started. No release binaries or production-ready gateway are published yet. The executable work packages and acceptance gates are in [the MCP specification](docs/modules/mcp/LOW_LEVEL.md). See [implementation status](docs/IMPLEMENTATION.md) for verified scope.

## Run from source

Install Rust through rustup. The repository pins its toolchain and lockfile.

```sh
cargo run --locked -- version
cargo run --locked -- config check --config examples/runtime.json --json
```

These commands work without an account, credentials, or a network connection once build dependencies are available. [Configuration v1](docs/CONFIGURATION.md) documents limits, errors and output. Scanner and gateway commands are being implemented in the ordered MCP work packages; they are not available in this foundation commit.

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
