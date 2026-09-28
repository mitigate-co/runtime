# ADR 0005: Read-only project discovery

Status: accepted. Scope: MCP-002.

## Decision

Start with Claude Code and Cursor project files under a caller-selected repository root. Share strict parsing/normalization but keep the source kind and checked location explicit. Global/home discovery and execution are separate consent and compatibility boundaries. Missing files are normal; a malformed present file fails the entire inventory.

Keep report types separate from executable launch settings and Platform telemetry. Local output cannot hold argv, environment/header values or OAuth secrets. It retains local labels and endpoint origins and therefore is not eligible for direct cloud egress. Tool enumeration must use a separate explicit launch/connect path; selecting a repository is never permission to run its commands.

The duplicate-key JSON visitor adapts an existing customer-side implementation owned by this project. No private hosted implementation, customer data or Git history was imported. Its bounds, error handling and tests were reviewed in this repository.

## URL parser dependency

Use exact `url` 2.5.8 rather than hand-written authority splitting: user information, IPv6, Unicode domains and query/fragment boundaries are security-relevant. Rust's standard library has no URL parser. [The Servo project](https://github.com/servo/rust-url) maintains the implementation, test corpus and security policy under MIT/Apache-2.0. The selected release and every resolved manifest were reviewed; RustSec and cargo-deny are required checks.

This adds 28 external crates, including IDNA and ICU Unicode support, to the foundation's 17. That compile-time/binary-size cost is accepted for correct domain/origin normalization; no network client, DNS resolver or async runtime is introduced. The dependency parses bounded local strings only. No latency or binary-size target is claimed before release measurement. License/source/bans and vulnerability checks pass with the updated lockfile.

## Consequences

Discovery is useful offline without an account, cannot execute an untrusted repository and does not misrepresent transport/package declarations as observed facts. Some client configuration options remain unreviewed and transport inference stays unknown. This reduces initial compatibility; the documented matrix and fixtures define support. A later adapter must add equivalent hostile-input tests and documentation.
