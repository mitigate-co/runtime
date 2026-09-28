# ADR-0004: Standalone Runtime foundation

Status: Accepted
Date: 2026-09-27

## Context

Both canonical repositories were empty. The earlier private prototype includes useful customer-side MCP inventory components, but its executable requires enrollment and couples discovery output to a hosted graph. Importing that private history would violate the repository boundary.

## Decision

Start a minimal public-safe workspace, then selectively adapt reviewed customer-side components with provenance in the relevant change. Keep the original checkout and preview intact. Do not copy Platform history, credentials, private strategy, legacy policy intelligence, or parked modules into Runtime.

The CLI owns process I/O. `mitigate-config` owns the strict, bounded local configuration contract. Use the standard library for error types and file access. No network, async runtime, logger, or policy dependency is needed for MCP-001. Regorus remains the required policy engine for MCP-011.

Direct dependencies are Clap 4.6.7 (argument/help parsing), Serde 1.0.229 (typed serialization), and serde_json 1.0.151 (JSON). Published source manifests and license files were inspected; all offer MIT or Apache-2.0. Default Clap color/suggestion features are disabled. These crates do not initiate networking or telemetry. Derive macros execute at build time; serialization/parsing execute at the input boundary. Serde JSON's recursion guard remains enabled. Lockfile, RustSec scan, and cargo-deny license/source checks cover the resolved graph.

Upstream sources reviewed: [Clap](https://github.com/clap-rs/clap), [Serde](https://github.com/serde-rs/serde), [serde_json](https://github.com/serde-rs/json). Security status is a dated scan result, not a guarantee.

## Alternatives

Reusing the entire private monorepo would publish unrelated code and preserve account coupling. Handwritten CLI and JSON parsers would add avoidable compatibility and hostile-input risk. Separate crates for every future module would add empty abstractions.

## Verification

CLI subprocess tests run without home/account variables. Hostile configuration cases cover unknown and duplicate keys, wrong types, unsupported versions, bounds, nesting, file types and content-free errors. CI runs formatting, Clippy, tests, and documented commands on Windows, Linux and macOS. No production release is claimed by this foundation.
