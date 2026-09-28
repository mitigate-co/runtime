# ADR 0019: Bounded local tool schema validation

Status: accepted for implementation; cross-platform verification pending.

## Problem

Fingerprint consistency and JSON-RPC shape checks do not validate tool arguments
or structured results. Executing a tool with unchecked constraints, or ignoring an
unsupported result schema until after execution, would weaken the gateway boundary.
Untrusted schemas can also request resource retrieval or expensive evaluation.

## Decision

Use `jsonschema` 0.58.2 with default features disabled and `.offline()`, Draft
2020-12, embedded meta-schema validation and explicitly selected linear-time
regex matching. A separate admission pass checks a closed keyword profile,
local-only acyclic reference graph, expansion limits and value complexity.
Compile both schemas before dispatch; reject invalid inputs locally and withhold
invalid results. Documentation names every unsupported construct. No unsupported
constraint is silently ignored as an assertion.

The versioned [execution profile](../SCHEMA_VALIDATION.md) preserves standard
2020-12 annotation semantics: formats/content annotations do not assert, defaults
are not inserted, and readOnly/writeOnly are not access controls. Supporting
another dialect/vocabulary or recursive references requires a reviewed profile
change, bounds and conformance tests. Scanning/enumeration remain possible when
execution is unsupported. Existing fingerprint and audit encodings do not change.

Blocking work runs behind a four-slot semaphore and a two-second caller deadline.
Workers retain permits through timeout/cancellation. Static structural/graph
limits bound admitted inputs independently; the deadline does not kill a thread
or establish a CPU/memory sandbox. No operating-system endpoint collection or
parked Sandbox product is introduced.

Successful results with outputSchema must include conforming structuredContent.
Tool errors may omit it, matching established SDK error handling. Present error
structuredContent is validated too; this deliberately rejects incompatible error
shapes instead of forwarding unvalidated structured data. Output validation cannot
undo tool effects. No automatic retry occurs.

## Dependency review

The standard library/current dependencies do not implement JSON Schema. Writing
a new validator would duplicate complex applicator/reference semantics. This
maintained Rust implementation supplies Draft 2020-12 and conformance suites.
The crate is MIT and the exact version is locked. Thirty-six additional lockfile
packages are introduced; existing versions are unchanged. HTTP, file and async
retrievers, TLS, scripting-language bindings and code generation are disabled.
No reqwest/rustls dependency is introduced by this feature. Tokio's existing
dependency enables its `sync` feature for worker admission.

Transitive `borrow-or-share` 0.2.4 (MIT-0) and `foldhash` 0.2.0 (Zlib) had license
texts reviewed from the downloaded packages. Exact-package/version exceptions
permit them without expanding the global license list. Preserve their notices
in distribution; altered-source attribution remains required by Zlib. No source
modifications are made. Audit/advisory, source and license checks pass locally.
GitHub's Rust advisory query returned no jsonschema advisories on 2026-09-28;
this does not imply the code is free of defects.

The dependency executes on the sensitive local call path. Our crate forbids unsafe
code; that does not guarantee dependencies do. SIMD/hash/value implementations
include platform-specific optimized code. Existing per-OS CI and hostile-value
tests cover the supported builds; the release SBOM/license inventory must include
the expanded graph. Regex/fancy-regex both compile transitively, but admitted
schema patterns use only the configured linear engine. `serde_json` gains
`float_roundtrip` through feature unification; fingerprint regression tests must
continue to pass. In local Linux x86-64 Rust 1.98.1 release builds (thin LTO,
stripped symbols), the invocation fixture grew from 6,703,992 to 12,315,416 bytes,
an increase of 5,611,424 bytes. The current inventory-only CLI was 10,761,784 bytes
(baseline 10,761,624); it does not yet link the unused invocation path. Budget the
validator's size for the enforcing CLI. These are local artifact measurements,
not cross-platform release sizes. End-to-end latency remains a release gate.

## Verification and rollout

Unit tests cover nested assertions/applicators, pointers, annotations, hostile
references, cycles/expansion/regex bombs, malformed schemas, complexity bounds,
deadline and cancelled-worker capacity. Real-process tests prove invalid input
and unsupported output contracts never invoke the tool; bad output invalidates
the connection. A synthetic executable demonstration runs in all three OS CI
jobs. Fixed errors contain neither instance data nor dependency diagnostics.
The CLI installs a fixed process-wide panic notice before parsing arguments;
a separate subprocess regression verifies that dependency panic payloads and
requested backtraces cannot reveal local values. Library embedders own their hooks.

This adds no persistence schema or migration. The public CLI still refuses calls.
Rollback may restore inventory-only operation; it must never enable execution
while skipping schema validation. Full grants/policy/approval/control/audit
composition remains required before enabling tool calls.

## Primary references

- [MCP 2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12)
- [Rust jsonschema source and releases](https://github.com/Stranger6667/jsonschema)
- [Pinned validator API](https://docs.rs/jsonschema/0.58.2/jsonschema/struct.ValidationOptions.html)
- [Official SDK error-result behavior](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/server.md)
