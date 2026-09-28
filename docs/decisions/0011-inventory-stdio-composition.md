# ADR 0011 — Explicit inventory endpoint and bounded stdio shutdown

Status: accepted. Date: 2026-09-28.

## Context

The listener and managed upstream transport now exist. The ordered backlog places secrets, audit, Regorus, grants and approvals after transport integration. Connecting unchecked tool execution to the CLI in the meantime would create a misleading security product. Native stdin reads can also block after a session timeout, preventing normal Tokio runtime destruction.

## Decision

Expose `mcp serve` with required launch intent and required `--inventory-only`. Use a concrete service that refreshes the observed inventory, returns bounded definition pages and rejects every tool call before upstream invocation. There is no permissive default or hidden bypass. Explicit caller profiles are parsed before launch and remain operator declarations. Later security packages can add a deliberate enforcing mode through the same service boundary.

Use Tokio's existing `io-std` support for this non-interactive single-command executable. The only enabled blocking workers are stdin/stdout (pool capped at two). Explicitly await upstream cleanup, then call `shutdown_timeout(50ms)` and finish the CLI. The OS may retain a blocked stdin worker until process exit; no tool operation or child cleanup is delegated to that worker or abandoned with it. This avoids a bespoke unsafe cross-platform pipe layer while bounding termination when the client holds stdin open. This pattern is CLI-specific, not a library/service-host lifecycle recommendation.

The actual-binary contract keeps stdin open during a partial-frame timeout and requires process exit. It separately closes the pipe handle to test ordinary EOF; on Windows an asynchronous write shutdown alone does not close the pipe.

## Consequences

Inventory-only operation is useful for compatibility and deployment testing without claiming policy enforcement. Full production gates still require enabling authorized calls after policy, grants, approvals, schema validation, secrets and audit. No account or network listener is required. Only the existing Tokio feature changes; no new external dependency is added. Abrupt OS termination cannot guarantee cleanup on all platforms and remains a documented release-hardening concern, not a graceful-shutdown guarantee.

References: [Tokio stdin](https://docs.rs/tokio/1.53.1/tokio/io/fn.stdin.html), [Tokio runtime shutdown](https://docs.rs/tokio/1.53.1/tokio/runtime/struct.Runtime.html#shutdown).
