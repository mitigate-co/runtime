# Local gateway protocol

`mitigate mcp serve` connects the local listener to a [managed stdio upstream](UPSTREAM.md). It opens no TCP socket and has no account dependency. The current explicit inventory-only mode lists real upstream definitions and disables all tool invocations. Native secrets and local audit are available; enforcing calls still await policy, grants, approvals and complete schema validation/integration. It is not production enforcement yet.

## Start an inventory endpoint

Build with `cargo build --workspace --locked`, generate the synthetic launch file as described in [enumeration](ENUMERATION.md), then configure an MCP client to launch:

```sh
mitigate mcp serve --launch-config target/fixture-launch.json --allow-exec --inventory-only
```

This command reads MCP messages from stdin and writes only MCP messages to stdout. It is a client-launched stdio service, not an interactive terminal prompt. Startup/session diagnostics use fixed content-free stderr messages and exit 2, including startup cancellation. Normal EOF and explicit shutdown after startup exit 0 after upstream cleanup. `--json` conflicts with serve because stdout is already the MCP transport. Launch intent and `--inventory-only` are required; there is no hidden allow-call switch. Use `--profile examples/gateway-profile.json` only after reviewing its declared mapping. Invalid profiles fail before process launch. [Native credential bindings](SECRETS.md) resolve inside the startup deadline before a child is spawned.

Tool listing refreshes the upstream baseline before returning definitions. Pages contain at most 16 tools and are reduced to stay below 512 KiB and the strict parser complexity limits. Versioned local cursors do not accept an offset outside the retained inventory. Tool calls return fixed error `-32006` and never reach the upstream. No file or client configuration is modified automatically.

Add `--audit-db FILE` after creating a private database with `mcp audit init`.
Startup verifies it before child execution. Completed inventory requests and
denied calls are committed before returning their response; a storage failure
returns `-32007`. SQLite work runs on a blocking worker, so disk contention does
not block the async protocol reactor. Cancellation may occur before a completion
record exists; an already-started audit commit may still finish after cancellation.
See [audit scope, bounds and recovery](AUDIT.md). Full execution auditing is a later
enforcement gate; this option never enables tool invocation.

## Identity

The caller is unknown by default: client, principal and agent references are absent; source and confidence are `unknown`. An explicitly selected local profile can declare a mapping:

```json
{"schema_version":1,"client_ref":"cli_example","agent_ref":"agt_example"}
```

The profile allows only `schema_version`, required `client_ref`, optional `principal_ref` and optional `agent_ref`. Version 1 is supported. References are 1–128 ASCII letters, digits, dots, underscores or hyphens. The file content is at most 4 KiB; duplicate/unknown fields are rejected. The profile is supplied by the Runtime operator, never discovered in an MCP message. Source becomes `gateway_profile` and confidence `declared`; missing principal/agent stay absent. This is a local declaration, not authenticated enterprise identity. Protecting the selected profile is the operator's local trust boundary.

`clientInfo`, arguments, `_meta`, method names and client capabilities cannot overwrite this context. Local profile labels are not automatically safe telemetry and must go through later egress validation if synchronized.

## Compatibility

The listener negotiates MCP 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05. It returns the requested version when supported and offers 2025-11-25 otherwise; an incompatible client must disconnect. It accepts ping before initialization but does not relay tool requests until `notifications/initialized`. Repeated initialization is a protocol failure.

Implemented methods: `initialize`, `ping`, `tools/list`, `tools/call`, `notifications/initialized`, `notifications/cancelled`. The service determines whether tools are advertised. Sampling, roots, resources, prompts, tasks, elicitation, logging and list-change notifications are not advertised. Task-augmented tool calls are rejected. Tool-list cursors are opaque and bounded. MCP `_meta` on tool calls remains local content, separate from identity and policy facts. Progress emission is an upstream integration concern in MCP-008.

Request IDs are strings up to 128 bytes or integer JSON numbers. String and numeric IDs are distinct. Null/fractional IDs, duplicate object keys, JSON-RPC batches, response-shaped client messages, reused request IDs and unknown envelope fields fail closed. IDs remain reserved until the session ends. Unknown request methods receive `-32601`; notifications receive no response. Malformed/unknown cancellation references are ignored when the envelope is valid; cancellation reasons are discarded.

## Bounds and termination

| Resource | Bound |
| --- | --- |
| Frame including newline | 1 MiB |
| Parsed depth / nodes / string / key | 32 / 32,768 / 64 KiB / 4 KiB |
| Session input | 256 MiB |
| Unique request IDs / all messages | 32,768 / 65,536 |
| Session lifetime | 24 hours |
| Initialization / partial frame | 10 seconds each |
| Active tool request / output write | 30 seconds / 5 seconds |
| Concurrent tool requests | 1; additional requests receive `-32005` |

Idle initialized sessions remain open within the lifetime budget. Pings and cancellation continue while the service is busy. Reading a partial next frame is cancellation-safe: its bytes and deadline survive completion of current work. Oversized frames, malformed sessions, pipe failure and deadlines terminate the connection. Request timeout first sends a fixed `-32002` error if output is available. Fixed writes can add up to their five-second deadline to termination. Output is bounded and revalidated before writing.

A matching cancellation drops in-flight work and ends the connection, without sending a response for that request. Explicit shutdown and client EOF also drop work. The service must release/terminate the operation on drop, and its owner must confirm upstream cleanup after the listener returns. A new connection is required after cancellation. This deliberately avoids continuing with an ambiguous upstream response stream.

## Content and authorization boundary

`serve` optionally accepts `--launch-review FILE` from the [local review
workflow](LAUNCH_REVIEW.md). It verifies selected code and exact launch facts
before execution and detects later selected-code drift on inventory refresh.
It still requires `--allow-exec --inventory-only`; a launch review never enables
calls. A changed reviewed launch fails rather than falling back to unbound mode.

The listener does not decide that a tool is safe. Each service implementation must authorize calls before forwarding them. There is no default permissive service. Raw arguments and tool results travel only through the local content plane to an explicitly selected service. The listener has no file persistence, logging or Platform networking. `ToolRequest` and caller identity have no `Debug` implementation. Upstream operational errors map to a closed `Fault` enum; descriptions, arguments, credentials and arbitrary error bodies are not diagnostics.

Successful tool results and definitions can contain sensitive content. Returning those to the requesting MCP client is workload traffic, not telemetry. A service must not conceal an operational error body inside a successful result to bypass sanitization. Policy, grants, native secrets, audit, schema validation/change gates and optional egress remain separate production gates.

## Exercise the listener

```sh
cargo run --locked -p mitigate-mcp-fixture -- listener-contract
cargo test --locked -p mitigate-gateway
```

The first command drives initialization, listing and policy denial over a local asynchronous byte stream, using the synthetic fixture and an explicit profile. It prints only the verification outcome. It neither starts a customer server nor executes a tool. The test corpus also covers hostile messages, spoofed identities, duplicate IDs, bounded memory, cancellation, shutdown, backpressure and partial-frame races. CI runs both on Windows, macOS and Linux.

After building both binaries, exercise the actual executable end to end:

```sh
cargo run --locked -p mitigate-mcp-fixture -- gateway-contract target/debug/mitigate
```

Append `.exe` on Windows. This starts the real CLI and synthetic upstream, lists tools, verifies denial without invocation, pages through ordinary and large-schema inventories, closes stdin, and tests both a full/unread stdout pipe and partial-frame timeout while stdin remains open. Tokio's standard-input worker can block in an OS read; the CLI confirms upstream cleanup and then bounds runtime shutdown before exiting. It never waits indefinitely for an extra stdin byte. See ADR 0011.

Protocol references: [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle), [stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
