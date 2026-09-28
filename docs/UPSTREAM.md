# Managed stdio upstream

`mitigate_mcp::StdioServer` keeps an explicitly selected local MCP process alive between requests. It uses the same reviewed launch schema, cleared environment, direct executable/argument invocation and OS job/process-group cleanup as [enumeration](ENUMERATION.md). It adds no network transport, account requirement, secret store, logging or persistence. The initial client/config matrix is Claude Code and Cursor with stdio endpoints. HTTP/SSE declarations can be discovered but are not connected by this adapter.

## Ownership and authorization

`connect` executes the selected program, initializes MCP and retains a complete inventory and fingerprint baseline. This is execution with the caller's OS privileges; the owner must explicitly authorize launch. It does not use discovered configs implicitly.

The `call` API is a low-level transport for an already-authorized invocation. Its owner must evaluate policy, grants, approval and schema-review requirements before using it. No ordinary CLI command exposes unchecked invocation. The fixture harness can invoke only its own synthetic test server. The current [gateway CLI](GATEWAY.md) connects to this adapter for inventory and explicitly disables calls. The transport alone is not an enforcing gateway.

Raw arguments/results are local content. A result may legitimately contain sensitive text or resources and must not enter diagnostics or telemetry. The adapter neither prints nor persists them. Server stderr is discarded. JSON-RPC errors become fixed `mitigate_mcp::Error` categories; their messages/data are never returned. MCP tool results marked `isError` remain tool content destined for the authorized caller, not operational logs.

## Connection state

`inventory()` returns the initial local definitions. `check_inventory()` re-enumerates on the same connection and compares all fingerprints with the initial baseline; a server without tools is pinged instead. `call()` first performs this comparison, then sends the invocation. Added/removed tools, input/output schema edits and normalized description changes fail before a tool call is sent. A list-change notification also invalidates the connection. Review and reconnect to accept a new baseline; this transport never silently updates one.

This is observed consistency, not a guarantee that a malicious server executes its advertised behavior. The server could alter its implementation after enumeration. Later grant/approval binding must also include exact launch identity and reviewed policy facts; the declaration summary fingerprint is insufficient.

`connect_reviewed` and `connect_reviewed_with_shutdown` accept a private
[launch review](LAUNCH_REVIEW.md). Their `launch_receipt()` exposes exact local
launch evidence. Selected executable/artifact bytes and canonical targets are
checked after inventory refresh and before invocation. Changes poison the
connection before a tool call; no automatic review/baseline update occurs.
Unselected transitive code and privileged same-user replacement races are outside
this fingerprint boundary. This remains a transport API, not authorization.

Request IDs increase monotonically across initialization, refresh and calls. Server-initiated ping is answered, unsupported server requests are rejected, logs are discarded. Both request namespaces reject reuse. Incoming responses must match the outstanding request. A process cannot be reused after a protocol, drift, upstream or transaction-timeout failure.

## Bounds and cancellation

- Launch `timeout_ms` bounds the entire initialization or transaction, including refresh and call, rather than resetting on each progress event.
- Each transaction receives at most 8 MiB; each incoming frame is at most 1 MiB and uses the strict JSON depth/node/string limits.
- Arguments are an object, at most 60,000 serialized bytes, leaving room under the 64 KiB outbound envelope bound. The tool must exist in the initial inventory. Invalid local arguments fail before starting a transaction and do not invalidate a healthy connection.
- At most 64 incoming messages are processed while waiting for one response, and at most 256 unsolicited messages per whole transaction, retaining the existing enumeration limit. The lifetime limits are 65,535 outbound request IDs, 4,096 unique server-request IDs and 65,536 unsolicited messages.
- Call results require the MCP `content` array (up to 256 blocks), supported block kinds/required value types, optional boolean `isError` and optional object `structuredContent`/`_meta`. Input and output schemas use the [bounded local execution profile](SCHEMA_VALIDATION.md). Both compile before dispatch; invalid input is refused locally and invalid/missing success output is withheld and invalidates the connection. Unsupported constraints never fall back to unchecked execution.

Dropping an in-flight operation immediately marks the connection unusable, closes its input and terminates the process group/job. No late response can be reused. Explicit `close()` confirms completion within two seconds and is idempotent. Error returns after a started transaction also confirm cleanup; cleanup failure takes precedence. Construction cancellation and final object drop initiate termination but cannot await reaping, so owners should use explicit cleanup whenever possible. Termination cannot undo side effects a tool already performed, and calls are never automatically retried.

`connect_with_shutdown` confirms cleanup when a shutdown signal arrives during initialization. The executable uses this path for Ctrl+C before switching to the listener's own shutdown handler.

## Progress

An optional callback requests progress using a fresh internal token. Received tokens must match, counters must be finite/nonnegative and strictly increasing, and an optional total must be at least the completed count. Only counters leave the adapter through the callback; upstream free-form progress messages are discarded. Progress does not extend deadlines. The gateway integration maps counters to the downstream client's own token. Call metadata is not used for identity or authentication.

## Demonstration and tests

```sh
cargo run --locked -p mitigate-mcp-fixture -- upstream-contract
cargo test --locked -p mitigate-mcp-fixture --test upstream
```

The demonstration starts the synthetic fixture as a real child process, refreshes its definitions, invokes its synthetic tool, receives progress, and confirms cleanup. It prints a fixed summary, excluding content. Tests cover repeated calls, changed definitions with proof no invocation occurred, crashes, malformed results, sanitized errors, wrong progress tokens, timeout, rejected local input, and cancellation with a live descendant. These tests run on all three supported operating systems.
