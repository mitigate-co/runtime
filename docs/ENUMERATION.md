# Enumerate a trusted MCP server

`mcp scan` only reads project configuration. `mcp inspect` **executes** a separately selected program. Review its executable, arguments, working directory and environment references first. It runs with your OS privileges; job/group cleanup is not a sandbox.

## Local demonstration

From the repository root, in a POSIX shell or PowerShell 7:

```sh
cargo run --locked -p mitigate-mcp-fixture -- launch-config > target/fixture-launch.json
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec --json
```

The first command builds the synthetic fixture server and writes its absolute executable path into a launch file. Inspection reports one `read_status` tool and exits. It does not call that tool. This fixture package is unpublished and excluded from default workspace builds and Runtime installation. No network, account or real service credential is needed. The generated file is build output, not a committed portable configuration.

## Launch configuration v1

| Field | Required | Meaning |
| --- | --- | --- |
| `schema_version` | Yes | `1` |
| `executable_path` | Yes | Absolute path to a reviewed regular executable; Windows requires `.exe` |
| `working_directory` | Yes | Absolute existing directory |
| `argv` | No | Literal argument array, maximum 64 entries, 4 KiB each, 32 KiB total |
| `allowed_environment_keys` | No | Up to 32 named references from the current environment; values are never stored in this file |
| `timeout_ms` | No | Whole enumeration deadline, default 30,000; range 100–120,000 |

Configuration is strict JSON, at most 64 KiB. Unknown/duplicate fields, inline `env` values, NUL arguments, duplicate/case-conflicting environment names and unsupported schema versions are refused. No shell string is constructed. Executable resolution never searches PATH. Absolute paths are canonicalized, but another process with the same OS identity can still replace a file; this is explicit execution of trusted local software, not verified executable provenance or isolation.

The child starts with an empty environment except available `SystemRoot`, `WINDIR`, `TEMP` and `TMP`. PATH, HOME, loader switches, proxies and API keys are not inherited unless explicitly named. Referenced values must already exist and be bounded (8 KiB each, 64 KiB total environment). The future OS secret broker is a separate package; this command does not claim to provide a credential vault. Do not put secrets in argv.

## Supported protocol

Stdio uses one JSON-RPC message per newline. The client offers `2025-11-25` and accepts `2025-06-18`, `2025-03-26` and `2024-11-05` for this common initialization/tools-list subset. Other versions fail. It validates initialization, sends `notifications/initialized`, and requests tools only if the server advertised that capability. A server without tools is distinguished from one with an empty tool list.

Pagination supports up to 32 pages and 512 unique, case-sensitive tools. Repeated cursors and duplicate tool names fail the inventory. Names use ASCII letters, digits, underscore, hyphen and dot (1–128 bytes). Input schemas require an object with `type: "object"`; output schemas, when present, must be objects. Definitions are bounded and retained locally; remote schema references are never fetched. This is shape validation, not full JSON Schema semantic validation.

The client answers pings and rejects unsupported server requests with a fixed method-not-supported response. It advertises no sampling, roots, elicitation or tasks. Logs and other notifications are discarded. A tool-list-change notification during enumeration aborts the result so mixed versions are not silently accepted. HTTP/SSE and call relay arrive in MCP-008; they are not supported by `inspect` yet.

Reference: [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle), [stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [tool listing](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), reviewed 2026-09-27.

## Resource and data boundaries

- 1 MiB per protocol line, 8 MiB total incoming stream, 64 messages while waiting for one response, 256 unsolicited messages per session.
- Shared strict JSON parser: depth 32, 32,768 nodes, 64 KiB strings, 4 KiB keys; duplicate keys and trailing data rejected.
- Each schema is at most 64 KiB; descriptions at most 16 KiB. These are untrusted definitions, never instructions to Mitigate.
- Whole-session deadline includes stalled writes/reads. Completion, errors, timeout and Ctrl+C close stdin, terminate the job/process group and await cleanup for up to two seconds. An unconfirmed cleanup returns a distinct failure. Forced OS termination and deliberate process-group escape are outside the lifecycle guarantee.

The default report contains only server-declared labels/version, negotiated protocol and tool names/counts/definition-presence fields. Descriptions, schemas, initialization instructions, notifications, stderr and upstream error text are excluded. These remaining labels are still customer-controlled local inventory, **not** approved Platform telemetry. Neither report nor definitions are transmitted or persisted by inspection.

Exit 0 means complete enumeration, including zero tools; exit 2 means invalid input, protocol/lifecycle failure or cancellation. Success JSON goes to stdout; fixed versioned errors go to stderr. No partial inventory is emitted. Operational errors provide corrective guidance without echoing server payloads, credentials or local paths.

## Verified failure cases

The real subprocess fixture exercises initialization, version fallback, pagination, pings, unsupported requests, literal quoting, child environment isolation, malformed JSON, duplicate keys/IDs, oversized streams, floods, cursor loops, duplicate tools, invalid names/schema shapes, server crashes, withheld upstream error canaries, changing inventory, deadlines, explicit shutdown, cancellation and descendant cleanup. Tests run on Windows, macOS and Linux in CI. No production server or customer account is used by this suite.
