# MCP scanner

```sh
cargo run --locked -- mcp scan --root examples/scanner-project
cargo run --locked -- mcp scan --root examples/scanner-project --json
cargo run --locked -- mcp scan --root examples/scanner-project --runtime-config examples/runtime.json --json
```

The fixture has three synthetic declarations. No account or running MCP server is needed. Discovery never launches a program, makes a network request, expands variables, reads an environment file, invokes a header helper, or writes configuration. It does not establish installed server identity, tool capabilities, or safety.

## Supported sources

| Adapter | Path under `--root` | Format |
| --- | --- | --- |
| Claude Code project | `.mcp.json` | Strict JSON object with `mcpServers` |
| Cursor project | `.cursor/mcp.json` | Strict JSON object with `mcpServers` |

This is also the repository adapter: point `--root` at a checked-out repository. There is no recursive search, automatic home-directory scan, workspace inheritance, JSONC, client settings merge, or global-config support. Missing sources are reported as absent. A present source that cannot be fully read and validated fails the whole scan. This scope is intentionally explicit so an empty report cannot be mistaken for a device-wide inventory.

Supported declarations contain exactly one `command` or `url`. Stdio arguments, environment/header entries, environment-file references and OAuth configuration are inspected only for their shape and risk categories. Unknown options produce `unreviewed_options`. A remote transport must be explicitly declared as `http`, `streamable-http` or `sse`; a URL alone remains `unknown`, because discovery cannot establish the client's transport negotiation. Declared transport is not verified connectivity.

The formats were checked against [Claude Code's MCP reference](https://code.claude.com/docs/en/mcp) and [Cursor's MCP reference](https://cursor.com/docs/mcp) on 2026-09-27. Client behavior outside this supported subset is not emulated.

## Local output and data handling

JSON schema version 1 reports sources and ordered server declarations. It includes a bounded local label, transport, executable basename or endpoint origin, argument count, declared npx package/version when recognizable, credential mechanism categories and configuration risks. Package versions are declarations, never installed provenance or resolved registry tags. Unknown versions remain null.

Reports exclude raw command paths, arguments, environment/header names and values, OAuth values, helper commands, referenced filenames, and URL user information, paths, queries and fragments. Parser/OS diagnostics never echo configuration content or absolute paths. Human output escapes server labels and destination text.

This is **local inventory**, not a safe Platform event. Labels, package declarations, executable basenames and endpoint origins are still customer-controlled and can be sensitive. Do not upload this report directly. Optional Platform synchronization must use the later closed Zero-Content schema and firewall. The scanner necessarily reads the selected local configuration into bounded memory; it does not resolve or persist credentials. It does not promise to detect arbitrary secrets disguised as server names.

## Limits and failures

Default: 256 KiB per source and 128 total declarations. Supported configurable ranges: 1 KiB–1 MiB per source, 1–256 servers. Fixed limits: depth 32, 32,768 JSON nodes, 64 arguments, 4,096 bytes per argument/command/URL, 64 environment/header entries per map, 8,192 bytes per value, 128-byte local server names. Duplicate object keys at any level, terminal controls in displayed labels, invalid field types, unsupported URL schemes and incompatible transport settings are rejected. JSON's parser recursion guard remains enabled.

Symlinks, Windows reparse points, special files and linked `.cursor` parents are refused. The explicitly selected root is canonicalized. Paths declared inside configuration are never followed. These checks are not a sandbox against another process under the same OS identity racing filesystem changes.

Exit 0 means discovery completed, including an empty result or declarations needing review; exit 2 means invalid/unavailable input. Success JSON goes to stdout; versioned error JSON goes to stderr with empty stdout. Errors give a fixed source path and recovery guidance. CLI syntax errors retain Clap's normal human format. Findings currently do not alter the exit code.

## Verification and next scope

Tests cover deterministic ordering, absent sources, duplicate keys, bounds, malformed and ambiguous settings, credential canaries, hostile shell declarations without execution, package declaration uncertainty, CLI failures and account-free operation. Unix CI exercises source and parent symlink rejection; Windows code rejects all reparse attributes, not just symbolic links.

MCP-003 adds explicit tool enumeration. Fingerprints, capability classification, grants, gateway policy and Platform synchronization remain separate ordered packages. Configuration risks here must not be treated as tool capability classification or authorization.
