# Runtime configuration v1

The initial configuration controls scanner resource limits. It contains no secrets, server commands, or Platform account settings. Configuration checking does not read client configs, launch programs, or make network requests.

```sh
cargo run -- config check --config examples/runtime.json
cargo run -- config check --config examples/runtime.json --json
```

`schema_version` is required and must be `1`. The optional `scan` object accepts:

| Field | Default | Allowed range |
| --- | --- | --- |
| `max_file_bytes` | 262144 | 1024–1048576 |
| `max_servers` | 128 | 1–256 |

Unknown/duplicate fields, wrong types, trailing JSON, documents over 64 KiB, directories, and final-component symlinks are rejected. Default JSON recursion limits remain enabled. File checks are not a defense against a same-user attacker concurrently replacing filesystem paths.

Success goes to stdout. Operational errors go to stderr and never include configuration contents, paths, or parser diagnostics. `--json` adds a `schema_version: 1` output contract. Exit codes: `0` success, `2` invalid command/configuration, `1` output failure. Clap usage errors use its human help format even with `--json`. A consumer closing stdout early is normal success.

Configuration checking enables no background telemetry or file logging and does
not look up credentials, search home directories or require Platform. Use
[scan](SCANNER.md) for project declarations, [inspect](ENUMERATION.md) to explicitly
launch a selected server, and [serve](GATEWAY.md) for an MCP endpoint. Server launch,
governed authority and [optional sync](SYNC_CONTROLS.md) use separate explicit
configuration; this resource-limit document does not enable them.
