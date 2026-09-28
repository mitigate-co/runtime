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

No background telemetry or file logging is enabled. There is no default credential lookup, home-directory configuration search, or Platform dependency. Later work packages add explicit scanner/gateway actions; they are not advertised as implemented commands today.
