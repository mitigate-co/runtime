# Command line reference

Build with `cargo build --workspace --locked`. Run `cargo run --locked -- COMMAND` or `target/debug/mitigate` (`mitigate.exe` on Windows). No account is required. The first build downloads dependencies; these commands do not contact Platform.

## Choose a command

| Task | Command | Side effect |
| --- | --- | --- |
| Check installed version | `mitigate version` | None |
| Validate Runtime limits | `mitigate config check --config FILE` | Reads one local file |
| Find declarations | `mitigate mcp scan --root PROJECT` | Reads documented project configs; no execution/network |
| Review configuration flags | Add `--details` to scan | Same read-only scope |
| Enumerate and classify tools | `mitigate mcp inspect --launch-config FILE --allow-exec` | Executes the reviewed server with your privileges, then stops it; never calls tools |
| Review classification evidence | Add `--details` to inspect | Shows full labels, classes, rules, sources and flags |
| Save fingerprints | Add `--snapshot NEW_FILE` to inspect | Creates a new file; never overwrites |
| Apply reviewed classification | Add `--classification-overrides FILE` to inspect | Reads bound administrator decisions; never grants access |
| Compare fingerprints | `mitigate mcp diff --before FILE --after FILE` | Reads two snapshots; no execution/network |
| Expose an inventory endpoint | `mitigate mcp serve --launch-config FILE --allow-exec --inventory-only` | Executes the reviewed server; serves MCP on stdin/stdout; all tool calls disabled |
| Store a local credential | `mitigate secrets import --stdin` | Reads a pipe into the OS store; returns only a reference |
| Check a local credential | `mitigate secrets check --reference REF` | Reports availability without printing its value |
| Rotate a local credential | `mitigate secrets replace --reference REF --stdin` | Replaces one existing reference using a pipe |
| Delete a local credential | `mitigate secrets delete --reference REF --confirm` | Deletes one reference; already running servers retain their environment |

`--help` works at each command level. Human tables give a compact overview; `--details` shows full labels and review guidance. Long table cells end with `...`. Terminal controls, bidirectional/invisible text and non-ASCII characters are escaped in human labels. JSON retains exact validated labels. Do not parse human tables as an API. Absence of flags does not establish server safety.

## Machine output and exits

For report commands, `--json` can appear before or after the command. It emits one complete success document to stdout, with no progress chatter. Input/operational errors use stderr and leave stdout empty. Help and `--version` remain text. `--details` and `--json` conflict because JSON already contains the complete report. `mcp serve` conflicts with `--json`: stdout carries an ongoing MCP session and stderr contains only fixed operational diagnostics. A failed session can follow prior valid protocol responses; report atomicity does not apply to that stream.

| Exit | Meaning |
| --- | --- |
| `0` | Completed, including empty inventories and findings under default behavior |
| `1` | Output could not be written |
| `2` | Invalid arguments/configuration, unavailable input, MCP failure, cancellation, incompatible snapshot or stale override |
| `3` | Completed with findings, when the caller requested a findings exit |

`--fail-on-risk` on scan/inspect returns 3 when any review flag exists. `--fail-on-change` on diff returns 3 for any fingerprint change. The complete success report is still printed. Input errors take precedence and return 2 without a partial report. These switches are automation signals, not policy enforcement. A consumer closing stdout early is a normal broken pipe and returns 0.

Every error JSON has exactly `schema_version: 1`, a fixed `error` code and a `message` with fixed corrective guidance. Parser failures use `cli_invalid_arguments` without echoing invalid values or paths. Avoid credentials in command arguments: shell history and process listings are outside this output guarantee.

## Success contracts

| Command | Schema | Fields (besides `schema_version`) |
| --- | --- | --- |
| `version` | 1 | `product`, `version`, `config_schema_version` |
| `config check` | 1 | `valid`, validated `config` |
| `mcp scan` | 2 | `sources`, `servers`; [declaration contract](SCANNER.md) |
| `mcp inspect` | 2 | `protocol_version`, `server_name`, `server_version`, `tools_supported`, `tools`; [classification contract](CLASSIFICATION.md) |
| `mcp diff` | 1 | `server_identity_changed`, `server_facts_changed`, `tools_supported_changed`, `tools`; [change contract](FINGERPRINTS.md) |

Ordering is deterministic. Absence, empty lists and unknown capability remain distinct. Labels and hashes are local metadata, not a Platform telemetry contract. Source code, raw arguments/results, schemas/descriptions and credentials are excluded from normal reports.

## Tested examples

From the repository root in PowerShell 7 or a POSIX shell:

```sh
cargo run --locked -- mcp scan --root examples/scanner-project
cargo run --locked -- mcp scan --root examples/scanner-project --details
cargo run --locked -- mcp scan --root examples/scanner-project --json --fail-on-risk
```

The third command intentionally exits 3 for synthetic configuration risks.

```sh
cargo run --locked -p mitigate-mcp-fixture -- launch-config > target/fixture-launch.json
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec --details
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec --json --fail-on-risk
```

The last command intentionally exits 3 for the fixture's open input schema. It does not call tools. After building both programs, run the real-binary contract harness:

```sh
cargo run --locked -p mitigate-mcp-fixture -- cli-contract target/debug/mitigate
```

On Windows append `.exe` to the binary path. This checks actual JSON/human reports, findings exits, empty/unsupported states, bound overrides, stale-override rejection without partial snapshots, and overwrite refusal. CI runs it on all three operating systems, using only temporary synthetic files and the fixture server.

## Recovery

- `cli_invalid_arguments`: run the command with `--help`; inspection requires `--allow-exec`.
- `scan_*` / `config_*`: correct the selected file or limits; invalid present sources fail the entire scan.
- `mcp_configuration_invalid` / `mcp_executable_invalid`: review the [launch schema](ENUMERATION.md), absolute executable and working directory.
- `mcp_classification_invalid`: review overrides against a fresh snapshot; never silently reuse stale classifications.
- `mcp_snapshot_invalid`: use compatible snapshots or a new filename when saving.
- `mcp_cleanup_failed`: inspect the selected server process before retrying; termination could not be confirmed.

The [gateway reference](GATEWAY.md) covers serve, explicit profiles, inventory pagination and shutdown. Gateway enforcement, grants, approvals and Platform synchronization remain later packages.
