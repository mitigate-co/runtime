# Command line reference

Build with `cargo build --workspace --locked`. Run `cargo run --locked -- COMMAND` or `target/debug/mitigate` (`mitigate.exe` on Windows). Local MCP use requires no account. The first build downloads dependencies. Enrollment start/pending retry and explicitly started sync delivery can contact Platform. Selected MCP servers may contact their own destinations; command side effects are listed below.

## Choose a command

| Task | Command | Side effect |
| --- | --- | --- |
| Check installed version | `mitigate version` | None |
| Collect a support report | `mitigate diagnostics --output NEW_FILE --json` | Creates a checked local report; explicit configuration/synthetic checks only; no upload; [contract](DIAGNOSTICS.md) |
| Connect to an organization | `mitigate enroll start --platform ORIGIN --state NEW_FILE` | Prompts for a hidden code, saves a native credential, sends one HTTPS proof; sync stays off; [setup and recovery](ENROLLMENT_CLI.md) |
| Recover enrollment | `mitigate enroll retry --platform ORIGIN --state FILE` | Sends the original pending proof, or returns a confirmed local receipt |
| Inspect enrollment | `mitigate enroll status --platform ORIGIN --state FILE` | Reads local state and native receipt; no network |
| Remove enrollment credential | `mitigate enroll forget --platform ORIGIN --state FILE --confirm` | Deletes the exact native entry; retains the anchor; does not revoke remote access |
| Verify privacy admission | `mitigate privacy self-test` | Creates/removes a private synthetic temporary queue; no network; [details](PRIVACY_COMMANDS.md) |
| Inspect egress fields | `mitigate egress inspect` | Lists supported closed event fields; optional scoped queue inspection is read-only |
| Look up public registry facts | `mitigate registry lookup --catalog FILE --subject NAMESPACE/SERVER` | Reads one explicit public catalog; no network, installation or grant changes; [contract](REGISTRY.md) |
| Validate Runtime limits | `mitigate config check --config FILE` | Reads one local file |
| Find declarations | `mitigate mcp scan --root PROJECT` | Reads documented project configs; no execution/network |
| Review configuration flags | Add `--details` to scan | Same read-only scope |
| Enumerate and classify tools | `mitigate mcp inspect --launch-config FILE --allow-exec` | Executes the reviewed server with your privileges, then stops it; never calls tools |
| Review classification evidence | Add `--details` to inspect | Shows full labels, classes, rules, sources and flags |
| Save fingerprints | Add `--snapshot NEW_FILE` to inspect | Creates a new file; never overwrites |
| Apply reviewed classification | Add `--classification-overrides FILE` to inspect | Reads bound administrator decisions; never grants access |
| Get exact governance references | `mitigate mcp context --launch-config FILE --launch-review FILE --tool-snapshot FILE --profile FILE --allow-exec` | Executes and enumerates the reviewed server, confirms cleanup, prints local references; no tool calls or grant changes |
| Compare fingerprints | `mitigate mcp diff --before FILE --after FILE` | Reads two snapshots; no execution/network |
| Expose an inventory endpoint | `mitigate mcp serve --launch-config FILE --allow-exec --inventory-only` | Executes the reviewed server; serves MCP on stdin/stdout; all tool calls disabled |
| Govern local calls | `mitigate mcp serve --launch-config FILE --launch-review FILE --profile FILE --enforce FILE --allow-exec` | Explicit execution after local policy, grants, approvals, controls and required audit; [configuration](ENFORCEMENT.md) |
| Store a local credential | `mitigate secrets import --stdin` | Reads a pipe into the OS store; returns only a reference |
| Check a local credential | `mitigate secrets check --reference REF` | Reports availability without printing its value |
| Rotate a local credential | `mitigate secrets replace --reference REF --stdin` | Replaces one existing reference using a pipe |
| Delete a local credential | `mitigate secrets delete --reference REF --confirm` | Deletes one reference; already running servers retain their environment |
| Initialize local audit | `mitigate mcp audit init --db NEW_FILE` | Creates a private bounded SQLite database; never overwrites |
| Record inventory decisions | Add `--audit-db FILE` to inventory-only serve | Requires initialized storage; records completed inventory requests and denied calls |
| Verify audit integrity | `mitigate mcp audit verify --db FILE` | Verifies schema and complete retained chain |
| Read audit records | `mitigate mcp audit list --db FILE --limit 50` | Verifies, then exports bounded local metadata |
| Prune expired records | `mitigate mcp audit prune --db FILE --confirm` | Permanently applies stored retention limits |

`--help` works at each command level. Human tables give a compact overview; `--details` shows full labels and review guidance. Long table cells end with `...`. Terminal controls, bidirectional/invisible text and non-ASCII characters are escaped in human labels. JSON retains exact validated labels. Do not parse human tables as an API. Absence of flags does not establish server safety.

## Optional synchronization

For optional synchronization, use the [setup and recovery guide](SYNC_CONTROLS.md).
Enrollment, capture and delivery are separate choices:

| Task | Command | Side effect |
| --- | --- | --- |
| Enable local sync consent | `mitigate sync enable --profile NEW_FILE --enrollment FILE --platform ORIGIN --outbox NEW_FILE` | Creates local profile, catalog and queue; checks confirmed native enrollment; no sending |
| Inspect sync | `mitigate sync status --profile FILE` | Reads local consent and queue counts; no network or credential lookup |
| Capture gateway decisions | Add `--sync-profile FILE` to governed serve | Requires existing consent and a passing privacy probe; admits only typed metadata; no sending |
| Also capture tool inventory | Add `--sync-inventory` with `--sync-profile FILE` | Admits bounded fresh inventory metadata, never scanner reports or raw schemas |
| Send one queued event | `mitigate sync send --profile FILE` | Rechecks consent, native enrollment and exact lease; may send one signed HTTPS event |
| Run the sender | `mitigate sync run --profile FILE` | Foreground delivery until paused, interrupted or failed; never enables consent |
| Pause and drain | `mitigate sync pause --profile FILE` | Commits withdrawal and waits for in-flight delivery; queued events remain |
| Resume consent | `mitigate sync resume --profile FILE` | Checks the original native binding; no automatic capture or sending |
| Purge local queue | `mitigate sync purge --profile FILE --confirm` | Pauses, drains and deletes retained queue payloads; does not delete hosted records |

## Machine output and exits

For report commands, `--json` can appear before or after the command. It emits one complete success document to stdout, with no progress chatter. Input/operational errors use stderr and leave stdout empty. Help and `--version` remain text. `--details` and `--json` conflict because JSON already contains the complete report. `mcp serve` conflicts with `--json`: stdout carries an ongoing MCP session and stderr contains only fixed operational diagnostics. A failed session can follow prior valid protocol responses; report atomicity does not apply to that stream.

| Exit | Meaning |
| --- | --- |
| `0` | Completed, including empty inventories and findings under default behavior |
| `1` | Output could not be written, or privacy self-test completed with a failed assertion |
| `2` | Invalid arguments/configuration, unavailable input, MCP failure, cancellation, incompatible snapshot or stale override |
| `3` | Completed with findings, when the caller requested a findings exit |

`--fail-on-risk` on scan/inspect returns 3 when any review flag exists. `--fail-on-change` on diff returns 3 for any fingerprint change. The complete success report is still printed. Input errors take precedence and return 2 without a partial report. These switches are automation signals, not policy enforcement. A consumer closing stdout early is a normal broken pipe and returns 0.

Every error JSON has exactly `schema_version: 1`, a fixed `error` code and a `message` with fixed corrective guidance. Parser failures use `cli_invalid_arguments` without echoing invalid values or paths. Avoid credentials in command arguments: shell history and process listings are outside this output guarantee.

`diagnostics` returns 0 when collection succeeds, including an unavailable or
failed requested check. Inspect each nested status and `passed` field. A refused
export returns 2 with no report; it does not bypass the privacy gate. See the
[support runbook](SUPPORT.md).

`enroll start --json` requires `--stdin` and a secure pipe. Interactive code entry
uses a hidden terminal prompt only in human mode, so machine output stays closed.

## Success contracts

| Command | Schema | Fields (besides `schema_version`) |
| --- | --- | --- |
| `version` | 1 | `product`, `version`, `config_schema_version` |
| `diagnostics` | 1 | `kind`, `runtime_version`, `operating_system`, `architecture`, `configuration_schema`, `configuration`, `storage_check`; [closed export fields](DIAGNOSTICS.md) |
| `egress inspect` | 3 | `delivery_status`, `destination`, `supported_events`, `observed_event_types`, `observed_schema_versions`, `observed_scope`, `queue`; [pending-only inspection](PRIVACY_COMMANDS.md) |
| `enroll start/retry/status/forget` | 1 | `status`, `sync_enabled`; pending/confirmed add `runtime_ref`, `enrollment_ref`; confirmed adds `enrolled_at_ms`; [contract](ENROLLMENT_CLI.md) |
| `config check` | 1 | `valid`, validated `config` |
| `mcp scan` | 2 | `sources`, `servers`; [declaration contract](SCANNER.md) |
| `mcp inspect` | 2 | `protocol_version`, `server_name`, `server_version`, `tools_supported`, `tools`; [classification contract](CLASSIFICATION.md) |
| `mcp diff` | 1 | `server_identity_changed`, `server_facts_changed`, `tools_supported_changed`, `tools`; [change contract](FINGERPRINTS.md) |
| `mcp context` | 1 | `client_ref`, `principal_ref`, `agent_ref`, `attribution`, `server_ref`, `tools`; [local context contract](GOVERNANCE_CONTEXT.md) |
| `registry lookup` | 1 | `subject`, `found`, `generated_at_ms`, `expires_at_ms`, `checked_at_ms`, `freshness`, `publisher_authenticated`, `grants_access`, `facts`, `sources`; [public claims](REGISTRY.md) |
| `mcp audit init/verify` | 1 | `records`, `payload_bytes`, `anchor_sequence`, `anchor_hash`, `head_sequence`, `head_hash`, `retention` |
| `mcp audit list` | 1 | `anchor_sequence`, `anchor_hash`, `head_sequence`, `records`, `next_after`; [local audit contract](AUDIT.md) |
| `mcp audit prune` | 1 | `removed_records`, nested `verification` report |

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

The [approval reference](APPROVALS.md) documents `mcp approvals init`, `request`,
`list`, `show`, `approve` and `deny`. Operator decisions require `--confirm` and an
explicit declared operator reference. Commands operate only on local metadata;
none consumes an approval or invokes a tool.

The [grant reference](GRANTS.md) documents `mcp grants check --rules FILE` and
`mcp grants test --rules FILE --input FILE`. These validate local rules and resolve
synthetic/administrator-selected metadata without starting a server. Exit 0 also
covers denied/no-match resolutions; exit 2 means invalid or unavailable input.

The [control reference](CONTROLS.md) documents `mcp controls init`, `status`,
`history`, `stop`, `resume`, `apply` and `test`. Changes require an operator
reference and `--confirm`. Test is a read-only preview, never an invocation or
quota reservation. State, counters and bounded operator history remain local.

The [launch review reference](LAUNCH_REVIEW.md) documents `mcp launch review
--launch-config FILE --out FILE` and `mcp launch check --launch-config FILE
--review FILE`. Both read selected code without executing it or retrieving native
credentials. `serve --launch-review FILE` verifies the exact launch and checks
code drift on the live connection. Inventory mode keeps calls disabled; governed
mode additionally requires its complete local authority configuration.

The [policy reference](POLICY.md) documents `mcp policy check`, `test`, `keygen`,
`sign`, `init`, `activate`, `status` and `evaluate`. Source tests do not invoke
tools. Stored evaluation requires a separately pinned authority and verified
bundle. Source, raw metadata values and private keys are omitted from reports.

- `cli_invalid_arguments`: run the command with `--help`; inspection requires `--allow-exec`.
- `scan_*` / `config_*`: correct the selected file or limits; invalid present sources fail the entire scan.
- `mcp_configuration_invalid` / `mcp_executable_invalid`: review the [launch schema](ENUMERATION.md), absolute executable and working directory.
- `mcp_classification_invalid`: review overrides against a fresh snapshot; never silently reuse stale classifications.
- `mcp_snapshot_invalid`: use compatible snapshots or a new filename when saving.
- `mcp_cleanup_failed`: inspect the selected server process before retrying; termination could not be confirmed.
- `mcp_launch_review_invalid`: use a valid private review or a new output path; check selected artifact paths and limits.
- `mcp_launch_changed`: inspect changed executable/code/configuration/environment before creating a fresh review; do not silently reuse old grants.
- `audit_integrity_failed`: preserve the database; investigate without resetting or overwriting.
- `audit_unavailable`: check disk space, competing writers and permissions; verify before retrying.
- `policy_profile_invalid`: check the restricted Rego syntax and resource bounds.
- `policy_bundle_unverified`: verify the independently pinned public key and signed manifest.
- `policy_version_rejected`: use a higher signed version; inspect current status after uncertain writes.
- `policy_evaluation_failed`: execution is not authorized; review overlapping rules and retry.
- `policy_signing_key_unavailable`: check the native key reference and unlock the OS store.
- `grant_rules_invalid`: correct missing/unknown scope fields, duplicate references, class lists or time windows; no rules were accepted.
- `grant_context_invalid`: provide closed action metadata, nonempty classes and explicit nulls for unknown identity.
- `grant_file_unavailable`: check file type, size and permissions; no source values are echoed.
- `approval_state_conflict`: inspect current state; expired/terminal approvals cannot be reused.
- `approval_store_unavailable`: preserve corrupt state; check storage and permissions before retrying.
- `approval_clock_invalid`: correct the system clock; do not reset approval state to bypass the check.
- `approval_capacity_reached`: resolve active requests; active approvals are never evicted to admit new ones.
- `control_store_unavailable`: keep admission closed; inspect access, disk space and integrity without resetting the database.
- `control_clock_rejected`: restore trustworthy time; do not reset counters to bypass rollback detection.
- `control_input_invalid`: correct the exact target/action or rate bounds; unknown fields are rejected.
- `control_capacity_reached`: review existing configured targets before adding another.
- `gateway_governance_invalid`: check the explicit governance document, pinned authority, grants, reviewed snapshot and initialized databases.
- `gateway_review_changed`: inspect observed definitions and overrides before starting a newly reviewed connection.
- `gateway_cleanup_unavailable`: inspect approvals and audit after failed cleanup; do not assume the prior call can be replayed.

The [gateway reference](GATEWAY.md) covers serve, explicit profiles, inventory
pagination and shutdown. [Governed calls](ENFORCEMENT.md) document live authority
and failure semantics. [Optional sync](SYNC_CONTROLS.md) requires explicit
enrollment, consent, capture and delivery; local scanning and governance remain
available without Platform. See [implementation status](IMPLEMENTATION.md) for
the remaining release and hosted-provider gates.
