# Local audit

## Governed-call records

Version-two events add a closed `call` context with session/call references,
phase, complete-definition and exact signed-policy-bundle references, and optional
operator attribution. References remain local; no raw arguments/results, argument
hashes, comments or arbitrary metadata are stored. Existing version-one events
retain their exact encoding and hashes, with no `call` field added.

The phases are `decision` (refused before invocation), `approval_pending`,
`dispatch` (authorization recorded before an attempt) and `completion` (observed
outcome). Dispatch requires known caller/resolved tool/policy facts and, when
approval is referenced, the approving operator. Operator attribution is
`declared_local`, not authenticated identity. `allow_and_log`, `rate_limit`,
`disable_tool` and the `uncertain` outcome are version-two vocabulary.

`AuditStore::append_call` commits these records through the existing atomic
append/retention path. It does not authorize or execute a call. A dispatch without
completion means the outcome is unknown; never assume a retry is safe. Earlier
phases can also be absent due to retention. The gateway owns lifecycle consistency.

Mixed-version chains need no table migration or rewrite. Older binaries refuse
version-two records; preserve the database during rollback. Never remove records
to make an older reader accept it. See [ADR 0020](decisions/0020-versioned-local-call-audit.md).

Synthetic CLI demonstration after building `mitigate`:

```sh
cargo run --locked -p mitigate-mcp-fixture -- audit-contract target/debug/mitigate
```

Use `target/debug/mitigate.exe` on Windows. The fixture writes only temporary
synthetic metadata and makes no real MCP invocation. The ordinary `serve` CLI
still runs in inventory-only mode until governance composition is complete.

MCP-010 provides durable local metadata storage and opt-in recording for the
inventory-only gateway. No Platform account or network service is involved.
Raw arguments, results, descriptions, schemas, credentials, MCP metadata and
free-form error messages are never audit fields. Raw-content recording is not
implemented.

## Start recording

Choose a private local directory. On Windows protect it with the current user's
ACL; new files inherit that ACL. On Unix new files use mode 0600 and reopening
rejects group/other access. Do not use a shared directory or network filesystem.

```sh
mitigate mcp audit init --db target/audit.sqlite
mitigate mcp serve --launch-config target/fixture-launch.json --allow-exec --inventory-only --audit-db target/audit.sqlite
```

`init` creates a new file exclusively. `serve` requires an existing initialized
database and verifies it before executing the upstream. No default path is
discovered or created. The serve command is an MCP stdio endpoint; configure the
client to launch it, or use the contract harness below.

Completed tool-list requests and denied tool calls are recorded before returning
their response. Audit failures return fixed MCP error `-32007`; no success is
returned without a committed record. All calls remain disabled (`-32006`) even
when auditing is healthy. A blocked upstream request, malformed protocol message,
startup failure or cancelled in-flight request may have no completion record.
This inventory-only integration is not a complete enforcement activity trail.
The later enforcing call path must commit a decision before invocation and bind
completion/cancellation to it. Those gates are still open.

When `serve --launch-review FILE` is supplied, `server_ref` is the verified local
launch reference and tool references are scoped to it. Without a review the
inventory-only path retains its legacy server-declared identity fingerprint.
Neither is publisher authentication. This opt-in use of the existing opaque
reference fields does not migrate or rewrite stored event/hash-chain records.

## Read and verify

```sh
mitigate mcp audit verify --db target/audit.sqlite --json
mitigate mcp audit list --db target/audit.sqlite --limit 50 --json
mitigate mcp audit list --db target/audit.sqlite --after 50 --limit 50 --json
mitigate mcp audit prune --db target/audit.sqlite --confirm --json
```

Use the returned `next_after` value to continue a page; the example `50` applies
only when that is the returned cursor. Each page verifies the entire retained
chain first. A corrupt database produces no partial report. Pages are independent
read transactions, so retention can advance between them. `anchor_sequence` and
`anchor_hash` expose the removed prefix; `head_sequence` identifies the current
tail. An empty database/history is a successful result.

Logical reads open SQLite for read/write recovery and connection configuration;
they do not append or delete events. Filesystem modification times are not an
integrity signal. `prune --confirm` explicitly deletes expired records. No command
accepts arbitrary SQL, imported events, raw evidence, a schema upgrade, or reset.

## Records and bounds

Local record v1 has `sequence`, `previous_hash`, `hash` and `event`. The event has
`schema_version`, a random 128-bit hex `event_id`, `time_ms` and closed `detail`:

- operation: `inventory` or `tool_call`;
- optional client/principal/agent references and `unknown`/`declared_profile` attribution;
- server/tool references, optional input schema fingerprint, at most 11 distinct capability classes;
- optional policy reference/version, decision, approval reference;
- closed result class, duration up to one day, optional local evidence reference.

Decisions are `inventory_only`, `allow`, `deny`, `require_approval` or `error`.
Results are `pending`, `success`, `error`, `cancelled` or `not_invoked`. The current
inventory endpoint never records an allowed tool invocation. Policy/approval
fields remain null until those systems are implemented and actually evaluated.
Tool fingerprints describe the last observed inventory, not executable provenance.

Explicit profile references are hashed with distinct client/principal/agent
domains. Missing attribution remains null/unknown. Raw tool names are omitted.
All references are local correlation metadata: hashing does not make them
anonymous, authenticated, or eligible for Platform telemetry. Event fields are
validated before writes and again on reads; unknown fields are rejected.

| Limit | Default | Accepted range / hard limit |
| --- | --- | --- |
| Retained records | 10,000 | 1–100,000 |
| Age | 30 days | CLI: 1–365 days; library: 1 second–365 days |
| Encoded event bytes | 16 MiB | 4 KiB–64 MiB |
| Individual encoded event | — | 4 KiB |
| SQLite database pages | — | 128 MiB |
| Export page | 50 | 1–250 records |
| SQLite contention wait | — | 250 ms |
| SQL/verification budget | — | 5 seconds per operation |

Select retention at initialization with `--max-records`, `--max-age-days` and
`--max-payload-bytes`. There is no implicit policy replacement on reopen. The
oldest contiguous prefix rotates on append or explicit prune. The sequence never
resets. The event/retention clock is clamped to the most recent stored time when
the OS clock moves backwards. An idle closed database has no retention scheduler.

SQLite uses DELETE journaling, FULL synchronous commits, secure_delete and FULL
auto-vacuum. Database pages are reclaimed during rotation. Temporary rollback
journals can consume approximately another database's size during a transaction;
keep free disk space accordingly. This is not secure erasure of filesystem
snapshots, SSD history or backups. No WAL or network storage is used.

## Integrity and recovery

Records bind their sequence, previous hash and canonical event using a versioned
SHA-256 domain. Retention keeps the last removed hash as an anchor. Full verification
runs on open, explicit verify/prune, export, and when another SQLite writer changes
the file before append. The exact supported schema is checked before writes;
unexpected tables, views, indexes, triggers or versions fail.

This detects unrecomputed edits, missing records and corruption. It cannot detect
a full rewrite with recomputed hashes, a forged checkpoint, deletion of the whole
file, or rollback to an older valid copy by someone controlling local storage.
Protect the directory; this is not remote attestation or a signed ledger.

`audit_integrity_failed`: preserve the file and investigate. Do not automatically
reset, repair or overwrite it. `audit_unavailable`: check disk space, locks and
permissions, then verify before retrying. A failed commit can have an uncertain
durability outcome; absence of a returned event is never permission to execute.
`audit_path_invalid`: select a regular private file, or a new path for init.
Errors omit SQLite messages, paths and source values.

## Verification

After building both binaries:

```sh
cargo test --locked -p mitigate-audit
cargo run --locked -p mitigate-mcp-fixture -- gateway-contract target/debug/mitigate
```

Append `.exe` to the CLI path on Windows. The harness uses synthetic temporary
files and checks real audit commands, actual gateway writes, unavailable storage,
denial without invocation, corruption rejection before launch, and absence of
argument/metadata canaries in the database and reports. Unit tests cover byte,
count and age rotation, clock rollback, private files, schema injection, competing
writers, full storage and integrity failures. See ADR 0013 for dependency review.
