# Local stops and rate limits

`mitigate mcp controls` manages a private local control database. It works without
Platform, network access or credentials. These controls restrict admission; they
never grant permission or invoke tools. The executable gateway still requires
inventory-only mode while the enforcing composition is completed.

## Try the local workflow

The examples contain synthetic references. Use a fresh database path:

```sh
mitigate mcp controls init --db controls.db
mitigate mcp controls status --db controls.db --json
mitigate mcp controls stop --db controls.db --operator-ref eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --confirm
mitigate mcp controls test --db controls.db --context examples/controls/context.json --json
mitigate mcp controls resume --db controls.db --operator-ref eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --confirm
mitigate mcp controls apply --db controls.db --change examples/controls/limit.json --operator-ref eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --confirm
mitigate mcp controls apply --db controls.db --change examples/controls/disable.json --operator-ref eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --confirm
mitigate mcp controls history --db controls.db --json
```

`stop` blocks new admissions. `resume` clears that global stop while preserving
individual disables and rate limits. Already-dispatched effects cannot be undone.
`test` previews metadata against current controls without charging any quota or
changing stored state. Its result can race with real admissions or administrator
changes and must never authorize a tool call. It does not test grants or policy.

Every mutation requires `--operator-ref` and `--confirm`. The operator reference
is exactly 64 lowercase hexadecimal characters. It is declared attribution;
ownership of the local database is the write-authorization boundary. Do not use
an email address, person name, credential, or raw MCP value as a reference.

## Change format

`apply --change FILE` accepts one strict JSON object, at most 4 KiB. Duplicate or
unknown fields are rejected, including extra fields on empty actions/targets.

| Action | Additional fields | Effect |
| --- | --- | --- |
| `stop` | None | Emergency deny-all |
| `resume` | None | Clear emergency stop |
| `disable` | `target` | Disable exact non-global target |
| `enable` | `target` | Remove that exact disable |
| `set_limit` | `target`, `rate` | Create or replace a shared token bucket |
| `remove_limit` | `target` | Explicitly remove that bucket |

Targets use a closed `kind` tag. `global` has no other fields and is only valid
for quotas. `client`, `principal`, `agent` and `server` require `reference`.
`tool` requires both `server` and `tool` references. All references are exactly
64 lowercase hexadecimal characters. There are no names, globs, implied roles,
or caller-controlled dynamic bucket creation.

A `rate` has exactly `capacity` (1–1,000,000), `refill_tokens` (1–1,000,000) and
`period_ms` (1–86,400,000). A new bucket starts at its burst capacity. Every
admitted call costs one token from every matching bucket. Refill is continuous,
computed with integer sub-token units and bounded to capacity. For example,
three tokens per 1,000 ms earns the first full token after 334 ms from empty;
fractional tokens carry forward.

Disables win before quota checks. If any matching bucket is depleted, none of
the matching buckets is charged. `retry_after_ms` is the earliest possible
retry, not a reservation: competing calls and configuration changes may extend
it. Runtime must never retry an upstream tool automatically.

Unchanged rate configuration does not reset a bucket. Changing its rate preserves
the currently earned token balance, rounds down conversion between unit scales
and caps it to the new burst. Increasing burst capacity does not refill it.
An explicit remove/re-add intentionally creates a new bucket and records both
administrator changes. Stop/resume neither removes nor replenishes buckets.

## Context and enforcement boundary

The diagnostic context is a closed 4 KiB JSON object with `schema_version: 1`,
`client`, `principal`, `agent`, `server`, and `tool`. The three identity fields
must be present, using null for unknown identity. A known identity target does
not match an unknown subject. Global and server/tool controls still match;
grants independently require an explicitly mapped client before allowing action.

Library `ControlStore::admit` receives trusted gateway facts and UTC Unix
milliseconds. It re-reads current control state, checks disables, calculates all
quotas and commits consumption atomically before returning `Allowed`. Separate
processes sharing this database cannot overspend the same bucket. The gateway
must enforce grants, policy, exact launch/schema binding, approval and required
audit independently, then check controls immediately before dispatch. Never use
a cached preview as a permit. An admitted call stays charged when a later check
or upstream call fails; automatic refunds would enable quota bypass.

## Storage and recovery

The database allows 256 disabled targets, 128 configured buckets and the most
recent 256 administrator changes. Each actual change increments a monotonic
revision and records its time, fixed action and declared operator. The first
retained revision identifies history pruning. Reapplying an identical setting
does not change its revision or erase a quota. There are no raw payloads, tokens,
free-form notes, server descriptions or arbitrary metadata fields.

The SQLite file is limited to 4 MiB (plus its bounded rollback journal), uses
full synchronous transactions and checks exact schema, bounded records and
history continuity on every operation. Its clock high-water mark survives
restarts and denied admissions. Older timestamps fail closed. Wall-clock jumps
forward may earn refill up to capacity; a bad clock must be corrected rather
than bypassed by deleting the database. Use trustworthy OS time. A privileged
same-user attacker restoring an entire old file remains outside this guarantee.
History is local metadata, not signed remote attestation.

Use a protected parent directory. Files are created exclusively with Unix 0600
permissions; Windows uses inherited directory ACLs. Final-component symlinks and
reparse points are rejected. This does not protect against privileged path races
or writes by the database owner. Missing/corrupt/busy/full storage is an error,
never an automatic empty configuration. Investigate access, disk capacity,
clock and integrity errors while keeping the gateway closed to calls.

Exit 0 means the requested diagnostic/administrative operation completed, even
when a preview says disabled or rate-limited. Exit 2 is invalid input or a
control failure; exit 1 is output failure. JSON reports and errors use the
versioned CLI contract. No raw backend errors, file paths or rejected input are
printed. Failed/uncertain commits return no admission result.

`python scripts/verify-controls.py PATH_TO_MITIGATE` exercises these real CLI
commands with synthetic fixtures, confirmations, restarts and privacy canaries.
Unit tests also cover concurrent admission, exact refill boundaries, quota
reconfiguration, emergency precedence, unknown identity, clock rollback,
bounded history, corrupt storage, full disk and aborted commits.
