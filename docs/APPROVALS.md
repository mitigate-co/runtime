# Local MCP approvals

Approvals are local, metadata-only and valid for **one call**. An operator decision
never executes a tool by itself. The [governed gateway](ENFORCEMENT.md) joins
approval waiting and consumption with reviewed launch, policy, grants and limits.
The library and CLI support review and decisions independently of Platform.

## Try the local workflow

Build with `cargo build --locked`. Use a private local directory for the database.
The context below is synthetic and does not refer to an executing tool.

```sh
mitigate mcp approvals init --db approvals.db
mitigate mcp approvals request --db approvals.db --context examples/approvals/context.json --expires-in-seconds 60 --json
mitigate mcp approvals list --db approvals.db
```

Copy the returned `approval_ref` as `REFERENCE`. Inspect that exact request before
deciding. `OPERATOR_REF` is your explicitly declared local operator reference,
encoded as 64 lowercase hexadecimal characters; it is not a secret or evidence of
directory authentication. Do not enter tokens, names or email addresses here.

```sh
mitigate mcp approvals show --db approvals.db --reference REFERENCE --json
mitigate mcp approvals approve --db approvals.db --reference REFERENCE --operator-ref OPERATOR_REF --confirm
mitigate mcp approvals deny --db approvals.db --reference REFERENCE --operator-ref OPERATOR_REF --confirm
```

`deny` can revoke an approval before the gateway consumes it. Both the original
approval and subsequent denial remain in the bounded local record. A consumed call
cannot be revoked retroactively. There is no CLI command to consume or dispatch a
tool. Repeating the example request with the same session/call pair is rejected
while the old record is retained. Real gateway requests must generate fresh random
session and call references rather than copying this fixture.

## State and scope

| State | Possible next states |
| --- | --- |
| `requested` | `approved`, `denied`, `expired`, `cancelled` |
| `approved` | `consumed`, `denied`, `expired`, `cancelled` |
| `denied`, `expired`, `cancelled`, `consumed` | Terminal; cannot be approved again |

Every binding includes a known client, optional principal/agent, fresh random
session and call references, reviewed server/tool references, input schema and
complete definition fingerprints, policy reference/version/exact bundle hash,
capabilities and environment. See [the example](../examples/approvals/context.json)
for the closed version-one schema. Principal, agent and environment must be
explicitly null when unknown. References are 64 lowercase hexadecimal characters;
policy version is a positive safe integer. Capabilities are nonempty, unique and
sorted for comparison. Environment uses the same bounded exact label as grants.

The gateway must keep the corresponding tool arguments immutable in memory for
that invocation. Fresh random call references bind approvals without storing raw
arguments or deterministic hashes of predictable argument values. Nothing in an
MCP message can choose the approval binding. A changed identity, session, call,
server, tool, schema, definition, policy, capability set or environment cancels a
still-active request before consumption. Changing only capability order does not
change its meaning.

Validity starts at creation and ends exclusively at the expiry timestamp, at most
five minutes later. CLI requests accept 1–300 seconds, defaulting to 60; the library
accepts 100–300,000 milliseconds. Approval does not extend that window. Initially
only one-call scope is supported: no reusable tool, session or permanent approvals.

## Gateway API and failure contract

`ApprovalStore::request` creates a bounded request. An operator uses `decide` or the
CLI to approve/deny. `get` and `list` apply expiry before returning metadata.
`cancel` terminates requests on caller cancellation or session shutdown.

After waiting, the gateway must recheck its current grant, policy, schema, emergency
and rate controls, then call `consume` with the exact current binding. A changed
binding cancels the request. A still-requested call returns `Pending`; terminal
states return `Unavailable`. Only a still-valid approved request can return a
non-cloneable `Permit`, after `consumed` commits durably. Competing consumers cannot
both receive a permit. The permit identifies the approving operator for local audit
and satisfies only the approval check. It is not general authorization.

The asynchronous gateway must own synchronous storage on a blocking worker and
bound its wait with a monotonic deadline no longer than the request validity.
Cancellation, policy refresh and schema drift require rechecks before dispatch.
This package supplies the state/CLI/storage boundary; [governed mode](ENFORCEMENT.md)
implements bounded waiting and rechecks. The existing inventory endpoint remains
explicitly unable to execute calls.

Storage errors return no permit. Consumption occurs **before dispatch**, so a crash
after consumption can leave a call unexecuted or its outcome uncertain. Never
automatically retry that call with the old approval. Restart creates a fresh gateway
session; old approvals do not apply to its calls. Missing or unavailable local
approval storage fails closed; no Platform request or permissive fallback occurs.

## Storage and attribution

Production operations pass `mitigate_policy::SystemClock`. The store observes
UTC time after acquiring its transaction, so concurrent operator/gateway work
cannot reorder pre-lock samples. Explicit `u64` observations remain available
for deterministic simulations. Genuine backward time, unavailable time and
expired approvals still fail closed; no tolerance or clock clamping is used.
See [ADR 0023](decisions/0023-transactional-clock-observation.md).

The store is a separate SQLite database: private `0600` file on Unix, inherited
parent-directory ACL on Windows, regular-file checks, bounded SQL execution,
250 ms busy timeout, full synchronous rollback-journal transactions, fixed schema
and bounded metadata records. Use a protected parent directory on a filesystem that
supports permissions. WSL NTFS mounts without permission metadata are unsuitable
for private runtime state; use a Linux directory.

Maximum size is 2 MiB of database pages plus a bounded rollback journal. The store
holds at most 256 records, each at most 4 KiB. Never evict an active request to make
room. A new request may evict the oldest terminal record when full; otherwise
terminal records expire after 24 hours from their terminal transition. All-active
capacity exhaustion rejects new requests. There are at most two operator decisions
per record: initial choice and optional revocation. Approval records are a bounded
local mailbox/history, not a substitute for the gateway's retained audit log.

Each operation verifies stored schema and records, applies expiry, and advances a
persisted nondecreasing clock. Clock observations older than the last committed
one fail closed, including out-of-order concurrent observations. Read/decision
commands use current system time. Fix a clock error before retrying; do not reset
the database to bypass it. An observed expiry commits even if an attempted operator
transition is rejected. Parent-directory replacement or whole-database rollback by
a privileged same-user attacker remains outside this protection.

Only administrator-trusted processes may access the store. The CLI records operator
attribution as `declared_local`; it does not authenticate the supplied reference or
provide separation from another process running with the same OS privileges.
Protecting against such a process requires an additional OS/service authentication
boundary. Never present these declarations as verified human identity.

Records contain no arguments, results, descriptions, arbitrary metadata, credentials
or free-form comments. Unknown fields and duplicate JSON keys are rejected. Reference
hashes remain customer-local correlation data, not anonymization. This schema must
not be sent directly to Platform; optional sync uses its separate egress contract.

## Verification and recovery

```sh
cargo test -p mitigate-policy
python scripts/verify-approvals.py target/debug/mitigate
```

Tests cover restart, duplicate decisions, replay, simultaneous consumers, expiry,
clock rollback, every binding dimension, cancellation, denial/revocation history,
storage contention/corruption/capacity, failed commit, full database, schema
tampering and private files. The actual CLI fixture uses a temporary synthetic
database and verifies that rejected raw-content canaries reach neither output nor
storage. CI runs it on Windows, macOS and Linux.

Exit 0 means the metadata operation completed, not that a tool ran. Exit 2 means a
rejected or unavailable operation; JSON errors go to stderr with empty stdout.
`approval_state_conflict` means inspect current state. `approval_missing` means the
reference is absent or was retained only temporarily. For storage corruption,
preserve the database for investigation and do not recreate it automatically.
Approval from an old backup is never sufficient for a newly started session.
