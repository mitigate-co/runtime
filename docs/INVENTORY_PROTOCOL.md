# Bounded inventory observation protocol

`mitigate_egress::inventory::CheckedPart` validates individual parts and the pure
assembler requires complete observations. `CheckedEvent` accepts those same
closed parts into the existing consent, journal, outbox and signing boundary.
The inspector reports exact retained pending types. Live inventory capture and
hosted inventory ingestion remain unimplemented: this preparation does not start
a producer or sender. An older receiver rejects inventory under its existing
permanent schema-refusal behavior; do not enable a producer before receiver rollout.

## Version 2: `mcp_inventory_snapshot`

Each part has exactly six fields: `schema_version` integer `2`, `event_type`
`mcp_inventory_snapshot`, `event_id`, `occurred_at_ms`, `runtime_ref` and `facts`.
References retain the independent random `ref_` plus 32 lowercase hex contract.
The event ID is fresh per part; the runtime mapping belongs to one enrollment.
Observation time is the same trusted UTC millisecond value across all parts and
is bounded through the last millisecond of year 9999. It is not a retention clock.
Version-one decision events and version-two inventory parts cannot substitute
for one another.

The exact `facts` object contains:

| Field | Contract |
| --- | --- |
| `snapshot_ref` | Fresh independent random reference shared by this observation's parts |
| `server_ref` | Enrollment-scoped random mapping for the local server identity |
| `tools_supported` | Boolean advertised capability; false requires zero tools |
| `tool_count` | Integer 0–512, matching the current local enumerator's bound |
| `part_index` | Zero-based index, smaller than the required part count |
| `tools` | Exactly four tools per part except the final remainder; zero for the sole empty part |

Required parts are `max(1, ceil(tool_count / 4))`, at most 128. The producer sorts
the complete observed inventory by opaque tool reference before splitting it.
Sorting opaque references avoids exporting local tool-name ordering. Each part
and its canonical serialization fit the existing 4096-byte limit, including a
four-tool part with every supported capability and review flag.

Each tool has exactly `tool_ref`, `schema_ref`, `capabilities`, `risk_flags`,
`classification_sources` and `confidence`. The tool reference is a persistent
local mapping; the schema reference maps the locally observed definition revision
and never exports its hash. There are no names, description text, schema bodies,
arguments, results, executable/configuration paths, raw fingerprints or arbitrary
metadata. This permits observations of changed revisions, not reconstruction of
the customer's schema.

Capabilities use the existing eleven-label taxonomy, with one to eleven distinct
values. The seven supported review flags are `destructive`, `credential_access`,
`arbitrary_code_execution`, `external_communication`, `identity_admin`,
`infrastructure_change` and `unknown_high_impact`. An empty flag list is valid;
flags retain the conservative union even when an administrator overrides an
effective capability. No inference rule IDs or matched property values are sent.

Classification sources are `deterministic` and optionally `admin`, matching the
currently implemented local classifier. Confidence is `low` or `medium` for
deterministic evidence, or `high` when an administrator declaration contributes.
The deterministic source is always retained. Unknown/future source labels are
rejected. These are reported local evidence, not authenticated enterprise identity,
remote implementation verification, a safety score or a permission grant.

Tools sort by reference; capability, flag and source arrays sort by their fixed
enum order. Duplicate values, missing/null/unknown fields, ambiguous/deep JSON,
unsupported versions, arbitrary text, inconsistent counts and excessive input
or canonical size are refused. Rejection retains no input or parser exception.

## Completeness and receiver obligations

`CheckedSnapshot::from_parts` is a pure bounded assembler. It accepts at most 128
checked parts in any arrival order and releases a snapshot only when there is
exactly one part for every required index. Runtime/server/snapshot identity,
observation time, tools-supported flag and total count must agree. Part event IDs
must be distinct. Tool references must be globally ordered and distinct across
parts. It distinguishes incomplete, conflicting and excessive input; none yields
a partial success. Zero tools is an explicit complete observation, distinct from
receiving no parts at all or a server not advertising tools.

Before assembly, the hosted receiver must authenticate and verify each signed
event, bind it to the same active enrollment and tenant, enforce arrival/retention
and capacity limits, durably deduplicate exact retries and refuse changed bytes
for an existing part/event identity. A same-shaped opaque reference is not proof
of authority. Conflicting duplicate parts must never be silently overwritten.
Assembly does not perform any of those storage/authentication operations.

The fleet view must distinguish the last complete observation from newer partial
uploads and from no observation. Missing or expired parts cannot imply zero tools,
tool deletion or a healthy/up-to-date Runtime. A complete snapshot describes that
server at its observation time; it does not prove current installation or fleet
coverage. Separate observations must not be merged to fill gaps. Schema-change
presentation may compare complete observations, with their actual times and
coverage limitations visible.

## Demonstration and checks

```sh
cargo run -p mitigate-egress --example inventory --locked < examples/egress/inventory-part.json
cargo test -p mitigate-egress --locked
```

PowerShell can pipe `Get-Content -Raw examples/egress/inventory-part.json` into the
same Cargo example without the shell redirection. The example outputs only fixed
type/version and safe counts, explicitly reporting no admission or network
requests. Its repeated references are synthetic and must not be reused by an
actual producer.

Tests exercise exact nested fields, nulls, duplicate JSON keys, unsupported
versions, all reference/enum positions with synthetic sensitive strings, every
inventory size through 512, numeric and collection limits, full-taxonomy size,
canonical sorting and classification consistency. Assembly tests cover empty and
maximum-size observations, reordered arrival, missing parts, mixed identity/time,
count conflicts, repeated events/tools and global-order violations. Existing
decision validation remains unchanged. Both kinds share partition, consent,
capacity, lease, retry, receipt and retention rules. An event ID cannot be reused
across kinds with different bytes. The privacy probe exercises both kinds through
actual admission. No dependency or stored queue schema changes; inspector output
version 3 and queue report version 2 describe pending types explicitly.

Existing stores require no migration. An older binary rejects a queue containing
v2 parts as unsupported state; it must not reinterpret or discard them. Before
downgrading, use the current binary to pause and drain or explicitly purge that
queue. Existing v1 event/signature bytes remain compatible. The outer signature
envelope stays v1 and binds the full nested event, including its own type/version.
