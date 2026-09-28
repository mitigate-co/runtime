# Closed sync event candidates

`mitigate-egress` validates the first optional Platform event contract. It has no
sender, enrollment, durable queue or egress journal yet; validating a candidate
does not authorize delivery. Local audit/snapshot exports are not accepted events.
See [ADR 0024](decisions/0024-closed-events-before-durable-sync.md).

## Version 1: `mcp_tool_decision`

The top-level object has exactly six required fields:

| Field | Contract |
| --- | --- |
| `schema_version` | Integer `1` |
| `event_type` | `mcp_tool_decision` |
| `event_id` | Stable opaque identifier used for idempotent retries |
| `occurred_at_ms` | Trusted UTC Unix milliseconds, 0 through 253402300799999 |
| `runtime_ref` | Opaque enrollment-scoped runtime mapping |
| `facts` | The exact decision object below; never arbitrary metadata |

Every reference has `ref_` followed by 32 lowercase hexadecimal characters.
Generate it independently using the OS random source. Retain a customer-local
mapping and rotate it on reenrollment. Never reuse local audit fingerprints,
hash a customer label/value into it, or copy an MCP-supplied identifier.
Identifiers are correlation metadata, not authentication or anonymity.

`facts` contains exactly:

| Field | Contract |
| --- | --- |
| `call_ref`, `server_ref` | Opaque mappings |
| `client_ref`, `principal_ref`, `agent_ref` | Opaque mappings or explicit `null` |
| `attribution` | `unknown` or `declared_profile` |
| `tool_ref`, `schema_ref` | Opaque tool/revision mappings; both known or both `null` |
| `capabilities` | Up to eleven distinct taxonomy labels, canonically sorted |
| `policy_ref`, `policy_version` | Mapping and positive integer through 9007199254740991, or both `null` |
| `approval_ref` | Opaque mapping or explicit `null` |
| `phase` | `decision`, `approval_pending`, `dispatch`, `completion` |
| `decision` | `allow_and_log`, `deny`, `require_approval`, `rate_limit`, `disable_tool`, `error` |
| `outcome` | `pending`, `success`, `error`, `cancelled`, `not_invoked`, `uncertain` |
| `duration_ms` | Monotonic elapsed integer, 0 through 86400000 |

Capability labels are `read_data`, `write_data`, `delete_data`, `execute_code`,
`credential_access`, `external_communication`, `browser_action`, `identity_admin`,
`financial_action`, `infrastructure_change`, `unknown`. They describe capability,
not permission or proof of a server's implementation.

Unknown attribution requires all caller mappings to be null. A declared profile
requires a client mapping. Unresolved tools have no capabilities. Approval,
dispatch and completion require a known client/tool/policy and nonempty classes.
Decisions before dispatch have a refusal/error and `not_invoked`; pending approvals
have an approval reference and `pending`; dispatch has `allow_and_log` and `pending`;
completion has `allow_and_log` and a terminal observed outcome. These are per-event
checks, not an authenticated lifecycle or proof of execution.

The untrusted and canonical forms are each limited to 4096 bytes. Duplicate keys,
unknown/missing fields (including missing nulls), unsupported versions, excessive
nesting and inconsistent facts are rejected. Prohibited content fields are rejected
even when empty or nested. No names, paths, descriptions, schema bodies/digests,
tool arguments/results, evidence locations, arbitrary strings or embeddings exist.
All string values must match an exact enum or opaque-reference shape; there is no
free-text field for a secret-pattern scanner to accept by mistake.

## Validate a synthetic fixture

```sh
cargo run -p mitigate-egress --example check --locked < examples/egress/decision.json
```

PowerShell:

```powershell
Get-Content -Raw examples/egress/decision.json | cargo run -p mitigate-egress --example check --locked
```

The development example prints only type, version, canonical byte count and fixed
field paths. It neither persists nor sends the event. Its repeated reference values
are synthetic fixtures, not valid identifiers to reuse in enrollment. Rejection
prints a fixed category and exits 2 without echoing the candidate.

Tests cover the documented fixture, canonical round trips, every required/unknown
field, prohibited nested keys, secret/token/PII/code/high-entropy text in every
reference/enum position, malformed JSON, bounds, identity and lifecycle semantics.
