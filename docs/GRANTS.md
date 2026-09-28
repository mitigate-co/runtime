# Local MCP grants

`mcp grants` validates administrator-owned grant rules and tests action metadata.
It does not start servers or authorize execution. `mcp serve` still requires
`--inventory-only`; enforcing composition with policy, exact launch binding,
schema checks, approval and limits remains a launch gate.

```sh
mitigate mcp grants check --rules examples/grants/read-development.json
mitigate mcp grants test --rules examples/grants/read-development.json --input examples/grants/read-context.json --json
```

Both examples use synthetic references. The test resolves to `explicit` because
the client and server match, the environment is `development`, and the action
only reads data. Changing its capabilities to include `delete_data` resolves to
`denied`. No tool is invoked by either command.

## Rule document

The root contains exactly `schema_version: 1` and `grants`, an array of at most
64 rules. Total UTF-8 file size is at most 32 KiB. Empty sets are valid and grant
nothing. Every rule has exactly:

- `grant_ref`: a unique opaque reference, encoded as 64 lowercase hexadecimal
  characters. Treat this as an identifier, not a secret or authentication proof.
- `effect`: `allow` or `deny`.
- `scope`: the fields listed below. All must be present. An omitted field is an
  error, never an implicit wildcard.

| Scope field | Exact constraint | Explicit `null` |
| --- | --- | --- |
| `client`, `principal`, `agent` | 64-character lowercase reference | Any value, including unknown; the known-client rule still applies |
| `server`, `tool` | 64-character lowercase reference | Any server/tool |
| `capabilities` | Nonempty unique list from the capability taxonomy | Any class, including `unknown` |
| `environment` | Case-sensitive 1–64 character label: ASCII letters, digits, `_`, `.`, `-` | Any environment, including unknown |
| `not_before_ms` | Inclusive UTC Unix millisecond start | No lower time bound |
| `expires_at_ms` | Exclusive UTC Unix millisecond end | No upper time bound |

All non-null constraints in a rule must match together. Times must be integers
from zero through 9,007,199,254,740,991; an end must be greater than its start
(or zero when there is no start). There are no priorities, regexes, role
inheritance, source paths, payload predicates or exceptions to denial precedence.
Duplicate keys, duplicate grant references, duplicate classes, unknown fields,
unknown effects and unsupported versions reject the entire document.

## Deterministic resolution

1. Validate the action context. Invalid context is an error and never an allowance.
2. Find matching denials. For a denial's capability constraint, **any overlap**
   with the action is sufficient. Any matching denial returns `denied`.
3. If client attribution is unknown, return `none` with `unknown_client`.
4. Find matching allowances. A **single rule must cover every action class**.
   Do not combine partial allowances from different rules. A matching rule returns
   `explicit`.
5. Otherwise return `none` with `no_matching_grant`.

Rule order and specificity never override a denial. Matching references in the
result are sorted lexicographically and contain only rules responsible for the
winning effect. A more specific allowance cannot bypass a broader denial.

`null` in a rule is a wildcard; `null` in action context means unknown. A known
exact principal/agent/environment never matches an unknown value. A known client
with unknown principal or agent can match rules that explicitly wildcard those
fields. Require exact principal/agent values when those identities matter.
An unknown client cannot receive an allowance, even from an all-wildcard rule.

The closed capability vocabulary is `read_data`, `write_data`, `delete_data`,
`execute_code`, `credential_access`, `external_communication`, `browser_action`,
`identity_admin`, `financial_action`, `infrastructure_change`, and `unknown`.
An empty action class list is invalid; classify it as `unknown` instead.

## Action context and policy

Test input has exactly `schema_version: 1`, `client`, `principal`, `agent`,
`server`, `tool`, `capabilities`, `environment`, and `time_ms`. It is at most
4 KiB. Optional identity and environment fields must be explicitly null when
unknown. Capabilities must be nonempty and unique. The example is the complete
wire format.

The eventual gateway must construct these facts from its reviewed local profile,
resolved server/tool and trusted clock. MCP messages and `clientInfo` cannot
choose their own grant context. Declared profile identity remains declared,
not cryptographically authenticated. Server-name/discovery-summary fingerprints
alone are insufficient for launch authorization: the enforcing gateway must bind
the reviewed executable/launch and current tool definition before using grants.

`GrantResolution::state()` supplies the policy grant field. For the same action,
`GrantResolution::constrain(policy_decision)` independently forces `deny` when
the grant is `none` or `denied`, even if a policy says `allow` or
`require_approval`. With an explicit grant, a policy denial stays denied and an
approval requirement stays required. These functions do not execute anything.
Do not reuse results across calls or context changes. After waiting for approval,
re-evaluate current grants, time, policy, schema and emergency controls immediately
before dispatch.

## Local operation and failures

Rules are explicitly selected local files. No automatic discovery, network,
background reload, key lookup or Platform account is involved. Protect the file
and its parent directory from unauthorized modification. Local administrator
control is the trust boundary; these files are not signed policy bundles and must
not be accepted directly from a cloud response. Optional sync must authenticate
and validate changes through its separate control boundary.

The library keeps a validated immutable rule set. A caller can parse a complete
replacement and swap it only on success. Time-limited rules are checked on every
evaluation; a cached set does not freeze expiry. System-clock rollback and local
state rollback by the same privileged user are not prevented by the pure matcher.
The gateway must handle clock failure and rechecks rather than accepting time from
an MCP request. Local reference hashes are not anonymization and are not approved
for telemetry merely because they are hashes.

Exit 0 means a successful check or resolution, including denial/no match. Exit 2
means invalid rules/context or an unreadable, oversized, non-regular or linked
file. JSON failures go to stderr with empty stdout; inputs, paths and parser
messages are not echoed. Human output explains the resolution and states that no
tool was invoked. Fix invalid files explicitly; never replace a parse failure
with an empty or permissive set automatically.

Run `cargo test -p mitigate-policy` for matching and abuse cases and
`python scripts/verify-grants.py target/debug/mitigate` for the actual CLI
contract. CI runs both on Windows, macOS and Linux.
