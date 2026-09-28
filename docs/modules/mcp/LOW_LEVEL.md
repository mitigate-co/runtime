# Mitigate MCP — Low-Level Engineering Specification

**Status:** ACTIVE — canonical module implementation plan.

## 1. Runtime topology

```text
MCP client / AI agent
        │
        ▼
Mitigate local MCP endpoint
        │
        ├─ identify caller
        ├─ resolve server/tool
        ├─ normalize action facts
        ├─ evaluate Regorus policy
        ├─ acquire approval if required
        ├─ inject local credential
        ├─ relay MCP call
        ├─ return upstream result
        └─ write local audit / optional safe sync
                 │
                 ▼
            MCP servers
```

## 2. Core Rust domains

Recommended core types:

```text
DiscoveredServer
DiscoveredTool
NormalizedToolSchema
ToolSchemaFingerprint
CapabilityClass
CallerIdentity
Grant
ApprovalScope
PolicyInput
PolicyDecision
AuditEvent
SafeSyncEvent
RegistryFact
```

Avoid string maps for these concepts.

## 3. Scanner adapters

Each config source implements a small adapter returning normalized server declarations. It must not own global scanning policy.

Adapter contract conceptually:

```rust
trait DiscoverySource {
    fn discover(&self, context: &DiscoveryContext) -> Result<Vec<ServerDeclaration>, DiscoveryError>;
}
```

Only introduce async if the source actually performs async I/O.

P0 supports a deliberately small, high-value client/config matrix chosen from real usage. Add adapters behind fixtures and docs.

## 4. Server/tool normalization

Normalize MCP server/tool responses before hashing/classification.

Fingerprint separately:

- tool identity,
- input schema,
- normalized description,
- server/version facts.

Do not make a description whitespace edit indistinguishable from a capability/schema change.

Schema canonicalization must be deterministic and tested across map-key ordering and equivalent encodings.

## 5. Capability classifier

Baseline deterministic rules use:

- tool name,
- normalized schema shape,
- explicit registry facts,
- administrator override.

Descriptions are hints, not authority.

Output:

```text
classes[]
confidence
sources[]
flags[]
```

Security-significant flags:

- destructive,
- credential_access,
- arbitrary_code_execution,
- external_communication,
- identity_admin,
- infrastructure_change,
- unknown_high_impact.

## 6. MCP transports

Implement only transports required by target clients/servers, but place them behind a transport boundary.

Requirements:

- initialize/capability negotiation correctness,
- tool listing,
- call relay,
- progress/stream/cancel semantics where required,
- bounded message sizes,
- timeouts,
- transparent but sanitized upstream errors,
- lifecycle cleanup.

## 7. Caller identity

Never silently attribute an unknown client to a user.

P0 identity sources may include:

- explicit gateway profile/config,
- client-generated local token,
- process/client registration,
- enrolled organization principal mapping later.

Output includes `identity_source` and `confidence` where mapping is not cryptographically direct.

## 8. Grant evaluation

Grant match input:

```text
principal_ref?
agent_ref?
client_ref
server_ref
tool_ref
capabilities[]
environment?
time
```

Evaluation order should be documented and deterministic. Explicit deny beats broad allow unless an ADR says otherwise.

Keep P0 model simple enough for an administrator to reason about.

## 9. Regorus policy

Regorus is embedded in Runtime.

Policy input is structured and contains no raw tool payload by default:

```json
{
  "principal": "prn_x",
  "agent": "agt_x",
  "server": "srv_x",
  "tool": "tool_x",
  "capabilities": ["delete_data"],
  "schema_changed": false,
  "grant": "explicit",
  "offline": false
}
```

Expected output is a constrained decision type, not arbitrary Rego output.

Maintain policy conformance fixtures against the documented Mitigate Rego Profile.

## 10. Approval state machine

```text
requested
  ├─ approved → execute if still valid
  ├─ denied   → return policy error
  ├─ expired  → deny
  └─ cancelled → deny
```

Bind approval to:

- exact caller/agent,
- server/tool,
- policy version,
- schema fingerprint,
- scope/window.

If schema/policy changed before execution, approval no longer applies.

## 11. Command-based servers

Launcher input:

```text
executable_path
argv[]
working_directory
allowed_environment_keys[]
secret_references[]
timeout/lifecycle profile
```

Never concatenate into a shell string.

Tests include hostile quoting, spaces, variable expansion, path traversal and fake executable substitution.

## 12. Secret broker

Secret record has an opaque reference. Metadata may know that a credential exists and its provider/type, but not the value.

Broker API supports read-for-execution with narrow lifetime. Avoid returning long-lived secret strings across unnecessary module boundaries.

## 13. Local audit

Default event stores safe detail:

```text
event_id
time
caller refs
server/tool refs
capability classes
schema fingerprint
policy/version
decision
approval ref
result class/duration
local evidence ref?
```

Raw arguments/results: disabled by default and customer-controlled if implemented.

Audit storage must be bounded/rotatable.

## 14. Zero-Content sync

Safe event types are closed schemas. No generic `metadata` object.

Runtime queue:

- locally durable where needed,
- bounded,
- retries transport failures,
- does not retry privacy rejections unchanged,
- idempotent event IDs.

## 15. Registry client

Public lookup is optional for local function.

Registry fact includes provenance:

```text
subject
fact_type
value
source
observed_at
confidence
```

Never collapse source-attributed facts into an unsourced accusation.

## 16. Failure behavior

### Platform offline

Local scanning/gateway works. Cached policy remains active.

### Approval service offline

Local approval can work if configured. Cloud-only required approval defaults deny for destructive calls unless admin configured an explicit offline policy.

### Policy bundle invalid

Keep last-known-good. Emit local diagnostic. Never activate unsigned/invalid policy.

### Upstream server crashes

Return a clear mapped upstream error; clean process/resources.

### New/unclassified tool

Observe mode: report clearly. Enforcement mode: follow explicit unknown-tool policy.

## 17. Security test corpus

Include fixtures for:

- malicious server descriptions,
- schema bombs/oversize nesting,
- malformed JSON-RPC,
- command injection config,
- secret values in error messages,
- child process env leakage,
- changed tool after approval,
- replayed/expired approval,
- cloud egress with prohibited content,
- fake registry data/source conflict.

## 18. Performance measurement

Measure:

- normalized gateway overhead with local mock server,
- policy evaluation,
- schema fingerprinting,
- scanner duration on representative config/repo corpus,
- audit write overhead.

Do not set marketing SLOs before collecting Mitigate benchmarks.

## 19. Work packages

### MCP-001 — Runtime foundation

- Rust workspace
- CLI skeleton
- logging hygiene
- config schema
- test/CI baseline
- AGENTS/README/security docs

### MCP-002 — Scanner sources

- selected client config adapters
- repository adapter
- normalized server declarations
- fixtures

### MCP-003 — Tool enumeration

- launch/connect representative server
- initialize
- list tools
- normalize
- timeout/cleanup

### MCP-004 — Fingerprints and diff

- canonical schema
- hashes
- snapshots
- diff output
- regression fixtures

### MCP-005 — Capability classification

- deterministic taxonomy/rules
- source/confidence
- admin override model

### MCP-006 — CLI UX

- human table/detail
- JSON contract
- exit codes
- docs/examples

### MCP-007 — Gateway listener

- supported inbound transport
- client identity/profile
- protocol relay

### MCP-008 — Upstream adapters

- stdio/network transports required by launch clients
- lifecycle/errors/cancel/progress

### MCP-009 — Secret broker

- OS store abstraction
- narrow child injection
- no secret logs

### MCP-010 — Local audit

- SQLite schema
- retention/rotation
- safe default event

### MCP-011 — Regorus

- Mitigate Rego Profile
- policy input/output
- signed/local bundle activation
- conformance fixtures

### MCP-012 — Grants

- principal/agent/server/tool matching
- explicit decision order
- tests

### MCP-013 — Approvals

- state machine
- local CLI/UI mechanism
- expiry/scope
- changed-schema invalidation

### MCP-014 — Kill switch and limits

- server/tool/client disable
- emergency policy
- rate limiting

### MCP-015 — Offline behavior

- last-known-good policy
- approval fail semantics
- safe queue

### MCP-016 — Privacy boundary

- egress schemas
- egress firewall
- `privacy self-test`
- `egress inspect`
- leak fixtures

### MCP-017 — Registry v0

- source import model
- public facts
- CLI lookup

### MCP-018 — Optional Platform sync

- account/org/enrollment
- safe ingest
- inventory/fleet view
- cross-tenant tests

### MCP-019 — Reputation/index aggregation

- disclosed contribution
- opt-out
- cohort/suppression rules
- public index skeleton

### MCP-020 — Release engineering

- cross-platform builds required for initial launch
- macOS signing/notarization
- checksums/SBOM/signatures/provenance
- Homebrew/install path
- container if useful

### MCP-021 — Adversarial hardening

- malicious corpus
- fuzzing targets where useful
- update/signature failure
- logs/telemetry review

### MCP-022 — Documentation/research

- README quickstart
- threat/privacy docs
- responsible disclosure
- research methodology

### MCP-023 — Design-partner readiness

- diagnostics bundle without sensitive content
- support/runbook
- feedback instrumentation

### MCP-024 — Production gate

- fresh-machine install/use tests
- all release gates
- documented known limitations

## 20. Definition of done per work package

A package is not done until:

- implementation merged,
- tests pass,
- docs updated,
- security/privacy impact reviewed,
- CLI/API behavior demonstrated where relevant,
- no unrelated TODO debt was created,
- Git history/PR is reviewable.
