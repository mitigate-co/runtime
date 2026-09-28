# Mitigate — Master Product, Architecture, Security & Launch Specification

**Version:** 2.0  
**Status:** Canonical execution specification  
**Date:** 2026-09-27  
**Company/product:** Mitigate  
**Public runtime repository:** `https://github.com/mitigate-co/runtime`  
**Private platform repository:** `https://github.com/mitigate-co/platform`  
**Current wedge:** Mitigate MCP  
**Target:** production-quality 90-day wedge release, then organization adoption

---

## 0. Executive decision

Mitigate is a privacy-first AI security/control platform. The near-term strategy is intentionally narrow:

> Build the best local-first MCP security wedge we can ship, earn organization-level deployments, collect privacy-safe operational signals, and prove retention before expanding the broader platform.

Do **not** attempt to launch the full AI governance suite at once.

The active product is **Mitigate MCP**, comprising three connected capabilities:

1. **Scanner** — discover MCP servers/tools on endpoints and in repositories, fingerprint schemas and classify capability/risk.
2. **Gateway** — one governed local MCP endpoint with identity-aware grants, approvals, credential injection, rate limits, change detection, kill switch and local audit.
3. **Registry / fleet sync** — optional platform sync of Zero-Content inventory/audit metadata plus public, source-attributed MCP registry/reputation facts.

The broader Router, Trace, Behavior, Evals, Work, Sandbox and Models modules remain architectural roadmap only. Their docs are retained to preserve design continuity, but agents must not implement them until MCP meets its launch gates or the owner explicitly changes priority.

---

# 1. Product thesis

## 1.1 Problem

MCP dramatically reduces the friction required to connect AI agents to tools and data. That also creates capability sprawl:

- unknown MCP servers installed on developer machines,
- tools whose schemas or descriptions change without review,
- agents receiving broader permissions than their user intended,
- long-lived credentials exposed to local processes,
- destructive/write tools treated the same as read tools,
- local servers launched with unsafe command/environment configuration,
- little organization-level inventory of what is installed,
- weak auditability of which agent or principal invoked which tool.

## 1.2 Product promise

> Discover and govern MCP locally. Keep credentials and tool payloads on the customer side. Give security teams the inventory, policy and audit facts they need without turning Mitigate into another sensitive-data repository.

## 1.3 Five-minute individual value

A developer should be able to install the `mitigate` binary and run:

```bash
mitigate mcp scan
```

without creating an account.

The output should immediately show:

- discovered MCP servers,
- source/config location,
- package/version when known,
- tools exposed,
- capability categories,
- destructive/credential/exec flags,
- schema fingerprints,
- obvious configuration risk,
- provenance/reputation facts when locally available or public registry lookup is enabled.

## 1.4 Organization value

An organization can optionally enable Mitigate Platform sync to see:

- endpoints/gateways,
- discovered MCP servers/tools,
- versions/schema changes,
- principals/agents using them,
- grants and policy outcomes,
- safe audit events,
- deployment breadth,
- health/version state.

Raw MCP arguments/results and credentials are not required for this view.

---

# 2. Non-negotiable invariants

1. **Local-first** — Scanner and Gateway remain useful with no Mitigate account or cloud connection.
2. **Zero-Content Platform** — cloud telemetry has no generic/raw field for prompts, tool arguments/results, documents, credentials, source code, PHI/PII values or packet bodies.
3. **Open trust boundary** — customer-side Runtime code is auditable/open-source under Apache-2.0.
4. **Proprietary intelligence layer** — Platform, registry curation pipeline, analytics, benchmark aggregation and proprietary policy/intelligence remain private.
5. **Observe first** — discovery is safe by default; blocking/destructive enforcement requires explicit configuration.
6. **Deterministic authority** — structured policy/code makes final allow/deny/approval decisions.
7. **Fail locally** — loss of Platform connectivity does not disable existing local policy enforcement.
8. **No shell interpolation** — command MCP servers are launched by explicit executable + argv, never by concatenated shell commands.
9. **Secrets remain local** — provider/MCP credentials stay in OS/customer secret stores when Runtime is present.
10. **No arbitrary metadata blobs** — sync schemas enumerate keys and bound string lengths.
11. **Signed distribution** — release binaries, containers, manifests and update metadata are signed.
12. **Security gates beat schedule** — a failing privacy/security test blocks release.
13. **Readable engineering** — architecture and code must remain understandable without tribal knowledge.

---

# 3. Repository and licensing model

## 3.1 Runtime (public at release)

Repository: `mitigate-co/runtime`

The repo may remain private during pre-release development but is treated as public-safe from its first commit and is intended to be public at release.

License: Apache-2.0.

Contains:

- Rust workspace and `mitigate` CLI,
- MCP scanner,
- MCP gateway,
- protocol/schema types,
- local audit,
- local secret-broker interfaces,
- egress firewall,
- privacy self-test,
- update/signature verification,
- public SDK/client snippets needed for interoperability,
- tests and reproducible-build guidance.

The public repository must not contain:

- Platform credentials,
- registry crawler/curation internals,
- proprietary cross-org analytics,
- private customer data,
- private policy intelligence,
- internal production infrastructure configuration containing secrets.

## 3.2 Private Platform

Repository: `mitigate-co/platform`

Proprietary.

Contains:

- account and organization management,
- optional runtime/device enrollment,
- Zero-Content inventory/audit ingestion,
- fleet view,
- public registry presentation/API,
- private registry curation pipeline,
- reputation/aggregate index computation,
- private operational tooling,
- hosted web UI,
- future proprietary graph/policy/intelligence capabilities.

## 3.3 Contribution rights

Before accepting outside code:

- publish CONTRIBUTING and CLA/DCO requirements,
- require contributor agreement/sign-off as configured,
- keep a clean provenance record,
- reject copied/proprietary code from unknown sources,
- run license scanning in CI.

## 3.4 Public release provenance

Every release should link:

- source tag,
- commit SHA,
- checksums,
- SBOM,
- signature/attestation,
- release notes,
- supported platforms,
- known security limitations.

Aim for reproducible builds for the trust-boundary artifacts.

---

# 4. Product surfaces

## 4.1 CLI

Primary binary: `mitigate`.

Initial commands:

```text
mitigate version
mitigate mcp scan
mitigate mcp inspect <server>
mitigate mcp diff
mitigate mcp serve
mitigate mcp status
mitigate mcp grants ...
mitigate mcp approvals ...
mitigate mcp audit ...
mitigate registry lookup ...
mitigate sync status
mitigate privacy self-test
mitigate egress inspect
```

CLI output must support:

- readable human format,
- `--json` stable machine format,
- useful exit codes,
- `--quiet`/noninteractive automation where appropriate.

## 4.2 Local gateway

Agent/MCP client connects to a Mitigate-owned local MCP endpoint.

Gateway resolves upstream server/tool, applies policy, obtains credentials locally, relays the call and emits local audit facts.

Raw arguments/results are not required for Platform sync.

## 4.3 Platform UI

P0 hosted UI is deliberately thin:

- account/org,
- runtime/gateway enrollment,
- fleet health,
- MCP inventory,
- server/tool detail,
- schema-change view,
- safe audit events,
- aggregate index/registry.

Do not build full GRC, FinOps, use-case lifecycle, or broad AI inventory during the wedge.

---

# 5. Runtime architecture

## 5.1 Language

Rust for the request-path/customer trust boundary.

No embedded Python runtime in the normal MCP gateway path.

## 5.2 Suggested workspace

```text
runtime/
├── Cargo.toml
├── crates/
│   ├── mitigate-cli/
│   ├── mitigate-runtime/
│   ├── mitigate-mcp-protocol/
│   ├── mitigate-mcp-scan/
│   ├── mitigate-mcp-gateway/
│   ├── mitigate-policy/
│   ├── mitigate-audit/
│   ├── mitigate-secrets/
│   ├── mitigate-egress/
│   ├── mitigate-registry-client/
│   └── mitigate-update/
├── schemas/
├── examples/
├── docs/
└── tests/
```

Do not split crates merely for aesthetics. A crate must own a real dependency/security/lifecycle boundary.

## 5.3 Policy runtime

Use **Regorus** as the embedded Rego interpreter.

Define a **Mitigate Rego Profile**:

- supported Rego language/version,
- supported builtins,
- deterministic input schema,
- expected decision output schema,
- resource limits.

CI must run representative policy fixtures against Regorus and an OPA reference implementation when feasible. Divergence is a release blocker for affected policies.

## 5.4 Local state

SQLite may store:

- discovery snapshots,
- schema fingerprints,
- non-secret gateway configuration,
- grant/policy cache,
- audit index,
- pending metadata sync queue,
- update/version state.

Secrets do not go into plaintext SQLite.

## 5.5 Secret storage

Use OS/customer-native secure storage:

- Windows Credential Manager / DPAPI-backed storage,
- macOS Keychain,
- Linux Secret Service/keyring or explicitly encrypted store,
- external vault references where configured.

The gateway should receive secret material only for the smallest execution scope possible.

---

# 6. Scanner

## 6.1 Discovery targets

P0 supports common local/repository MCP configuration patterns for the target clients chosen during implementation.

The scanner should be adapter-based, where each adapter returns the same normalized record:

```text
source_kind
source_path_or_ref
server_name
transport
command_or_url
package_name
package_version
config_fingerprint
credential_reference_types
```

Sensitive environment values are never included in normalized output.

## 6.2 Tool inventory

For reachable/configured servers, normalize:

- server identity,
- tool name,
- normalized description hash,
- input schema hash,
- capability classification,
- risk flags,
- server/package/version facts,
- provenance source.

Descriptions may be malicious/untrusted content. Never treat descriptions as policy authority.

## 6.3 Capability taxonomy

At minimum:

- `read_data`
- `write_data`
- `delete_data`
- `execute_code`
- `credential_access`
- `external_communication`
- `browser_action`
- `identity_admin`
- `financial_action`
- `infrastructure_change`
- `unknown`

Classifications need confidence/source:

```text
classification_source = deterministic | registry | admin | assisted
confidence = low | medium | high
```

LLM-assisted classification may be offered locally/BYOK later; it never overrides explicit policy without an admin/deterministic rule.

## 6.4 Schema change detection

Canonicalize and hash tool schemas. On change:

- record previous/current fingerprint,
- identify added/removed/changed tools,
- reclassify affected tools,
- flag newly destructive/credential/exec capability,
- optionally require reapproval under policy.

---

# 7. Gateway

## 7.1 Request flow

```text
MCP client / agent
   ↓
client identity resolution
   ↓
server + tool resolution
   ↓
normalized action facts
   ↓
policy decision
   ↓
approval if required
   ↓
credential injection
   ↓
upstream MCP call
   ↓
result relay
   ↓
local audit + optional Zero-Content sync
```

## 7.2 Identity

P0 must support explicit local agent/client identities even before full enterprise directory integration.

Every governed call should have, where available:

- `principal_ref`
- `agent_ref`
- `client_ref`
- `session_ref`
- `server_ref`
- `tool_ref`

Unknown identity is represented explicitly; never fake attribution.

## 7.3 Grants

Grant scopes should support:

- principal,
- agent/client,
- server,
- tool,
- capability class,
- time window,
- environment/profile.

Start with simple explicit matching. Avoid a giant permissions DSL before real design-partner needs exist.

## 7.4 Policy outcomes

Canonical outcomes:

- `allow`
- `allow_and_log`
- `require_approval`
- `deny`
- `rate_limit`
- `disable_tool`

Warnings belong primarily in user-facing clients; the gateway must have unambiguous execution semantics.

## 7.5 Approval

When a policy requires approval:

- pause with a bounded timeout,
- produce a metadata-only approval request,
- support local approval first,
- optional Platform approval may be added without uploading raw arguments,
- scope approvals tightly: one call, tool, session or bounded window,
- log who approved and policy version.

If cloud is unavailable and a destructive action requires cloud approval, default deny unless the administrator explicitly configured another offline rule.

## 7.6 Kill switch

Support:

- disable server,
- disable tool,
- deny agent/client,
- emergency deny-all profile.

Kill-switch state must be locally enforceable and auditable.

## 7.7 Rate limiting

Implement deterministic token-bucket or equivalent limits locally. Limit dimensions can include agent/tool/principal/server.

---

# 8. Command server security

Command-based MCP servers are a major trust boundary.

Requirements:

- executable path is explicit,
- argv is explicit array,
- no `sh -c`, `cmd /c`, PowerShell command-string wrapping by default,
- explicit working directory,
- environment allowlist/denylist,
- credentials injected only into the intended child,
- stdout/stderr handling avoids accidental secret sync/logging,
- process lifetime tied to gateway/session policy where appropriate,
- executable/package fingerprint recorded,
- process tree never grants arbitrary shell expansion from config values.

Add malicious config fixtures for:

- command injection attempts,
- env expansion tricks,
- path traversal,
- executable substitution,
- oversized output,
- malformed JSON-RPC.

---

# 9. Local audit

## 9.1 Principle

Customer may need detailed local evidence. Mitigate Platform only needs structured facts.

## 9.2 Local event

Local audit may record, subject to customer retention configuration:

- exact server/tool,
- caller identity,
- timing,
- policy decision,
- approval,
- local evidence pointer,
- result/error metadata.

Raw tool arguments/results should be off by default and require explicit customer retention configuration.

## 9.3 Platform sync event

Platform event contains only bounded fields such as:

```json
{
  "schema_version": 1,
  "event_type": "mcp_tool_decision",
  "occurred_at": "...",
  "runtime_ref": "...",
  "principal_ref": "...",
  "agent_ref": "...",
  "server_ref": "...",
  "tool_ref": "...",
  "capability": "write_data",
  "decision": "require_approval",
  "result": "approved",
  "policy_ref": "...",
  "policy_version": "..."
}
```

There is no generic `metadata` field.

---

# 10. Zero-Content egress firewall

Every Runtime → Platform event passes:

1. event-type allowlist,
2. exact schema validation,
3. unknown-field rejection,
4. bounded strings/enums,
5. serialization size limit,
6. secret/high-entropy scan on permitted free-form identifiers,
7. PII/credential pattern scan on permitted strings,
8. prohibited-key check (`prompt`, `content`, `arguments`, `result_body`, etc.),
9. local audit of egress decision,
10. event signing/integrity mechanism when enrolled.

If validation fails, drop/quarantine locally and increment a safe diagnostic counter. Never "best effort" serialize unknown content.

## 10.1 Privacy self-test

`mitigate privacy self-test` must inject synthetic fixtures containing:

- API keys,
- JWT-like tokens,
- email addresses,
- SSN-like identifiers,
- card-like identifiers,
- source-code snippets,
- long arbitrary text,
- nested unknown objects.

The test passes only when fixtures cannot enter accepted Platform telemetry.

## 10.2 Egress inspector

`mitigate egress inspect` shows the customer:

- which event types were emitted,
- exact field names,
- destination,
- byte counts,
- rejection counts,
- recent schema versions,

without revealing sensitive local content.

---

# 11. Optional Platform

## 11.1 Launch stack

Keep the previously selected cost-conscious stack unless implementation evidence requires change:

- Cloudflare edge / Workers / Queues / R2 as appropriate,
- Neon PostgreSQL,
- TypeScript,
- Hono,
- React + Vite,
- Drizzle,
- Better Auth,
- Resend for transactional mail,
- OpenTelemetry instrumentation.

## 11.2 Thin P0 domain model

P0 entities:

- accounts/users,
- organizations,
- memberships,
- runtimes/devices,
- MCP servers,
- MCP server versions,
- MCP tools,
- MCP tool versions,
- principals/agents (minimal refs),
- grants/policies (only if cloud-managed),
- material audit events,
- registry sources,
- aggregate reputation/index facts.

Do not build the full future AI graph yet.

## 11.3 Tenant isolation

Every organization-scoped row includes `organization_id` and is protected by:

- application authorization,
- PostgreSQL RLS where appropriate,
- automated cross-tenant tests.

## 11.4 Cloud not required for local operation

Gateway startup and cached policy evaluation must not depend on Platform availability.

---

# 12. Public registry and reputation

## 12.1 Registry data

Source-attributed public facts may include:

- server/project identity,
- publisher/source,
- repository/package reference,
- version,
- transport,
- tools/capability taxonomy,
- schema/version changes,
- signature/package facts where verifiable,
- disclosed vulnerabilities/advisories,
- first/last observed public version dates.

Never publish unverified accusations as fact.

## 12.2 Aggregate operational signal

When cloud sync is enabled, operational metadata can contribute to aggregate registry/reputation/index output subject to plain disclosure and a one-click opt-out.

Publication safeguards:

- no organization/user/device identity,
- no exact timestamps,
- no raw payloads,
- cohort minimum `k >= 50` for segmented statistics,
- suppression of rare categories,
- coarse time/size buckets,
- explicit sample-selection caveat.

Rich/private benchmark contributions remain opt-in.

## 12.3 Useful reputation facts

Prefer operationally useful statements such as:

- schema changed recently,
- capability class added/removed,
- observed deployment breadth bucket,
- high deny/disable-rate bucket,
- provenance/signature state,

rather than arbitrary opaque "risk scores."

---

# 13. Engineering quality

The detailed standard is in `docs/engineering/ENGINEERING_STANDARD.md`.

Launch code must have:

- Rust formatting/clippy clean,
- TypeScript strict mode,
- deterministic tests,
- documented public protocol types,
- explicit error types at subsystem boundaries,
- no sensitive bodies in logs,
- dependency/license checks,
- SBOM,
- secret scanning,
- threat-model updates for meaningful trust-boundary changes.

Do not accept code that is technically functional but structurally confusing.

---

# 14. Git and release discipline

See `docs/engineering/GIT_STANDARD.md` and `RELEASE_STANDARD.md`.

Minimum rules:

- protected `main`,
- branch-per-change,
- reviewable commits,
- no secret/history rewriting games,
- CI required before merge,
- signed release tags/artifacts,
- changelog/release notes,
- release provenance and SBOM,
- no public release built from an uncommitted worktree.

---

# 15. 90-day execution plan

Security gates can extend dates. The sequence matters more than the calendar.

## Weeks 1–2 — Scanner and research foundation

Deliver:

- Rust workspace/CLI quality baseline,
- config discovery adapters,
- server normalization,
- reachable server tool enumeration,
- schema canonicalization/fingerprinting,
- capability taxonomy/classification,
- local report formats,
- privacy/security fixtures,
- initial public registry source importer,
- repeatable dataset for research findings.

Exit criteria:

- `mitigate mcp scan` works on clean supported environments,
- no account required,
- deterministic JSON output documented,
- malicious config fixtures pass,
- source attribution is retained.

## Weeks 3–4 — Gateway core

Deliver:

- local MCP endpoint,
- upstream server adapters,
- tool list normalization,
- tool call relay,
- errors/progress/stream semantics needed by target clients,
- explicit agent/client identity,
- local audit skeleton,
- secret broker.

Exit criteria:

- representative clients can use representative servers through Mitigate without semantic breakage,
- secrets stay local,
- baseline gateway overhead measured.

## Weeks 5–6 — Governance

Deliver:

- Regorus policy integration,
- grants,
- approval semantics,
- kill switches,
- rate limits,
- unknown/new tool policy,
- schema-change invalidation/review flow,
- offline behavior.

Exit criteria:

- destructive action can be required to receive approval,
- change to a tool schema can invalidate prior trust,
- cloud outage does not disable cached local policy,
- privacy self-test passes.

## Weeks 7–8 — Optional sync + registry

Deliver:

- Platform account/org,
- Runtime enrollment,
- Zero-Content ingest,
- fleet/inventory view,
- public registry v0,
- aggregate contribution disclosure/opt-out,
- registry lookup in CLI.

Exit criteria:

- local product still works without account,
- enrolled org can view inventory with no raw tool payload in Platform,
- cross-tenant tests pass.

## Weeks 9–10 — Release hardening and launch assets

Deliver:

- signed/notarized artifacts,
- Homebrew tap/install path,
- Linux install script/package path as appropriate,
- container image where useful,
- checksums/SBOM/provenance,
- security policy,
- disclosure process,
- threat model,
- clean docs site/readme,
- responsible research publication draft,
- client configuration snippets.

Do not delay initial wedge launch for MSI/Intune/Jamf unless a real design partner requires it. macOS release still needs signing/notarization.

## Weeks 11–12 — Design partners and index

Deliver:

- 3–5 serious design-partner conversations/deployments target,
- feedback-driven fixes,
- organization retention instrumentation,
- first public aggregate MCP index/report if the dataset is defensible,
- roadmap review based on actual adoption.

---

# 16. Launch gates

Do not call the wedge production-ready until:

- scanner discovers supported configs reliably,
- gateway preserves required MCP semantics,
- grants/approval/kill switch work,
- unknown/new tool behavior is explicit,
- credentials remain local,
- Zero-Content privacy fixture suite passes,
- local product works with Platform offline,
- malicious MCP/config test suite passes,
- logs are sanitized,
- open-source runtime license/provenance is clean,
- release is signed and has checksums/SBOM,
- vulnerability-reporting path exists,
- docs accurately explain limits,
- Platform tenant isolation tests pass if sync ships,
- restore/backup/monitoring exist for any production Platform data,
- a fresh user can install and get useful scan output without developer help.

---

# 17. Adoption metrics

Primary:

- active organizations,
- weekly active organizations,
- organization-level deployments vs individual installs,
- 30/90-day organization retention,
- governed MCP calls/month,
- discovered MCP servers/tools,
- schema changes detected,
- policy decisions and deny/approval rates,
- opt-in/opt-out aggregate contribution rate,
- named design partners/customers,
- paid enterprise organizations/ARR if/when introduced.

Secondary:

- downloads,
- GitHub stars,
- registry/index traffic,
- research reach.

Never substitute GitHub stars for retained organizational use.

---

# 18. Commercial posture

Core remains useful/free.

An enterprise tier may be introduced once real organizations ask for enterprise administration or procurement features. Appropriate paid value includes:

- SSO/SCIM,
- larger fleet administration,
- audit export/integration,
- contractual SLA/support,
- managed onboarding,
- dedicated deployment options.

Never gate the core privacy property or privacy opt-out behind payment.

Certification is not a precondition to shipping. Begin SOC 2 work when a real enterprise opportunity blocks on it or when the paid enterprise posture makes it necessary. Do not claim certifications not held by Mitigate.

---

# 19. Corporate/IP hygiene

Before meaningful outside contributions/design-partner deployment:

- ensure company owns relevant founder-created IP,
- review employment/invention assignment obligations with counsel,
- keep cap table/entity clean,
- publish third-party notices,
- preserve contributor provenance,
- establish trademark/domain strategy for Mitigate,
- ensure encryption/export obligations are reviewed before broad open-source binary distribution.

This document is an engineering/product plan, not legal advice.

---

# 20. Parked roadmap

The following modules are deliberately parked:

- Router
- Trace
- Behavior
- Evals
- Work
- Sandbox
- Models
- broad browser/end-user AI monitoring
- broad Entra/Google AI discovery
- full AI governance/GRC graph
- full FinOps
- native EDR adapters (ETW/WFP, EndpointSecurity, eBPF)
- Windows/macOS local sandbox claims

Their docs remain under `docs/modules/` with a PARKED banner.

When a module is activated, create an ADR that states:

- why now,
- customer evidence,
- dependencies,
- scope,
- which current wedge work is not being displaced.

---

# 21. Explicit technical decisions

## 21.1 Router

When Router is eventually built:

- common providers use native Rust adapters,
- no mandatory Python sidecar in the endpoint request path,
- LiteLLM may be used as a reference/optional long-tail server compatibility path,
- latency SLOs are set from Mitigate benchmarks, not assumed.

## 21.2 Policy

Regorus replaces OPA-to-WASM for the embedded Rust runtime. Rego remains the policy language/profile.

## 21.3 Sandbox

P0 sandbox, when activated, is Linux/container-capable host first. Do not market Windows/macOS endpoint sandboxing based on Docker Desktop assumptions.

## 21.4 Behavior

Native EDR-style adapters are aspirational. Behavior should first consume instrumented MCP/Router/Work/Sandbox/OTel facts and integrate existing EDR/security platforms before Mitigate attempts deep OS telemetry collection.

---

# 22. Definition of beautiful code

Mitigate code is "beautiful" when another strong engineer can safely change it without needing the original author.

That means:

- clear module boundaries,
- precise names,
- short dependency chains,
- explicit types,
- documented invariants,
- useful errors,
- disciplined tests,
- consistent formatting,
- no unexplained magic,
- no framework theater,
- no giant generated-looking files,
- no duplicated concepts with slightly different names,
- no speculative abstraction without evidence.

The code should feel calm.

---

# 23. Agent execution rule

Coding agents must follow `AGENTS.md` and `AGENT_CONTINUE_PROMPT.md`.

They are expected to continue milestone-by-milestone, communicate progress frequently, keep live preview available for UI work, maintain Git hygiene and update docs/tests with implementation changes.

The objective is not to produce a lot of code. The objective is to produce a small, trustworthy product that security teams will actually deploy.
