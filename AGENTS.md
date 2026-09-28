# AGENTS.md — Mitigate Engineering Operating Contract

This file is mandatory reading for every coding agent, developer and reviewer working on Mitigate.

## 1. Source of truth

When documents conflict, use this precedence order:

1. `docs/MASTER_SPEC.md`
2. `docs/ARCHITECTURE.md` and `docs/PRIVACY_ARCHITECTURE.md`
3. active module low-level spec (`docs/modules/mcp/LOW_LEVEL.md`)
4. engineering standards under `docs/engineering/`
5. ADRs under `docs/decisions/`
6. active GitHub issue / PR acceptance criteria
7. parked roadmap docs

Do not resurrect superseded "Mitigate Zero" or broad 31-day-suite plans.

## 2. Repository boundaries

### `mitigate-co/runtime` — PUBLIC / Apache-2.0

Put customer-side trust-boundary code here:

- Rust runtime and CLI
- MCP scanner and gateway
- Zero-Content telemetry schema implementation
- Egress firewall
- privacy self-test / egress inspector
- local secret broker interfaces
- local audit storage
- public SDK/protocol code
- release/signing metadata and reproducible-build support

Never place proprietary registry curation logic, hosted analytics, secret platform credentials, private benchmark logic or proprietary policy intelligence in this repository.

### `mitigate-co/platform` — PRIVATE / proprietary

Put hosted services here:

- control plane and account/org management
- optional fleet sync
- public registry UI/API and private curation pipeline
- reputation/index aggregation
- fleet dashboard
- hosted audit metadata views
- proprietary policy authoring/intelligence
- operational tooling and infrastructure

The platform must never become mandatory for the runtime's local core function.

## 3. Current scope

The active wedge is **Mitigate MCP**.

Build in this order:

1. scanner
2. normalized MCP inventory and capability classification
3. gateway/relay
4. per-agent/per-principal grants
5. approval and kill-switch semantics
6. schema-change detection
7. local audit
8. Zero-Content optional sync
9. registry/fleet view
10. release hardening and research launch

Do not implement Router, Trace, Behavior, Evals, Work, Sandbox or Models unless the user explicitly re-prioritizes them or an active issue says otherwise.

## 4. Work continuously until the current milestone is complete

Do not stop after scaffolding, a partial TODO list or a happy-path mock.

For each assigned milestone:

- inspect existing code first,
- identify the smallest coherent implementation slice,
- implement it completely,
- write/update tests,
- update documentation in the same change,
- run formatting/lint/type/test/security gates,
- exercise the feature manually,
- keep the live preview/dev environment running when UI is involved,
- commit a clean unit of work,
- continue to the next unblocked slice.

Stop only when:

- the requested milestone is complete,
- a genuine external blocker exists,
- a security decision requires human approval,
- or the user explicitly changes direction.

Do not manufacture clarification questions for decisions already made in the specs.

## 5. User updates while working

Keep the user informed. Never disappear for a long multi-step implementation.

Update cadence:

- at the start: state the milestone being executed,
- after roughly 2–3 meaningful tool/action groups or a meaningful milestone,
- immediately when a material bug, risk, blocker or design correction is discovered,
- after tests or preview validation,
- at completion with exact files, tests, commit/branch and remaining work.

Updates should be concise and factual. Do not narrate trivial commands.

## 6. Live preview is mandatory for UI work

When changing the web UI:

- start/maintain the local dev server,
- surface the preview URL/port to the user,
- keep it available throughout the UI task when the environment supports it,
- inspect the changed screen after each meaningful UI milestone,
- test empty/loading/error/success states,
- test narrow and wide layouts,
- do not call UI work finished without a working preview unless the environment makes preview impossible.

See `docs/engineering/LIVE_PREVIEW_AND_UPDATES.md`.

## 7. Code quality standard

Write code that looks intentionally designed by a senior security/platform engineer.

Priorities, in order:

1. correctness
2. security and privacy
3. clarity
4. testability
5. maintainability
6. performance based on measurement
7. terseness

Do not optimize for style gimmicks, AI-detector scores, novelty or cleverness.

### Required characteristics

- descriptive domain names, not vague abbreviations,
- explicit invariants at trust boundaries,
- small modules with single responsibilities,
- no generic dumping-ground `utils` modules,
- no unnecessary inheritance/framework abstractions,
- no speculative factories or plugin layers without a second real implementation,
- comments explain **why**, threat assumptions and invariants—not obvious syntax,
- errors preserve actionable context without leaking secrets,
- public Rust items are documented when their behavior or invariants are non-obvious,
- security-sensitive functions document inputs, outputs, failure mode and data-handling expectations,
- TODOs require an issue/reference and reason; never leave anonymous TODO/FIXME debt,
- dead code is removed rather than commented out,
- no generated-looking walls of commentary or repetitive boilerplate.

## 8. Documentation is part of the product

A code change is incomplete if the relevant docs are wrong afterward.

Update at least one of the following when behavior changes:

- module README/doc comment,
- architecture doc,
- protocol/schema doc,
- threat model,
- ADR,
- operator/runbook docs,
- CLI help/examples.

Examples must be executable or explicitly labeled pseudocode.

## 9. Testing discipline

At minimum:

- unit tests for pure logic,
- contract tests at protocol boundaries,
- integration tests for MCP transports/gateway behavior,
- adversarial/privacy tests for egress and secret handling,
- regression tests for every fixed bug that can reasonably be reproduced,
- deterministic fixtures,
- no tests that pass only because they sleep and hope.

Security/privacy tests are release blockers.

## 10. Git discipline

Follow `docs/engineering/GIT_STANDARD.md` exactly.

Key rules:

- never commit directly to protected `main`,
- branch from current `main`,
- one concern per commit,
- commits must build/test at meaningful checkpoints,
- use Conventional Commit-style subjects,
- do not mix formatting-only churn with behavior changes,
- never rewrite shared branch history,
- no force-push to protected branches,
- no secrets, local credentials, `.env`, generated build output or customer data,
- PRs explain why, design, tests, risks, migration and screenshots/preview for UI.

## 11. Security rules

Never:

- log raw prompts/tool arguments/tool results by default,
- send arbitrary `metadata` blobs through telemetry,
- bypass the egress firewall,
- persist secrets in SQLite/plaintext config,
- silently weaken fail-closed semantics for destructive MCP actions,
- auto-enable blocking for existing customers without explicit admin action,
- trust MCP tool descriptions as authoritative security metadata,
- execute command-based MCP servers through shell interpolation,
- accept an upstream dependency license without checking it.

## 12. Performance rules

Do not promise latency numbers before benchmarking our own implementation.

Measure separately:

- local parsing/normalization,
- policy evaluation,
- gateway relay overhead,
- content classification,
- upstream provider/server latency.

Optimize proven hot paths only after profiles/benchmarks identify them.

## 13. Human-quality standard

The goal is not to make code "look non-AI." The goal is for a skilled engineer to read any file and understand:

- why it exists,
- what invariant it owns,
- what it is allowed to depend on,
- how it fails,
- how it is tested,
- and where to change it safely.

If a file cannot answer those questions, improve the structure before adding more code.


# Runtime Agent Instructions

This is the public Apache-2.0 customer-side trust boundary for Mitigate.

Read the shared `AGENTS.md`, Master Spec, Privacy Architecture, Threat Model and MCP low-level spec before work.

Priority: Mitigate MCP scanner/gateway.

Never move proprietary Platform intelligence into this repo. Never weaken Zero-Content egress, local-first operation, secret handling or command-launch safety for convenience.

Every security-sensitive change needs tests and clear documentation. Public code quality is part of the product's trust claim.
