# MCP implementation status

Updated 2026-09-28. Follow the canonical ordered work packages. This file reports implementation evidence, not production readiness.

| Package | State | Evidence or next acceptance |
| --- | --- | --- |
| MCP-001 — Runtime foundation | Merged | PR #1, main `6600c08`. Standalone CLI, strict configuration, content-free errors. Windows/macOS/Linux tests and dependency/license/secret gates passed. |
| MCP-002 — Scanner sources | Merged | PR #2, main `9222188`. Claude Code/Cursor project adapters, normalized declarations, bounded parser and hostile/privacy fixtures. All three OS test runs and security gates passed. |
| MCP-003 — Tool enumeration | Merged | PR #3, main `f3e85ff`. Explicit stdio launch, protocol negotiation, bounded pagination, environment isolation and job/group cleanup. 24 Windows tests; all three OS CI runs and security gates passed. |
| MCP-004 — Fingerprints and diff | Merged | PR #4, main `45cd2ab`. Separate input/output/description/identity/server facts, explicit snapshots and offline diff. 34 Windows tests; all three OS CI runs and security gates passed. |
| MCP-005 — Capability classification | Merged | PR #5, main `27e7375`. Deterministic taxonomy, source/confidence, conservative risk flags and fingerprint-bound admin overrides. Windows job-completion regression fixed and documented. 44 Windows tests; all three OS CI runs and security gates passed. |
| MCP-006 — CLI UX | Merged | PR #6, main `1b0a234`. Human tables/details, stable JSON/errors, opt-in findings exits and actual-binary contract harness. 49 Windows tests; all three OS CI runs and security gates passed. |
| MCP-007 — Gateway listener | Merged; enforcement awaits later security packages | PR #7 `a4146b7`, CLI PR #9 `d3be494`. Explicit inventory-only CLI connects real upstreams with bounded pagination/profile validation. 70 Windows tests, real-pipe checks and all three OS/security CI runs passed. |
| MCP-008 — Upstream adapters | Stdio and CLI merged | PR #8 `b99b139`, CLI PR #9 `d3be494`. Managed calls, drift, progress and cancellation verified with real processes. Initial supported transport is stdio; public call authorization/progress integration depends on later security packages. |
| MCP-009 — Secret broker | Merged | PR #10, main `334dfc1`. Native Windows/macOS/Linux storage, scoped injection and management CLI. 77 unit/integration tests, compile-fail privacy check, Windows persistence fixture and real native-store/CLI/child contracts passed on all three operating systems; dependency/license/secret gates passed. |
| MCP-010 — Local audit | In verification | Bounded SQLite metadata, retention checkpoints, hash-chain verification, explicit CLI and inventory-gateway recording. 89 Windows unit/integration tests plus compile-fail privacy test pass; real CLI/gateway, repeated rotation, contention, full-capacity, corruption and privacy checks pass. Reviewed SQLite 3.53.4 source and compiled version verified. Full enforcing-call audit integration remains a later gate. Cross-OS CI and merge pending. |
| MCP-011 through MCP-024 | Not started in this repository | Follow the [low-level packages](modules/mcp/LOW_LEVEL.md#19-work-packages). Existing prototype evidence does not establish acceptance in this repository. |

The original private prototype and local preview remain intact. No private history or account-bound executable was imported into Runtime. Reviewed customer-side pieces may be adapted in later changes with provenance.

Known launch gates include gateway semantics, grants, Regorus conformance, approvals, secrets, audit, optional sync, registry/fleet, hostile/privacy corpus and signed platform releases. Private vulnerability reporting is enabled. No public binary release or hosted deployment has occurred.
