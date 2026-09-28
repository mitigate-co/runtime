# MCP implementation status

Updated 2026-09-27. Follow the canonical ordered work packages. This file reports implementation evidence, not production readiness.

| Package | State | Evidence or next acceptance |
| --- | --- | --- |
| MCP-001 — Runtime foundation | Merged | PR #1, main `6600c08`. Standalone CLI, strict configuration, content-free errors. Windows/macOS/Linux tests and dependency/license/secret gates passed. |
| MCP-002 — Scanner sources | Merged | PR #2, main `9222188`. Claude Code/Cursor project adapters, normalized declarations, bounded parser and hostile/privacy fixtures. All three OS test runs and security gates passed. |
| MCP-003 — Tool enumeration | Merged | PR #3, main `f3e85ff`. Explicit stdio launch, protocol negotiation, bounded pagination, environment isolation and job/group cleanup. 24 Windows tests; all three OS CI runs and security gates passed. |
| MCP-004 — Fingerprints and diff | In verification | Domain-separated canonical fingerprints, explicit local snapshots and offline diff; separate input/output/description/identity/server facts. 34 Windows tests and CLI demonstration passed; remote CI and merge pending. |
| MCP-005 through MCP-024 | Not started in this repository | Follow the [low-level packages](modules/mcp/LOW_LEVEL.md#19-work-packages). Existing prototype evidence does not establish acceptance in this repository. |

The original private prototype and local preview remain intact. No private history or account-bound executable was imported into Runtime. Reviewed customer-side pieces may be adapted in later changes with provenance.

Known launch gates include gateway semantics, grants, Regorus conformance, approvals, secrets, audit, optional sync, registry/fleet, hostile/privacy corpus and signed platform releases. Private vulnerability reporting is enabled. No public binary release or hosted deployment has occurred.
