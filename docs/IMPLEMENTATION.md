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
| MCP-010 — Local audit | Merged | PR #11, main `e8e0f9b`. Bounded SQLite metadata, retention checkpoints, chain verification and inventory-gateway recording. 89 Windows tests plus compile-fail privacy test, Linux/macOS suites, actual CLI/gateway contracts and security gates passed. Reviewed SQLite 3.53.4 source and compiled version verified. Full enforcing-call audit integration remains a later gate. |
| MCP-011 — Regorus | Merged | PR #12, main `2ff8669`. Restricted Rego profile, closed inputs/decisions, strict Ed25519 trust, native signing CLI and transactional activation. Windows/macOS/Linux suites, actual CLI/native signing contracts, 22 OPA comparison cases and dependency/license/secret gates passed. Local Windows still requires the MSVC Spectre component; isolated WSL supports verification. |
| MCP-012 — Grants | Merged | PR #13, main `cc13a10`. Explicit scopes, deny precedence, whole-action allowance and independent policy constraint. Policy/grant unit tests, actual CLI/privacy fixtures and complete Windows/macOS/Linux/security CI passed. |
| MCP-013 — Approvals | Merged | PR #14, main `60fc055`. One-call binding, local decisions, atomic consumption, expiry/revocation/cancellation and bounded storage. Approval, CLI/privacy, full Windows/macOS/Linux and dependency/secret gates passed. Live enforcing-call composition remains a launch gate. |
| MCP-014 — Kill switch and limits | Control component merged | PR #15, main `77877aa`. Persistent stops, exact target disables, deterministic atomic quotas, bounded operator history and management CLI. Windows/macOS/Linux suites, actual CLI/privacy fixtures and dependency/secret gates passed. Enforcing gateway composition remains required within this package. |
| MCP-015 — Offline behavior | In verification; safe queue still open | Executable cached-policy/approval outage corpus and recovery documentation added. Final CI is pending. |
| MCP-016 through MCP-024 | Not started in this repository | Follow the [low-level packages](modules/mcp/LOW_LEVEL.md#19-work-packages). Existing prototype evidence does not establish acceptance in this repository. |

The original private prototype and local preview remain intact. No private history or account-bound executable was imported into Runtime. Reviewed customer-side pieces may be adapted in later changes with provenance.

Enforcing-gateway prerequisite merged in PR #16, main `eab5a6b`: exact private launch review binds
executable/selected artifact bytes, argv, cwd, ordinary environment and native
credential references. Optional reviewed inventory connections detect code drift
and record the launch reference locally. Launch metadata, symlink/code-drift,
actual CLI/privacy/audit contracts and Windows/macOS/Linux/security CI passed.

Tool schema validation merged in PR #17, main `8aa9aa4`: the explicit bounded local Draft
2020-12 profile compiles input/output schemas before invocation, rejects invalid
arguments and withholds invalid results. No remote/file retrieval or coercion is
allowed; unsupported constraints fail closed. Schema/real-process tests, full
Linux workspace tests, actual executable demonstration, strict lint and dependency/
license/secret checks passed locally. CLI panic privacy is covered by a subprocess
regression. Windows/macOS/Linux suites and dependency/secret CI gates passed.

Versioned call audit merged in PR #18, main `f723855`: closed correlation/phase/operator facts
preserve legacy event bytes and support mixed-version chains without migration.
Local workspace tests and actual CLI verification passed, including a saved older
binary refusing new records without modifying history. Windows/macOS/Linux and
dependency/license/secret CI gates passed.

Final dispatch boundary merged in PR #19, main `47fb540`: the upstream adapter invokes an
owner gate after schema/inventory/selected-code checks, before sending a tool call.
Five gate regressions and all 19 real-process upstream tests, strict workspace
lint and the executable relay demonstration passed locally. Timeout/cancellation
cannot dispatch a late gate result; explicit refusal preserves healthy reuse.
Windows/macOS/Linux and dependency/license/secret CI gates passed.

Local governance composition is in verification. Explicit `serve --enforce` joins
reviewed launch and definitions with verified policy, current grants, bounded
one-call approvals, final controls and required versioned call audit. The actual
CLI fixture passed allowed/denied calls, unknown identity, approval consumption,
expiry/cancellation, live authority changes, drift, invalid output, audit failure,
bounded progress and cancellation after dispatch. Final-refresh revocation and
startup-failure coverage is added. Strict workspace lint and the initial live
fixture passed locally. The subsequent full Linux suite was interrupted by host
disk exhaustion/WSL I/O failures in three process tests; its partial result is not
a passing gate. Cross-OS CI must verify the complete final change.
Operator setup/reference ergonomics remain open within MCP-014.

An intermittent executable CI failure exposed pre-lock clock sampling in shared
approval/control stores. Production callers now use in-transaction `SystemClock`
observations; deterministic lock probes retain rollback, expiry and quota checks.
The policy suite (53), CLI authority/unit tests (11) and CLI integration tests (17)
passed locally after the correction, together with strict workspace lint and the
CLI/fixture build. WSL could not launch the final executable check after host disk
exhaustion recurred. Final executable/CI validation is pending.

Known launch gates include gateway semantics, grants, Regorus conformance, approvals, secrets, audit, optional sync, registry/fleet, hostile/privacy corpus and signed platform releases. Private vulnerability reporting is enabled. No public binary release or hosted deployment has occurred.
