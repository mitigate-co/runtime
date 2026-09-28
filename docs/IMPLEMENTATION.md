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
| MCP-014 — Kill switch and limits | Merged | Controls PR #15, governance PR #20 and exact-reference setup PR #21, main `72e68fe`. Governed calls enforce stops/targets/quotas alongside policy/grants/approvals and required audit. Both final CI runs passed all three operating systems and security gates. |
| MCP-015 — Offline behavior | Local authority and safe queue merged | PR #22 at `def9772` and PR #24 at `e952779` passed final Windows/macOS/Linux and security CI. Cached policy and unavailable approvals remain local; the durable queue validates before persistence. Enrolled delivery remains MCP-018 work. |
| MCP-016 — Privacy boundary | Local boundary and CLI merged | PR #23 at `22244f5`, PR #24 at `e952779` and PR #25 at `2ef62f0` passed final Windows/macOS/Linux and security CI. The 147-candidate privacy self-test and read-only scoped inspector work with real storage. Enrolled integrity remains MCP-018 work. |
| MCP-017 — Registry v0 | Runtime contract/client merged | PR #26, main `768a4e0`; final cross-platform/security CI passed. Closed source-attributed catalogs and offline CLI lookup preserve conflicts and stale/unknown status. Hosted integration remains a separate gate. |
| MCP-018 — Optional Platform sync | Protocol/native lifecycle merged; HTTPS in verification | PR #27 at `77e8133` and PR #28 at `f567bc4` passed all five gates in both three-OS/security CI runs. Native recovery and explicit verified HTTPS now have failure tests. CLI orchestration, signed event ingest and fleet composition remain open. |
| MCP-019 through MCP-024 | Not started in this repository | Follow the [low-level packages](modules/mcp/LOW_LEVEL.md#19-work-packages). Existing prototype evidence does not establish acceptance in this repository. |

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

Local governance composition merged in PR #20, main `e19aa6e`. Explicit `serve --enforce` joins
reviewed launch and definitions with verified policy, current grants, bounded
one-call approvals, final controls and required versioned call audit. The actual
CLI fixture passed allowed/denied calls, unknown identity, approval consumption,
expiry/cancellation, live authority changes, drift, invalid output, audit failure,
bounded progress and cancellation after dispatch. Final-refresh revocation and
startup-failure coverage passed. Final Windows/macOS/Linux workspace and executable
contracts, native credential fixtures, OPA comparison, dependency/license and secret
gates passed in both push and PR CI runs. Local WSL disk exhaustion interrupted
some local verification; those interrupted attempts are not reported as passes.

An intermittent executable CI failure exposed pre-lock clock sampling in shared
approval/control stores. Production callers now use in-transaction `SystemClock`
observations; deterministic lock probes retain rollback, expiry and quota checks.
The policy suite (53), CLI authority/unit tests (11) and CLI integration tests (17)
passed locally after the correction, together with strict workspace lint and the
CLI/fixture build. Final executable verification then passed on all three CI
operating systems. The fix retains strict rollback detection without tolerances.

`mcp context` supplies exact reviewed caller/server/tool references for grants and
control targets. It requires explicit process execution, compares the selected
snapshot and overrides, confirms cleanup and emits no schemas or raw caller
labels. The executable fixture uses its output for an exact grant and compares
the resulting call audit. Full Linux workspace tests and strict lint passed;
final Windows/macOS/Linux executable contracts and security gates passed in both
CI runs. Merged in PR #21, main `72e68fe`. Local WSL remains unavailable during
host disk exhaustion; interrupted local attempts are not reported as passes.

Known launch gates include gateway semantics, grants, Regorus conformance, approvals, secrets, audit, optional sync, registry/fleet, hostile/privacy corpus and signed platform releases. Private vulnerability reporting is enabled. No public binary release or hosted deployment has occurred.

Safe-queue prerequisite: `mitigate-egress` defines the closed version-one tool
decision candidate, opaque enrollment-scoped references, string allowlist and
strict bounds/fact checks. This is not a sender or completed MCP-015/016 gate.
Nine Windows privacy/contract tests, the compile-fail export check, strict crate
lint, documented fixture acceptance/rejection and secret scanning passed locally.
Both final Windows/macOS/Linux and dependency/secret CI runs passed. Merged in PR #23 at `22244f5`. See [candidate contract](SYNC_EVENTS.md).

The durable outbox component passed 25 local Windows contract/privacy/storage
tests, a compile-fail export check, strict crate lint and the executable restart/
retry/purge demonstration. Coverage includes full capacity, actual SQLite-full
and failed commits, concurrent leases, stale acknowledgements, bounded retry/
retention, corrupt state and rejection-canary exclusion. It has no sender or
automatic gateway producer. See [outbox contract](OUTBOX.md); cross-OS/security
CI passed on the stacked branch. A later Windows run exposed a contention assumption in the concurrent-worker test; fixed Busy diagnostics and exact-lease assertions passed final main-based CI on all three operating systems. PR #24 merged at `e952779`.

The privacy CLI slice adds a 147-candidate probe through actual outbox admission
and a read-only scoped inspector. Twenty-seven local Windows egress/storage/probe
tests, the compile-fail check, strict crate lint, executable probe, advisory audit,
license/source checks and Gitleaks passed. Full CLI checking is blocked locally
by the missing MSVC Spectre libraries; both final main-based Windows/macOS/Linux and security CI runs passed, including actual subprocess commands. PR #25 merged at `2ef62f0`.

The Runtime registry slice adds a closed bounded public import contract and
`registry lookup --catalog FILE --subject NAMESPACE/SERVER`. Eight local
Windows hostile/provenance/resource tests, strict crate lint and the standalone
synthetic lookup demonstration passed. Four actual CLI tests and final main-based
Windows/macOS/Linux/security CI passed before PR #26 merged. No new external
dependency/version, online lookup or authorization input was added. See
[registry contract](REGISTRY.md); hosted work belongs in private Platform.

The enrollment protocol slice adds a secret-owned one-use code, canonical HTTPS
audience, fresh Ed25519 key and independent opaque references, closed bounded
claim, and exact receipt validation. Six hostile/protocol/privacy tests and two
compile-fail API checks cover malformed codes, ambiguous origins, field tampering,
lost-response identity restoration and prohibited event admission. Independent
Node/OpenSSL reproduction and the executable Rust fixture are CI contracts. See
[enrollment](ENROLLMENT.md) and ADR 0027. No network/native-store side effects or
automatic sync activation are implemented by this component.

Local enrollment verification passed all 246 Linux workspace tests with zero
failures/ignored tests, strict workspace Clippy, the independent Node/OpenSSL
fixture comparison, advisory audit and license/source/bans checks. The reviewed
base64 codec adds no runtime transitive dependencies and only its `alloc` feature
is enabled. The actual Platform verifier accepted the Rust synthetic output and
rejected a changed audience and all six individually mutated fields. Three-OS/
native-store/executable CI passed before PR #27 merged at `77e8133`.

The native lifecycle slice stores pending credentials and confirmed receipts in
the existing OS broker, with only an immutable origin/reference anchor on disk.
Failed writes, lost responses, malformed records, wrong-origin access, concurrent
operations and deletion are checked without regenerating identity. An inherited-
descriptor regression explicitly verifies lock release at operation end; a Windows
test was corrected to inspect the anchor after its mandatory lock is released.
Eighteen Windows/Linux tests plus two compile-fail checks passed, with one helper
executed in a child process. The actual Windows native fixture passed pending/
confirmed restart, identical proof and precise idempotent deletion. No network
operation or automatic sender is added. See [native lifecycle](ENROLLMENT_STORAGE.md).

Native lifecycle PR #28 passed both complete Windows/macOS/Linux and security
CI runs before merge at `f567bc4`, including the real OS-store demonstrations.
The optional HTTPS slice adds one authenticated, bounded, nonredirecting bootstrap
request and a claim-bound receipt. Real loopback TLS fixtures cover failure and
privacy behavior. Source/dependency choices and trust limits are documented in
[HTTPS transport](ENROLLMENT_HTTPS.md) and ADR 0029. It does not activate a sender
or complete enrollment CLI composition.

Local verification passed 267 Linux workspace tests (one lock helper is invoked
by a parent test), all 27 Windows enrollment tests and two enrollment compile-fail
checks, strict workspace/crate Clippy, and the real Windows native-store fixture
with HTTPS enabled. The fresh advisory audit covered 310 locked external packages;
all-feature license/source/bans checks passed with reviewed duplicate-version
warnings. No existing external version changed. Three-OS CI remains required.
