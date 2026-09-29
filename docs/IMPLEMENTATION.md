# MCP implementation status

Updated 2026-09-29. Follow the canonical ordered work packages. This file reports implementation evidence, not production readiness.

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
| MCP-018 — Optional Platform sync | Runtime inventory producer merged | PR #47 at `48f993b` passed three-OS/security CI for explicit fresh inventory capture. Hosted composition and release acceptance are separate gates. |
| MCP-019 — Reputation/index | Hosted implementation belongs to Platform | No private cohort/publication logic is added to Runtime. See the private repository's implementation evidence. |
| MCP-020 — Release engineering | Packaging, verification, installation and native staging under review | Clean-commit builds, SPDX/notices/checksums, source/CI gates, bounded publisher verification and a closed new-directory installer. [Native staging](RELEASE_STAGING.md) composes fresh builds, Apple signing/notarization and final archive validation. The protected direct signing workflow, authentic signing evidence and positive fresh-machine installation remain acceptance gates. |
| MCP-021 — Adversarial hardening | Deterministic input corpus merged | PR #53 at `2389967` passed native/security CI for exact parser boundaries, hostile event controls, decoded duplicates and 6,144 bounded mutations. PR #58 at `a26c85f` preserves fixed capture failure diagnostics. Unresolved failure causes remain release gates; see [adversarial testing](ADVERSARIAL_TESTING.md). |
| MCP-022 through MCP-024 | Remaining acceptance work | Follow the [low-level packages](modules/mcp/LOW_LEVEL.md#19-work-packages). Existing prototype evidence does not establish acceptance in this repository. |

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
warnings. No existing external version changed. Both complete Windows/macOS/Linux
and security CI runs passed before HTTPS PR #29 merged at `30e1944`.

The enrollment CLI now composes explicit start, retry, local status and precise
credential deletion. Pending proof is persisted before HTTPS and retained on
failure; confirmed retry is local. A bounded pipe keeps codes out of arguments
and fixed diagnostics. No external dependency/version is added by the CLI slice.
Actual-binary validation and an isolated Linux native-store demonstration passed,
including failed TLS, stable retries, duplicate-start refusal and idempotent
deletion. Interactive hidden input remains separate. See [CLI](ENROLLMENT_CLI.md).
The full Linux workspace/all-feature suite and strict workspace Clippy passed;
the staged secret scan found no leaks. Three-OS CI remains the merge gate.
Initial CLI CI passed Windows/Linux and dependency/privacy gates. macOS stalled
when the CLI accessed the unsigned example's Keychain item. The macOS fixtures
now keep native receipt checks in the creating binary and run the actual CLI's
pending/retry/deletion lifecycle with its own entries; Keychain ACLs stay intact.

Interactive enrollment now reads a hidden code with bounded owned input, normal
keyboard cancellation and exact terminal restoration. Pipe input remains explicit
and required for machine output. Linux actual-CLI tests and PTY scenarios passed;
the same production prompt module passed Windows ConPTY scenarios in a disposable
harness. Both complete Windows/macOS/Linux and security CI runs passed before
PR #31 merged at `47a20bc`, including the actual terminal scenarios. Dependency
review, advisory audit and license checks passed. See ADR 0030 and the enrollment CLI guide.

Both corrected CLI CI runs passed all five gates before PR #30 merged at
`e002511`. The signed event contract now requires a committed checked outbox
lease, binds the canonical event to its exact enrollment/audience/endpoint and
validates a closed acknowledgment without changing the queue. Windows and Linux
passed all 30 enrollment tests plus four compile-fail checks (one separate lock
helper runs through its parent). Strict workspace Clippy and the independent
Node/OpenSSL signature/body/tamper fixture passed. No dependency version changed.
See [signed events](SIGNED_EVENTS.md) and ADR 0031; this does not yet activate a
sender or compose confirmed native credentials with delivery.
The full Linux workspace/all-feature suite passed 275 test cases, with no failures;
the lock helper is invoked by its parent test. The staged secret scan found no leaks.

Native event signing now requires confirmed local enrollment and uses the restored
key, identity and pinned origin under the existing operation lock. Pending state
and another enrollment's queue are refused. Interrupted confirmation tests require
reopening to reconcile actual native state before signing. All 32 enrollment
tests and four compile-fail checks passed on Windows/Linux, plus strict workspace
Clippy. Real Windows Credential Manager and isolated Linux Secret Service fixtures
passed identical-signature recovery and exact credential/queue cleanup without
network requests. Event HTTPS, consent coordination and hosted ingest remain open.

Signed-event protocol PR #32 passed both complete three-OS/security CI runs before
merge at `508a5c9`. The explicit HTTPS exchange now borrows confirmed native
enrollment, signs the checked lease and returns only an exact authenticated receipt.
It shares the private bootstrap TLS policy/JSON reader without new dependencies.
All 38 enrollment/transport tests plus four compile-fail checks passed on Windows
and Linux; the separate lock helper runs through its parent. Default-feature tests,
strict workspace Clippy and the Linux CLI regression suite also passed. Real
Windows and isolated Linux native demonstrations verify pending submission refusal
without a network request. See [event HTTPS](EVENT_HTTPS.md) and ADR 0032. Consent,
lease/shutdown coordination and hosted ingest remain required before continuous sync.

Event transport PR #33 passed both complete three-OS/security CI runs before
merge at `7efa002`. The next composition rechecks committed pause state, exact
lease ownership and remaining lease/retention time before HTTPS. Its explicit
one-attempt runner records only fixed outcomes: exact accepted receipt, permanent
refusal, retained retry or authority-induced pause. Local completion failure
cannot report acceptance. No producer, consent activation or continuous worker is
enabled. See [event delivery](EVENT_HTTPS.md) and ADR 0033.

Windows passed 30 outbox/egress tests, 44 enrollment/transport tests and five
compile-fail checks. The separate native lock helper runs through its parent.
Default-feature enrollment tests and the real synthetic Windows credential-store
demonstration passed. Strict Linux workspace Clippy, the advisory audit and
all-feature dependency/license/source checks passed without dependency changes.
Coordinated shutdown, explicit user controls and fleet composition remain open.
The full Linux workspace/all-feature suite passed 293 test cases, including
compile-fail contracts, without failures.
The isolated Linux Secret Service fixture and actual enrollment CLI lifecycle
passed; native fixtures also reject mismatched queue scope before claiming.

Explicit sync controls now bind a new private queue to the original confirmed
native enrollment. Enrollment remains separate from consent. Status is local;
resume verifies the native binding; send attempts at most one queued event.
Pause first persists withdrawal, then drains the original owner lock and
reasserts pause before reporting completion. Purge follows that sequence without
requiring credential-store access. No automatic producer or worker is activated.
See [sync controls](SYNC_CONTROLS.md) and ADR 0034. Enrollment and egress CLI
reports advance to version 2 so they no longer claim unknown sync state is off.
The prerequisite delivery composition passed both complete three-OS/security CI
runs before PR #34 merged at `49e6af9`.

The full Linux workspace/all-feature suite passed 301 cases, including the new
actual CLI contracts and compile-fail checks; strict workspace Clippy and
formatting passed. Default-feature enrollment passed 29 tests plus four
compile-fail checks. The native lock helper is executed through its parent.
Windows passed 50 enrollment tests and four compile-fail checks. Synthetic
Windows and isolated Linux native-store demonstrations verified consent,
resume, pause/drain, purge, paused send and exact credential deletion; Linux also
exercised those operations through the actual CLI without external requests.
An earlier Linux privacy-probe test reported storage unavailable once; the
targeted rerun, full workspace run and ten additional probes passed without a
reproduction. Its cause remains unconfirmed; no storage limit or assertion was
relaxed. Both complete Windows/macOS/Linux and security CI runs passed before
controls PR #35 merged at `a126eeb`.

The local reference catalog now assigns independent random wire IDs to seven
closed domains of local governance keys. Exact enrollment scope, atomic batches,
durable restart, concurrent resolution, failed commits, capacity and corrupt-file
refusal are covered. No gateway producer, automatic sender or profile migration
is enabled. See [reference mapping](SYNC_REFERENCES.md) and ADR 0035.

Reference mapping passed 37 egress tests and two compile-fail checks on Windows
and Linux, plus the synthetic mapping-to-queue demonstration on both systems.
The full Linux workspace suite passed 309 cases. A subsequent privacy diagnostic
regression passed with all 38 egress tests, two compile-fail checks, four actual
CLI privacy contracts and strict workspace Clippy. It preserves closed storage
failure categories without exposing local paths or content. The intermittent
privacy-probe storage failure remains under investigation in
[issue #36](https://github.com/mitigate-co/runtime/issues/36); successful reruns
and improved diagnostics do not close that release gate.

Sync setup now creates an enrollment-scoped catalog beside the queue and pins it
in a version-two profile. Existing version-one profiles retain their controls
without migration. Pause/purge preserve stable mappings and tolerate a missing
catalog; resume validates the original catalog before unpausing. Tests cover
preexisting-file refusal, partial setup, catalog retention and closed versioned
profiles. All 53 enrollment tests and four compile-fail checks passed on Windows
and Linux; the native lock helper runs through its parent. Windows also passed
all 38 egress tests and two compile-fail checks. Synthetic Windows and isolated
Linux native fixtures verified missing/wrong-scope catalog refusal and legacy
resume without recreation; Linux exercised the setup controls through the actual
CLI. No gateway producer or background sender is activated by this change.

Buffered captures now require an opaque queue-specific consent permit. Queue
admission checks it atomically; pause, purge and authentication withdrawal
invalidate old captures even after resume, restart or journal eviction. New
queues use storage version two; legacy queue upgrade occurs only on explicit
resume, with commit-veto rollback and accepted-record preservation covered.
Profiles and wire events do not change. See [outbox](OUTBOX.md) and ADR 0037.
Windows and Linux passed 44 egress tests, 53 enrollment tests and six compile-fail
checks; the native lock helper runs through its parent. Strict workspace Clippy
passed, and the executable mapping example verified stale-capture refusal.
The first Linux run returned `Storage(Clock)` in the privacy self-test before a
subsequent full run passed. This narrows that recurrence to the clock guard; it
does not establish the original cause or close issue #36. No timeout, clock
tolerance, retry or privacy assertion was relaxed.

The governed CLI now accepts an explicit sync profile for live typed metadata
capture. Consent is sampled before the audit write; only a successful required
commit may publish into the bounded nonblocking buffer. A dedicated worker maps
seven local key domains to random references and admits checked events under the
original owner and consent permit. It has no tool transport, credential or HTTP
client. Startup requires the real privacy probe to pass. See
[capture behavior and loss limits](SYNC_CAPTURE.md) and ADR 0038.

The Linux workspace suite passed 325 cases, including compile-fail contracts;
after tightening consent sampling before audit, all 17 CLI unit tests passed.
Windows passed 54 enrollment tests and four compile-fail checks. Strict workspace
Clippy passed. An isolated Linux native fixture exercised real CLI capture,
durable allow/deny records, random-reference correlation after restart,
pause/purge and continued local operation with a missing sync profile. Automatic
HTTP delivery and fleet composition remain open. These passing checks do not
close the intermittent privacy-probe clock investigation in issue #36.

Optional send now prepares its queue before opening native credentials. Empty,
paused, leased and backing-off queues wait without taking the enrollment owner
or rewriting the queue. Due expiry uses a fresh bounded transaction; abandoned
leases receive their normal delayed retry without identity/body changes. Claims
also reserve the complete retention budget, preventing a nearly expired record
from taking leases ahead of deliverable work. These are scheduling hints only:
native confirmation, consent, exact lease and final HTTPS checks still run.
See [delivery preparation](OUTBOX.md#delivery-lifecycle).

The Linux workspace passed 332 tests including compile-fail contracts; the native
lock helper runs through its parent. Windows passed the relevant egress/enrollment
tests, native credential-store lifecycle fixture, no-HTTPS compilation and strict
package Clippy. Strict workspace Clippy and Linux executable builds pass. New
cases cover read-only polling, unchanged retry bytes/delays, abandoned leases,
retention eligibility, independent pause, corruption, rollback and a vetoed
maintenance commit. The existing concurrent pause test now treats documented
SQLite `Busy` as contention while retaining its original deadline and requiring
the actual committed pause. No runtime timeout, clock guard, wire/profile/storage
version or consent rule changes. A continuous sender remains the next slice.

The explicit `sync run` CLI now continuously delivers through the existing native
owner, checked lease and signed HTTPS path. It requires a passing actual privacy
probe, polls idle queues without credential access, honors durable backoff and
stops on observed pause, authority refusal or fatal storage errors. Signals wait
for current work without changing consent. A ready manual send applies the same
privacy gate. See [controls](SYNC_CONTROLS.md) and ADR 0039.

The full Linux workspace passed 339 tests, including compile-fail contracts;
the native lock helper runs through its parent. Strict workspace Clippy and
executable builds passed. An isolated Linux native-store fixture exercised real
continuous CLI instances, failed-probe refusal, unchanged idle queue bytes,
Ctrl-C/SIGTERM and durable pause, plus the existing capture/enrollment lifecycle.
Seven deterministic driver tests cover cancellation boundaries, in-flight drain,
backoff, permanent/authority refusals, output failure and fatal native/storage
errors. No dependency, wire, profile or SQLite version changes. Three-OS CI remains
the merge gate; inventory/fleet composition and issue #36 remain open. The preceding
preparation change passed all ten CI checks and merged as PR #42 at `85ed4ad`.

A separate version-two inventory candidate now validates fixed classification
facts in four-tool parts, with at most 512 tools per observation. Pure assembly
requires every part, matching scope/time/counts and distinct ordered tools.
Missing/conflicting parts cannot produce a complete snapshot. This type is not
accepted by the decision outbox, signer, sender or inspector; producer and hosted
composition remain required before activation. See [inventory protocol](INVENTORY_PROTOCOL.md)
and ADR 0040. No active wire/queue/command behavior is widened.

Windows and Linux each passed all 61 egress tests and three compile-fail checks.
Eleven new tests cover every snapshot size, full-taxonomy byte limits, private
input refusal, exact nested schemas and complete/partial/conflicting assembly.
Strict workspace Clippy and formatting passed. The executable candidate example
validated the synthetic part while explicitly reporting zero admission/network
requests. No dependency or storage migration was added. Three-OS CI remains the
merge gate; MCP-018 and the privacy-probe issue remain open.
Continuous sender PR #43 passed all ten three-OS/security checks and merged at
`d267dc7`; its tests do not close the outstanding inventory or release gates.

Inventory candidate PR #44 passed all ten public checks and merged at `97e3e7e`.
The next composition admits its exact v2 type/version through CheckedEvent and
the existing shared outbox. Consent-generation checks, durable journal, partition,
capacity, retry, retention, leases and receipts apply unchanged. The inspector
now reports exact pending type/version counts, without inferring historical types
from untyped counters. Its output is v3 and the queue report is v2; stored schemas
are unchanged. See ADR 0041 and the inventory downgrade/receiver-rollout guidance.

Windows passed 65 egress and 56 enrollment tests plus seven compile-fail contracts;
the native lock helper is invoked by its parent. Linux workspace tests and strict
all-target/all-feature Clippy passed. Added checks exercise mixed queues, retry and
receipt recovery, original capture consent, rollback/corruption, full 1,000-part
taxonomy queues and exact inventory HTTPS receipts/refusals. Actual CLI inspection
remains read-only and drops observed types after drain, while retaining untyped
counters. The executable privacy probe rejects all 260 hostile candidates across
both kinds and preserves only two safe controls. Node/OpenSSL independently
reproduces Rust signatures and rejects changed fields for both public fixtures.
No inventory producer or hosted receiver is activated; MCP-018 remains open.
The native Linux lifecycle/CLI fixture passed after adding bounded failure
categories and synthetic assertion line diagnostics. An earlier run failed with
only the legacy generic message; its cause remains unproven. This successful
rerun does not close issue #36 or the intermittent-fixture release gate.

One Windows governance fixture on the initial inventory-egress revision returned
`governance_unavailable` after a local approval denial, instead of the expected
`denied`. The matching PR run passed; that is not evidence of a fix. Approval and
control failures now retain only their fixed library error codes on local stderr,
and the failing assertion can report one allowlisted category within 257 bytes
and 500 ms. No workload data or backend exception is printed. A deterministic
approval-clock regression confirms the invocation remains undispatched when
approval inspection and cancellation both fail. Authorization, clock guards,
timeouts and expected fixture results are unchanged; the intermittent failure
still needs a demonstrated cause before release.

Inventory egress PR #45 passed all ten three-OS/security checks and merged at
`62bd9a4`. The explicit `--sync-inventory` gateway flag now captures fresh initial
tool listings only after inventory review and required local audit. Original
consent is reserved before the request, and a single bounded observation shares
the decision worker. Small mapping/admission steps release enrollment ownership
between operations; partial capture never claims completeness or renews consent.
Existing commands remain decision-only. See ADR 0042 and [capture](SYNC_CAPTURE.md).

The Linux workspace passed 362 tests, including compile-fail contracts; strict
all-target/all-feature Clippy and formatting passed. The native lock helper runs
through its parent. The actual isolated native-store CLI fixture
passed decision/inventory capture, denied calls, audit-failure refusal, continuation
exclusion, restart-stable references, new observation IDs, pause/purge, continuous
sending and enrollment/TLS-refusal checks. Inventory unit tests cover 512 tools,
all parts, taxonomy preservation, oversize refusal and revoked original consent.
No dependency, storage schema, authority or automatic sync activation changed.

An earlier native fixture attempt stopped at the installed privacy probe. The
capture worker now retains fixed assertion/workspace/setup/cleanup/storage/clock/
budget categories, with no backend text or workload content. That attempt did not
preserve its cause; the successful final run does not close issue #36.
Issues #36 and #46 remain release
gates. Three-OS CI and hosted fleet composition remain required.
