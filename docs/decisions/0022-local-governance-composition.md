# ADR 0022: Compose local governance at the dispatch boundary

Status: Accepted

## Context

Independently verified grants, approvals, policy, controls and audit do not protect
a call unless their decisions govern the actual send. Approval can take minutes;
policy, stops or reviewed definitions can change during that interval. Blocking
storage operations can complete after an async future is cancelled.

## Decision

Add an explicit `mcp serve --enforce FILE` mode requiring an exact launch review,
reviewed tool snapshot and initialized local authority stores. Preserve explicit
inventory-only mode. Validate schemas and arguments before creating an approval;
keep arguments owned by the request future, outside metadata workers.

Use the adapter's final dispatch gate from ADR 0021. After refreshing schemas,
inventory and code, recheck current grants and verified policy, admit controls,
consume a bound approval when present, and append the versioned dispatch audit
before sending. A changed approval binding cancels rather than broadens permission.
Loaded last-known-good policy survives invalid refreshes. Unknown clients remain
denied independently of Rego. The initial implementation is fully local/offline.

One mutex serializes metadata work for the session. Blocking workers own only
bounded metadata and store handles. Cancellation marks the call, drops the sole
transport owner, confirms child cleanup, then queues metadata completion behind
any started commit. No worker can send a delayed call.

The listener accepts an operator-selected bounded request budget and a constant
space progress sink. It correlates only counters with the downstream token; no
server message text or token is forwarded as progress.

## Consequences

Admission is conservative, not a distributed transaction across SQLite stores
and a process pipe. A control charge or consumed approval is never automatically
refunded when later work fails. Audit dispatch means committed authorization, not
proof of execution; completion can be uncertain or absent after a crash. Success
is returned only after completion audit commits. No automatic call replay exists.

Protect local configuration/store directories and OS time. Same-user tampering,
whole-store rollback, unselected transitive code and already-admitted side effects
remain outside these guarantees. Startup credential injection authorizes the
selected process lifetime, not a per-tool credential lease. No telemetry or new
external dependency is introduced. Operator configuration and exact reference
ergonomics remain required before declaring the work package complete.

Verification combines authority lifecycle tests with real CLI subprocesses and
synthetic invocation markers. The documented behavior and limits are in
[ENFORCEMENT.md](../ENFORCEMENT.md).
