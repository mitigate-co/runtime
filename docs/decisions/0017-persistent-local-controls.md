# ADR 0017: Transactional local stops and admission quotas

Status: accepted. Date: 2026-09-28. Scope: MCP-014 Runtime control component.

## Decision

Use the existing reviewed SQLite dependency for an explicit local control store.
Exact client/principal/agent/server/tool disables and an emergency stop share a
transaction boundary with deterministic token buckets and bounded administrator
history. A tool target includes its server. Rate limits have fixed configured
targets; observed identities cannot allocate unbounded buckets.

One token is `period_ms` integer units; refill adds `elapsed_ms * refill_tokens`
units with u128 intermediates and a capacity clamp. All matching quotas are
checked before any deduction. Stored balances and a nondecreasing clock prevent
ordinary restart-based resets or overspending by concurrent gateways. Quota
changes preserve earned balances and never automatically refill to burst.

Every change commits its declared operator/time/action with its configuration
revision. Repeated identical settings are no-ops. History retains the newest 256
changes; it is not a remote attestation mechanism. Strict bounded schemas admit
no arguments/results, free-form labels, secrets or arbitrary metadata. No new
external dependencies, package versions, Platform calls or credential flows.

## Consequences and limits

Storage failure or backward time blocks admission. Transactions charge before
returning an allowance; a failed later call is not refunded. A commit whose
outcome cannot be confirmed produces no allowance and may consume quota safely.
Disabled admissions do not consume quota. Explicit removal and recreation is
an administrator-authorized reset, visible in retained history.

File ownership is the local write boundary. Operator references are declared,
never inferred or presented as independent authentication. Trusted system time
is required. Whole-file rollback and writes by a privileged same-user attacker
are outside this protection. Already-dispatched side effects cannot be undone.

The API's `Allowed` result satisfies controls only. Live gateway composition,
approval waiting, binding checks and complete call audit remain required before
calls are enabled. The CLI preview never charges quota or authorizes action.
This preserves the current safe inventory-only executable during construction.

## Verification

Exact-scope and unknown-identity tests; emergency/individual precedence; integer
refill boundaries; overlapping quota atomicity; restart/edit reset resistance;
concurrent independent connections; clock rollback; strict input/privacy;
bounded configuration/history; file protection; full/corrupt/busy databases;
injected commit failure. Real-binary CLI fixtures run on all three CI operating
systems. See [control contract](../CONTROLS.md).
