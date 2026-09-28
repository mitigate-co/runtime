# ADR 0016: Local approvals for one pending call

Status: Implemented (MCP-013; enforcing gateway composition is a launch gate)

## Decision

Use a customer-local SQLite mailbox shared by gateway and operator CLI. The initial
scope is one call with a validity window of at most five minutes. No Platform
account, network service, browser approval listener or reusable broad approval is
introduced. Reuse the reviewed SQLite wrapper, strict JSON parser and existing
`getrandom` dependency. No external package or version is added.

An immutable metadata binding captures caller/principal/agent, fresh random session
and call references, reviewed server/tool, schema/definition, policy identity,
version and exact bundle hash, classes and environment. Raw arguments remain in
the gateway's immutable invocation memory; no argument digest is persisted. The
gateway must generate unpredictable references and never resume an old session's
pending calls after restart. Unknown principal/agent stay null; a known client is
required. Capability order is normalized, not treated as a semantic change.

Requested and approved records can expire or be cancelled. Operators can approve
only requested calls, or deny/revoke before consumption. Revocation retains both
decisions and their declared local operator references. Other terminal states never
return to approved. Binding change cancels an active request.

`consume` performs all binding/state/expiry checks inside a write transaction and
commits consumed state before returning a non-cloneable permit. A commit failure
returns no permit. Consumption is intentionally at-most-once; exactly-once tool
effects cannot be guaranteed across process/transport crashes. Uncertain calls are
not automatically retried. A permit satisfies only the approval gate.

## Clock, bounds and trust

The database persists a nondecreasing UTC observation. An older observation is an
error, including concurrent operations arriving out of order. Expiry is committed
even if a requested operator transition fails. The live gateway must also maintain
a monotonic bounded wait, cancel on disconnect and recheck policy/grants/schema and
emergency controls before consumption/dispatch. That integration is not enabled in
the inventory-only endpoint by this package.

Bound metadata to 4 KiB per record, 256 records, and 2 MiB of database pages. Never
evict active requests. Retain terminal records for up to 24 hours, evicting the oldest
terminal record if needed for a new request. This mailbox is not the long-term audit
store; gateway audit composition records approval references and operator decisions
under its separate retention controls.

Use private Unix file permissions and protected Windows parent ACLs, reject linked
or incompatible files, cap SQL work and fail on corrupt records. Full synchronous
transactions and independent connections serialize consumers. Loaded metadata is
always revalidated before transition. These checks do not protect against a
privileged process rewriting the complete store or trust configuration.

Operator references are explicitly declared (`declared_local`), never presented as
authenticated directory identities. Same-user processes with database access share
the trust boundary. Enterprise authenticated approvals require an additional
verified control path; neither clientInfo nor an operator-supplied label establishes
one. No raw workload data or credential reaches normal output or Platform.

## Verification and rollback

Unit/integration tests cover complete lifecycle, every binding mismatch, restart,
expiry boundaries, persistent clock rejection, races, replay, capacity/retention,
private files, corrupt schema/records, database-full rollback and commit failure.
The CLI contract checks actual request/review/approve/revoke commands, confirmation
requirements, fixed errors and raw-content rejection with a temporary database.

The feature is opt-in with an explicit new database. No existing state migrates.
Rollback removes the new commands and API; retain the local database for inspection.
Never reset it as a fallback or use its approvals for a new gateway session.
