# ADR 0025: Durable optional outbox after privacy admission

Status: Accepted

## Context

MCP-015 needs bounded offline retention without making Platform availability an
authority dependency. Retries must preserve event identity and must not persist
or resubmit rejected workload content. Process crashes and concurrent workers
make an in-memory queue or a delete-before-send workflow insufficient.

## Decision

Reuse the reviewed bundled SQLite dependency for a customer-local outbox. Keep
it in `mitigate-egress`, separate from required audit and policy stores. Validate
the closed candidate first, then commit only checked canonical bytes and a fixed
admission journal together. Persist no rejected source, source ID or source digest.
Bind each store to independently supplied runtime/enrollment references.

Use a committed 30-second random lease and consume its handle for completion.
Expired attempts back off; stale responses cannot acknowledge new attempts.
Retry only transient failures, preserve ID/body, pause on enrollment refusal and
remove permanently rejected events. Bounded completed-ID receipts support local
deduplication; the future receiver remains responsible for its own idempotency.

Inspectors expose fixed counts/actions and partition references, never event
bodies. All operations validate a bounded complete view under a transaction.
Sample time after lock acquisition and validation, preserving strict rollback
detection. Failures return no admission/delivery capability. Mutations prune age
and capacity deterministically; no full queue silently evicts pending events.

## Consequences

No new external dependency/version is introduced: existing SQLite and SHA-256
are reused. The digest applies only to previously checked event bytes for local
duplicate receipts. No arbitrary payload queue, free-form diagnostics or network
sender is added. Work is bounded but linear in retained events; no throughput
or latency marketing claim follows from this choice.

This is at-least-once telemetry delivery support, not a distributed transaction
with tool execution. Dedicated workers must isolate failures from local authority,
maintain expiry and recheck consent/enrollment before sending. Pause/purge cannot
unsend an in-flight request. Actual enrollment, signing, sending, fleet ingestion
and tenant isolation remain separate acceptance gates.

The store is not cryptographically authenticated or encrypted, and whole-file
rollback/same-user attacks remain outside the boundary. Preserve a failed store;
never auto-repair it into a permissive state. See [operator contract](../OUTBOX.md).
