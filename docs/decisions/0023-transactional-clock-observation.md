# ADR 0023: Observe authority time inside the store transaction

Status: Accepted

## Context

A real CLI approval fixture intermittently returned governance-unavailable during
a concurrent denial. Approval/control stores reject timestamps below their last
committed observation. Sampling OS time before acquiring SQLite's lock permits
normal scheduling to reorder observations: a later sample can commit first, making
the earlier waiting operation look like clock rollback. Failing closed protects
execution, but incorrectly disrupts ordinary operator decisions.

## Decision

Approval and control operations accept a trusted `Clock` and sample it only after
acquiring their transaction and reading validated state. Production gateway, CLI
and real-process fixtures pass `SystemClock`. Explicit `u64` timestamps continue
to implement the clock contract for deterministic tests and simulations.

Keep the persistent nondecreasing clock and all range, expiry and quota checks.
Do not clamp time to the stored value, add a rollback tolerance or automatically
retry a consumed approval/admitted call. Failed clock reads still return no permit.
Approval creation and expiry are derived from the same in-transaction observation.
Embedders control the clock source; MCP messages never select it.

## Verification and consequences

Deterministic probe clocks use an independent SQLite connection to prove the store
already holds a lock when time is sampled. Tests retain exact expiry, rollback,
unavailable-clock and no-extra-quota assertions. Existing fixed-time tests remain
unchanged, and the executable fixture exercises gateway/operator concurrency.

There is no database migration, stored clock reset, error-category expansion or
new dependency. Trusted OS time and same-user database ownership remain assumptions.
