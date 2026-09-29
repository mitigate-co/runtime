# Customer-local optional sync outbox

`mitigate_egress::outbox::Outbox` is the durable queue and admission journal for
closed sync candidates. It is a library component, with an executable synthetic
demonstration. It has no HTTP client, credentials, enrollment workflow or automatic
gateway producer of its own. The CLI's explicit [capture worker](SYNC_CAPTURE.md)
uses it after required local audit. Creating a queue does not start synchronization.

An integration must obtain explicit local consent, provision independent random
runtime/enrollment references and own the queue on a dedicated worker. Queue
errors must not change local tool authorization or required local audit behavior.
There is no conversion from arbitrary local audit exports to this queue.

## Admission and retained data

`create` exclusively creates a private SQLite store; `open` requires the exact
independently configured partition. Neither repairs or overwrites an existing
store. `admit` validates the [closed event contract](SYNC_EVENTS.md) before any
input can be persisted. Accepted event bytes and the content-free journal commit
atomically. No admission success or delivery lease is returned on commit failure.

Rejected input never becomes a queued event. Only the fixed rejection category,
bounded observed byte count, trusted time and local sequence are retained. No
rejected payload, identifier, digest or backend exception is stored or printed.
Every candidate runtime must match the configured runtime reference.

A buffered producer must call `capture_permit` before taking optional metadata,
then use `admit_captured` with the original opaque permit and typed checked event.
The worker checks the permit in the same write transaction as admission. Pause,
authorization refusal and purge invalidate it durably; later resume cannot make
old buffered captures eligible again. Queue-specific randomness prevents a permit
from another queue, including one with the same enrollment, from being accepted.
Control generations survive restart and journal eviction. No permit identifiers
or generations enter wire events or diagnostic reports.

`None` means capture is disabled or legacy storage needs explicit resume.
`ConsentChanged` means discard the capture. Never retry it with a new permit.
The unbuffered `admit` API remains for low-level immediate admission and privacy
probes; it must not be used to drain buffered gateway activity. These APIs do not
turn on a gateway producer or create a background sender.

The same pending/completed ID with the same canonical body is a duplicate. Reusing
that ID with different validated facts is a conflict. Completed/expired events
leave only an event ID, completion time and digest of the already validated
canonical event for duplicate detection. This digest is never computed from
rejected or raw workload content. Receipts are bounded; deduplication is not an
unlimited history or an exactly-once delivery guarantee.

## Limits

| Resource | Bound |
| --- | --- |
| Pending events | Configured 1–1,000; default 1,000 |
| Event input and canonical bytes | 4 KiB each |
| Pending retention | Configured 1 second–7 days; default 7 days |
| Completed-ID receipts | Same count and age bounds, oldest removed first |
| Recent journal | 128 entries, also age bounded |
| Lifetime counters | Fixed action categories; saturate at 2^53−1 |
| SQLite file | 16 MiB, 4,096 pages, reviewed bundled SQLite |
| Transaction work | 2 seconds; SQLite busy wait 250 ms |
| Delivery lease | 30 seconds |
| Transient retry | 1 second doubling to 1 hour maximum |

Full queues refuse new events without evicting pending events. Retention uses the
trusted admission clock, never the event-provided timestamp. Mutating operations
apply expiry before their own work; `claim` does this even while paused. An active
integration must run maintenance through periodic claims. An inactive process
cannot erase an offline disk on a timer. `inspect` reports retained state without
pruning or extending retention. Correct a backward/unavailable OS clock before
resuming; rollback observations are rejected, never clamped.

## Delivery lifecycle

`claim` commits an exclusive random lease before returning the exact checked
event. Dropping a handle does not acknowledge delivery. An expired lease schedules
backoff; another worker can later claim the same ID and bytes. A stale response
cannot delete a newer attempt. `complete` consumes the handle and accepts only a
fixed outcome:

- `Accepted`: the authenticated receiver confirmed durable acceptance; remove
  the body and retain a duplicate receipt.
- `Transient`: retry the same ID/body after bounded exponential backoff.
- `Rejected`: permanently remove this event; never automatically retry an
  unchanged privacy/schema refusal.
- `Unauthorized`: pause admission/delivery until explicit operator recovery.

A crash after receiver acceptance but before the local completion commit can
redeliver. The receiver must independently deduplicate stable event IDs.
The sender must verify enrollment/consent, destination and signature immediately
before transmission, use a timeout shorter than the lease and classify responses
without passing their bodies into this API. The queue alone does not authenticate
a destination or authorize any network action.

`delivery_ready(&Lease, budget_ms)` checks the exact committed token/body and
partition, current pause state, and remaining lease and retention time. Budgets
must be 1–30,000 ms; both remaining times must be strictly greater. It commits
clock/expiry maintenance before returning and never extends a deadline. Failure
or `false` forbids submission. [Event HTTPS](EVENT_HTTPS.md) uses a 25-second
budget and offers a one-attempt runner that persists only classified outcomes.
The preflight does not hold a transaction across network I/O or coordinate
shutdown: a sender owner must still drain outstanding work on opt-out.

The pure [event signing contract](SIGNED_EVENTS.md) takes this committed lease and
checks both partition references before signing. It binds the exact canonical
body and verifies matching receipt fields without changing the queue. It cannot
establish current consent, native enrollment, lease validity or durable remote
acceptance by itself.

`set_paused` prevents new admission/claims. `purge` pauses and removes pending
bodies and duplicate receipts; it retains the bounded content-free journal and
counters. Neither can retract bytes already copied into an outstanding lease or
sent on the network. The owning sender must cancel outstanding work on opt-out.

## Storage and recovery

Lock contention beyond the 250 ms wait returns the distinct fixed `Busy` error
with no delivery lease. The optional worker may retry after backoff; contention
never enters tool authorization. Other SQLite failures remain `Storage` and
must not be silently treated as an empty queue. Concurrent-worker tests allow
only successful/empty claims or explicit lock contention, then verify exactly
one committed lease and delivery. A held-lock regression verifies that failed
admission/claim attempts leave counts and leases unchanged.

Each transaction verifies the exact schema, closed stored records, canonical event
bytes, reference binding, numeric/time bounds and capacity. SQLite uses full
synchronous DELETE journaling, secure deletion, full auto-vacuum, bounded SQL,
defensive mode and no trusted schema. Unix files require private permissions;
Windows files inherit the customer's directory ACL. Symlinks/final reparse points,
non-files and oversized stores are refused. Keep the parent directory private.

This is not encrypted storage, tamper-proof storage or secure erasure of external
backups, filesystem snapshots or SSD remanence. A malicious same-user process or
whole-file rollback is outside the guarantee. Immutable partition comparison
prevents accidentally using a queue with a different configured enrollment.

On storage/integrity failure, stop this optional queue worker, preserve the file
and inspect permissions, free space, clock and backups. Do not delete local
authority/audit stores or replay tool calls to recover telemetry. An uncertain
completion must be reconciled by reopening the queue, not by inventing success.
New queues use storage version 2 with an exact non-null capture-consent object.
Version 1 remains readable and supports existing admission, delivery, pause and
purge without migration. It cannot issue capture permits. Explicit
`set_paused(false)` (including `mitigate sync resume`) upgrades it atomically to
version 2, preserving pending bodies, leases, duplicate receipts and journal.
Both record and SQLite version roll back on a failed commit. A missing/null/
malformed capture field or a field/version mismatch fails closed; open/inspect
never repair it. Other versions are unsupported.

Earlier binaries cannot open version-2 queues. Before rolling back a binary,
use the matching binary to pause/drain and preserve the queue. There is no
in-place downgrade or automatic file deletion. This storage version is separate
from the immutable sync profile version; neither wire events nor CLI reports
change. See ADR 0037.

## Demonstrate and verify

```sh
cargo test -p mitigate-egress --locked
cargo run -p mitigate-egress --example outbox --locked
```

The example creates its own temporary synthetic queue, rejects a content canary,
reopens committed events, acknowledges a delivery, schedules a retry, reopens
duplicate receipts and explicitly purges. It prints a closed local report and
removes only its own fixture directory. It performs no network or credential I/O.

Tests additionally cover clock rollback, disk-full/commit failures, exact capacity,
lease expiry, concurrent workers, stale acknowledgements, permanent rejection,
bounded backoff/journal/receipts, invalid stored content/schema and private paths.
[CLI inspection and privacy self-test](PRIVACY_COMMANDS.md) exercise this boundary
without a sender. Optional authenticated Platform delivery remains MCP-018 work.
