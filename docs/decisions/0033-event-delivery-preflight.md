# ADR 0033: Recheck queue state before one-attempt delivery

Status: implemented library composition; continuous sync remains disabled.

A checked lease can outlive a pause, purge or its delivery deadline in memory.
Signing alone must not authorize transmission. Enrollment unlock may also take
longer than the lease; obtain the native owner before claiming an event.

The outbox now performs a committed final check of consent, exact token/body and
partition, clock, remaining lease and retention. The transport requires more than
25 seconds for its 20-second exchange plus local completion. It never renews a
lease or extends retention. Storage/preflight failure sends nothing.

The final clock observation occurs after the maintenance commit. It checks both
wall time and monotonic elapsed time across preflight so a slow SQLite filesystem
commit cannot spend a previously reserved exchange budget unnoticed. Insufficient
time retains the claim without sending or silently retrying. Suspension after
this final check remains an owner-coordination limitation, as before.

An explicit runner claims and sends at most one event, then commits a fixed
outcome. It returns acceptance only after receipt verification and local commit.
Permanent rejection removes unchanged input; uncertain delivery retains the same
ID/body with backoff. Authority rejection or redirect pauses the queue. A crash or
local completion failure can redeliver, so the receiver still deduplicates.

No new dependency, event field, credential storage, background producer, CLI
consent or network destination is introduced. The native owner remains locked
through the attempt. Preflight cannot atomically span SQLite and HTTPS, prevent
OS suspension, or retract a dispatched request. Coordinated worker shutdown is a
separate required boundary before exposing continuous sync.

Tests use real SQLite, independent connection controls, injected commit failure,
deterministic clocks and loopback verified TLS. Native fixtures check pending and
paused refusal without making a request. No customer input is used.
