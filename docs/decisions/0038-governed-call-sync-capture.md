# ADR 0038: Project live governed calls after required local audit

Status: implemented; automatic delivery and fleet composition remain separate.

The local audit record is not a Platform event. Exporting or replaying that JSON
would couple local schema growth to the egress boundary and could accidentally
include governance detail not approved for sync.

An explicit `mcp serve --sync-profile` opts a governed gateway into live metadata
capture under an already-consented profile. Required audit commits happen first.
The producer copies a fixed typed projection through a bounded nonblocking
channel. Only a dedicated metadata thread owns optional SQLite/reference work;
it never owns a tool transport, argument/result, native credential or HTTP client.
A successful privacy self-test is required before capture becomes ready. Consent
is sampled before the audit write and publication uses that original permit;
resume during a delayed commit cannot retroactively enable that record.

Seven named local key domains resolve through the pinned random-reference catalog.
Fresh per-invocation call/approval IDs and per-event IDs do not enter that catalog.
Local audit chain IDs, evidence, environment, operator attribution and full
definition/policy hashes are excluded. The independently closed wire builder and
queue admission guard remain mandatory.

Short-lived capture sessions hold the original enrollment owner during mapping
and admission. Permits from ADR 0037 are checked before mapping and atomically at
queue admission. The owner is released before channel/timer waits. Explicit
pause/purge can withdraw immediately and then certify drain. Captures with stale
consent are dropped rather than moved into a new consent interval.

Optional capture is best effort until durable admission. Full buffers, startup,
unavailable storage and shutdown may cause gaps; no tool is retried and local
authorization never waits for those gaps to be repaired. Committed events retain
the existing outbox guarantees. Shutdown signals stop without waiting for optional
storage; explicit pause/purge remains the operation that certifies drain.

The new flag is optional, requires enforcement and does not change its closed
configuration format. Existing profiles, audit records and wire events are
unchanged. No background HTTP delivery is enabled by this slice. Tests include
the actual built CLI, native test enrollment and synthetic upstream on all three
supported operating systems.
