# ADR 0037: Bind buffered metadata to its original sync consent

Status: implemented; gateway producer composition remains separate.

A bounded producer channel separates optional sync from local authorization. A
paused flag alone is insufficient: an old buffered event could be admitted after
the operator resumes sync. Purge could also be followed by stale buffer refill.

Each new queue stores a random local queue reference and monotonic consent
generation in storage version two. The opaque capture permit copies that state
before metadata capture. `admit_captured` compares it under the same write lock
and transaction as admission. Pause transitions, authentication-induced pause and
purge increment the generation; resume cannot revive old permits. Idempotent
repeated controls do not discard valid active captures. Purge always invalidates.
Generation changes use no randomness, network or native credential access.

The scope is queue-local even when two queues share an enrollment. Generation is
independent of the bounded journal, so restart and journal eviction cannot erase
withdrawal. A stale capture is discarded, never retagged under fresh consent.
Permits cannot be serialized/exported through the public API and are not added
to wire events or CLI reports. Already admitted events retain existing delivery
semantics; already sent bytes cannot be retracted.

Version-one stores retain their existing controls and delivery without silent
migration. They do not issue capture permits. Explicit resume creates capture
state and advances SQLite's version in one transaction, preserving accepted
events, leases, receipts and journal. Mixed/malformed versions are refused.
Earlier binaries cannot open version two. Rollback requires pausing/draining
with the matching binary and preserving state; no automatic downgrade, repair
or deletion is introduced. Immutable profile and wire schemas are unchanged.

Tests use real SQLite connections for pause/resume, purge, restart, queue scope,
authorization withdrawal, journal eviction, competing admission/purge, corrupt
state refusal and legacy commit-veto rollback. The synthetic mapping example
exercises typed admission and proves purge/resume cannot restore old consent.
