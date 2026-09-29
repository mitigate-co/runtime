# ADR 0041: Inventory uses the existing egress authority boundary

Status: accepted.

Inventory candidates have a reviewed closed v2 contract, but cannot be useful
unless admitted, journaled and signed under the same authority as decisions.
Accept exactly the reviewed type/version pair in CheckedEvent and preserve
existing v1 validation/canonicalization. Expose a closed EventKind for diagnostics.
Typed conversion does not bypass durable admission or grant delivery permission.

Share partition checks, consent-generation permits, capacity, lease/retry,
retention and same-ID/body receipts across both kinds. No second queue, serializer,
sender or raw inventory import command is added. The outer signature protocol
stays v1 because its canonical digest already binds nested type/version/facts.
Extend the executable privacy probe through actual storage for both kinds.

The old inspector could infer v1 observations from untyped lifetime counters.
That inference is no longer valid. Derive counts/types only from revalidated
retained pending rows, with explicit pending scope. Bump inspector output to v3
and its nested queue report to v2. Historical receipts/journal totals remain
untyped. No payload, event ID or schema fingerprint enters the report.

Stored schemas and v1 bytes are unchanged. Older binaries refuse stores containing
new parts; downgrade requires the current binary to pause and drain or explicitly
purge first. Producers and hosted receiver integration remain separate and must
not activate before the receiver supports durable authenticated inventory ingest.
Older receivers permanently refuse unsupported inventory; this is not delivery
success. No changes to local tool authorization, automatic consent or network policy.
