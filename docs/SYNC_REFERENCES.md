# Local sync reference mapping

Local governance fingerprints must not become Platform identifiers. A digest of
a predictable name or schema is not anonymization. `ReferenceMap` keeps those
lookup keys in a private customer-local SQLite file and assigns independent
128-bit random references for the closed event contract.

The store is pinned to an independently supplied runtime/enrollment partition.
Seven closed domains distinguish client, principal, agent, server, tool, schema
and policy keys, even when their 32-byte digests match. Only trusted local
identity/schema facts belong here. Do not map raw arguments, results, matched
sensitive values or content fragments. Call, event and approval references are
per-invocation random values, outside this durable catalog.

## Persistence and limits

Creation requires a new path in a private directory and explicit consent from the
owning integration. Opening requires an existing valid store and the same scope.
There is no automatic repair, adoption, overwrite, reenrollment or key rotation.
This library does not itself enroll, enable sync or start a producer/sender.

Each resolution transaction accepts one to sixteen typed keys, checks the entire
stored schema and catalog, and returns references only after commit. Duplicate
input keys preserve order and share one reference. Concurrent writers serialize
through SQLite. New references are checked against the catalog and enrollment
references before insertion. Commit failure returns no mapping; after an
uncertain write, reopen the original store to reconcile its actual state.

The catalog holds at most 8,192 mappings. Full catalogs still resolve known keys;
new keys fail atomically without eviction. References remain stable across
restarts and are not automatically aged out. This avoids silently assigning a
new hosted identity while older events still refer to the previous one. A new
enrollment uses a new catalog. Version-two [sync profiles](SYNC_CONTROLS.md)
create and pin the catalog during explicit consent. Pause/purge retain stable
mappings; resume verifies the original store and never regenerates a missing one.
[Gateway capture](SYNC_CAPTURE.md) resolves these references on a separate
metadata worker. [Continuous sending](SYNC_CONTROLS.md) is an explicit foreground
command; neither mapping nor gateway capture starts network delivery.

The shared private SQLite opener applies the existing 16 MiB file cap, 250 ms
busy wait, two-second work budget, defensive/trusted-schema settings, restricted
SQL limits, DELETE journal, FULL synchronous/secure-delete and bounded memory.
Unix requires mode 0600; Windows inherits the private parent ACL. The mapping
file has its own exact version-one schema, separate from the existing outbox.
Unexpected tables/indexes, scope changes, malformed references and oversized
catalogs fail. Local keys have no serialization/debug implementation, export API
or command report. Existing same-user/root tampering and filesystem rollback
limits still apply; this catalog is not authentication or consent authority.

## Egress boundary and validation

Only random mapping outputs may enter `DecisionFacts`. The candidate still
passes `CheckedEvent` validation and the queue's independent consent, partition,
capacity and privacy journal checks. Mapping success is not queue admission or
delivery. Use the synchronous catalog only on a metadata worker, outside local
tool authorization; mapping/storage failure must never disable local protection.

Tests cover domain separation, durable recovery, reenrollment isolation,
non-overwrite, concurrent allocation, commit rollback, full-store batch atomicity,
closed/corrupt schema, private files and nonserializable keys. Run the synthetic
mapping-to-queue demonstration with no account or network:

```sh
cargo run -p mitigate-egress --example reference_mapping --locked
```

The demonstration owns a temporary local fixture and removes its exact files.
It prints only a fixed verification result, never keys or mapping pairs.

The concurrent-allocation fixture opens its independent connections before
starting the coordinated resolution race. Windows [run 36776763277](https://github.com/mitigate-co/runtime/actions/runs/36776763277/job/110096518699)
failed in `ReferenceMap::open` with `Storage(Busy)`, before reaching that race:
simultaneous SQLite connection setup is not guaranteed to succeed within the
existing lock budget. A separate deterministic exclusive-lock fixture requires
opening to return `Storage(Busy)` and verifies that explicit reopening after lock
release preserves the original reference. Production lock limits and resolution
assertions are unchanged; opening is not automatically retried.
