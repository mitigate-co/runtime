# ADR 0042: Explicit, bounded inventory capture from fresh listings

Status: accepted.

The receiver and outbox support closed inventory parts. Compose a live producer
only when the operator adds `--sync-inventory` to an already-enforced gateway
with an existing consented profile. Keep existing decision-only commands stable
so receiver rollout can precede v2 production.

Reserve the original consent permit and one observation slot before an initial
tool-list request. Copy approved local keys/classification facts only after the
upstream freshness/review check and required local audit succeed. No historical
inventory replay or background enumeration is implied. A server without advertised
tools produces no listing observation; absence remains unknown, not empty.

The existing worker carries at most one inventory observation alongside its
bounded decision channel. Resolve at most 16 keys or admit one four-tool part per
step, releasing the enrollment owner between steps. Each iteration also allows
one decision to progress. Sort all opaque tool references before part construction.
Every part retains the original capture permit, independent snapshot reference and
observation time. Queue failure, consent change or shutdown may leave incomplete
parts; never synthesize missing data or reissue with renewed consent.

Server/tool mappings join decision metadata. Inventory's revision mapping uses the
full local definition digest; the existing v1 decision input-schema mapping is
unchanged. Their schema references do not describe the same revision domain.
Only random catalog outputs and closed enums enter CheckedPart/CheckedEvent.
No native credential, network operation, new database schema, arbitrary field or
change to local authorization is introduced.
