# ADR 0035: Persist independent random references for local governance facts

Status: implemented bounded mapping library; gateway activation remains separate.

The closed wire contract accepts opaque references, but shape validation cannot
prove those bits were independent of customer content. Local audit fingerprints
must not be copied, truncated or hashed again into wire IDs.

Use a separate private catalog of typed, domain-separated 32-byte local keys and
independently generated random wire references. Pin it to one runtime/enrollment
pair, validate its exact schema and all rows, and commit each bounded batch
before returning any new reference. Full catalogs refuse new identities without
evicting stable mappings; new enrollment creates a new catalog. Ephemeral call,
approval and event IDs are excluded from the durable identity catalog.

Keep this code in the public egress trust boundary, with no dependency on local
audit schemas or hosted Platform code. Reuse only the existing private SQLite
file/connection defenses, not its outbox tables. No new external dependency,
wire field, automatic consent, producer, sender or workload authority is added.
The future gateway integration must own catalog lifecycle and handle failure
off the authorization path. A mapped reference still requires closed event
validation, journaled queue admission, consent and confirmed signing/delivery.
