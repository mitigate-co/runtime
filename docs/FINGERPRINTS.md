# Fingerprints, snapshots and diff

Snapshot files are opt-in local change records. They are not authorization, signatures, trusted provenance or approved Platform telemetry. Tool labels can be sensitive. Content-derived hashes are not anonymization: predictable definitions may be guessed. Keep snapshots inside your customer boundary; later optional sync must use its separate privacy contract and guard.

## Demonstrate locally

Use unused snapshot filenames; saving never overwrites an existing file:

```sh
cargo run --locked -p mitigate-mcp-fixture -- launch-config > target/fixture-launch.json
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec --snapshot target/before.json --json
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec --snapshot target/after.json --json
cargo run --locked -- mcp diff --before target/before.json --after target/after.json
cargo run --locked -- mcp diff --before target/before.json --after target/after.json --json
```

The unchanged fixture reports no differences. Inspection still executes only the reviewed fixture and does not call a tool. Snapshot saving occurs after successful enumeration; a failed save produces an error without partial success output. Diff only reads the two explicitly selected snapshot files.

## Versioned profile

`mitigate-local-jcs-sha256-v1` uses [RFC 8785 JSON canonicalization](https://www.rfc-editor.org/rfc/rfc8785) with SHA-256. Input is prefixed with the profile, a zero byte, a fixed domain label, another zero byte, and then canonical JSON bytes. Domains are separate for server identity, server facts, tool identity, input schema, output schema, description and configuration summary.

Object key ordering, JSON escapes and equivalent supported numeric encodings do not create differences. Array ordering and Unicode string content remain unchanged. No external references are fetched; schemas are not simplified and semantically equivalent schemas expressed differently may still differ. Descriptions alone are normalized by trimming/collapsing Unicode whitespace. That normalization never applies to schema string values.

The bounded profile rejects integers (including integral floats) outside ±9,007,199,254,740,991 rather than allowing double-precision conversion to conflate distinct constraints. This is a compatibility limit: schemas using larger numeric constraints cannot currently produce snapshots. Finite non-integral numbers use JCS's IEEE-754 semantics. Depth/node/string/key/total-size limits also apply. A failure is explicit, never an omitted or placeholder fingerprint.

## Snapshot v1

The closed schema records the profile, declared server identity hash, server-facts hash, tools-capability presence and sorted tool records. Each tool record contains its local name and independent identity/input/output/description hashes. No raw schema, description, argument, credential, command path or server instruction is stored. The tool identity is scoped to the declared server name; it remains an unverified declaration. Tool identity consistency is validated when loading a snapshot.

Snapshot loading rejects unknown/duplicate fields, unsupported versions/profiles, malformed digests, invalid/duplicate/unsorted tool names, inconsistent capability state, links/special files and files over 1 MiB. Saving uses exclusive file creation and flushes to disk. Unix permissions are owner-only; Windows uses the selected directory's ACL. If storage fails mid-write, an incomplete new file can remain; it will be rejected on reading. Existing files and symlinks are never overwritten.

Snapshots are unsigned and can be replaced by someone with filesystem access. A valid structure does not establish authenticity. Do not use imported snapshots as approval or policy evidence.

## Difference report

Diff reports server-identity/facts/capability changes and sorted added, removed and changed tools. Changed tools identify input schema, output schema, description and identity independently. An added/removed tool has no comparable previous/current schema, so its per-field change flags are false. A server-version-only edit changes server facts without falsely changing each tool schema. A renamed tool appears as removal plus addition.

Exit 0 means comparison completed, whether or not differences exist; exit 2 means invalid/unavailable input. JSON goes to stdout on success and fixed errors go to stderr. There is no reapproval, reclassification or enforcement action yet; those use these facts in later packages.

Discovery v2's `config_fingerprint` has a deliberately different scope: it covers only the normalized redacted summary. It does not detect changes to omitted secret, argument or URL values and cannot attest exact execution configuration.

## Verification

Tests cover map ordering, numeric/escape equivalence, UTF-16 key order, preserved Unicode distinctions and array order, hash domain separation, safe-integer boundaries, description-only changes, input/output changes, server-version changes, additions/removals, incompatible snapshots, unknown/duplicate fields, local-file protections, CLI errors and content canaries. CI runs the snapshot/diff demonstration on all supported OSes.
