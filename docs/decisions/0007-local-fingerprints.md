# ADR 0007: Separate local fingerprints and closed snapshots

Status: accepted. Scope: MCP-004.

## Decision

Fingerprint identity, schemas, description and server facts independently. A description edit must not be indistinguishable from a schema change. Store only digests and local tool labels in explicit snapshots; do not store raw definitions. Require a fixed profile and bounded closed snapshot schema. Snapshot files are unsigned local change records, not trusted approval input.

Use RFC 8785 for key/string/numeric encoding, with conservative safe-integer guards to prevent numeric collisions. Preserve schema arrays and Unicode content. Description normalization only collapses whitespace. Differences identify categories, not a claim that schemas are logically equivalent or that declared server identity is authenticated.

Discovery's `config_fingerprint` covers its existing redacted summary fields. It intentionally omits credential values and raw argv/URL parts. It must not be reused for exact gateway launch or approval binding. That boundary needs the concrete executable/launch identity, not a discovery summary.

Local content-derived fingerprints are not an anonymization mechanism. Direct snapshot/report upload is prohibited by the still-separate Zero-Content egress design. No sensitive-value hash is described as privacy protection.

## Dependency decision

Choose exact `serde_json_canonicalizer` 0.3.2 (MIT), maintained at [evik42/serde-json-canonicalizer](https://github.com/evik42/serde-json-canonicalizer). Its published RFC/number test corpus and implementation were reviewed. It uses the existing Serde stack plus `ryu-js` 1.x. The older prototype's `serde_jcs` 0.1 serializer has incomplete generic numeric paths and is not imported. Rust's standard JSON output does not provide the required RFC key/numeric behavior.

Use exact `sha2` 0.10.9 (MIT OR Apache-2.0), maintained in [RustCrypto/hashes](https://github.com/RustCrypto/hashes), for SHA-256 rather than implementing cryptography. Existing dependencies do not provide the primitive. Its established 0.10 API is sufficient; a newer major version is not required for this slice. Published manifests/licenses were inspected. These choices add ten external packages to the lockfile. Cargo-deny license/source/bans and RustSec checks pass. No network capability or OS privilege is added. No new performance promise is made.

Public library callers can construct definitions, so canonicalization rechecks bounds before serializing and rejects unsupported numbers. Domain labels and the profile are fixed enums/constants. Snapshot loading validates tool-identity consistency and never accepts arbitrary free-form metadata.
