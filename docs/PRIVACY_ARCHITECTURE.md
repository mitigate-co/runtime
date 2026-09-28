# Mitigate Privacy Architecture

## Promise

Mitigate is designed so customers can secure and govern MCP/AI activity without making Mitigate Platform a repository of raw confidential content.

Precise claim:

> Mitigate Platform is designed not to receive or store raw customer AI/tool content by default. Content-aware inspection and enforcement can remain inside the customer boundary.

Do not claim that Mitigate "never processes sensitive data." The Runtime may process it locally.

## Open trust boundary

The customer-side Runtime is public/auditable. The parts responsible for serialization and egress are intentionally inspectable.

This matters more than a closed binary saying its own privacy test passed.

## Zero-Content event contract

Platform telemetry schemas must not contain fields intended for:

- raw MCP arguments,
- raw MCP results,
- prompts/responses,
- document bodies,
- source code,
- credential values,
- matched PII/PHI values,
- arbitrary HTTP bodies,
- arbitrary nested free-form metadata.

Identifiers and short names must be bounded and pass local egress scanning.

## Egress architecture

```text
local event producer
      ↓
canonical safe event builder
      ↓
exact schema validation
      ↓
unknown-field rejection
      ↓
secret/PII/high-entropy guard
      ↓
size/length limits
      ↓
local egress audit
      ↓
sign/enqueue
      ↓
Platform
```

No module bypasses the egress guard for Mitigate telemetry.

The first implemented [closed event candidate contract](SYNC_EVENTS.md) uses only
fixed enum strings and enrollment-scoped random reference shapes. It excludes
free-form identifiers and local content-derived fingerprints. This is a validation
component, not a complete egress path. The [local outbox](OUTBOX.md) records fixed
admission reasons/counts and durably queues only validated candidates, scoped to
one runtime/enrollment pair. Rejected input, identifiers and input digests are
never persisted. Enrollment integrity, signing and delivery gates remain open.

The [privacy CLI](PRIVACY_COMMANDS.md) injects synthetic content through the actual
queue admission boundary, checks retained bytes and removes its private fixture.
The inspector opens existing queues read-only and distinguishes supported fields
from observed queue state. Neither command sends telemetry or claims certification.

## Provider/tool traffic is different

If the customer tells Mitigate Gateway to call an upstream MCP server, payloads necessarily travel to that customer-approved server. That is customer workload traffic, not Mitigate Platform telemetry.

Mitigate Platform is not inserted into that data path.

## Local evidence

Detailed local evidence can be stored only when the customer configures it. Platform may store:

- evidence ID,
- salted digest,
- signature/key reference,
- classification,
- policy/version,
- timestamp bucket,
- customer-local storage reference.

Do not hash small predictable sensitive values directly as "privacy." Use artifact-level randomized/salted commitments where proof is required.

## Aggregate contribution

When optional cloud sync is enabled, safe operational metadata may contribute to aggregate public statistics under plain disclosure and one-click opt-out.

Publication safeguards:

- cohort minimum,
- rare-value suppression,
- coarse buckets,
- no company/person/device names,
- no exact timestamp,
- no raw content,
- no small cohorts that effectively identify one customer.

Rich/private benchmark/evaluation contribution is opt-in.

## Logging

Runtime and Platform logs must not include:

- request/tool payloads,
- auth headers,
- access/refresh tokens,
- secret environment variables,
- raw matched sensitive values.

Log identifiers, categories, sizes, decisions and safe error classes instead.

## Privacy regression suite

Every release runs synthetic privacy fixtures against:

- scanner output,
- local audit defaults,
- telemetry builders,
- egress guard,
- API logging,
- error reporting.

Any fixture leakage is a release blocker.

Tool-schema compilation and validation run locally with resource retrieval
disabled. Dependency diagnostics are discarded in favor of fixed errors. Schemas,
arguments and results have no new persistence or telemetry path. The executable
also replaces default Rust panic diagnostics with a fixed notice: panic payloads
and backtraces must not expose values handled by dependencies. A subprocess test
injects a synthetic panic payload with backtraces enabled and verifies omission.
Library embedders remain responsible for their own process-wide panic hooks.

Version-two local audit adds only typed correlation, phase, exact definition/
policy references and declared operator-choice metadata. It contains no raw
arguments/results or hashes of argument content. Version-one records receive no
synthetic attribution or added null fields. Neither version is a Platform egress
contract; exports must not be forwarded around the Zero-Content boundary.

## Implemented local control metadata

The MCP-014 control database stores exact hashed references, numeric quota state,
fixed administrator actions, revisions/timestamps and declared operator references.
It has no arguments, results, descriptions, credential values, free-form notes or
generic metadata. Its CLI accepts only closed bounded documents, rejects unknown
fields and prints fixed errors without input/path/backend echoes. Local control
reports are not Platform telemetry contracts and must not be forwarded as such.
See [storage, retention and trust limits](CONTROLS.md).

## Implemented private launch review

Exact launch facts are committed locally using an independent random salt and
the versioned fingerprint profile. Raw paths, arguments and ordinary environment
values are not stored in the review/receipt; native credential values are never
part of the commitment. The salt remains in the private local review document,
excluded from receipts. Reviews and receipts are not Platform event contracts.
They do not authorize forwarding content-derived configuration fingerprints.
See [launch-review privacy and filesystem boundaries](LAUNCH_REVIEW.md).

## Optional enrollment bootstrap

The public [enrollment protocol](ENROLLMENT.md) authenticates a fresh Runtime key
using an explicitly supplied one-use code and canonical HTTPS origin. The bounded
credential exchange is separate from telemetry admission; claims are rejected by
the Zero-Content event parser. No workload/config fingerprints or machine/human
identifiers are added. The private seed never enters the claim. Secret owners
zeroize their allocations and expose no generic diagnostic/serialization trait.
Enrollment neither implies consent to telemetry nor activates a sender. The pure
protocol performs no I/O. Explicit [native lifecycle](ENROLLMENT_STORAGE.md)
persists the bounded seed/code/receipt record only in the native broker; its
immutable plaintext anchor holds only a canonical Platform origin and random
credential reference. Confirming a matching receipt removes the bootstrap code.
Neither component performs network requests or enables synchronization.
