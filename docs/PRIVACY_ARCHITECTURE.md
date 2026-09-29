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
never persisted. The [signed event contract](SIGNED_EVENTS.md) hashes only an
already validated, journaled event and checks its enrollment partition. Its closed
envelope adds only version, enrollment reference and signature; no bootstrap
credential, key or arbitrary metadata. Active delivery and consent composition
remain required; a signature alone never enables sync.

The [local reference catalog](SYNC_REFERENCES.md) maps fixed-size, domain-separated
customer-local identity/schema keys to independent random wire references. Keys
never enter event serialization or command reports. Mapping batches commit before
returning references, remain scoped to the original enrollment and never evict
stable mappings at capacity. This separate bounded library does not activate a
gateway producer or replace the event/queue admission boundary.

New explicit sync setup binds that catalog in a version-two local profile without
another CLI argument. Resume verifies the original catalog; pause/purge keep
stable mappings and remain usable if the catalog is missing. Version-one profiles
retain their existing controls without implicit migration or catalog creation.

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

Native event signing uses the confirmed record's original key, opaque identity
and pinned origin. It rejects pending enrollment and a lease from another queue
partition, without storing signatures, changing credentials or enabling sync.
Current consent, valid leases and remote revocation remain separate delivery gates.

The explicit [event HTTPS exchange](EVENT_HTTPS.md) borrows that confirmed native
owner, sends only its signed checked lease to the pinned endpoint and returns an
exact bound receipt. It reuses the bootstrap's TLS/proxy/redirect/logging controls
and bounded JSON reader. No background producer, consent activation or queue
completion is implicit in `submit`. It now requires committed consent and lease
preflight. The explicit `deliver_next` runner composes one attempt with local
completion, fixed retry categories and authority-induced pause. It cannot enable
or resume consent. Coordinated opt-out remains required before continuous sync.

Explicit [sync controls](SYNC_CONTROLS.md) create a separate bounded private
profile only on local consent. It stores original enrollment/queue paths, origin,
opaque anchor reference and queue partition; no secret value or workload content.
These local paths never enter events or command reports. Pause persists withdrawal
before waiting for the original enrollment owner and reasserts it under that lock.
Purge happens only after drain. Neither operation needs native credential access.
Resume/send still restore and verify the exact confirmed native binding.

The explicit [gateway capture worker](SYNC_CAPTURE.md) runs a privacy self-test
before enabling a bounded, typed metadata channel. Required audit commits precede
capture. Seven named governance keys stay in the local catalog; only their random
mappings, fresh invocation IDs, closed enums and bounded numeric fields reach
checked events. Audit JSON/chain IDs, evidence, operator identity, environment,
full definition/policy hashes and workload data have no producer field. The
worker owns no native credential or network handle. Short-lived owner sessions
and durable consent permits prevent pause/resume from reviving old buffers.
Optional capture can lose events before durable admission without changing local
authority. No automatic HTTP delivery loop is activated. See ADR 0038.

The optional [HTTPS transport](ENROLLMENT_HTTPS.md) explicitly sends the bootstrap
claim to its signed audience with certificate verification, no redirects or
ambient proxies, bounded deadlines/response and fixed errors. Dependency `log`
output is compiled out. Mitigate-owned claim/receipt buffers zeroize; third-party
TLS/HTTP/OS buffers are not promised to be erased. The transport does not persist
confirmation, enable sync or admit bootstrap material as telemetry.

The explicit [enrollment CLI](ENROLLMENT_CLI.md) composes native persistence and
HTTPS while holding the operation lock. Its bounded pipe or hidden terminal input
never accepts a code argument or environment fallback. Errors do not echo input;
status and confirmed retry are local. Removing a credential requires explicit intent and
does not claim remote revocation. Enrollment reports describe only local receipt
state and keep synchronization off.

Hidden input disables terminal echo before showing the prompt, reads a fixed
85-byte owned buffer and restores the original mode before creating credentials.
Keyboard cancellation is handled as input, so normal cleanup still runs. Input
buffers owned by std/OS and forced process termination remain outside these
zeroization/restoration guarantees. Machine output requires explicit piped input.
