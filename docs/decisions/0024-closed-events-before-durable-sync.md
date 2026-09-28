# ADR 0024: Closed events before durable optional sync

Status: Accepted

## Context

MCP-015 requires a safe offline queue before MCP-016 completes the egress path.
A generic byte/string queue would persist unchecked content and turn retries into
a second privacy boundary. Existing local audit reports are expressly not Platform
contracts. Their names and content-derived references cannot be copied wholesale.

## Decision

Define a minimal closed candidate event in `mitigate-egress` before implementing
the queue. It accepts only `mcp_tool_decision` version 1, with explicit bounded
facts and a fixed vocabulary. There are no free-form strings: reference fields
have one fixed opaque shape, and other strings are closed enums. Strict parsing,
recursive prohibited-key checks, the string allowlist, unknown-field rejection,
fact validation and a 4 KiB canonical limit precede a private `CheckedEvent` value.

References are random 128-bit enrollment-scoped mappings. Do not send local
schema/description/configuration digests or hashes of identity labels. An opaque
schema-revision mapping can describe change without exposing its source digest.
Mapping persistence and rotation belong to enrollment integration. Unknown caller
facts remain explicit nulls; declared profiles do not become authenticated identity.

The initial contract has no free-form identifiers for a probabilistic secret/PII
scanner to permit. All non-contract strings, including high-entropy text, are
rejected. Fixed opaque references are an intentional entropy exception. Parsing
cannot prove that a malicious producer did not encode content into identifier bits
or numbers. Trusted Runtime producers must generate mappings independently of
workload content; MCP arguments and metadata never supply these fields.

Validation does not authorize transmission. The next queue/egress layer must
record each admission/rejection safely, enforce opt-in enrollment, partition by
runtime, preserve idempotent IDs, bound retention/retries, and sign for enrolled
delivery. It must not retry privacy rejections unchanged. No sender is added here.

## Consequences

Wire enums intentionally do not reuse local audit/model enums. A future local
variant cannot silently enlarge a cloud schema. Rust wire types and tested fixtures
are the canonical contract; Platform validation must match them. Field/type changes
require a reviewed schema version. This slice has no network or file side effects,
no new external dependency/version, and no automatic conversion from local reports.

These operational identifiers remain correlatable metadata, not a claim of
anonymity, authenticated identity, certification or zero processing of sensitive data.
