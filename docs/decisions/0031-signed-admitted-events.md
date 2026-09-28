# ADR 0031: Sign only admitted events and bind acknowledgments

Status: accepted for MCP-018 protocol implementation.

## Context

Enrollment proves possession of a Runtime key, while the outbox owns validation,
journaling and retries. Connecting these with an arbitrary byte-signing API would
make the egress boundary optional. A generic success response would also allow a
stale or mismatched acknowledgment to remove an unrelated event.

## Decision

Add a pure signing contract to the public enrollment crate. Construction requires
an opaque, committed outbox lease with both configured enrollment references.
Sign an Ed25519 transcript containing a versioned domain, exact HTTPS origin,
method, endpoint, Runtime/enrollment/event references and the SHA-256 digest of
the canonical checked event. Expose a bounded closed request, not a generic
signing primitive. Require the acknowledgment to echo the exact identity and
canonical digest before the caller can consider completing its original lease.

Hashing applies only after closed event validation; no raw workload fingerprint
is introduced. The existing dependencies provide the primitives and strict JSON
parser. No external crate, version, license exception or native permission changes.

Keep this component pure so independent implementations can verify the protocol.
It cannot inspect current native enrollment, consent or queue state. Document
those obligations explicitly: the later sender must check them, authenticate
HTTPS, coordinate cancellation and preserve the lease on uncertain acceptance.
The receiver must independently enforce tenant authorization, current enrollment,
revocation, validity and durable replay handling. Possession is not authorization.

## Alternatives and consequences

Signing arbitrary JSON or local audit exports was rejected because it admits
unreviewed content. Signing only an event ID was rejected because a changed body
could reuse the proof. Returning an unbound Boolean acknowledgment was rejected
because it cannot establish which body the receiver accepted. Adding a receiver
or background sender to this protocol change would mix tenant/storage authority
and cancellation with the independently testable cryptographic boundary.

Retries are deterministic for the same event and identity. Replay to the original
audience remains possible; receiver deduplication and revocation are required.
An outstanding lease retains bytes after purge, so constructing a signature is
never evidence of current consent. This change enables no network traffic.

## Verification

Real outbox tests cover rejected-content exclusion, enrollment mismatch,
deterministic signatures, transcript tampering and closed/bounded acknowledgments.
They demonstrate that validation alone never mutates the queue. Compile-fail
checks prevent generic deserialization. A separate Node/OpenSSL verifier checks
the executable Rust fixture and rejects changes to its content and transport
scope on all three CI operating systems.
