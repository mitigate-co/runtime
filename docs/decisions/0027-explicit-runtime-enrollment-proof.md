# ADR 0027: Explicit Runtime enrollment possession proof

Status: Accepted for the public authentication protocol component.

## Context

MCP-018 needs optional organization enrollment without treating a browser cookie,
machine label or user-supplied organization identifier as Runtime authority.
Enrollment cannot become a generic telemetry exception or mandatory local
dependency. Lost responses must not silently create another Runtime identity.

## Decision

Use an explicit, one-use Platform grant and a fresh Runtime Ed25519 key. Sign a
versioned LF transcript binding the canonical HTTPS origin, grant, random-token
digest, public key and independent opaque references. Separate this bounded
credential exchange from strict Zero-Content events and from consent to sync.

Keep the pure public protocol in `mitigate-enrollment`; private grant issuance,
tenant authorization and persistence stay in Platform. Secret types expose no
generic formatting or serialization. Validate closed receipts against the exact
claim, with no public construction bypass. Add native lifecycle and HTTPS delivery
only with persistence-before-send, exact retry and abuse/failure coverage.

## Dependency review

Reuse reviewed Ed25519 Dalek, SHA-256, URL parsing, secure randomness, zeroize,
strict JSON and native secret ownership. Rust std/current direct dependencies do
not expose the canonical unpadded base64url codec this wire contract needs.
Add pinned `base64` 0.23.1 (MIT OR Apache-2.0), `default-features = false`, `alloc`
only. It adds no transitive runtime dependencies, performs no I/O/telemetry, has
no build script, supports Rust 1.71+ and is portable Rust. Its source forbids
unsafe code when the unselected `simd-unsafe` feature is disabled. Cargo feature
review must retain that exclusion. Small fixed 32/64-byte inputs need no SIMD.

Crates.io records publication on 2026-08-04; source, canonical-decoding behavior
and lockfile were reviewed. Existing versions were not upgraded. Advisory and
license/source checks are required before merge; absence of an advisory is not a
security audit. The codec is only reached during explicit enrollment, outside
normal local tool-call handling. No new cryptographic primitive is implemented.

## Consequences

The protocol is independently verifiable with a public Node/OpenSSL fixture and
has no network/persistence side effects. The selected Platform sees the bootstrap
credential, public key and opaque references; the seed never leaves native/local
ownership. TLS still authenticates Platform. This is not hardware attestation or
proof of a human actor. Enrollment does not activate telemetry or weaken local
authority. Storage/transport/fleet and launch gates remain incomplete until their
own acceptance checks pass. See [wire contract](../ENROLLMENT.md).
