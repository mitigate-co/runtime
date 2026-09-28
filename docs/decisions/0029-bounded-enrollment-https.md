# ADR 0029: Bounded enrollment HTTPS

Status: Accepted for explicit bootstrap delivery.

## Decision

Use the optional `mitigate-enrollment/https` feature for one synchronous verified
HTTPS POST to the signed audience. There is no generic destination/headers/body
API, caller-supplied HTTP agent or production trust override. Persist-before-send
and exclusive ownership remain caller obligations. A successful bounded response
must also pass the existing claim-bound receipt validator. No telemetry is enabled.

Disable redirects, ambient proxies, cookies, compression, connection reuse and
automatic retry. Bound DNS/connection/send/receive phases and the whole call.
Reject unsupported status/media/framing/receipt; discard all provider diagnostics.
Compile dependency `log` output out in every profile so a verbose environment or
embedding logger cannot expose HTTP/TLS fields. This is a deliberate executable-
wide diagnostic tradeoff, not an unannounced process-global logger installation.

## Dependency review (2026-09-28)

Rust std and the existing graph provide no authenticated HTTPS implementation.
Reusing a maintained HTTP/TLS implementation avoids hand-written HTTP framing or
cryptography. Select [ureq 3.4.2](https://github.com/algesten/ureq) with defaults
disabled and only `rustls`; its blocking model fits native enrollment ownership
without a second async reactor or subprocess. Ureq forbids unsafe code and is
MIT/Apache-2.0. Its source/changelog cover active HTTP framing, timeout and TLS
maintenance. JSON, gzip, cookies, SOCKS, platform verifier and native-TLS features
remain absent. The crate's default proxy and redirect behavior are overridden.

The locked production graph adds 22 distinct package versions across all targets:
12 HTTP/TLS/codec/randomness packages and 10 Windows target/import packages.
Existing versions are unchanged. The existing base64 codec gains `std` through
ureq; no unsafe SIMD feature is enabled. `log` 0.4.34 is already in the graph and
adds only `max_level_off`. Review `cargo tree` with `--target all -e normal,build`.

Rustls 0.23.45 is MIT/Apache-2.0/ISC; the selected ring 0.17.14 provider is
Apache-2.0 AND ISC and uses reviewed upstream unsafe C/assembly/Rust with a `cc`
build script. This expands build/crypto trust and binary size; it is confined to
explicit enrollment, outside the normal local tool-call path. No latency or
binary-size claim is made before release measurement. It avoids system OpenSSL
and an AWS-LC build. Rustls does not retrieve roots or transmit telemetry; the
transport makes only its explicit request (and ordinary DNS resolution).

The selected versions include fixes for
[Rustls RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)
and [ring RUSTSEC-2025-0009](https://rustsec.org/advisories/RUSTSEC-2025-0009.html).
An advisory-free lockfile is not a security audit. Continue locked advisory,
license and platform CI gates for updates.

`rustls-webpki` 0.103.15 and `untrusted` 0.9.0 use ISC; `webpki-roots` 1.0.9 uses
CDLA-Permissive-2.0 for bundled root data. Narrow exact-version license exceptions
retain their notices and do not globally relax the project's license policy.

Tests use pinned `rcgen` 0.14.10 (MIT/Apache-2.0), ring/zeroize only, and the same
rustls version to generate certificates entirely in memory. Seven additional
active development-only packages cover rcgen/ASN.1 encoding/time; 11 optional
rcgen parser-related lockfile entries are not compiled. No copied private keys,
installed certificate authority, external HTTPS test site or verification bypass
is required. Neither development graph enters distributed library dependencies.

## Consequences

The selected HTTPS endpoint receives the explicitly supplied bootstrap credential,
public key and opaque references, never the signing seed or workload payload.
No local persistence/consent is implied by calling this library. HTTP/TLS/OS
buffers are not claimed to be erased merely because Mitigate's owners zeroize.
Corporate intercepting proxies/private CAs need a subsequent explicit reviewed
policy; failure must not silently weaken trust. See [transport](../ENROLLMENT_HTTPS.md).
