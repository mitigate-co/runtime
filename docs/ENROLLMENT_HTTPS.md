# Enrollment HTTPS transport

The optional `mitigate-enrollment/https` feature provides `https::submit(&claim)`.
It sends one blocking bootstrap request to the canonical HTTPS origin already
bound into the proof. It is not a generic HTTP client, telemetry sender or CLI.
Before calling, the embedding application must obtain explicit user intent and
persist the pending identity, key and code in native storage. Keep the enrollment
operation lock until its receipt is confirmed. Enrollment does not enable sync.

## Connection and response policy

- HTTPS only, with rustls 1.2/1.3 and the bundled Mozilla/WebPKI trust roots.
- Certificate chain, hostname and expiry verification remain enabled. There is
  no public insecure mode, trust-root override, HTTP fallback or redirect option.
- No environment/system proxy, cookie jar, client certificate, browser cookie,
  bearer header, referer, query or automatic retry. No version-bearing user agent.
- POST the closed claim to `/api/v1/runtime/enroll`, with JSON content type,
  `Cache-Control: no-store`, `Accept-Encoding: identity` and connection closure.
- Twenty-second overall deadline; five-second DNS, connection/TLS, request-send,
  response-header and response-body phase bounds. Timed-out DNS resolver work may
  finish in its own worker, but cannot send a credential after the request ends.
- Fixed 16-KiB input and 2-KiB output buffers; an 8-KiB HTTP header cap and a
  1-KiB receipt cap, including chunked/EOF-delimited bodies. TLS maintains its
  own bounded protocol buffers; these values are not a whole-process memory cap.
- Only HTTP 200 with one `application/json` or `application/json; charset=utf-8`
  content type can confirm enrollment. Encoding or Set-Cookie headers fail.
  The existing closed parser rejects malformed/extra/duplicate fields and
  references that do not match the claim. Truncated bodies fail.

All redirects and error statuses return fixed local categories. Their bodies are
not read. Location, Retry-After, response fields and underlying provider errors
never become diagnostics. The validated result exposes receipt facts and bytes
for native confirmation; it cannot be generically formatted or serialized.

An interrupted connection may have been accepted remotely. Keep and retry the
same pending proof; never rotate identity merely because the response was lost.
Rate limiting requires an explicit later retry. A previous receipt is not proof
of current authorization. Outages leave local MCP protection available.

## Privacy and deployment limits

The selected Platform receives the one-use code's token, public key and opaque
references. The private key is never transmitted. This explicitly authorized
bootstrap exchange is separate from Zero-Content telemetry. No workload content,
machine identifier, human attribution or generic metadata is added.

`log` facade output is compiled out when this feature is selected, including
dependency TLS/HTTP diagnostics; public operations return fixed typed errors.
This affects other `log` users in the same executable. Do not replace that gate
with an environment-driven debug logger. The Runtime's explicit safe reports
remain available. Claim and receipt buffers owned here are zeroized on drop;
TLS, HTTP and OS transient buffers are not guaranteed to be zeroized. This is
not protection against local process inspection, crash dumps, swap or root.

Corporate TLS interception/private CAs and mandatory outbound proxies are not
supported by this initial transport. A future explicit, reviewed proxy/trust
policy must not silently inherit environment settings or disable verification.
Bundled root updates travel through dependency/release review. No hosted endpoint
or real enrollment credential is used by the test suite.

## Executable verification

```sh
cargo test -p mitigate-enrollment --features https --locked
cargo clippy -p mitigate-enrollment --all-targets --all-features --locked -- -D warnings
```

Nine HTTPS tests use real loopback TLS sockets and in-memory, per-test certificates
and keys. They cover the exact request, bound success, untrusted/wrong-host/expired
certificates, redirect destinations, proxy environment interception, status/media/
cookie/encoding failures, body/header limits, truncation and stalled headers/body.
No certificate is installed in the OS, no key is checked in and no server
verification is disabled. Test-only code injects its ephemeral trusted root.
CI runs the feature on Windows, macOS and Linux alongside existing privacy gates.

The library transport does not complete MCP-018. The [CLI](ENROLLMENT_CLI.md)
composes it with durable native state. Signed event delivery, safe ingest and
fleet composition remain separate acceptance gates.
