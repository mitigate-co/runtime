# Explicit event HTTPS exchange

With the optional `mitigate-enrollment/https` feature,
`event_https::submit(&EnrollmentStore, &Lease)` signs and submits exactly one
checked outbox event. A pending enrollment or different queue partition fails
before any network operation. The confirmed native owner selects its original
key, identity and pinned Platform origin and remains borrowed, holding the
enrollment operation lock, until the synchronous exchange returns.

This is a transport component, not an active sync service. It does not obtain
consent, validate current queue leases, create events, run a background worker,
schedule retries or change queue/native state. Local MCP operation does not call
it automatically. Run it on the owning blocking worker, outside an async reactor.

## Fixed destination and shared transport policy

The only destination is the enrolled canonical HTTPS origin plus
`/api/v1/runtime/events`, with `POST`. It is also bound into the [event
signature](SIGNED_EVENTS.md). Bootstrap codes, private/public keys, cookies and
ambient user authorization are absent. No MCP-provided destination is accepted.

The event and [enrollment bootstrap](ENROLLMENT_HTTPS.md) paths share a private
ureq/rustls configuration and JSON-framing reader:

- Certificate chain, hostname and expiry verification with bundled Mozilla roots.
- No redirects, inherited proxies, cookies, client certificates, compression,
  insecure switch, exposed generic HTTP agent or automatic retry.
- `Content-Type: application/json`, `Accept: application/json`,
  `Accept-Encoding: identity`, `Cache-Control: no-store`, `Connection: close`.
- No User-Agent, Referer, Origin or browser session headers.
- Twenty-second global deadline and five-second per-phase limits.
- 16 KiB fixed input buffer, 2 KiB output buffer and 8 KiB response-header cap.
- Successful JSON body bounded to 1 KiB, including chunked/EOF-delimited bodies.
- Exactly one supported JSON Content-Type; reject Content-Encoding and Set-Cookie.
- Dependency `log` output compiled out; no provider error chains or response text.

This shares the already reviewed dependencies without adding versions, features,
root overrides or license exceptions. TLS/HTTP/OS buffers are not guaranteed to
be erased. Owned response buffers zeroize even on partial reads and invalid JSON;
arbitrary error bodies are never read into a receipt buffer.

## Result handling

Only HTTP 200 with the exact closed, duplicate-rejecting acknowledgment returns
`HttpsEventReceipt`. It exposes checked receipt facts without raw response bytes,
a public constructor or generic serialization. The event ID, both enrollment
references and canonical event digest must match the original signed request.

| Response/failure | Fixed result | Caller responsibility |
| --- | --- | --- |
| Native pending/integrity/scope failure | `Enrollment` | Send nothing; resolve local enrollment/configuration |
| 200 with exact bound receipt | `HttpsEventReceipt` | Complete only the original current lease |
| 401, 403, 404, 410 | `Unauthorized` | Pause optional delivery and check current authority |
| 400, 409, 413, 422 | `Rejected` | Do not retry the unchanged event automatically |
| 429 | `RateLimited` | Retain event; use bounded local backoff |
| 5xx | `Unavailable` | Retain event; use bounded local backoff |
| 3xx | `Redirect` | Follow nothing; pause and inspect the pinned destination |
| Timeout/connection failure | `Timeout` / `Connection` | Acceptance may be uncertain; retain the exact event |
| Other status or invalid receipt/framing | `Response` | Acceptance is unconfirmed; retain the exact event |

No outcome in this table automatically mutates the outbox. A crash after remote
acceptance can redeliver the same event; the hosted receiver must durably deduplicate
it. A local receipt never establishes current remote authorization after revocation.
The receiver remains responsible for tenant isolation and event retention.

## Consent and lease integration boundary

The caller must obtain explicit current consent and validate its lease immediately
before submission. The global HTTP limit is shorter than the outbox's thirty-second
lease, but time spent before the request counts too. A stale response must not
complete a renewed lease. Enrollment locking prevents cooperating local credential
deletion during the request; it is not an outbox lock or remote authorization.

This synchronous API has no mid-flight cancellation handle. A future owning sync
worker must coordinate opt-out, stop new sends, account for an in-flight exchange
and confirm shutdown before reporting that sync has stopped or purging/removing
state. Closing a connection cannot retract bytes already transmitted. No UI or
CLI exposes continuous sync until that coordination is implemented and tested.

## Verification

```sh
cargo test -p mitigate-enrollment --all-features --locked
cargo run -p mitigate-enrollment --all-features --example native_lifecycle --locked -- --allow-native-fixture
```

The native demonstration uses only its own synthetic OS credential/queue and
checks pending submission refusal without opening a connection. It requires an
unlocked native store and deletes its exact credential; it never prints secrets.

Loopback TLS tests use ephemeral in-memory certificates and a private test-only
agent. They verify the exact transmitted checked body and headers, certificate
rejection before HTTP, unchanged queues, redirect refusal, proxy isolation,
status classification, receipt binding, malformed/oversized/truncated framing
and stalled response deadlines. Production has no test-root injection API. The
existing bootstrap transport suite runs against the same extracted policy and
reader so the shared implementation cannot silently weaken enrollment.
