# Explicit event HTTPS exchange

With the optional `mitigate-enrollment/https` feature,
`event_https::submit(&EnrollmentStore, &mut Outbox, &Lease)` signs and submits exactly one
checked outbox event. A pending enrollment or different queue partition fails
before any network operation. The confirmed native owner selects its original
key, identity and pinned Platform origin and remains borrowed, holding the
enrollment operation lock, until the synchronous exchange returns.

The final preflight reads committed consent and exact lease ownership, then
requires more than 25 seconds remaining in both lease and event retention. That
reserves the 20-second exchange plus five seconds for completion. It does not
extend either deadline. Preflight commits clock/expiry maintenance before sending;
storage failure releases no permission. A paused queue, purged/replaced claim,
clock rollback or insufficient time sends nothing.

After that commit returns, preflight samples wall time again and checks monotonic
time spent in the whole preflight. SQLite filesystem work can outlast its VM
progress callbacks; time reserved before a slow commit cannot authorize a late
send. Either clock can refuse readiness, but neither renews the lease or retention.
A refused final observation preserves the original claim for ordinary recovery;
it does not mark delivery, pause consent or retry the operation automatically.

This is not an active sync service. Neither API obtains consent, creates events,
runs a background worker or changes native credentials. Local MCP operation does
not call it automatically. Run it on the owning blocking worker, outside an async
reactor. Enrollment alone never activates delivery.

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
| Queue preflight failure | `Outbox` / `NotReady` | Send nothing; preserve/reconcile local state |
| 200 with exact bound receipt | `HttpsEventReceipt` | Complete only the original current lease |
| 401, 403, 404, 410 | `Unauthorized` | Pause optional delivery and check current authority |
| 400, 409, 413, 422 | `Rejected` | Do not retry the unchanged event automatically |
| 429 | `RateLimited` | Retain event; use bounded local backoff |
| 5xx | `Unavailable` | Retain event; use bounded local backoff |
| 3xx | `Redirect` | Follow nothing; pause and inspect the pinned destination |
| Timeout/connection failure | `Timeout` / `Connection` | Acceptance may be uncertain; retain the exact event |
| Other status or invalid receipt/framing | `Response` | Acceptance is unconfirmed; retain the exact event |

`submit` leaves outcome completion to its caller. A crash after remote
acceptance can redeliver the same event; the hosted receiver must durably deduplicate
it. A local receipt never establishes current remote authorization after revocation.
The receiver remains responsible for tenant isolation and event retention.

## One-attempt queue runner

`event_https::deliver_next(&EnrollmentStore, &mut Outbox)` composes a claim,
preflight, signed HTTPS exchange and local completion. Restore the native owner
first, before a claim: an OS unlock prompt must not consume lease time. Pending
native state or a mismatched queue fails before any claim. The owner remains
borrowed through the final queue commit. The claim excludes candidates with too
little retention for the full exchange, keeping a nearly expired record from
consuming leases ahead of a deliverable one. The final exact-lease preflight still
runs immediately before network I/O.

The runner returns `Idle` for an empty, paused or backoff-delayed queue. An exact
receipt produces `Accepted` only after local completion commits. Permanent
refusals produce `Rejected` and a duplicate receipt; unchanged events do not retry.
Unauthorized responses and redirects pause the entire outbox. Connection, timeout,
rate-limit, server and malformed-receipt failures retain the same event with bounded
backoff. It makes at most one request and never resumes the queue.

A local completion failure returns an error, even after remote acceptance. Reopen
to reconcile; never manufacture an acknowledgment. A purge after transmission wins
over a late response. Local preflight failures retain an uncompleted claim for
normal expiry, without changing consent or treating it as remote rejection.

## Shutdown integration boundary

The caller must obtain explicit consent before creating/resuming an outbox.
Preflight observes that queue state immediately before transmission; it is not
an atomic lock spanning the network. OS scheduling or suspension can consume the
remaining deadline after the check. A stale response cannot complete a renewed
lease. Enrollment locking prevents cooperating local credential
deletion during the request; it is not an outbox lock or remote authorization.

This synchronous API has no mid-flight cancellation handle. The
[sync profile](SYNC_CONTROLS.md) coordinates its explicit sends with pause/purge
using the original native owner lock. It commits withdrawal before waiting for
drain and never reports shutdown while that operation is outstanding. Closing a
connection cannot retract bytes already transmitted. The explicit CLI
`sync run` uses this ownership path on its dedicated blocking worker; the
gateway's separate capture worker owns no network handle. The CLI requires a
successful actual privacy probe before its delivery loop or a ready manual send.
Low-level embedders remain responsible for that startup gate as well as consent
and shutdown coordination; the transport API does not run a probe implicitly.
`SyncProfile::delivery_readiness`
performs local queue preparation without a native owner; empty, paused or delayed
work does not prompt the OS credential store. Every ready attempt still restores
the original confirmed identity before obtaining a lease.

## Verification

```sh
cargo test -p mitigate-enrollment --all-features --locked
cargo run -p mitigate-enrollment --all-features --example native_lifecycle --locked -- --allow-native-fixture
```

The native demonstration uses only its own synthetic OS credential/queue and
checks pending submission/claim refusal and confirmed paused refusal without
opening a connection. It requires an
unlocked native store and deletes its exact credential; it never prints secrets.

Loopback TLS tests use ephemeral in-memory certificates and a private test-only
agent. They verify the exact transmitted checked body and headers, certificate
rejection before HTTP, unchanged queues, redirect refusal, proxy isolation,
status classification, receipt binding, malformed/oversized/truncated framing
and stalled response deadlines. Production has no test-root injection API. The
composed runner additionally tests durable acceptance, permanent refusal, backoff,
authority/redirect pause, withdrawal after claim, and purge before local completion.
Outbox tests cover independent-connection controls, exact time boundaries, retention,
foreign/replaced claims, modified bytes, rollback and injected commit failure. The
commit-boundary regressions use a private clock seam with real SQLite commits to
verify exact lease/retention boundaries, stalled/backward/unavailable clocks and
unchanged pending events. No host clock changes or timing sleeps are required. The
existing bootstrap transport suite runs against the same extracted policy and
reader so the shared implementation cannot silently weaken enrollment.
