# Signed optional sync events

`mitigate_enrollment::event` binds an already admitted outbox event to one
enrollment and canonical HTTPS Platform origin. It performs no network or native
credential I/O and does not enable synchronization. See [ADR 0031](decisions/0031-signed-admitted-events.md).

## Input boundary

`EnrollmentKey::sign_event` requires an opaque `outbox::Lease`, acquired only
after [closed event validation](SYNC_EVENTS.md) and a committed [admission
journal](OUTBOX.md). There is no raw-body, arbitrary local-export or generic
deserialization constructor. Both lease partition references and the checked
event's Runtime reference must match the explicitly configured identity.

A lease in memory can outlive cancellation, expiry or purge. This pure function
does not read the queue again, prove confirmed native enrollment or grant consent.
The owning sender must check those conditions immediately before transmission and
cancel outstanding work on opt-out. Platform must resolve the active enrolled key
and current organization authority; a valid signature alone grants neither.

The native lifecycle's `EnrollmentStore::sign_event` adds the confirmed local
receipt requirement and selects the original key, identity and pinned origin
itself. It refuses pending enrollment and wrong queue partitions, while keeping
the enrollment operation lock held. Reopening after uncertain confirmation must
observe confirmed native state before this method can sign. That local receipt
still does not establish current remote authorization, consent or lease validity.

## Request version 1

Send only to `POST /api/v1/runtime/events` at the configured canonical HTTPS
origin. The body has exactly four required fields:

| Field | Value |
| --- | --- |
| `schema_version` | Integer `1` |
| `enrollment_ref` | The enrollment's opaque `ref_` reference |
| `event` | Nested closed version-one checked event |
| `signature` | Raw 64-byte Ed25519 signature in canonical unpadded base64url |

The full request is bounded to 5 KiB. Its nested checked event remains limited to
4 KiB and contains no arbitrary strings or metadata. The signature transcript is
UTF-8 with LF separators and **a final LF**:

```text
mitigate.runtime.event.v1
<canonical Platform origin>
POST
/api/v1/runtime/events
<runtime_ref>
<enrollment_ref>
<event_id>
<base64url SHA-256 of RFC 8785 canonical checked event bytes>
```

Hash only the already validated canonical event, including its fixed schema,
timestamp, references and decision facts. Never hash rejected input, raw workload
content or a local configuration fingerprint. Enrollment bootstrap tokens and
private/public keys are absent from the event request. No cookie or ambient user
session is needed to prove possession of the enrolled key.

Retries preserve the event ID, canonical body and enrollment identity. The
signature binds audience, method and endpoint so the same proof cannot move to a
different service, action or enrollment. It does not prevent replay to the same
endpoint. The receiver must enforce revocation, event validity, bounded retention
and durable same-ID/same-body deduplication; conflicting bodies must be rejected.

## Acknowledgment

After authenticated durable acceptance, the receiver returns an object with
exactly six required fields:

| Field | Value |
| --- | --- |
| `schema_version` | Integer `1` |
| `event_id` | The submitted event ID |
| `runtime_ref` | The submitted Runtime reference |
| `enrollment_ref` | The submitted enrollment reference |
| `event_digest` | The exact canonical event digest from the transcript |
| `status` | `accepted` |

`SignedEvent::verify_receipt` accepts at most 1 KiB and rejects duplicates,
missing/unknown fields, malformed JSON and every changed binding. It returns an
opaque `EventReceipt`, with no public constructor or deserializer. It neither
authenticates the transport nor deletes a queued event. The sender must verify
HTTPS first, validate this bound acknowledgment and then complete the original
current lease. A parsed JSON object alone cannot establish durable delivery.

Errors are fixed categories without rejected content, identifiers or parser
diagnostics. Signed requests and receipts have no generic `Debug`, `Serialize`
or `Deserialize` implementations. Explicit request-byte access is for delivery,
not ordinary logs. Opaque correlation references are still metadata, not anonymity.

## Independent executable fixture

```sh
cargo test -p mitigate-enrollment --all-features --locked
cargo run -p mitigate-enrollment --example event_proof --locked > event-fixture.json
node scripts/verify-event-proof.mjs event-fixture.json
```

The example creates and removes its own temporary SQLite queue, admits the public
decision fixture, acquires a journaled lease and signs using the public synthetic
seed (32 bytes of decimal 23). It never reads user input or the native store and
never opens a network connection. Only this public fixture is printed; production
request bodies must not be logged. Node/OpenSSL independently canonicalizes the
fixture, recreates its signature and checks the exact Rust output. Mutations of
all transcript fields, every event field/fact, the final LF and the signature fail.
CI runs the fixture on Windows, macOS and Linux.

The native signing path does not yet compose an HTTPS event sender, consent/lease
cancellation, automatic gateway producer or hosted receiver.
