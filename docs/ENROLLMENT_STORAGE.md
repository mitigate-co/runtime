# Enrollment storage and recovery

`EnrollmentStore` owns one optional enrollment's native credentials and local
operation lock. It exposes create, open, pending claim, confirm, status, checked
event signing and forget.
No network transport, sync consent, outbox producer or CLI command is included in
this component. Local MCP operation remains independent of it.

## What is stored

The operator selects a file inside an existing private local state directory.
This **immutable anchor** contains a version marker, canonical HTTPS origin and
random `sec_` reference only, with a 384-byte read limit. It contains no signing
seed, one-time code, signature, workload fingerprints, human or machine identity.
The origin is checked against the operator's expected destination before any
native lookup. Existing files, even empty/damaged files, are never overwritten.

The reference selects one entry in the existing OS-native broker: Windows
Credential Manager with Local persistence, macOS default Keychain, or Linux
Secret Service. A bounded private record binds the exact anchor reference and
origin to the two opaque Runtime references, Ed25519 seed and lifecycle phase.
Pending records additionally contain the one-time code; confirmed records contain
only an accepted server timestamp in its place. The record is limited to 768 UTF-8
bytes, well below the broker's 2560-byte portable limit.

The versioned native record uses an exact fixed sequence of LF-delimited fields,
not a generic metadata/JSON container. Each field is independently validated and
none permits LF. Parsing borrows from a zeroizing owner, so intermediate JSON
strings cannot retain copies of the seed or code. Native encode/decode has no
general serialization or diagnostic API. Native-library/OS copies, swap and
privileged memory access remain outside owned-allocation zeroization guarantees.

## Durable operation order

1. Generate a fresh key, independent opaque references and native secret reference.
2. Atomically create the anchor, exclusively lock it, write and synchronize it.
   On Unix also synchronize the parent directory before mutating the native store.
3. Refuse a preexisting native entry at the random reference. Write the pending
   record and require an exact read-back before returning a claim-capable owner.
4. Keep that owner locked through the caller's HTTPS request and receipt handling.
   A lost response leaves the pending record intact. Reopening regenerates the
   identical claim from the same key, code, origin and opaque references.
5. After independently authenticated HTTPS, validate the exact closed receipt,
   replace the pending record with confirmed state, and require exact read-back.
   Confirmation removes/zeroizes the local bootstrap code. It does not enable sync.

Both sides of a native write can fail: an error may occur before or after the
provider committed it. A failed confirmation consumes the in-memory session so
the caller must reopen. If storage contains pending state, retry the original
claim. If it contains confirmed state, report that local receipt; never claim or
rotate again. Missing/corrupt/ambiguous state fails closed and is not repaired.
For an initial write interrupted before native persistence, the anchor remains
but no claim has been released; explicit recovery is required.

`Status::Confirmed` is only a locally retained receipt. It does not mean the
Runtime is online, authorized after revocation, assigned a human identity or
transmitting telemetry. The timestamp cannot control local policy/clock authority.

`sign_event` requires that confirmed local state and a committed outbox lease for
the same Runtime/enrollment pair. It uses only the key, references and origin
restored from the native record/anchor; callers cannot supply replacement signing
material or a different destination. Pending state returns `enrollment_pending`;
a wrong queue returns `enrollment_scope`, without modifying either store. Failed
confirmation consumes the owner, so signing requires reopening and reconciling
the actual native state first. Keep the owner locked through event delivery.

The method does not check current remote revocation, consent or lease validity,
perform HTTPS, complete a queue entry or enable sync. Those remain the sender's
responsibilities. See [the signed event protocol](SIGNED_EVENTS.md).

## Concurrency and native prompts

An exclusive nonblocking [standard-library file lock](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock)
serializes cooperating operations on the same anchor across processes. Busy is a
fixed retryable failure. The file is never replaced/unlinked by lifecycle methods,
which avoids creating a second independently lockable inode. Drop explicitly
unlocks before close, including when a concurrently spawned child briefly
inherits the open description before close-on-exec. Regression tests retain a
duplicate descriptor and also exercise a second process.

All native lifecycle operations are synchronous. Call them on a plain blocking
thread outside a Tokio runtime, including outside Tokio-owned blocking tasks.
Nested async callers are rejected before anchor/native mutation. The lock remains
owned until native permission prompts/operations finish; cancellation of an outer
task must not be represented as cancellation of an OS write. Do not detach an
enrollment sender from its owner or continue sending after dropping the owner.

The parent directory, its ACLs and same-user ownership are trusted. Unix anchors
are created mode 0600 and reject group/other permissions. Known symlink/reparse
paths, nonfiles and oversized inputs are rejected before use. Windows uses the
private directory's inherited ACL. This is not protection against privileged path
replacement, whole-file restore, copies of an anchor with a second inode, native
store rollback, a same-user process bypassing the lock or every power-loss scenario.
Store anchors on a local filesystem with working exclusive locks; no network-share
lock/durability guarantees are claimed. Never copy an active anchor for parallel use.

## Forgetting and recovery

Explicit `forget` locks the anchor, validates that the native record belongs to
it, deletes only that entry and requires a subsequent Missing result. Missing is
idempotent, and an uncertain deletion can be reconciled by repeating it. A corrupt
or mismatched native record is never deleted as if it were an enrollment record.

Forgetting does **not** revoke a remote key, clear an outbox or stop another
noncooperating process. A composed sync command must stop/purge sync and arrange
remote revocation where needed before invoking local deletion. The anchor remains
as recovery metadata and cannot silently create a new identity. To start a new
enrollment, use a new private anchor. Remove an old anchor only after confirming
its credential is gone and all users of that path have stopped.

There is no native-store enumeration, environment fallback or plaintext key file.
An unavailable/locked native broker affects optional enrollment, not local MCP.

## Verification

Fault-injection tests cover interrupted writes before/after native commit,
incorrect read-back, idempotent deletion, failed deletion, exact identity recovery,
token removal, wrong-origin refusal before lookup, cross-process contention,
duplicate-handle lock release, malformed/swapped records and unsafe anchor paths.
Signing tests additionally cover pending refusal, exact confirmed-key recovery,
wrong-enrollment refusal and reconciliation after uncertain native confirmation.
The explicitly ignored subprocess helper is invoked by the parent lock test; it
is not a skipped security assertion. Linux/Windows crate suites and compile-fail
checks passed locally; actual Windows native round-trip passed and deleted its
precise temporary entry. Three-OS CI verifies the actual native adapters.

With an unlocked native store, opt in to the synthetic demonstration:

```sh
cargo run -p mitigate-enrollment --example native_lifecycle --locked -- --allow-native-fixture
```

It creates a unique temporary anchor and synthetic native credential, reopens
pending and confirmed states, refuses pending event signing and verifies identical
bootstrap proofs and confirmed event signatures after restart. It purges its
synthetic queue and deletes its exact native entry. It performs no network
requests and prints no key, code, claim or signed event. Cleanup
is attempted on failure; a fixed warning leaves the anchor if deletion cannot be
confirmed. CI uses temporary isolated macOS/Linux stores and an exact temporary
Windows entry. Do not point an isolated test keyring at user data.
