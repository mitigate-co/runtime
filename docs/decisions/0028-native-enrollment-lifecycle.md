# ADR 0028: Native enrollment lifecycle with an immutable lock anchor

Status: Accepted for optional enrollment storage and recovery.

## Context

An enrollment claim must not be released before its identity can survive a lost
response/restart. Separate plaintext records cannot contain seeds/codes. Native
write success can be uncertain; concurrent retries/forget operations must not
silently replace each other's identity or recreate a deleted credential.

## Decision

Use one bounded, strictly parsed native secret record for the key, code/receipt
and opaque binding. Use an immutable local anchor for its origin/reference and
exclusive standard-library file lock. Synchronize the anchor before native writes
and require exact native read-back. Keep ownership through the caller's entire
bootstrap operation. A failed confirmation consumes the session; reopen to
reconcile pending or confirmed state before another operation.

Use synchronous native management outside a Tokio runtime so an OS prompt/write
cannot continue after a dropped future releases the operation lock. Reject nested
async entry before mutation. Explicitly unlock when ownership ends because a
concurrently forked child may briefly inherit a descriptor before close-on-exec.
Do not unlink/recreate the lock anchor during normal lifecycle or forget.

Reuse the reviewed OS-native broker, Tokio and standard filesystem APIs; no new
external dependency/version or plaintext SQLite credential record is introduced.
Private fault injection tests provider failures without relaxing the native API.

## Consequences

Local recovery is exact and bounded, and confirmed state removes the bootstrap
token. Forget verifies precise deletion but does not imply remote revocation or
outbox purge. Keep anchors in trusted private local directories, do not copy active
anchors, and stop all users before removing a retired anchor. Whole-file/native
rollback and same-user tampering are not remote attestation problems solved here.

This intentionally separates local credential management from HTTPS, telemetry
consent and closed signed ingest. Those composed flows still need their own
failure/abuse tests. See [lifecycle and limits](../ENROLLMENT_STORAGE.md).
