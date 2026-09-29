# Optional sync controls

Enrollment does not enable telemetry. Explicit sync setup binds a new private
queue to one confirmed native enrollment. Local MCP protection never depends on
these controls or Platform availability. No gateway producer or background sender
is activated by this slice; `send` attempts at most one already queued event.

## Commands

Use an existing private local directory. Replace the uppercase arguments with
your selected paths and the original canonical HTTPS Platform origin:

```text
mitigate sync enable --profile PROFILE --enrollment ENROLLMENT --platform ORIGIN --outbox QUEUE
mitigate sync status --profile PROFILE
mitigate sync send --profile PROFILE
mitigate sync pause --profile PROFILE
mitigate sync resume --profile PROFILE
mitigate sync purge --profile PROFILE --confirm
```

`enable` is explicit consent. It requires confirmed native enrollment and creates
new files without replacing existing ones. It does not send an event or start a
worker. The queue defaults to 1,000 events and seven-day admission retention.
The library permits shorter retention only above the sender's 25-second budget.

Subsequent commands need only the profile path. `status` is read-only and does not
unlock credentials or contact Platform. Its `paused` field describes current local
consent, not whether an earlier network request has finished. `send` never resumes
consent. A paused profile returns idle without unlocking the credential store.
Enabled delivery restores its original confirmed native binding before claiming
an event and uses the [bounded one-attempt sender](EVENT_HTTPS.md).

`pause` immediately commits withdrawal for new admission and attempts, then waits
up to 25 seconds for the enrollment operation lock. Holding that same lock, it
reasserts pause before reporting completion. A competing resume that acquired the
lock first cannot undo the final pause. Already transmitted bytes cannot be
retracted. A later deliberate resume is a new consent action.

`purge` follows the same pause/drain sequence, then deletes queued bodies and
duplicate receipts. It retains the bounded content-free journal, profile and
immutable enrollment anchor. It does not delete native credentials or previously
hosted records. Pause and purge work after native credentials are removed: they
verify the immutable anchor without reading the OS credential store.

`resume` requires the exact original confirmed native enrollment, anchor reference
and queue partition. It changes local consent only. A missing/locked/changed key or
pending enrollment cannot silently enable delivery.

## Local profile and failure behavior

The immutable version-one profile contains exactly six fields: `schema_version`,
canonical `platform`, absolute `enrollment_file` and `outbox_file`, the opaque
`native_reference` already present in the enrollment anchor, and the queue's
`partition`. It contains no key, bootstrap code, event body or workload identifier.
Paths are customer-local configuration and never enter telemetry or CLI reports.
The profile is capped at 8 KiB; unknown/duplicate fields, unsupported versions,
relative paths, malformed references and unsafe files are rejected.

Creation reserves a new empty profile, creates the new queue, then durably writes
the complete binding while holding the native owner. Interrupted setup may leave
an empty profile or queue. Inspect it; do not automatically remove/repair files or
rotate enrollment. An existing queue cannot turn a failed setup into a valid new
profile. An uncertain flush requires reopening to inspect actual state.

Unix files are mode 0600; Windows files inherit the selected directory's ACL.
Keep parent directories private. This does not defend against same-user/root
file replacement, copied anchors, memory access or complete filesystem rollback.
Every sender and controller must use the original enrollment anchor; never unlink
it while an operation can own its lock. Cooperating commands serialize through
that anchor, including credential deletion. A low-level embedder must follow the
same ownership contract.

If drain times out, `sync_draining` reports that new delivery is paused but an
existing operation is still finishing. Retry pause/purge before removing state.
Do not interpret a local paused flag as a completed shutdown. Native unlock
prompts or OS suspension can outlast the HTTP deadline. Queue/clock/storage errors
are explicit; they never cause automatic resume or replay a local tool call.

## Reports and checks

Sync commands emit schema-version-one JSON with fixed `status`, a safe `queue`
report, optional fixed `reason`, and `delivery_drained: true` only after a
successful pause/purge. No profile paths, native reference, payload or provider
text is emitted. Invalid input/local failure uses the normal stderr error contract
and exit 2. A classified permanent refusal, retained retry or authorization pause
also returns exit 2 with its structured outcome on stdout. Idle/accepted/control
success returns zero. Enrollment CLI reports separately use version 2 and state
`sync_status: "not_checked"` instead of inventing a disabled status.

Tests cover real SQLite consent, pause before native drain, missing native records,
competing resume, immutable/partial setup, closed/private profile parsing and
actual CLI input privacy. Synthetic Windows and isolated Linux native fixtures
exercise create/resume/pause/purge and paused send without external requests.
Three-OS CI also verifies the native fixture and command contracts.
