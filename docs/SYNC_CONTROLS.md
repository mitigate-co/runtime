# Optional sync controls

Enrollment does not enable telemetry. Explicit sync setup binds a new private
queue and local reference catalog to one confirmed native enrollment. Local MCP
protection never depends on these controls or Platform availability. The explicit
[gateway capture flag](SYNC_CAPTURE.md) queues governed-call metadata; setup alone
does not start it. `send` attempts at most one queued event. `run` explicitly
starts a foreground sender that drains eligible events until paused or stopped.

## Commands

Use an existing private local directory. Replace the uppercase arguments with
your selected paths and the original canonical HTTPS Platform origin:

```text
mitigate sync enable --profile PROFILE --enrollment ENROLLMENT --platform ORIGIN --outbox QUEUE
mitigate sync status --profile PROFILE
mitigate sync send --profile PROFILE
mitigate sync run --profile PROFILE
mitigate sync pause --profile PROFILE
mitigate sync resume --profile PROFILE
mitigate sync purge --profile PROFILE --confirm
```

`enable` is explicit consent. It requires confirmed native enrollment and creates
new files without replacing existing ones. It does not send an event or start a
worker. The queue defaults to 1,000 events and seven-day admission retention.
The library permits shorter retention only above the sender's 25-second budget.
The catalog is created beside the queue as `<queue filename>.references.sqlite`;
there is no additional setup argument. Its path is pinned in the new profile.

Subsequent commands need only the profile path. `status` is read-only and does not
unlock credentials or contact Platform. Its `paused` field describes current local
consent, not whether an earlier network request has finished. `send` never resumes
consent. Paused, empty, leased and backing-off queues return idle without unlocking
the credential store or acquiring its owner lock. Local preparation applies due
expiry through the existing bounded transaction; other polls use read-only
connections. A candidate must have enough retention for the entire exchange.
This hint does not authorize delivery. Ready work restores its original confirmed native binding before claiming
an event and uses the [bounded one-attempt sender](EVENT_HTTPS.md).

## Continuous delivery

Start `run` in a separate terminal after enabling sync and starting the governed
gateway with its explicit capture flag. No daemon, scheduled task or automatic
restart is installed. Starting this command never creates or resumes consent.
A paused profile exits immediately. Otherwise the real synthetic privacy
self-test must pass once in this process before any native unlock or delivery;
failure stops it without retries. `send` applies the same gate when work is ready.
Use `mitigate privacy self-test` to inspect an unsuccessful check.

The sender polls local readiness once per second when idle or delayed, without
holding the native owner. A ready attempt restores the original native binding
and rechecks current consent, exact lease and remaining time. One process spaces
completed attempts by at least 500 ms. Multiple senders use the existing owner
and queue leases; they do not share a global rate limiter. Prefer one sender per
profile. Transport retries retain their original event/identity and queue backoff.
Only documented owner/SQLite contention is retried locally; clock, integrity,
native-store and completion failures stop the sender for inspection. Permanent
event refusals do not block other events. Authorization failure or a redirect
pauses the queue and stops the sender.

Ctrl-C stops this process; Unix also handles SIGTERM. Shutdown starts no new
attempt once observed and waits for its already-started worker operation before
reporting stopped. Native unlock prompts, blocked output or OS suspension can
outlast the HTTPS deadline. A forced process termination cannot retract bytes or
confirm completion; a retained lease follows normal recovery on the next start.
Stopping a sender does not withdraw consent or stop a different sender. Use
`sync pause` for durable withdrawal and coordinated drain. A sender exits when
it observes local pause; a deliberate resume requires starting it again if it
has exited. A pause/resume completed between polls may not cause process exit,
but each attempt still checks current consent under the original owner.

`pause` immediately commits withdrawal for new admission and attempts, then waits
up to 25 seconds for the enrollment operation lock. Holding that same lock, it
reasserts pause before reporting completion. A competing resume that acquired the
lock first cannot undo the final pause. Already transmitted bytes cannot be
retracted. A later deliberate resume is a new consent action.

`purge` follows the same pause/drain sequence, then deletes queued bodies and
duplicate receipts. It retains the bounded content-free journal, profile, local
reference catalog and immutable enrollment anchor. Retained mappings preserve
identity across pause/purge/resume. It does not delete native credentials or
previously hosted records. Pause and purge work after native credentials are removed: they
verify the immutable anchor without reading the OS credential store.

`resume` requires the exact original confirmed native enrollment, anchor reference
and queue partition. Version-two profiles also verify the original catalog and
its scope before unpausing. It changes local consent only. A missing/locked/changed
key, pending enrollment or invalid catalog cannot silently enable delivery.

## Local profile and failure behavior

The immutable version-two profile contains exactly seven fields: `schema_version`,
canonical `platform`, absolute `enrollment_file` and `outbox_file`, the opaque
`native_reference` already present in the enrollment anchor, and the queue's
`partition`, plus absolute `reference_file`. It contains no key, bootstrap code,
event body or workload identifier.
Paths are customer-local configuration and never enter telemetry or CLI reports.
The profile is capped at 8 KiB; unknown/duplicate fields, unsupported versions,
relative paths, malformed references and unsafe files are rejected.

Creation reserves a new empty profile, creates the new queue and catalog, then
durably writes the complete binding while holding the native owner. Interrupted setup may leave
an empty profile, queue or catalog. Inspect it; do not automatically remove/repair
files or rotate enrollment. An existing queue or catalog cannot become part of a new
profile. An uncertain flush requires reopening to inspect actual state.

Legacy version-one profiles retain their original six-field contract and existing
controls. They are not silently migrated and no missing catalog is created on
open/resume. A version-one profile cannot carry `reference_file`; version two
requires it. Null, relative paths and catalog paths equal to the queue or anchor
path are rejected. The profile
change does not change version-one CLI reports or wire events. Queue storage
versioning is independent of the immutable profile.

Queue storage now has its own version-two consent guard (ADR 0037). New queues
use it immediately. Explicit `resume` upgrades a valid version-one queue
atomically, retaining its accepted events and receipts; status, pause, purge and
send do not upgrade it. The immutable profile is unchanged. Earlier binaries
cannot open the upgraded queue: pause/drain with the matching binary before a
rollback and preserve its files. Buffered producers must present the consent
permit captured with each event; pause/purge followed by resume cannot restore
permission for an older buffered capture.

Status, pause and purge intentionally do not open the reference catalog. They
remain available if that optional store is missing or damaged. Preserve a damaged
catalog for recovery rather than rebuilding it under the same enrollment. For
complete local retirement, first pause/drain and purge, then forget the native
enrollment before removing its profile, queue and catalog. Never remove the
original enrollment anchor while another operation can hold it; delete only the
explicitly retired files. A new enrollment uses a new catalog.

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

Single-operation sync commands emit schema-version-one JSON with fixed `status`, a safe `queue`
report, optional fixed `reason`, and `delivery_drained: true` only after a
successful pause/purge. No profile paths, native reference, payload or provider
text is emitted. Invalid input/local failure uses the normal stderr error contract
and exit 2. A classified permanent refusal, retained retry or authorization pause
also returns exit 2 with its structured outcome on stdout. Idle/accepted/control
success returns zero. Enrollment CLI reports separately use version 2 and state
`sync_status: "not_checked"` instead of inventing a disabled status.

`run --json` is a separate JSON Lines progress contract. Every stdout line has
exactly `schema_version: 1`, a fixed `status`, and an optional fixed `reason`.
Statuses are `waiting`, `sending`, `retrying`, `rejected`, `stopping` and `stopped`;
identical consecutive states are suppressed. Progress contains no paths, queue
IDs, event bodies or provider messages. `sending` announces an attempt, not
remote acceptance. Final `stopped` uses `sync_interrupted`, `sync_paused` or the
closed authorization/redirect reason. Interruption and observed local pause exit
zero; remote authority refusal exits 2. A fatal operational/privacy failure emits
the normal stderr error contract and exits 2, possibly after earlier progress.
It does not emit a successful final report. Output failure stops further attempts.

Tests cover real SQLite consent, pause before native drain, missing native records,
competing resume, immutable/partial setup, catalog preservation, legacy profiles,
closed/private profile parsing and actual CLI input privacy. Synthetic Windows and isolated Linux native fixtures
exercise create/resume/pause/purge and paused send without external requests.
The actual continuous CLI fixture checks simultaneous empty senders, unchanged
queue bytes, failed privacy-probe refusal, coordinated pause and immediate paused
exit. Unix additionally verifies both interrupt signals without changing consent.
Deterministic driver tests cover interrupted/in-flight work, backoff, authority
refusal, output failure and fatal storage errors. Actual CLI fixtures do not claim
successful delivery to a live Platform; the separately reviewed TLS/receipt tests
exercise real transport with private test certificates. Three-OS CI verifies the
native fixture and command contracts.
