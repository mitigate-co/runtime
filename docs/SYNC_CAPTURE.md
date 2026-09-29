# Capture governed calls for optional sync

First create a consented profile with [sync enable](SYNC_CONTROLS.md). Add its
path to the same reviewed gateway command used for local enforcement:

```text
mitigate mcp serve --allow-exec --launch-config LAUNCH --launch-review REVIEW --enforce GOVERNANCE --profile CALLER --sync-profile SYNC
```

Uppercase arguments are customer-selected local paths. `--sync-profile` requires
enforcement and never enables consent, enrolls an account or creates missing
files. An omitted flag preserves the existing local-only behavior. The local
caller profile and sync profile have different purposes; neither is inferred
from MCP client metadata or workload content.

This producer captures governed call decisions, approval waiting, dispatch and
observed completion. It does not export audit files, historical calls or inventory
snapshots. Start `mitigate sync run --profile SYNC` separately for continuous
delivery, or use `mitigate sync send --profile SYNC` to attempt one queued event.
The gateway never starts a sender automatically.

## Availability and consent

A dedicated metadata thread opens the selected profile and runs the real
synthetic privacy self-test before advertising capture readiness. A failed or
unavailable probe leaves capture disabled until restart; it is never silently
retried or interpreted as passing. Run `mitigate privacy self-test` and investigate
failures before restarting capture. Missing/invalid configuration cannot disable
local MCP protection or required local auditing.

After a successful required audit commit, the local authority may copy a narrow
typed projection into a 128-entry buffer using nonblocking admission. A busy
shared snapshot, full/disconnected buffer, randomness failure or invalid
projection cannot change tool authorization. Startup, pause, overload, storage
failure and process exit can leave gaps in hosted metadata. The local audit is
the required record; this is best-effort optional capture, not an exactly-once
audit replication claim. No historical audit replay fills those gaps.

Consent is sampled at the record boundary before the audit write. Publication
still requires that write to succeed. A resume during a delayed commit cannot
retroactively enable capture of a record begun without consent.

Each capture carries its original opaque consent permit. The worker uses the
original enrollment owner only during mapping/admission, then releases it before
waiting. Queue admission atomically checks the same permit. Pause/purge followed
by resume cannot revive older buffered captures. Rejected/uncertain buffer
admission is discarded rather than re-created with new IDs or renewed consent.
Once committed to the outbox, the event has the existing durable lease, retention
and idempotent-delivery semantics.

Normal gateway exit requests worker stop without waiting for optional storage.
An already-started metadata transaction may finish or need recovery on reopen;
uncommitted in-memory events may be lost. Use explicit `sync pause`/`purge` to
withdraw and drain before retiring state. Those commands independently coordinate
with the original enrollment owner. No native credential prompt or network
request is performed by the capture thread.

## Projection boundary

The producer copies only seven named governance keys (client, principal, agent,
server, tool, schema and policy), closed enums, bounded timing/version values and
independent random invocation references. It has no field for arguments, results,
tool names, descriptions, arbitrary JSON, environment, operator identity,
evidence or complete policy/definition hashes.

Governance keys remain customer-local catalog inputs. Only independent persisted
random mappings enter checked wire events. Event IDs are fresh per record; call
and approval IDs correlate phases of one invocation without accumulating entries
in the durable catalog. Unknown attribution remains explicit null/unknown.
Inventory-only or legacy unaudited allowances cannot be promoted to governed
sync events. The closed egress validator still checks every projected event.

Fixed stderr diagnostics announce readiness, pause, unavailability and metadata
loss without paths, key values, payloads or backend exception text. They never
enter MCP stdout. There is no change to the enforcement configuration schema,
local audit format, sync profile or wire event contract. Legacy profiles without
a pinned reference catalog cannot start capture; missing catalogs are not
recreated. Legacy queues require explicit resume before issuing capture permits.

## Verification

Unit tests cover independent reference mapping, lifecycle/approval correlation,
unknown attribution, buffer saturation, disconnected workers and audit failure.
Real-SQLite enrollment tests cover owner contention and pause/drain without
native credential access. The opt-in native lifecycle fixture runs an actual CLI
gateway against the synthetic MCP child, waits for readiness and durable records,
then verifies restart correlation, denial, pause/purge and missing-profile
isolation. Windows/Linux use `--cli`; macOS uses `--capture-cli` so only the
creating fixture binary accesses its native Keychain item. These fixtures never
contact Platform or read customer data.
