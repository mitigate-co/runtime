# Capture calls and inventory for optional sync

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
observed completion. It does not export audit files or historical calls.
Add `--sync-inventory` to opt into fresh inventory observations after installing a
receiver that accepts the v2 inventory contract. Existing capture commands keep
their decision-only behavior. Start `mitigate sync run --profile SYNC` separately for continuous
delivery, or use `mitigate sync send --profile SYNC` to attempt one queued event.
The gateway never starts a sender automatically.

## Inventory observations

With `--sync-inventory`, a successful initial `tools/list` request can capture the
complete bounded upstream inventory after its fresh review check and required
local audit commit. Continuation pages do not create repeated observations. The
worker must already be ready and consent must exist before the request starts.
There is no background enumeration, retrospective capture or historical replay.
Servers that do not advertise tools have no listing to capture; their absence is
not a complete zero-tool observation. Servers advertising tools with an empty
list can produce an explicit complete empty observation.

One observation may be reserved or buffered at a time, with at most 512 tools.
Local identity/definition digests and closed classification enums are the only
copied facts. The worker resolves at most 16 keys per step, sorts the complete
mapped inventory by independent random tool reference, then admits one four-tool
part per step. It processes at most one queued decision alongside that step and
releases local enrollment ownership before continuing. Calls never wait for the
optional queue. Failed listing/audit, overload, storage failure, shutdown or a
changed consent generation discards unfinished capture. Already admitted parts
remain incomplete until every part arrives; no failure fabricates completion.

Server/tool mappings are shared with decision events. Inventory `schema_ref`
maps the full observed definition revision, including input/output/description;
v1 decision `schema_ref` retains its existing input-schema mapping. They must not
be equated as revision identifiers across event kinds. Hashes stay local. Closed
capability, risk, source and confidence values preserve the classifier's
conservative flags and declared evidence. No names, rule matches, definitions,
free text or workload values enter the projection. See [inventory protocol](INVENTORY_PROTOCOL.md).

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

Each capture carries its original opaque consent permit. Inventory reserves that
permit before the fresh listing and retains it across every part. The worker uses the
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

Decision capture copies only seven named governance keys (client, principal, agent,
server, tool, schema and policy), closed enums, bounded timing/version values and
independent random invocation references. Inventory capture copies the server,
tool and full-definition keys described above. Neither projection has a field
for arguments, results, tool names, descriptions, arbitrary JSON, environment,
operator identity or evidence. Complete hashes never enter the wire event.

Governance keys remain customer-local catalog inputs. Only independent persisted
random mappings enter checked wire events. Event IDs are fresh per record; call
and approval IDs correlate phases of one invocation without accumulating entries
in the durable catalog. Unknown attribution remains explicit null/unknown.
Inventory-only or legacy unaudited allowances cannot be promoted to governed
sync events. The closed egress validator still checks every projected event.

Fixed stderr diagnostics announce readiness, pause, unavailability and metadata
loss without paths, key values, payloads or backend exception text. They never
enter MCP stdout. A failed startup privacy probe retains a closed category so a
clock or operation-budget failure can be distinguished from failed assertions.
There is no change to the enforcement configuration schema,
local audit format, sync profile or wire event contract. Legacy profiles without
a pinned reference catalog cannot start capture; missing catalogs are not
recreated. Legacy queues require explicit resume before issuing capture permits.

## Verification

Unit tests cover independent reference mapping, lifecycle/approval correlation,
unknown attribution, buffer saturation, disconnected workers and audit failure.
Inventory tests cover all 512 tools, globally sorted parts, restart-stable random
mappings, closed classifications, empty/unsupported distinction, oversize refusal,
single-observation reservations and consent withdrawal during partial admission.
Real-SQLite enrollment tests cover owner contention and pause/drain without
native credential access. The opt-in native lifecycle fixture runs an actual CLI
gateway against the synthetic MCP child, waits for readiness and durable records,
then verifies restart correlation, denial, inventory after required audit,
audit-failure refusal, continuation-page exclusion, fresh snapshot references,
pause/purge and missing-profile isolation. Windows/Linux use `--cli`; macOS uses
`--capture-cli` so only the
creating fixture binary accesses its native Keychain item. These fixtures never
contact Platform or read customer data.

Windows run [36561230328](https://github.com/mitigate-co/runtime/actions/runs/36561230328/job/109382314152)
failed in the native gateway-capture child with only a stage name retained;
[issue #57](https://github.com/mitigate-co/runtime/issues/57) preserves that evidence.
The diagnostic projector now accepts Windows and POSIX spellings of only the
two known public fixture source files, with positive numeric line/column values.
At most 8 KiB / 64 lines are inspected. Only fixed stages, privacy/inspection
categories, public assertion positions and the child's numeric exit code can be
printed; raw stderr, paths and panic payloads remain excluded. Regression fixtures cover both path formats, malformed/overflow
positions, private text and bounds. Capture stage labels carry no workload values.

This fixes missing Windows assertion diagnostics, not the underlying capture
failure. Readiness deadlines, required counts, privacy probes and expected MCP
outcomes are unchanged. A successful subsequent run cannot close the release
blocker without establishing its cause.

Linux main run [36781795025](https://github.com/mitigate-co/runtime/actions/runs/36781795025/job/110113580375)
failed at `sync.rs:218:34` on source `9f213a7`: the read-only `profile.inspect()`
returned an error after the fixture released its deliberate audit-store lock.
The pending-count comparison had not run. [Issue #75](https://github.com/mitigate-co/runtime/issues/75)
retains this separate failure; the original inner error was not projected.
The fixture now projects each closed outbox error through an explicit allowlist,
preserving caller assertion positions and refusing all arbitrary payload text.
Inspection still fails immediately on any error, without retries or repairs.
No count, deadline, storage budget, audit requirement or production behavior changes.

A deterministic regression holds an exclusive lock on the synthetic outbox,
requires `Busy` from read-only inspection, verifies unchanged file bytes and no
new files, then confirms the original pending event after rollback. This proves
the lock-refusal contract; it does not establish that contention caused #75.
Inspection does not sample the OS wall clock or access native credentials.
The original failure remains a release gate until its cause is demonstrated.
