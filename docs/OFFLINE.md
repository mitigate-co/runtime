# Local operation and outage recovery

Scanner and governed stdio calls require no Mitigate account or Platform
connection. The gateway evaluates `input.offline = true`; there is currently no
Platform transport. Upstream tools can still require their own network access.
This guarantee concerns Mitigate control availability, not the tool's availability.

## Policy

A new gateway requires a valid local policy database and a bundle verified against
the separately pinned authority. It cannot start from an empty/corrupt cache.
Once running, it retains the last verified policy in memory when a refresh is
unavailable, invalid, older, or an equal-version replacement with different bytes.
Both allow and deny decisions remain active. One fixed local warning is emitted
per failure period; rejected source and backend diagnostics are not printed.

A valid higher version from the pinned authority becomes active on the next
authorization check. A waiting approval bound to the previous version is cancelled,
even when the new policy is less restrictive. Fresh calls use the new version.
Restart loads the last valid committed store; memory is not a replacement backup.

For recovery, preserve the stores and correct permissions, disk capacity, clock
or the source of failed refreshes. Verify a known backup before restoring it with
the gateway stopped; do not delete authority databases to bypass a refusal.
Use the supported signed-policy activation command for ordinary policy updates.
A restored backup can roll back local history; same-user whole-file rollback is
outside the current trust guarantee. See [policy storage](POLICY.md).

## Approvals, grants and controls

Required approvals remain local, bound to one call, and time-limited. An unavailable
approval database returns no permit. Expiry, cancellation, revocation, changed
definitions or policy also prevent execution. The gateway does not substitute
automatic approval or a cached approval from another call. Cloud-only approval is
not implemented and cannot be configured as a permissive fallback.

Grants, stops and quota balances remain independent constraints. Missing or invalid
grants fail closed; a cached policy allowance cannot override them. Stops and quota
consumption survive normal restarts. Failed/uncertain calls are never automatically
replayed and do not refund admitted quota or revive consumed approvals. Required
local audit commits remain required during an outage.

## Optional synchronization

There is no sync queue or sender in this implementation yet. Local audit exports
are not Platform telemetry and must not be uploaded directly. MCP-015's bounded
safe queue and MCP-016's closed event/egress boundary remain open acceptance work;
this document does not claim those gates have passed. Future queue failure must
not block local policy enforcement or cause a raw-content fallback.

## Verify with synthetic processes

```sh
cargo build --workspace --locked
target/debug/mitigate-test-mcp offline-contract target/debug/mitigate
```

Append `.exe` to both binaries on Windows. This executes only the supplied fixture
server and isolated temporary stores. It tests cached offline allow/deny against
wrong-key, rollback, equal-version replacement and malformed refreshes; refusal
to start with corrupt authority; newer valid policy recovery and restart; and
unavailable local approvals followed by deliberate approval after recovery.
Invocation markers, audit policy versions and content canaries check the outcome.

The existing `governance-contract` additionally covers approval expiry/revocation,
live control/grant changes, exact schema/code boundaries, quota exhaustion, audit
failures and cancellation. All three OS CI jobs execute both contracts.

The executable fixture observes its synthetic approval mailbox with a bounded
read-only query. It does not repeatedly acquire the production expiry/clock writer
lock merely to wait for a request. Actual decisions and consumption still use the
production store APIs; busy/unavailable production authority remains fail-closed.
