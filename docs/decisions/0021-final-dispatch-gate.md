# ADR 0021: Final authorization after upstream refresh

Status: accepted for implementation; cross-platform verification pending.

## Problem

The upstream adapter refreshes inventory and checks selected executable/artifact
bytes before invoking a tool. These operations take time and can execute server
code. Evaluating authorization only before entering the adapter could miss an
operator stop, approval revocation or new policy during refresh.

## Decision

Add `StdioServer::call_with_gate`. After local argument/schema validation, fresh
inventory and launch checks, invoke one owner-provided asynchronous closure before
sending `tools/call`. The closure receives no arguments/results, mutable definition
or transport. It must perform the final authority checks and durable pre-dispatch
records. Existing `call` remains a low-level API for already-authorized invocations;
neither API is an enforcing gateway by itself. No ordinary CLI enables calls yet.

The gate uses the same transaction deadline as refresh and dispatch. Check the
absolute deadline before and after it, including ready non-yielding futures that
can otherwise outrun Tokio's cooperative timeout. Long human waits occur before
entering this transaction. Rejection preserves a healthy connection and is distinct
from validation/transport failure. Timeout, cancellation or a transport failure
invalidates the session and terminates its process group/job as before.

Only the request future owns dispatch. A cancelled gate's detached database worker
may complete a local commit, but must never own an upstream or send tool requests.
Such committed authority is not reusable. There is no automatic retry, rollback
of effects or distributed transaction between SQLite and the MCP process. A
dispatch record is not proof that a request reached the server. Missing completion
requires an uncertain outcome. Cross-store final admission ordering belongs to
the governing service, not this transport callback.

The final gate does not attest the program or close privileged same-user code
replacement races. Selected bytes are verified before the gate; they are not
locked while it runs. Process privileges and unselected transitive code remain
the existing launch-review boundary.

## Verification

Real-process fixtures change a control marker during refresh and prove the gate
observes it before any invocation. Tests cover refusal followed by healthy reuse,
invalid input/unsupported output/schema drift/code drift before gate consumption,
cancellation during the gate, pending and non-yielding late gate completion,
post-dispatch invalid output and refusal to reuse a poisoned connection. The
executable demonstration exercises refused and accepted gates with progress.

No external dependencies, persistence format, network path or telemetry fields
change. Rollback restores the previous transport API and inventory-only CLI; no
state migration is needed.
