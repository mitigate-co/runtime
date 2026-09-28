# Governed local tool calls

`mcp serve --enforce FILE` joins launch review, schema validation, policy, grants,
approvals, controls and required audit on one local stdio connection. It needs no
Platform account or network connection. This is an explicit mode: existing
`--inventory-only` clients continue to refuse every call. The remaining production
gates are tracked in [implementation status](IMPLEMENTATION.md).

## Start a reviewed connection

First use [local context inspection](GOVERNANCE_CONTEXT.md) to obtain the exact
references for grant scopes and control targets; no manual hash calculation is
required. It uses the same reviewed inputs as enforcement and invokes no tools.

Configure the MCP client to launch the following command with your selected files:

```sh
mitigate mcp serve --allow-exec --launch-config launch.json --launch-review review.json --profile profile.json --enforce governance.json
```

The command is a stdio endpoint, not an interactive terminal. Paths inside the
governance document must be absolute. The paths on the command line may be relative.
`--inventory-only`, `--audit-db` and `--json` conflict with `--enforce`: the selected
governance document owns its required audit store. A launch review is mandatory.
An omitted profile leaves the caller unknown and denies calls; `clientInfo` and
request metadata never establish an identity.

The governance document is strict JSON, at most 16 KiB, with exactly these fields:

| Field | Required value |
| --- | --- |
| `schema_version` | `1` |
| `policy_db` | Existing [policy database](POLICY.md) with an activated signed bundle |
| `policy_authority` | Separately pinned policy authority JSON file |
| `grants` | Complete local [grant rules](GRANTS.md) JSON file |
| `approvals_db` | Existing [approval database](APPROVALS.md) |
| `controls_db` | Existing [control database](CONTROLS.md) |
| `audit_db` | Existing [audit database](AUDIT.md) |
| `tool_snapshot` | Reviewed snapshot saved by `mcp inspect --snapshot NEW_FILE` |
| `classification_overrides` | Absolute path to bound local overrides, or explicit `null` |
| `environment` | 1–64 ASCII letters/digits/`_.-`, or explicit `null` |
| `approval_timeout_ms` | Integer from 100 through 270,000 |

Use private local directories and the documented initialization commands. The
gateway neither creates missing authority stores nor silently repairs corrupt
ones. Duplicate/unknown fields, missing explicit nulls and relative internal
paths fail startup before the child is launched. Launch review verifies the
executable and selected artifacts. After enumeration, definitions must match the
reviewed snapshot and any classification overrides before the listener starts.

## One call, one decision

1. Validate input/output schema support and the arguments before requesting human
   work. Raw arguments remain in the request future; they are not policy input.
2. Evaluate the verified policy and current grants against the fixed declared
   caller, reviewed launch, tool definition, capability classes and environment.
   Check the current kill switch, disables and quota availability without charging.
3. If required, create an approval bound to this session and call. Wait within
   the configured deadline, while continuing to handle ping and cancellation.
   Recheck policy, grants and controls during the wait.
4. Revalidate schemas/arguments, refresh upstream definitions and verify selected
   code again. Only then enter the final authorization gate: reevaluate policy
   and grants, atomically admit controls, consume any approval once, and durably
   append the dispatch audit record before sending the call.
5. Validate the result and commit a correlated completion record before returning
   it. Raw arguments/results, descriptions and MCP metadata never enter these
   local authority databases. Operational errors use fixed categories.

Every allowed invocation is `allow_and_log`. A denial or invalid request records
`not_invoked` if dispatch was not attempted. After dispatch admission, errors,
cancellation or missing results are conservatively `uncertain`, never evidence
that side effects were rolled back. A successful MCP result with `isError: true`
records `error`. No call is automatically retried.

While waiting, use `mcp approvals list/show` to inspect metadata and `approve/deny`
with an explicit declared operator reference and confirmation. Raw arguments are
deliberately absent from the approval database; review them in the trusted local
client when needed. Approval alone neither grants access nor overrides policy.
Expiry, denial, revocation, context change or unavailable approval storage prevents
dispatch. A policy version change cancels a pending approval even if the new
policy would otherwise allow the call. Start a fresh request for the new context.

## Authority and lifetime

The launch, caller, snapshot, classification overrides and environment are fixed
for the session. Grants are reloaded at each authorization check. A verified
newer policy becomes active on recheck. An invalid/missing refreshed policy leaves
the already verified in-memory policy active and emits one fixed warning per
failure period. Fresh processes still require valid local stores and a verified
bundle. `offline` is currently `true`: this gateway has no Platform channel.

See [offline operation and recovery](OFFLINE.md) for cache, restart and unavailable
approval behavior and the executable outage contract.

Server references use the reviewed `launch_ref`, not a server's claimed name.
Tool identity hashes `[launch_ref, tool_name]` in the `tool-identity` domain.
Definition identity hashes the closed object `tool`, `input_schema`,
`output_schema`, `description` in the `governed-tool-definition` domain, using
the existing input/output/normalized-description fingerprints and explicit nulls
for absent output or description. See [fingerprinting](FINGERPRINTS.md). These
local references are not anonymized telemetry or publisher authentication.

Control admission, approval consumption and audit are separate durable commits.
They do not form a transaction with the process pipe. A failure after a quota
charge or approval consumption does not refund or revive either. The dispatch
record means permission was committed, not proof that the server executed the
call. Its append can itself have an uncertain outcome; cleanup records uncertainty
when possible. A missing completion after an abrupt crash must remain unknown.
Inspect local records before deciding whether a new request is appropriate.

Stops and revocations take effect at their admission/consumption boundary; they
cannot undo already admitted or completed effects. Cancellation drops the only
future that owns the transport, terminates the upstream, then finishes queued
metadata cleanup. Blocking storage workers never own arguments or an upstream
handle, so a late worker completion cannot invoke a tool. Cleanup failure produces
a fixed diagnostic and exit 2, not a success claim.

Native credentials needed for MCP initialization are injected at the explicitly
authorized process launch. They remain available to that selected process; this
is not a per-call secret lease or a sandbox. See [secret lifetime](SECRETS.md).

## Protocol and recovery

The listener budget is the configured approval timeout plus 30 seconds, at most
five minutes. The upstream's own configured timeout also applies. Pings remain
available during a call. Matching cancellation, EOF and shutdown end the session;
start a new connection rather than reusing an uncertain response stream.

When requested, progress forwards only finite increasing counters and the current
downstream token. Message text, upstream tokens and other metadata are discarded.
Intermediate counters may coalesce; buffering stays constant.

| MCP error | Meaning and next action |
| --- | --- |
| `-32602` | Invalid tool/arguments or unsupported schema; inspect the local contract |
| `-32001` | Authority denied, approval unavailable/expired, or context changed; review local decisions |
| `-32003` | Upstream/schema-result failure; outcome may be uncertain, do not automatically retry |
| `-32004` | Reviewed definitions or selected code changed; inspect before creating a new review |
| `-32007` | Required audit could not commit; inspect storage and retained records |
| `-32008` | Local governance unavailable; inspect authority stores, grants and clock |
| `-32009` | Emergency stop or exact disable applies; review controls |
| `-32010` | Admission quota exhausted; inspect configured limits |

Existing session timeout, busy and protocol errors remain documented in
[the gateway reference](GATEWAY.md). No provider error text is exposed as a fault.

## Executable verification

```sh
cargo build --workspace --locked
target/debug/mitigate-test-mcp governance-contract target/debug/mitigate
```

Append `.exe` to both paths on Windows. This runs only our synthetic MCP server
and isolated temporary authority stores: allowed/denied calls, unknown identity,
approval consumption/expiry/cancellation, live policy/grant/control changes,
schema drift, invalid output, audit failure, bounded progress and cancellation
after dispatch. It also checks approval revocation and stops applied during the
final inventory refresh, policy replacement while waiting, invalid authority
before launch and stale initial definitions. It checks invocation markers and audits, and scans stores and
diagnostics for synthetic content canaries. It sends no provider messages.
