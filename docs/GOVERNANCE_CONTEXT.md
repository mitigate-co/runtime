# Inspect local governance references

Use `mcp context` to get the exact caller, reviewed launch and tool references used
by the governed gateway. These are the values to select in grant scopes and exact
control targets. Do not substitute scanner names or declared-server fingerprints.

```sh
mitigate mcp context --allow-exec --launch-config launch.json --launch-review review.json --tool-snapshot snapshot.json --profile profile.json
```

Add `--json` for a machine-readable report. These filenames refer to your own
reviewed files from [launch review](LAUNCH_REVIEW.md),
[inspection/snapshots](FINGERPRINTS.md) and [caller profiles](GATEWAY.md#identity).
Use the same optional `--classification-overrides FILE` as the intended gateway.
No policy, grant or authority database needs to exist yet.

The command explicitly starts the selected program with your OS privileges and
configured credential bindings, initializes MCP, compares its definitions against
the selected snapshot and then confirms cleanup. It never calls a tool or changes
grants/authority stores. This is process execution, not a passive config scan.
Invalid profiles, review files, snapshots or override documents fail before launch.
Observed drift and stale bound overrides fail with no partial report. Normal
operational errors remain fixed and content-free.

An omitted profile reports unknown attribution and null caller references. It
does not invent a client from `clientInfo`; unknown callers cannot receive an
allowance. An explicit profile reports `declared_profile`, not authenticated
enterprise identity. Profile labels are hashed with the same domain separation
as local audit. These hashes are local identifiers, not anonymized telemetry.

## JSON contract

Version 1 contains exactly:

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `client_ref`, `principal_ref`, `agent_ref` | Local 64-character reference, or `null` when unknown |
| `attribution` | `unknown` or `declared_profile` |
| `server_ref` | Verified exact launch reference |
| `tools` | Tools sorted by name, at most 512; empty when none are available |

Each tool contains `name`, `tool_ref`, `schema_fingerprint`,
`definition_fingerprint` and `capability_classes`. It contains no raw schemas,
descriptions, arguments, results, credential values or arbitrary MCP metadata.
Tool names are local operator labels, not a telemetry field. The report neither
evaluates policy nor grants authority; all values are checked again by enforcement.

## Apply a scope

For a reviewed tool, copy `client_ref` to a grant's `scope.client`, `server_ref` to
`scope.server`, and its `tool_ref` to `scope.tool`. Use any known principal/agent
references to narrow further. Select explicit capability and environment limits
according to your policy, and set time bounds when needed. Every nullable scope
field must be present; a `null` constraint is a wildcard, not a requirement that
the corresponding caller fact be unknown. Follow the complete [grant format](GRANTS.md).

Validate the resulting document with `mcp grants check --rules FILE`. Exact control
targets use the same references; see [controls](CONTROLS.md). A report is not an
approval token and does not authorize an action. New launch reviews or changed
definitions require fresh context inspection and deliberate scope review.

The executable governance fixture obtains these references through the real CLI,
uses them for an exact grant, invokes our synthetic tool and checks that all
caller/tool/definition facts agree with its audit record. It also verifies unknown
identity, human/JSON output, stale-snapshot refusal and content-canary exclusion.
