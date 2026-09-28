# Local capability classification

`mitigate mcp inspect --launch-config FILE --allow-exec` enumerates the selected server and classifies its tools. It does not call tools, grant access, block operations or contact Platform. `--json` returns inspection schema **2**, retaining tool names/counts/presence fields and adding `classification` to each tool. The library's older `Inventory::report()` remains schema 1 for inventory-only callers.

## Interpret the report

The closed taxonomy is `read_data`, `write_data`, `delete_data`, `execute_code`, `credential_access`, `external_communication`, `browser_action`, `identity_admin`, `financial_action`, `infrastructure_change`, and `unknown`. Multiple classes can apply.

Each classification has `taxonomy_version: 1`, effective `classes`, `confidence`, `sources`, `flags`, fixed `rules` identifiers, `inferred_classes` and `overridden`. Tool-name words are split at separators and camel-case/acronym boundaries; substrings such as `thread` are not interpreted as `read`. Schema evidence uses property names in nested/composed schemas. Descriptions, examples, defaults, enum/const values and arbitrary annotations cannot supply rules or authority. External schema references are never fetched.

- `low`: name-only evidence or unclassified behavior.
- `medium`: schema property names contribute evidence.
- `high`: an explicit, matching local administrator declaration. This describes the source of the decision, **not** verified safety.

Rules are conservative hints. A tool named `read_status` could execute malicious code; an SQL query could modify data. Generic query/action/operation/payload inputs, unresolved references and open object schemas retain `unknown_high_impact`. JSON Schema allows extra properties when `additionalProperties` is absent, so omission is treated as open. The classifier does not attempt complete JSON Schema evaluation or implementation auditing.

Flags identify potential destruction, credential access, arbitrary code execution, external communication, identity administration, infrastructure change and unknown high-impact behavior. Overrides replace effective classes but preserve inferred classes, fixed rule IDs and the union of inferred/declared flags. A warning cannot disappear merely by relabeling a tool. Later grants and policy decisions are separate controls. Registry evidence is not implemented until MCP-017; no registry provenance is fabricated.

## Administrator overrides

Pass `--classification-overrides FILE` explicitly. Mitigate never discovers this file inside a project. Review and protect it with OS permissions. A process with the same local identity can replace files or impersonate server declarations; fingerprints do not authenticate a server or executable.

The document is strict JSON, at most 256 KiB, with only these fields:

| Field | Value |
| --- | --- |
| `schema_version` | `1` |
| `fingerprint_profile` | `mitigate-local-jcs-sha256-v1` |
| `server_facts` | The fresh local snapshot's server-facts digest |
| `tools` | At most 512 overrides |

Each override copies `identity`, `input_schema`, `output_schema` and `description` digests from a reviewed tool snapshot and adds `classes`. Optional digests use `null` when absent. Tool `name` is not an override field. Classes must be a nonempty unique subset of the taxonomy; `unknown` cannot be combined with another class. Duplicate identities, unknown fields/classes, duplicate JSON keys, invalid digests and unsupported versions/profiles fail.

Every override must match an observed tool. Identity, server version/protocol/capability, input/output schema, description change or removed tool invalidates the applicable file; no partial report or requested snapshot is written. Whitespace-only description edits follow fingerprint normalization. New tools without overrides still receive deterministic classification. An invalid override document is rejected before launching the server.

Use the explicit [snapshot workflow](FINGERPRINTS.md) to review fingerprints. These remain local metadata, not Platform-safe events. Errors are fixed content-free messages. No new dependency, persistent store, telemetry or credentials are introduced.

## Tested fixture

From the repository root in PowerShell 7 or a POSIX shell:

```sh
cargo run --locked -p mitigate-mcp-fixture -- launch-config > target/fixture-launch.json
cargo run --locked -- mcp inspect --launch-config target/fixture-launch.json --allow-exec --classification-overrides examples/classification-overrides.json --json
```

The committed override contains synthetic fixture fingerprints only. It asserts `read_data` for `read_status`; the open-schema risk remains visible. Use your own reviewed snapshot for a real server. Never copy these fixture classifications blindly to another server.
