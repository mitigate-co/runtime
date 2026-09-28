# Changelog

## Unreleased — local audit

- Add bounded SQLite audit with a closed metadata schema, transactional retention and a verifiable hash chain.
- Add explicit initialization, verification, paginated reads and confirmed pruning. Reject corruption and incompatible schemas without resetting them.
- Record completed inventory requests and denied calls with `serve --audit-db`; refuse responses/startup when required storage fails.
- Verify corruption, rotation, competing writers, disk capacity, private files and real CLI/gateway privacy boundaries. No raw payload storage or Platform sync is added.

## Unreleased — native secret broker

- Store credentials in the current user's native OS store and reference them with opaque IDs in reviewed launch documents.
- Add pipe-only import/rotation, content-free availability checks and explicit deletion.
- Resolve all credential bindings before launch, clear owned values, reject name conflicts and refuse ambient fallback.
- Test actual native store operations and child injection with temporary synthetic credentials. No Platform or plaintext fallback is required.

## Unreleased — inventory gateway CLI

- Add explicit `mcp serve --inventory-only` with reviewed launch intent, optional caller profile and MCP-only stdout.
- List real upstream definitions with bounded pagination; reject all calls until later policy/grant integration.
- Confirm cleanup during startup cancellation and bound executable shutdown when stdin remains open. Add actual CLI/upstream/pagination/deadline verification.

## Unreleased — managed stdio upstream

- Retain initialized upstream connections with fresh inventory comparison before calls and correlated progress counters.
- Reject schema drift, invalid results and mismatched responses; terminate and invalidate connections after failure or cancellation.
- Add real-process hostile/cancellation fixtures. Authorization remains the gateway owner's responsibility; no unchecked CLI call path is added.

## Unreleased — gateway listener

- Add a bounded stdio-compatible protocol listener and immutable explicit caller profiles; unconfigured attribution stays unknown.
- Enforce initialization, unique request IDs, deadlines and cancellation-safe framing; keep operational errors content-free.
- Add a local listener contract demonstration and hostile protocol/race tests. CLI/upstream integration follows in MCP-008; no permissive call path is exposed.

## Unreleased — CLI usability

- Add compact scan/inspection tables and `--details` with full labels and review guidance.
- Add opt-in findings exits: `--fail-on-risk` and `--fail-on-change` return 3 while retaining complete JSON reports.
- Make parser failures content-free and versioned in JSON mode; add terminal-control escaping and a real-binary cross-platform contract harness.

## Unreleased — capability classification

- Inspection JSON advances to schema 2 with a closed capability taxonomy, confidence, evidence sources and risk flags.
- Ignore description instructions and metadata values; retain unknown risk for open or opaque schemas.
- Add explicit local classification overrides bound to server/tool fingerprints. Stale or ambiguous overrides fail without a partial report; inferred risk remains visible.
- Correct Windows job completion checks with a pinned source patch: wait for zero active members, including after parent exit and cancelled waits.

## Unreleased — fingerprints and diff

- `mcp inspect --snapshot` writes an explicit new local fingerprint snapshot; `mcp diff` compares snapshots without executing a server.
- Separate identity, input/output schema, normalized description and server-facts fingerprints with canonical JSON and distinct hash domains.
- Reject incompatible/ambiguous snapshots and numeric constraints that cannot fit the safe canonical profile without loss.
- Discovery output advances to schema v2 with a fingerprint of redacted summary facts; this is not exact executable/argument provenance.

## Unreleased — explicit tool enumeration

- `mcp inspect` starts a reviewed stdio MCP server only with `--allow-exec`, negotiates a supported version and enumerates tools without calling them.
- Bound protocol messages, pagination, tool counts and deadlines; reject ambiguous responses and inventory changes.
- Isolate environment inheritance, suppress upstream error/stderr content and terminate process groups/jobs on completion, timeout and cancellation.

## Unreleased — scanner sources

- Read-only discovery of Claude Code and Cursor repository configurations with human and JSON output.
- Report configuration risks without launching servers, expanding variables, opening referenced files, or transmitting data.
- Reject ambiguous, malformed, oversized and linked configuration sources; exclude credentials, raw arguments and URL paths from reports.

## Unreleased

- Add standalone `mitigate version` and strict `mitigate config check` commands.
- Configuration validation has no account, credential, network, or subprocess dependency.
- Establish Windows/Linux/macOS checks and dependency/license/secret gates.
