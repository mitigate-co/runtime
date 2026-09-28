# Changelog

## Unreleased — capability classification

- Inspection JSON advances to schema 2 with a closed capability taxonomy, confidence, evidence sources and risk flags.
- Ignore description instructions and metadata values; retain unknown risk for open or opaque schemas.
- Add explicit local classification overrides bound to server/tool fingerprints. Stale or ambiguous overrides fail without a partial report; inferred risk remains visible.

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
