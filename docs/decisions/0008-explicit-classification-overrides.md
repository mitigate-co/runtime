# ADR 0008: Bound local classifications with retained risk evidence

Status: accepted. Scope: MCP-005.

## Decision

Classify names and schema property shapes with a deterministic, versioned taxonomy. Treat declarations as untrusted evidence; omit description instructions, examples and default values from rule evaluation. Expose source/confidence and fixed evidence IDs. This is local review information, not permission enforcement or verified tool behavior.

Accept overrides only through an explicit caller-selected file. Bind them to the fingerprint profile, observed server facts and tool identity/input/output/description digests. Reject stale, malformed, duplicate or unmatched overrides. Do not silently skip an intended administrative decision. No new dependencies are required.

An override replaces effective classes while retaining baseline inference and the union of risk flags. This allows explicit administrative classification without concealing dangerous evidence. False-positive warnings may remain after an override; later policy/grants can record the distinct access decision. Never interpret high confidence as a safety score.

Report schema 2 adds classifications and retains existing presence/count fields. Local names and fingerprints are not safe cloud telemetry. Neither overrides nor tool definitions are persisted automatically or transmitted. These unsigned files assume a trusted local administrator; same-user tampering and executable impersonation are not solved by hashing.
