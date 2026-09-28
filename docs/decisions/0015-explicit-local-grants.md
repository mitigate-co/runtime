# ADR 0015: Explicit local grant matching

Status: Implemented (MCP-012; enforcing gateway integration remains a launch gate)

## Decision

Implement bounded, immutable grant rules in `mitigate-policy::grants` using the
existing strict JSON parser, closed capability taxonomy and fingerprint type.
No new dependency or permission language is needed. The matcher is pure and takes
explicit action facts and time; it has no filesystem, credential or network side
effects. CLI commands provide local validation and deterministic test resolution.

Every nullable scope constraint must be written explicitly. Null is a wildcard in
rules and unknown in context; those meanings never become an inferred identity.
Exact references are case-sensitive. A known client is mandatory for allowance.
Principal and agent may remain unknown when the rule explicitly permits them.

All matching denials take precedence over all allowances. A denial capability list
matches any intersection; an allowance must independently cover the complete
action's classes. Partial allowances cannot be unioned to invent permission for
a combined action. Rule order/specificity does not grant exceptions. Return sorted
references for the winning effect so tests and local audit composition can explain
the same decision consistently.

Time windows are inclusive-start/exclusive-end UTC milliseconds. Empty or reversed
windows are errors. Environments are bounded exact labels selected by the operator.
There are at most 64 rules in 32 KiB, and action fixtures are at most 4 KiB. Invalid
rules reject the complete document, with content-free errors.

## Trust boundary and composition

Grant files are protected local administrator configuration, not automatically
trusted cloud input. The matcher does not authenticate a client or a process.
Only trusted gateway composition may supply action facts; unknown attribution
remains unknown. Reviewed launch/tool binding is required before enabling calls.
Tool names, descriptions and self-declared identities are not sufficient authority.

The grant resolution exposes a policy state and a constraining operation: absent
or denied grants force denial independently of policy output. An explicit grant
does not bypass a policy denial, approval, schema check, kill switch or rate limit.
No execution entry point is enabled by this package. The result is not a reusable
token; expiry and all action facts must be checked again before dispatch.

An immutable loaded set supports local operation without Platform. A replacement
must parse completely before swap. Clock integrity, durable update/version
handling and enforcing-call composition belong to the respective gateway/offline
packages; the pure evaluator makes no claim to prevent privileged clock rollback.

## Consequences and verification

This model deliberately omits priorities, inheritance and wildcard patterns. It
can express per-principal, agent, client, server, tool, capability, environment and
time constraints with predictable deny precedence. Administrators requiring a
principal must constrain it explicitly; a broad wildcard rule is intentionally
broad. Hash references are local data and are not anonymized telemetry.

Tests cover every exact dimension, unknown identity, order/specificity conflicts,
half-open windows, complete capability subset/overlap combinations, non-combining
allowances, missing fields, duplicates, bounds and independent policy constraints.
Actual CLI fixtures cover successful and rejected documents with diagnostic
canaries. No migration is required for existing inventory-only installations.
Rollback removes the opt-in commands; retain local administrator files unchanged.
