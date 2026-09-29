# ADR-0046: Keep unresolved release failures in reviewed source

Status: Read-only signing prerequisite implemented; workflow composition pending
Date: 2026-09-29

## Decision

Record public unresolved release-failure issue numbers in a small closed JSON
policy. A signing preflight requires both the selected source policy and the
current protected-main policy to be valid and empty. Issue closure and later
successful runs cannot erase a recorded failure. Removal requires a corrective
reviewed change with technical cause, correction and regression/CI evidence.

Check the exact clean source, direct manual tag workflow and existing reviewed
signing-environment configuration before a downstream privileged job can start.
Read public metadata only; do not create an environment or grant permissions as
a side effect of checking readiness. Real approval remains GitHub's environment
gate, and administrators remain part of the trust boundary.

## Consequences

The policy contains public issue numbers only, never private reports or customer
data. Missing or malformed local/remote evidence fails closed. Current main can
block an otherwise valid older tag. A saved report is not approval, a signature
or a production-ready flag. Native failure causes and authentic release acceptance
still have to be demonstrated; the checker cannot manufacture that evidence.

The documented API does not expose administrator-bypass configuration. Operator
review of that setting remains explicit; the helper makes no unsupported claim
that it has proved the absence of bypass. See [signing prerequisites](../RELEASE_SIGNING_GATES.md).
