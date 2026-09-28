# ADR 0026: Public source-attributed registry facts

Status: Accepted for the Runtime registry contract/client.

## Context

MCP-017 needs a source import model, public facts and CLI lookup. Untrusted registry
data must not become an unsourced accusation, grant, executable installation
instruction or mandatory online dependency. Private collector/curation logic
belongs in Platform, not the public customer-side repository.

## Decision

Define a small closed public catalog in `mitigate-registry`. Each bounded typed
assertion retains its source, declared observation time and publisher-declared
confidence. Validate canonical public identifiers/references, JSON structure,
limits and provenance relationships. Require an explicit local file for the
initial CLI reader. Do not fetch links or derive subjects from private inventory.

Keep conflicting claims. Show unsigned publisher status and catalog freshness;
unknown/stale data does not imply safety. No Runtime classification, grant or
policy input is changed by lookup. This output is not a telemetry contract.

Use existing dependencies. Add a separate public API client only alongside a
specified hosted endpoint and explicit privacy/transport behavior. Keep collector
credentials, import execution and proprietary judgment in the private repository.

## Consequences

The contract/client can be tested without accounts or a hosted dependency.
Schemas, examples and abuse tests travel with the public trust layer. This does
not establish authenticity, completeness, advisory applicability or risk scores.
The explicit file is a trusted-parent read and is not resistant to same-user
replacement. Platform source import/API/UI and enrollment remain outstanding
work; the Runtime file reader alone does not complete the hosted registry gate.
