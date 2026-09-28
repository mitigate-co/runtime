# ADR-0001: Public Runtime and Private Platform

Status: Accepted  
Date: 2026-09-27

## Context

Mitigate's differentiator depends on customers trusting customer-side code that inspects sensitive MCP/AI activity. A closed binary with a vendor-written self-test is not independent evidence. At the same time, hosted intelligence/curation/analytics provide proprietary value and do not need public source.

## Decision

Use two canonical repositories:

- `mitigate-co/runtime` — public Apache-2.0 customer-side trust layer.
- `mitigate-co/platform` — private proprietary hosted control/intelligence plane.

## Consequences

- Runtime code must be audit-friendly and release provenance must map binaries to source.
- Platform cannot become required for local scanner/gateway function.
- APIs/protocols between repositories must be explicit and versioned.
- Proprietary logic must not leak into Runtime commits/history.
