# Mitigate Documentation Standard

## Principle

Documentation is part of the implementation. A security product with undocumented trust boundaries is unfinished.

## Audience layers

### README

Gets a competent person from zero to first successful use quickly.

### Product/high-level docs

Explain customer problem, guarantees, limitations, workflows and success criteria.

### Low-level engineering docs

Explain architecture, types, protocols, state machines, failure behavior, work packages and test requirements.

### ADRs

Explain consequential decisions and alternatives.

### Runbooks

Explain operational action during incidents/failures.

### API/schema docs

Are exact contracts, not marketing prose.

## Required documentation qualities

- concise title and status,
- owner/source-of-truth where relevant,
- exact terminology used consistently,
- diagrams using text/Mermaid where maintainable,
- examples that match real interfaces,
- known limitations stated plainly,
- no unsupported marketing claims,
- link to canonical docs rather than copy/pasting large boilerplate blocks.

## Code examples

Examples are either:

- tested/compiled in CI, or
- clearly labeled pseudocode.

Stale snippets are bugs.

## Security/privacy documentation

Every trust-boundary feature documents:

- data entering,
- data leaving,
- secrets involved,
- storage/retention,
- failure/offline behavior,
- customer controls,
- known blind spots.

## Diagrams

Prefer diagrams that communicate a decision. Avoid decorative boxes that add no information.

## Changelog discipline

User-visible behavior changes belong in release notes/changelog.

Security-sensitive changes note whether they:

- alter telemetry,
- alter local retention,
- alter permissions,
- alter policy defaults,
- alter update/signing behavior.

## Writing style

Write like an engineer talking to another capable engineer:

- direct,
- specific,
- no hype,
- no filler,
- define unusual terms,
- distinguish fact, target and aspiration.

Avoid phrases like "enterprise-grade" unless the document names the concrete controls that justify it.
