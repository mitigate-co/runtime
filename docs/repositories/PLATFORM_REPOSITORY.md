# Private Platform Repository

**Repository:** https://github.com/mitigate-co/platform  
**Visibility:** private/proprietary

## Purpose

Platform is the optional hosted control and intelligence plane around the open Runtime.

Current wedge scope:

- user/account/org,
- Runtime enrollment,
- safe inventory/audit ingest,
- fleet view,
- MCP registry UI/API,
- private registry source collectors/curation,
- aggregate reputation/index logic,
- operational/admin tooling.

## Explicit non-goals during the wedge

Do not build yet:

- full AI governance suite,
- broad FinOps,
- Router,
- Work,
- Evals,
- Trace,
- Behavior,
- Sandbox,
- complex GRC workflows,
- broad endpoint/browser monitoring.

## Data boundary

Platform validates closed Zero-Content schemas. It must reject unknown fields and cannot rely on raw tool payloads to render normal organization inventory/audit views.

## Web product standard

The UI should make the security product easy to understand, not decorate complexity.

Every screen needs:

- clear hierarchy,
- explicit state,
- meaningful empty state,
- actionable errors,
- auditability/provenance where relevant,
- no fake/synthetic real-org metrics.
