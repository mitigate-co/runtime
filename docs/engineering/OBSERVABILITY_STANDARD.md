# Observability Standard

## Goal

Know whether Mitigate works without collecting the content it protects.

## Runtime metrics

Safe metrics include:

- scan duration/counts,
- servers/tools discovered,
- gateway calls by result class,
- policy decision counts,
- approval latency/outcomes,
- upstream error classes,
- egress accepted/rejected counts,
- local queue depth,
- runtime version/health,
- update status.

## Platform metrics

- request/error/latency,
- auth failures,
- enrolled runtime health,
- ingest accepted/rejected,
- queue depth/age,
- DB latency/connections,
- tenant authorization denials,
- registry collector health,
- backup/restore-test health.

## Logging

Use structured logs with:

- timestamp,
- level,
- subsystem,
- event/error code,
- safe opaque IDs,
- request/span ID,
- bounded message.

No raw content/secret fields.

## Tracing

OpenTelemetry is preferred where it helps diagnose Platform/runtime control flows. Do not attach raw MCP payloads as span attributes/events.

## Diagnostics bundle

A support bundle should contain:

- versions,
- configuration shape with secrets removed,
- health state,
- safe logs,
- schema versions,
- policy bundle version,
- counts/error classes.

It must run a privacy scan before export.
