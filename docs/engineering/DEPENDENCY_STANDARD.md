# Dependency and License Standard

## Default posture

Every dependency is code we are choosing to ship/trust.

Prefer:

- standard library,
- small maintained libraries,
- permissive licenses compatible with Apache-2.0 Runtime / proprietary Platform,
- projects with clear release/security history.

## Runtime restrictions

Before adding a Runtime dependency document/check:

- license,
- transitive dependency count/surface,
- network/telemetry behavior,
- unsafe code implications,
- platform support,
- maintenance cadence,
- whether it runs on the sensitive request path.

Avoid AGPL/SSPL/source-available dependencies without explicit legal/owner approval.

## Platform restrictions

Private/proprietary Platform still requires license review. "Server-side" does not automatically make every license acceptable.

## Active architecture choices

- Regorus: embedded Rego interpreter decision for Runtime policy.
- OpenTelemetry: preferred observability interoperability layer where needed.
- LiteLLM: not a mandatory Runtime request-path dependency; may be used later only as an optional/reference/long-tail compatibility layer after license/architecture review.
- Pydantic AI/Harness: parked future Work/Evals implementation candidate, not current MCP dependency.

## Locking and review

- commit lockfiles,
- automated vulnerability/license scan,
- Dependabot/Renovate-style updates may open PRs but do not auto-merge security-sensitive dependency changes without tests/review,
- major-version updates require release notes/migration review,
- new cryptography should use well-reviewed libraries, never custom primitives.
